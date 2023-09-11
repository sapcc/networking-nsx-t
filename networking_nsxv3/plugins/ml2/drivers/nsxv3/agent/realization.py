import eventlet
eventlet.monkey_patch()

import time
import json
import itertools
from typing import Callable, List, Set, Tuple
from networking_nsxv3.common.constants import MP2POLICY_NSX_MIN_VERSION, MP2POLICY_STATES, NSXV3_MIGRATION_SUCCESS_TAG, NSXV3_MP_MIGRATION_SCOPE
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider,\
    provider_nsx_mgmt as m_prvdr, provider_nsx_policy as p_prvdr, mp_to_policy_migration as mi_prvdr
from networking_nsxv3.api.rpc import NSXv3ServerRpcApi
from oslo_config import cfg
from oslo_log import log as logging


LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class AgentRealizer(object):

    MIGR_IN_PROGRESS_MSG = "Migration is in progress. Skipping '{}'."

    def __init__(
        self,
        rpc: NSXv3ServerRpcApi,
        callback: Callable[[List or str, Callable[[str], None]], None],
        kpi: Callable[[], dict],
        mngr_provider: m_prvdr.Provider,
        plcy_provider: p_prvdr.Provider,
        migr_provider: mi_prvdr.Provider = None
    ):
        self.rpc = rpc
        self.callback = callback
        self.kpi = kpi

        self.mngr_provider = mngr_provider
        self.plcy_provider = plcy_provider
        self.migration_tracker = provider.MigrationTracker(self.plcy_provider)

        self.AGE = int(time.time())

        LOG.info("Detected NSX-T %s version.", self.mngr_provider.client.version)

        self.mp_to_policy_completed = self._check_mp_to_policy_completed()

        # Enable MP-to-Policy migration if force_mp_to_policy=True
        # It is used as a flag for using Policy API completely or not
        # in case migration canceled or failed this flag will be False
        # TODO: After completing the transition to NSX Policy API (ONLY if successful!), deprecate this flag
        self.USE_POLICY_API = self.mp_to_policy_completed or self._check_mp2policy_support()

        if self.mp_to_policy_completed:
            self._dryrun()
            return

        if self.USE_POLICY_API:
            self._try_start_migration()
        else:
            self._dryrun()

    def _check_mp_to_policy_completed(self):
        return any([t for t in self.plcy_provider.zone_tags
            if t.get("scope") == NSXV3_MP_MIGRATION_SCOPE and t.get("tag") == NSXV3_MIGRATION_SUCCESS_TAG])

    @staticmethod
    def _os_meta(query: Callable):
        step = cfg.CONF.AGENT.rpc_max_records_per_query
        cursor = 0
        meta = dict()
        while cursor != -1:
            result = query(step, cursor)
            meta.update({id: rev for id, rev, _ in result})
            cursor = result[-1][2] if len(result) >= step else -1
        return meta

    def refresh(self, list_aged: Set[Tuple[str, str, int]]):
        # TODO: mngr has to be removed after POLICY is fully supported
        provider = self.plcy_provider if self.USE_POLICY_API else self.mngr_provider

        for o in list_aged:
            if o[0] == provider.PORT:
                self.callback(o[1], self.port)
            elif o[0] == provider.QOS:
                self.callback(o[1], self.qos)
            elif o[0] == self.plcy_provider.SG_RULES:
                self.callback(o[1], self.security_group_rules)
            elif o[0] == self.plcy_provider.SG_MEMBERS:
                self.callback(o[1], self.security_group_members)

    def all(self, dryrun=False):
        """
        Enforce desired state between OpenStack and Provider objects
        Objects concidered outdated include new, updated or removed

        :force: bool -- if True concider all objects as outdated
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('synchronization')}")
            return
        with LockManager.get_lock("all"):
            if self.kpi().get("passive") > 0:
                return

            _slice = cfg.CONF.AGENT.synchronization_queue_size
            r = self.rpc

            # TODO: mngr has to be removed after POLICY is fully supported
            provider = self.plcy_provider if self.USE_POLICY_API else self.mngr_provider

            port_meta = self._os_meta(r.get_ports_with_revisions)
            sg_meta = self._os_meta(r.get_security_groups_with_revisions)
            qos_meta = self._os_meta(r.get_qos_policies_with_revisions)

            # Refresh entire metadata with its latest state
            LOG.info("Inventory metadata is going to be refreshed.")

            # Force networks refresh, only
            provider.metadata_refresh(provider.NETWORK)

            port_outdated, port_current = provider.outdated(provider.PORT, port_meta)
            sgr_outdated, sgr_current = self.plcy_provider.outdated(provider.SG_RULES, sg_meta)
            qos_outdated, qos_current = provider.outdated(provider.QOS, qos_meta)

            # There is not way to revision group members but can 'age' them
            sgm_outdated, sgm_maybe_orphans = self.plcy_provider.outdated(
                provider.SG_MEMBERS, {sg: 0 for sg in sg_meta})
            LOG.info("Inventory metadata have been refreshed.")

            if dryrun:
                LOG.info("Dryrun:%s. Metadata refresh completed.", dryrun)
                return

            # Don't count ports into synchronization limit, since they could exhaust the worker queue
            # and cause the agent to be stuck.
            outdated = list(itertools.islice(port_outdated, _slice))
            _slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:Ports", len(outdated), len(port_outdated))
            self.callback(outdated, self.port)
            if _slice <= 0:
                return

            outdated = list(itertools.islice(sgr_outdated, _slice))
            _slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:Security Group Rules", len(outdated), len(sgr_outdated))
            self.callback(outdated, self.security_group_rules)
            if _slice <= 0:
                return

            # sgm_outdated only includes missing objects, orphans are removed by ageing
            outdated = list(itertools.islice(sgm_outdated, _slice))
            _slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:Security Group Members", len(outdated), len(sgm_outdated))
            self.callback(outdated, self.security_group_members)
            if _slice <= 0:
                return

            outdated = list(itertools.islice(qos_outdated, _slice))
            _slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:QoS", len(outdated), len(qos_outdated))
            self.callback(outdated, self.qos)
            if _slice <= 0:
                return

            return self._age_cycle(_slice, port_current, sgr_current, qos_current, sgm_maybe_orphans)

    def _age_cycle(self, _slice, port_current, sgr_current, qos_current, sgm_maybe_orphans):
        # TODO: mngr has to be removed after POLICY is fully supported
        provider = self.plcy_provider if self.USE_POLICY_API else self.mngr_provider

        current = provider.age(provider.PORT, port_current)
        current += self.plcy_provider.age(provider.SG_RULES, sgr_current)
        current += self.plcy_provider.age(provider.SG_MEMBERS, sgm_maybe_orphans)
        current += provider.age(provider.QOS, qos_current)

        # Sanitize when there are no elements or the eldest age > current age
        aged = [entry for entry in current if entry[2] and int(entry[2]) <= self.AGE]
        LOG.info("Items outdated since last Agent sanitize:%d", len(aged))
        if aged:
            aged = set(itertools.islice(aged, _slice))
            LOG.info("Refreshing %s of least updated resources", len(aged))
            self.refresh(aged)
        else:
            LOG.info("Sanitizing provider based on age cycles")
            sanitize = self.plcy_provider.sanitize(_slice)

            for id, callback in sanitize:
                self.callback(id, callback)

            _slice -= len(sanitize)
            if _slice <= 0:
                return

            self.AGE = int(time.time())

    def security_group_members(self, os_id: str, reference=False):
        """
        Realize security group members state.
        Realization will happen only if the group has active ports on the host
        or if it used as remote security group by a group having such ports.
        :os_id: -- OpenStack ID of the Security Group
        :reference: -- if True will create the group if unknown by the provider
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('security_group_members realization')}")
            return
        with LockManager.get_lock("member-{}".format(os_id)):
            pp = self.plcy_provider
            meta = pp.metadata(pp.SG_MEMBERS, os_id)
            if not (reference and meta):
                if self.rpc.has_security_group_used_by_host(os_id):
                    cidrs = self.rpc.get_security_group_members_effective_ips(os_id)
                    port_ids_with_sg_count = self.rpc.get_security_group_port_ids(os_id)
                    max_sg_tags = min(cfg.CONF.AGENT.max_sg_tags_per_segment_port, 27)

                    filtered_port_ids = [p["port_id"] for p in port_ids_with_sg_count if int(p["sg_count"]) > max_sg_tags]

                    paths = [p.path for p in pp.get_port_meta_by_ids(filtered_port_ids)] if filtered_port_ids else []

                    # SG Members are not revisionable, use default "0"
                    pp.sg_members_realize({"id": os_id, "cidrs": cidrs, "revision_number": 0, "member_paths": paths})
                else:
                    pp.sg_members_realize({"id": os_id}, delete=True)

    def security_group_rules(self, os_id: str):
        """
        Realize security group rules state.
        Realization will happen only if the group has active ports on the host.
        :os_id: -- OpenStack ID of the Security Group
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('security_group_rules realization')}")
            return
        with LockManager.get_lock("rules-{}".format(os_id)):
            os_sg = self.rpc.get_security_group(os_id)

            if os_sg and os_sg.get("ports"):
                # Create Members Container
                self.security_group_members(os_id, reference=True)

                os_sg["rules"] = self.rpc.get_rules_for_security_group_id(os_id)

                for os_rule in os_sg["rules"]:
                    remote_id = os_rule.get("remote_group_id")
                    if remote_id:
                        self.security_group_members(remote_id, reference=True)

                logged = self.rpc.has_security_group_logging(os_id)
                LOG.info(f"Neutron DB logged flag for {os_id}: rpc.has_security_group_logging(os_id): {logged}")
                self.plcy_provider.sg_rules_realize(os_sg, logged=logged)

            else:
                self.plcy_provider.sg_rules_realize({"id": os_id}, delete=True)
                # Skip members as they can be used as references

    def precreate_port(self, os_id: str, network_meta: dict):
        """
        Try to precreate port on first binding request.
        :os_id: -- OpenStack ID of the Port
        :network_meta: -- NSX Switch metadata
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('port realization')}")
            return
        with LockManager.get_lock("port-{}".format(os_id)):
            port: dict = self.rpc.get_port(os_id)
            if port:
                os_qid = port.get("qos_policy_id")
                if os_qid:
                    self.qos(os_qid, reference=True)

                if not port.get("vif_details") and network_meta:
                    port["vif_details"] = network_meta
                self._port_realize(port)

    def precreate_unbound_port(self, os_id: str, network_meta: dict):
        """
        Try to precreate port on multiple binding ports, fetch port from active binding.
        :os_id: -- OpenStack ID of the Port
        :network_meta: -- NSX Switch metadata
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('port realization')}")
            return
        with LockManager.get_lock("port-{}".format(os_id)):
            port: dict = self.rpc.get_port_from_any_host(os_id)
            if port:
                port.pop("vif_details", None)
                os_qid = port.get("qos_policy_id")
                if os_qid:
                    self.qos(os_qid, reference=True)

                if network_meta:
                    port["vif_details"] = network_meta

                self._port_realize(port)

    def port(self, os_id: str):
        """
        Realize port state.
        :os_id: -- OpenStack ID of the Port
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('port realization')}")
            return
        with LockManager.get_lock("port-{}".format(os_id)):
            port: dict = self.rpc.get_port(os_id)
            if port:
                if port.get("binding_status") == "INACTIVE":
                    # port pre-creation happens in get_network_bridge - if that fails, we let the agent loop take care of
                    # fixing the (vmotioned) segment port after migration is finished.
                    # Otherwise, we would risk a duplicate port due to race condition with vmotion
                    LOG.info("Skipping realization of port %s with status %s", os_id, port.get("binding_status"))
                    return
                LOG.info("realization of port %s with status %s", os_id, port.get("binding_status"))
                os_qid = port.get("qos_policy_id")
                if os_qid:
                    self.qos(os_qid, reference=True)
                self._port_realize(port)
            else:
                LOG.info("deletion realization of port %s", os_id)
                self._port_realize({"id": os_id}, delete=True)

    def qos(self, os_id: str, reference=False):
        """
        Realize QoS Policy state.
        :os_id: -- OpenStack ID of the QoS Policy
        :reference: -- If True will create policy if unknown by the provider
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('qos realization')}")
            return
        with LockManager.get_lock("qos-{}".format(os_id)):
            # TODO: mngr has to be removed after POLICY is fully supported
            provider = self.plcy_provider if self.USE_POLICY_API else self.mngr_provider

            meta = provider.metadata(provider.QOS, os_id)
            if not (reference and meta):
                qos = self.rpc.get_qos(os_id)
                if qos:
                    self._qos_realize(os_qos=qos)
                else:
                    self._qos_realize(os_qos={"id": os_id}, delete=True)

    def network(self, os_seg_id: str):
        """
        Realize Network state.
        :os_seg_id: -- OpenStack Network Segmentation ID
        :return: -- provider ID for the network
        """
        if self.migration_tracker.is_migration_in_progress():
            LOG.info(f"{self.MIGR_IN_PROGRESS_MSG.format('network realization')}")
            return {}
        with LockManager.get_lock("network-{}".format(os_seg_id)):
            # TODO: mngr has to be removed after POLICY is fully supported
            provider = self.plcy_provider if self.USE_POLICY_API else self.mngr_provider
            meta = provider.network_realize(os_seg_id)
            return {"nsx-logical-switch-id": meta.unique_id, "external-id": meta.id, "segmentation_id": os_seg_id}

    def enable_policy_logging(self, log_obj: dict):
        """
        Realize security policy logging state enablement.
        :os_seg_id: -- OpenStack Security Group ID
        :return: -- None
        """
        with LockManager.get_lock("rules-{}".format(log_obj['resource_id'])):
            self.plcy_provider.enable_policy_logging(log_obj)

    def disable_policy_logging(self, log_obj: dict):
        """
        Realize security policy logging state disablement.
        :os_seg_id: -- OpenStack Security Group ID
        :return: -- None
        """
        with LockManager.get_lock("rules-{}".format(log_obj['resource_id'])):
            self.plcy_provider.disable_policy_logging(log_obj)

    def update_policy_logging(self, log_obj: dict):
        """
        Realize security policy logging state update.
        :os_seg_id: -- OpenStack Security Group ID
        :return: -- None
        """
        with LockManager.get_lock("rules-{}".format(log_obj['resource_id'])):
            self.plcy_provider.update_policy_logging(log_obj)

    def _qos_realize(self, os_qos: dict, delete=False):
        # TODO: mngr has to be removed after POLICY is fully supported
        provider = self.plcy_provider if self.USE_POLICY_API else self.mngr_provider

        return provider.qos_realize(os_qos, delete)

    def _port_realize(self, os_port: dict, delete: bool = False):
        # TODO: mngr has to be removed after POLICY is fully supported
        provider = self.plcy_provider if self.USE_POLICY_API else self.mngr_provider

        return provider.port_realize(os_port, delete)

    def _check_mp2policy_support(self):
        """Check if MP-to-Policy is forced, check if NSX-T version is supported

        Returns:
            bool: True if MP-to-Policy is supported, False otherwise
        """
        if cfg.CONF.AGENT.force_mp_to_policy:
            if self.mngr_provider.client.version >= MP2POLICY_NSX_MIN_VERSION:
                return True
            LOG.warning(
                f"MP-TO-POLICY API is supported from NSX-T ver. {'.'.join([str(n) for n in MP2POLICY_NSX_MIN_VERSION])} onward.")
        return False

    def _try_start_migration(self):
        try:
            self.migr_provider = mi_prvdr.Provider()
            # Check if migration is needed
            migr_state = self.migr_provider.get_migration_state()
            if not migr_state:
                raise RuntimeWarning("MP-to-Policy migration state is unknown.")
            if "FAIL" in migr_state:
                raise RuntimeWarning(f"MP-to-Policy migration state is failed: '{migr_state}'.")
            if MP2POLICY_STATES.PROMOTION_NOT_IN_PROGRESS.value == migr_state:
                LOG.info("MP-to-Policy migration is not in progress. Starting migration ...")
                return self._trigger_new_migration()
            if MP2POLICY_STATES.PROMOTION_IN_PROGRESS.value == migr_state:
                LOG.info("MP-to-Policy migration is in progress. Skipping migration start ...")
                return self._await_running_migration()
            raise RuntimeWarning(f"MP-to-Policy migration is in not supported by the agent state '{migr_state}'.")
        except Exception as e:
            self.migration_tracker.set_migration_in_progress(False)
            self.USE_POLICY_API = False
            LOG.error(f"Error while starting MP-to-Policy migration: {str(e)}")
            self._dryrun()

    def _await_running_migration(self):
        self.migration_tracker.set_migration_in_progress(True)
        eventlet.greenthread.spawn(self.migr_provider.migrate_generic, only_await=True).link(self._migration_handler)

    def _trigger_new_migration(self):
        migr_pre = self.migr_provider.get_migration_stats(pre=True)
        LOG.info(f"MP-to-Policy migration pre-check:\n{json.dumps(migr_pre, indent=4)}")
        if migr_pre and migr_pre.get("total_count", 0) > 0:
            self.migration_tracker.set_migration_in_progress(True)
            eventlet.greenthread.spawn(self.migr_provider.migrate_generic).link(self._migration_handler)
        else:
            LOG.info("MP-to-Policy migration not needed. No MP objects found.")
            self.migration_tracker.persist_migration_status(NSXV3_MP_MIGRATION_SCOPE, NSXV3_MIGRATION_SUCCESS_TAG)

    def _migration_handler(self, gt: eventlet.greenthread.GreenThread):
        try:
            success, migr_stats, fdbk = gt.wait()
            if not success:
                raise RuntimeWarning("MP-to-Policy migration failed.")
            self.migration_tracker.persist_migration_status(NSXV3_MP_MIGRATION_SCOPE, NSXV3_MIGRATION_SUCCESS_TAG)
            LOG.info("MP-to-Policy Migration finished successfully.")
        except Exception as e:
            LOG.error(str(e))
            self.USE_POLICY_API = False
        finally:
            self.migration_tracker.set_migration_in_progress(False)
            self._dryrun()

    def _dryrun(self):
        self.AGE = int(time.time())
        # Initializing metadata
        self.all(dryrun=True)
