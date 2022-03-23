import itertools
import time
from typing import Callable, List, Set, Tuple
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider import Resource, ResourceMeta
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import\
    provider_nsx_mgmt, provider_nsx_policy, mp_to_policy_migration
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.mp_to_policy_migration import\
    PayloadBuilder, Payload as MigrationPayload
from networking_nsxv3.api.rpc import NSXv3ServerRpcApi
from oslo_config import cfg
from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class AgentRealizer(object):
    def __init__(
        self,
        rpc: NSXv3ServerRpcApi,
        callback: Callable[[list or str, Callable[[str], None]], None],
        kpi: Callable[[], dict],
        mngr_provider: provider_nsx_mgmt.Provider,
        plcy_provider: provider_nsx_policy.Provider,
        migr_provider: mp_to_policy_migration.Provider = None
    ):
        self.rpc = rpc
        self.callback = callback
        self.kpi = kpi

        self.mngr_provider = mngr_provider
        self.plcy_provider = plcy_provider

        LOG.info("Detected NSX-T %s version.", self.mngr_provider.client.version)

        # Enable MP-to-Policy migration if force_mp_to_policy=True
        self.force_mp_to_policy = cfg.CONF.AGENT.force_mp_to_policy
        if self.mngr_provider.client.version < (3, 1):
            self.force_mp_to_policy = False
            LOG.warning("MP-TO-POLICY API is supported from NSX-T ver. 3.1.x onward.")

        if self.force_mp_to_policy:
            try:
                self.migr_provider = mp_to_policy_migration.Provider()
                self._promote_switching_profiles()
            except Exception as e:
                LOG.warning(str(e))
                self.force_mp_to_policy = False
                LOG.critical("MP-to-Policy Migration Functionality disabled.")

        self.age = int(time.time())
        # Initializing metadata
        self.all(dryrun=True)

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
        pp = self.plcy_provider
        mp = self.mngr_provider
        for o in list_aged:
            if o[0] == pp.SEGM_PORT:
                self.callback(o[1], self.port)
            elif o[0] == mp.PORT:
                self.callback(o[1], self.port)
            elif o[0] == mp.QOS:
                self.callback(o[1], self.qos)
            elif o[0] == pp.SG_RULES:
                self.callback(o[1], self.security_group_rules)
            elif o[0] == pp.SG_MEMBERS:
                self.callback(o[1], self.security_group_members)

    def all(self, dryrun=False):
        """
        Enforce desired state between OpenStack and Provider objects
        Objects concidered outdated include new, updated or removed

        :force: bool -- if True concider all objects as outdated
        """
        with LockManager.get_lock("all"):
            if self.kpi().get("passive") > 0:
                return

            _slice = cfg.CONF.AGENT.synchronization_queue_size
            pp = self.plcy_provider
            mp = self.mngr_provider
            r = self.rpc

            port_meta = self._os_meta(r.get_ports_with_revisions)
            sg_meta = self._os_meta(r.get_security_groups_with_revisions)
            qos_meta = self._os_meta(r.get_qos_policies_with_revisions)

            # Force networks refresh, only
            mp.metadata_refresh(mp.NETWORK)
            pp.metadata_refresh(pp.SEGMENT)

            # Refresh entire metadata with its latest state
            LOG.info("Inventory metadata is going to be refreshed.")
            seg_port_outdated, seg_port_current = pp.outdated(pp.SEGM_PORT, port_meta)
            port_outdated, port_current = mp.outdated(mp.PORT, port_meta)
            sgr_outdated, sgr_current = pp.outdated(pp.SG_RULES, sg_meta)
            qos_outdated, qos_current = mp.outdated(mp.QOS, qos_meta)

            # Remove duplicated policy/manager ports
            seg_port_outdated = seg_port_outdated.difference(port_outdated)
            seg_port_current = seg_port_current.difference(port_current)

            # There is not way to revision group members but can 'age' them
            sgm_outdated, sgm_maybe_orphans = pp.outdated(pp.SG_MEMBERS, {sg: 0 for sg in sg_meta})
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

            outdated = list(itertools.islice(seg_port_outdated, _slice))
            _slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:SegmentPorts", len(outdated), len(seg_port_outdated))
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

            return self._age_cycle(_slice, seg_port_current, port_current, sgr_current, qos_current, sgm_maybe_orphans)

    def _age_cycle(self, _slice, seg_port_current, port_current, sgr_current, qos_current, sgm_maybe_orphans):
        mp = self.mngr_provider
        pp = self.plcy_provider

        current = mp.age(mp.PORT, port_current)
        current += pp.age(pp.SEGM_PORT, seg_port_current)
        current += pp.age(pp.SG_RULES, sgr_current)
        current += pp.age(pp.SG_MEMBERS, sgm_maybe_orphans)
        current += mp.age(mp.QOS, qos_current)

        # Sanitize when there are no elements or the eldest age > current age
        aged = [entry for entry in current if entry[2] and int(entry[2]) <= self.age]
        LOG.info("Items outdated since last Agent sanitize:%d", len(aged))
        if aged:
            aged = set(itertools.islice(aged, _slice))
            LOG.info("Refreshing %s of least updated resources", len(aged))
            self.refresh(aged)
        else:
            LOG.info("Sanitizing provider based on age cycles")
            sanitize = pp.sanitize(_slice)

            for id, callback in sanitize:
                self.callback(id, callback)

            _slice -= len(sanitize)
            if _slice <= 0:
                return

            self.age = int(time.time())

    def security_group_members(self, os_id: str, reference=False):
        """
        Realize security group members state.
        Realization will happen only if the group has active ports on the host
        or if it used as remote security group by a group having such ports.
        :os_id: -- OpenStack ID of the Security Group
        :reference: -- if True will create the group if unknown by the provider
        """
        with LockManager.get_lock("member-{}".format(os_id)):
            meta = self.plcy_provider.metadata(self.plcy_provider.SG_MEMBERS, os_id)
            if not (reference and meta):
                if self.rpc.has_security_group_used_by_host(os_id):
                    cidrs = self.rpc.get_security_group_members_effective_ips(os_id)
                    # SG Members are not revisionable, use default "0"
                    # TODO: add port IDs to groups
                    self.plcy_provider.sg_members_realize({"id": os_id, "cidrs": cidrs, "revision_number": "0"})
                else:
                    self.plcy_provider.sg_members_realize({"id": os_id}, delete=True)

    def security_group_rules(self, os_id: str):
        """
        Realize security group rules state.
        Realization will happen only if the group has active ports on the host.
        :os_id: -- OpenStack ID of the Security Group
        """
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

                self.plcy_provider.sg_rules_realize(os_sg)

            else:
                self.plcy_provider.sg_rules_realize({"id": os_id}, delete=True)
                # Skip members as they can be used as references

    def precreate_port(self, os_id: str, network_meta: dict):
        """
        Try to precreate port on first binding request.
        :os_id: -- OpenStack ID of the Port
        :network_meta: -- NSX Switch metadata
        """
        with LockManager.get_lock("port-{}".format(os_id)):
            port: dict = self.rpc.get_port(os_id)
            if port:
                os_qid = port.get("qos_policy_id")
                if os_qid:
                    self.qos(os_qid, reference=True)

                if not port.get("vif_details") and network_meta:
                    port["vif_details"] = network_meta

                self._port_realize(port)

    def port(self, os_id: str):
        """
        Realize port state.
        :os_id: -- OpenStack ID of the Port
        """
        with LockManager.get_lock("port-{}".format(os_id)):
            port: dict = self.rpc.get_port(os_id)
            if port:
                os_qid = port.get("qos_policy_id")
                if os_qid:
                    self.qos(os_qid, reference=True)
                self._port_realize(port)
            else:
                self._port_realize({"id": os_id}, delete=True)

    def qos(self, os_id: str, reference=False):
        """
        Realize QoS Policy state.
        :os_id: -- OpenStack ID of the QoS Policy
        :reference: -- If True will create policy if unknown by the provider
        """
        with LockManager.get_lock("qos-{}".format(os_id)):
            mp = self.mngr_provider
            meta = mp.metadata(mp.QOS, os_id)
            if not (reference and meta):
                qos = self.rpc.get_qos(os_id)
                if qos:
                    mp.qos_realize(qos)
                else:
                    # TODO: QOS delete will be impossible after migration
                    mp.qos_realize({"id": os_id}, delete=True)

    def network(self, os_seg_id: str):
        """
        Realize Network state.
        :os_seg_id: -- OpenStack Network Segmentation ID
        :return: -- provider ID for the network
        """
        with LockManager.get_lock("network-{}".format(os_seg_id)):
            meta = self._network_realize(os_seg_id)
            return {"nsx-logical-switch-id": meta.id, "external-id": meta.id, "segmentation_id": os_seg_id}

    def _port_realize(self, os_port: dict, delete: bool = False):
        pp = self.plcy_provider
        mp = self.mngr_provider
        plcy_port_meta = pp.get_port(os_id=os_port.get("id"))
        mngr_port_meta = mp.get_port(os_id=os_port.get("id"))

        # Realize using Policy API
        if plcy_port_meta and plcy_port_meta[0]:
            return pp.port_realize(os_port, delete)

        # Realize using Manager API
        mp.port_realize(os_port, delete)

        # Try to promote port to Policy
        if self.force_mp_to_policy and mngr_port_meta and mngr_port_meta[0] and not delete:
            self.try_promote_port(os_port, mngr_port_meta)

    def try_promote_port(self, os_port, mngr_port_meta):
        pp = self.plcy_provider
        mp = self.mngr_provider
        os_id = os_port.get("id")
        try:
            self._check_port_migration_criteria(port=mngr_port_meta[1])
            vlan_id = os_port.get("vif_details").get("segmentation_id")
            segment = pp.metadata(pp.SEGMENT, vlan_id)
            net_id = mp.metadata(mp.NETWORK, vlan_id).id if not segment else None
            self._promote_port(net_id=net_id, port=mngr_port_meta[1])
            # Delete Manager Meta
            mp.metadata_delete(mp.PORT, os_id)
            # Update Policy meta
            pp.get_port(os_id=os_id)
        except Exception as e:
            LOG.info(f"Port with ID: {os_id} was not promoted to Policy API. ({e})")

    @staticmethod
    def _check_port_migration_criteria(port: dict):
        if len(port.get("tags")) < 5:
            raise RuntimeError("Not meet migration criteria.")

    def _network_realize(self, segmentation_id: int):
        segment_meta = self.plcy_provider.network_realize(segmentation_id)
        switch_meta = self.mngr_provider.network_realize(segmentation_id)

        if self.force_mp_to_policy and not segment_meta:
            self._promote_switch(switch_meta)
            self.plcy_provider.network_realize(segmentation_id)

        return switch_meta

    def _get_unmigrated_switching_profiles(self) -> Tuple[list, list]:
        mgmt_sw_profiles: List[dict] = self.mngr_provider.get_all_switching_profiles()
        policy_sw_profiles: List[dict] = self.plcy_provider.get_non_default_switching_profiles()

        if self.force_mp_to_policy and self.migr_provider:
            mgmt_profile_ids = [p.get("id") for p in mgmt_sw_profiles if p]
            plcy_profile_ids = [p.get("id") for p in policy_sw_profiles if p]

            not_migrated_ids = [p_id for p_id in mgmt_profile_ids if p_id not in plcy_profile_ids]

            if len(not_migrated_ids) > 0:
                not_migrated = [(p.get("id"), p.get("resource_type"), p.get("_system_owned"))
                                for p in mgmt_sw_profiles if p and p.get("id") in not_migrated_ids]
                # system owned profiles
                not_migrated_sys_owned = [
                    (p_id, p_type) for p_id, p_type, sys_owned in not_migrated
                    if sys_owned and p_type in MigrationPayload.SUPPORTED_RESOURCE_TYPES]

                # non system owned profiles
                not_migrated_not_sys_owned = [(p_id, p_type)
                                            for p_id, p_type, sys_owned in not_migrated
                                              if not sys_owned and p_type in MigrationPayload.SUPPORTED_RESOURCE_TYPES]

                return not_migrated_sys_owned, not_migrated_not_sys_owned

    def _promote_switching_profiles(self):
        self._raise_for_migration_disabled()
        not_migrated_sys_owned, not_migrated_not_sys_owned = self._get_unmigrated_switching_profiles()
        LOG.info(f"Not migrated to policy switching profiles: {not_migrated_sys_owned, not_migrated_not_sys_owned}")
        if len(not_migrated_sys_owned) > 0:
            self.migr_provider.migrate_sw_profiles(not_migrated_sys_owned)
        if len(not_migrated_not_sys_owned) > 0:
            self.migr_provider.migrate_sw_profiles(not_migrated_not_sys_owned)

    def _promote_switch(self, switch_meta: ResourceMeta) -> ResourceMeta:
        self._raise_for_migration_disabled()
        p_builder = PayloadBuilder()
        not_migrated_sys_owned, not_migrated_not_sys_owned = self._get_unmigrated_switching_profiles()

        p_builder\
            .sw_profiles(not_migrated_not_sys_owned)\
            .sw_profiles(not_migrated_sys_owned)\
            .switch(switch_id=switch_meta.id)

        self.migr_provider.migrate_bulk(payload=p_builder.build())
        return self.plcy_provider.await_network_after_promotion(metadata=switch_meta)

    def _promote_port(self, net_id: str or None, port: dict):
        self._raise_for_migration_disabled()
        port_id = port.get("id")
        p_builder = PayloadBuilder()
        not_migrated_sys_owned, not_migrated_not_sys_owned = self._get_unmigrated_switching_profiles()

        p_builder\
            .sw_profiles(not_migrated_not_sys_owned)\
            .sw_profiles(not_migrated_sys_owned)\
            .ports([port_id])
        if net_id:
            p_builder.switch(switch_id=net_id)

        self.migr_provider.migrate_bulk(payload=p_builder.build())

    def _raise_for_migration_disabled(self):
        if not self.force_mp_to_policy:
            raise Exception("MP-to-Policy migration is disabled.")
