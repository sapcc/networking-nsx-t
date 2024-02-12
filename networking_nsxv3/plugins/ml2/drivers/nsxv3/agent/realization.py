import eventlet
eventlet.monkey_patch()

from oslo_log import log as logging
from oslo_config import cfg
from networking_nsxv3.api.rpc import NSXv3ServerRpcApi
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider
from networking_nsxv3.common.locking import LockManager
from typing import Callable, List, Set, Tuple
import itertools
import json
import time


LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class AgentRealizer(object):

    def __init__(
        self,
        rpc: NSXv3ServerRpcApi,
        callback: Callable[[List or str, Callable[[str], None]], None],
        kpi: Callable[[], dict],
        nsx_provider: provider.Provider
    ):
        self.rpc = rpc
        self.callback = callback
        self.kpi = kpi
        self.nsx_provider = nsx_provider

        self.AGE = int(time.time())
        LOG.info("Detected NSX-T %s version.", self.nsx_provider.client.version)
        self._dryrun()

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
        for o in list_aged:
            if o[0] == self.nsx_provider.PORT:
                self.callback(o[1], self.port)
            elif o[0] == self.nsx_provider.QOS:
                self.callback(o[1], self.qos)
            elif o[0] == self.nsx_provider.SG_RULES:
                self.callback(o[1], self.security_group_rules)
            elif o[0] == self.nsx_provider.SG_MEMBERS:
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
            r = self.rpc

            port_meta = self._os_meta(r.get_ports_with_revisions)
            sg_meta = self._os_meta(r.get_security_groups_with_revisions)
            qos_meta = self._os_meta(r.get_qos_policies_with_revisions)

            # Refresh entire metadata with its latest state
            LOG.info("Inventory metadata is going to be refreshed.")

            # Force networks refresh, only
            self.nsx_provider.metadata_refresh(self.nsx_provider.NETWORK)

            port_outdated, port_current = self.nsx_provider.outdated(self.nsx_provider.PORT, port_meta)
            sgr_outdated, sgr_current = self.nsx_provider.outdated(self.nsx_provider.SG_RULES, sg_meta)
            qos_outdated, qos_current = self.nsx_provider.outdated(self.nsx_provider.QOS, qos_meta)

            # There is not way to revision group members but can 'age' them
            sgm_outdated, sgm_maybe_orphans = self.nsx_provider.outdated(
                self.nsx_provider.SG_MEMBERS, {sg: 0 for sg in sg_meta})
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

        current = self.nsx_provider.age(self.nsx_provider.PORT, port_current)
        current += self.nsx_provider.age(self.nsx_provider.SG_RULES, sgr_current)
        current += self.nsx_provider.age(self.nsx_provider.SG_MEMBERS, sgm_maybe_orphans)
        current += self.nsx_provider.age(self.nsx_provider.QOS, qos_current)

        # Sanitize when there are no elements or the eldest age > current age
        aged = [entry for entry in current if entry[2] and int(entry[2]) <= self.AGE]
        LOG.info("Items outdated since last Agent sanitize:%d", len(aged))
        if aged:
            aged = set(itertools.islice(aged, _slice))
            LOG.info("Refreshing %s of least updated resources", len(aged))
            self.refresh(aged)
        else:
            LOG.info("Sanitizing provider based on age cycles")
            sanitize = self.nsx_provider.sanitize(_slice)

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
        with LockManager.get_lock("member-{}".format(os_id)):
            meta = self.nsx_provider.metadata(self.nsx_provider.SG_MEMBERS, os_id)
            if not (reference and meta):
                max_sg_tags = min(cfg.CONF.AGENT.max_sg_tags_per_segment_port, 27)
                cidrs, ports_with_sg_count = self.rpc.fetch_security_group_information(os_id, max_sg_tags)
                if cidrs:
                    paths = [p.path for p in self.nsx_provider.get_port_meta_by_ids(
                        ports_with_sg_count)] if ports_with_sg_count else []

                    # SG Members are not revisionable, use default "0"
                    self.nsx_provider.sg_members_realize(
                        {"id": os_id, "cidrs": cidrs, "revision_number": 0, "member_paths": paths})
                else:
                    self.nsx_provider.sg_members_realize({"id": os_id}, delete=True)

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

                    addr_grp_id = os_rule.get("remote_address_group_id")
                    if addr_grp_id:
                        # Realize the remote address group first
                        self.address_group_members(addr_grp_id)

                logged = self.rpc.has_security_group_logging(os_id)
                LOG.info(f"Neutron DB logged flag for {os_id}: rpc.has_security_group_logging(os_id): {logged}")
                self.nsx_provider.sg_rules_realize(os_sg, logged=logged)

            else:
                self.nsx_provider.sg_rules_realize({"id": os_id}, delete=True)
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

    def precreate_unbound_port(self, os_id: str, network_meta: dict):
        """
        Try to precreate port on multiple binding ports, fetch port from active binding.
        :os_id: -- OpenStack ID of the Port
        :network_meta: -- NSX Switch metadata
        """
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
        with LockManager.get_lock("qos-{}".format(os_id)):
            meta = self.nsx_provider.metadata(self.nsx_provider.QOS, os_id)
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
        with LockManager.get_lock("network-{}".format(os_seg_id)):
            meta = self.nsx_provider.network_realize(os_seg_id)
            return {"nsx-logical-switch-id": meta.unique_id, "external-id": meta.id, "segmentation_id": os_seg_id}

    def enable_policy_logging(self, log_obj: dict):
        """
        Realize security policy logging state enablement.
        :os_seg_id: -- OpenStack Security Group ID
        :return: -- None
        """
        with LockManager.get_lock("rules-{}".format(log_obj['resource_id'])):
            self.nsx_provider.enable_policy_logging(log_obj)

    def disable_policy_logging(self, log_obj: dict):
        """
        Realize security policy logging state disablement.
        :os_seg_id: -- OpenStack Security Group ID
        :return: -- None
        """
        with LockManager.get_lock("rules-{}".format(log_obj['resource_id'])):
            self.nsx_provider.disable_policy_logging(log_obj)

    def update_policy_logging(self, log_obj: dict):
        """
        Realize security policy logging state update.
        :os_seg_id: -- OpenStack Security Group ID
        :return: -- None
        """
        with LockManager.get_lock("rules-{}".format(log_obj['resource_id'])):
            self.nsx_provider.update_policy_logging(log_obj)

    def address_group_members(self, addr_grp_id: str, revision_number: int = 0, addresses: List = None):
        """
        Realize address group members state.
        :addr_grp_id: -- OpenStack Address Group ID
        :return: -- None
        """
        with LockManager.get_lock("address-group-{}".format(addr_grp_id)):
            addr_grp_rev = self.rpc.get_address_group_revision_number(
                addr_grp_id) if not revision_number else [revision_number]
            addr_grp_members = self.rpc.get_addresses_for_address_group_id(addr_grp_id) or []
            self.nsx_provider.address_group_realize(
                {"id": addr_grp_id,
                 "revision_number": addr_grp_rev[0] if addr_grp_rev else 0,
                 "addresses": [ip[0] for ip in addr_grp_members] if not addresses else addresses})

    def address_group_update(self, address_group: dict):
        """
        Realize address group state.
        :address_group: -- OpenStack address group
        {
            'id': '<uuid>',
            'name': '<str>',
            'project_id': '<str>',
            'shared': <bool>,
            'addresses': [
                '<cidr>',
            ],
            'revision_number': <int>,
            'description': '<str>',
            'created_at': '<timestamp>',
            'updated_at': '<timestamp>',
            'tenant_id': '<str>'
        }
        :return: -- None
        """
        return self.address_group_members(address_group['id'], address_group['revision_number'], address_group['addresses'])

    def _qos_realize(self, os_qos: dict, delete=False):
        return self.nsx_provider.qos_realize(os_qos, delete)

    def _port_realize(self, os_port: dict, delete: bool = False):
        return self.nsx_provider.port_realize(os_port, delete)

    def _dryrun(self):
        self.AGE = int(time.time())
        # Initializing metadata
        self.all(dryrun=True)
