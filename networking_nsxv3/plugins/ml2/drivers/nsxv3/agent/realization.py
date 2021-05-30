import datetime
import itertools
import json
import time

from networking_nsxv3.common.locking import LockManager
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AgentRealizer(object):

    def __init__(self, rpc, callback, kpi, provider, legacy_provider):
        self.rpc = rpc
        self.callback = callback
        self.kpi = kpi
        self.provider = provider
        self.legacy_provider = legacy_provider
        self.age = int(time.time())
        # Initializing metadata
        self.all(dryrun=True)

    def _os_meta(self, query):
        step = cfg.CONF.AGENT.rpc_max_records_per_query
        cursor = 0
        meta = dict()
        while cursor != -1:
            result = query(step, cursor)
            meta.update({id:rev for id,rev,_ in result})
            cursor = result[-1][2] if len(result) >= step else -1
        return meta

    def refresh(self, list_aged):
        p = self.provider

        for o in list_aged:
            if o[0] == p.PORT:
                self.callback(o[1], self.port)
            if o[0] == p.QOS:
                self.callback(o[1], self.qos)
            if o[0] == p.SG_RULES:
                self.callback(o[1], self.security_group_rules)
            if o[0] == p.SG_MEMBERS:
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
            
            slice = cfg.CONF.AGENT.synchronization_queue_size
            p = self.provider
            l = self.legacy_provider
            r = self.rpc

            port_meta = self._os_meta(r.get_ports_with_revisions)
            sg_meta = self._os_meta(r.get_security_groups_with_revisions)
            qos_meta = self._os_meta(r.get_qos_policies_with_revisions)

            # Refresh entire metadata with its latest state
            LOG.info("Inventory metadata is going to be refreshed.")
            port_outdated, port_current = p.outdated(p.PORT, port_meta)
            sgr_outdated, sgr_current = p.outdated(p.SG_RULES, sg_meta)
            qos_outdated, qos_current = p.outdated(p.QOS, qos_meta)
            # There is not way to revision group members but can 'age' them
            sgm_outdated, _ = p.outdated(p.SG_MEMBERS, dict())
            # Only force networks refresh
            p.outdated(p.NETWORK, dict())
            LOG.info("Inventory metadata have been refreshed.")

            if dryrun:
                LOG.info("Dryrun:%s. Metadata refresh completed.", dryrun)
                return

            outdated = list(itertools.islice(port_outdated, slice))
            slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:Ports",
                len(outdated), len(port_outdated))
            self.callback(outdated, self.port)
            if slice <= 0:
                return
            
            outdated = list(itertools.islice(sgr_outdated, slice))
            slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:Security Group Rules",
                len(outdated), len(sgr_outdated))
            self.callback(outdated, self.security_group_rules)
            if slice <= 0:
                return

            outdated = list(itertools.islice(qos_outdated, slice))
            slice -= len(outdated)
            LOG.info("Realizing %s/%s resources of Type:QoS",
                len(outdated), len(qos_outdated))
            self.callback(outdated, self.qos)
            if slice <= 0:
                return

            current = p.age(p.PORT, port_current)
            current += p.age(p.SG_RULES, sgr_current)
            current += p.age(p.SG_MEMBERS, sgm_outdated)
            current += p.age(p.QOS, qos_current)

            def compare(a,b):
                ar = int(a[2]) if str(a[2]).isdigit() else 0
                br = int(b[2]) if str(b[2]).isdigit() else 0
                return ar - br

            current = sorted(current, cmp=compare)

            if len(current) > 1 and current[0][2] > self.age:
                LOG.info("Sanitizing provider based on age cycles")
                sanitize = p.sanitize(slice)

                for id, callback in sanitize:
                    self.callback(id, callback)

                slice -= len(sanitize)
                if slice <= 0:
                    return

                legacy_sgr_outdated, _ = l.outdated(l.SG_RULES, dict())
                outdated = list(itertools.islice(legacy_sgr_outdated, slice))
                slice -= len(outdated)
                LOG.info("Realizing %s/%s resources of Type:Security Group Rules (Legacy)",
                    len(outdated), len(legacy_sgr_outdated))
                def legacy_sg_rules_realize(id):
                    l.sg_rules_realize({"id": id}, delete=True)
                self.callback(outdated, legacy_sg_rules_realize)
                if slice <= 0:
                    return

                legacy_sgm_outdated, _ = l.outdated(l.SG_MEMBERS, dict())
                outdated = list(itertools.islice(legacy_sgm_outdated, slice))
                slice -= len(outdated)
                LOG.info("Realizing %s/%s resources of Type:Security Group Members (Legacy)",
                    len(outdated), len(legacy_sgm_outdated))
                def legacy_sg_members_realize(id):
                    l.sg_members_realize({"id": id}, delete=True)
                self.callback(outdated, legacy_sg_members_realize)
                if slice <= 0:
                    return

                LOG.info("Sanitizing (Legacy) provider based on age cycles")

                sanitize = l.sanitize(slice)
                for id, callback in sanitize:
                    self.callback(id, callback)

                slice -= len(sanitize)
                if slice <= 0:
                    return

                self.age = int(time.time())

            if len(current) > slice:
                current = set(itertools.islice(current, slice))

            LOG.info("Refreshing %s of least updated resources", len(current))
            self.refresh(current)


    def security_group_members(self, os_id, reference=False):
        """
        Realize security group members state.
        Realization will happen only if the group has active ports on the host
        or if it used as remote security group by a group having such ports.
        :os_id: -- OpenStack ID of the Security Group
        :reference: -- if True will create the group if unknown by the provider
        """
        with LockManager.get_lock("member-{}".format(os_id)):
            meta = self.provider.metadata(self.provider.SG_MEMBERS, os_id)
            if not(reference and meta):
                if self.rpc.has_security_group_used_by_host(os_id):
                    cidrs = self.rpc.get_security_group_members_effective_ips(os_id)
                    # SG Members are not revisionable, use default "0"
                    self.provider.sg_members_realize(\
                        {"id": os_id, "cidrs": cidrs, "revision_number": "0"})
                else:
                    self.provider.sg_members_realize(\
                        {"id": os_id}, delete=True)
            
            # TODO - remove after legacy provider is not supported
            try:
                self.legacy_provider.sg_members_realize({"id": os_id}, delete=True)
            except Exception:
                pass
        

    def security_group_rules(self, os_id):
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

                self.provider.sg_rules_realize(os_sg)

            else:
                self.provider.sg_rules_realize({"id": os_id}, delete=True)
                # Skip members as they can be used as references

            # TODO - remove after legacy provider is not supported
            try:
                self.legacy_provider.sg_rules_realize({"id": os_id}, delete=True)
            except Exception:
                pass     


    def port(self, os_id):
        """
        Realize port state.
        :os_id: -- OpenStack ID of the Port
        """
        with LockManager.get_lock("port-{}".format(os_id)):
            port = self.rpc.get_port(os_id)
            if port:
                os_qid = port.get("qos_policy_id")
                if os_qid:
                    self.qos(os_qid, reference=True)
                self.provider.port_realize(port)
            else:
                self.provider.port_realize({"id": os_id}, delete=True)


    def qos(self, os_id, reference=False):
        """
        Realize QoS Policy state.
        :os_id: -- OpenStack ID of the QoS Policy
        :reference: -- If True will create policy if unknown by the provider
        """
        with LockManager.get_lock("qos-{}".format(os_id)):
            meta = self.provider.metadata(self.provider.QOS, os_id)
            if not(reference and meta):
                qos = self.rpc.get_qos(os_id)
                if qos:
                    self.provider.qos_realize(qos)
                else:
                    self.provider.qos_realize({"id": os_id}, delete=True)
    

    def network(self, os_seg_id):
        """
        Realize Network state.
        :os_seg_id: -- OpenStack Network Segmentation ID
        :return: -- provider ID for the network
        """
        with LockManager.get_lock("network-{}".format(os_seg_id)):
            meta = self.provider.metadata(self.provider.NETWORK, os_seg_id)
            if not meta:
                self.provider.network_realize(os_seg_id)
                meta = self.provider.metadata(self.provider.NETWORK, os_seg_id)
            return {
                "nsx-logical-switch-id": meta.id,
                "external-id": meta.id,
                "segmentation_id": os_seg_id
            }
