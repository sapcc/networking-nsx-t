import datetime
import itertools
import json
import os
import re
import sys
import traceback
import time
import uuid

import netaddr
import oslo_messaging

from com.vmware.nsx_client import TransportZones
from com.vmware.nsx_client import LogicalPorts
from com.vmware.nsx.model_client import (FirewallRule,
                                         FirewallSection,
                                         IPSet,
                                         NSGroup,
                                         LogicalPort,
                                         QosSwitchingProfile,
                                         TransportZone)
from neutron.common import config as common_config
from neutron.common import profiler, topics
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron_lib.api.definitions import portbindings
from neutron_lib import context as neutron_context
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service, loopingcall

from networking_nsxv3.common import config  # noqa
from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.api import rpc as nsxv3_rpc
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_facada
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_policy
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_utils
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import vsphere_client
from networking_nsxv3.common import synchronization as sync
from networking_nsxv3.prometheus import exporter


# Eventlet Best Practices
# https://specs.openstack.org/openstack/openstack-specs/specs/eventlet-best-practices.html
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()

LOG = logging.getLogger(__name__)

AGENT_SYNCHRONIZATION_LOCK = "AGENT_SYNCHRONIZATION_LOCK"

def is_migration_enabled():
    return cfg.CONF.AGENT.enable_runtime_migration_from_dvs_driver


class NSXv3AgentManagerRpcCallBackBase(amb.CommonAgentManagerRpcCallBackBase):

    target = oslo_messaging.Target(version=nsxv3_constants.RPC_VERSION)

    """
    Base class for managers RPC callbacks.
    """

    def __init__(self, context, agent, sg_agent, nsxv3, nsxv3_infra, vsphere,
                 rpc, runner):
        super(NSXv3AgentManagerRpcCallBackBase, self).__init__(
            context, agent, sg_agent)
        self.nsxv3 = nsxv3
        self.infra = nsxv3_infra
        self.vsphere = vsphere
        self.rpc = rpc
        self.runner = runner
        self.policy_api_enabled = self.infra._client.version >= (2, 5)
        if cfg.CONF.NSXV3.nsxv3_use_policy_api is not None:
            self.policy_api_enabled = cfg.CONF.NSXV3.nsxv3_use_policy_api
        LOG.info("Using Policy-API=%s", self.policy_api_enabled)

    def _security_group_member_updated(self, security_group_id):
        sg_id = str(security_group_id)
        cidrs = \
            self.rpc.get_security_group_members_ips(sg_id) + \
            self.rpc.get_security_group_members_address_bindings_ips(sg_id)

        return [str(ip).replace("/32", "") for ip in netaddr.IPSet(
            [str(ip[0]) for ip in cidrs]).iter_cidrs()]

    def _security_group_rule_updated_mgmt_api(self, security_group_id):
        sg_id = str(security_group_id)
        LOG.debug("Updating Security Group '{}' rules".format(sg_id))
        (ipset, nsg, sec) = self.nsxv3.get_or_create_security_group(sg_id)
        _, revs_ips, _ = self.nsxv3.get_revisions(IPSet())
        _, revs_fwr, meta_fwr = self.nsxv3.get_revisions(
            FirewallRule(),
            attr_key="section_id",
            attr_val=sec.id)

        neutron_rules = self.rpc.get_rules_for_security_groups_id(sg_id)

        attrs = ["id", "port_range_min", "port_range_max", "protocol",
                 "ethertype", "direction", "remote_group_id",
                 "remote_ip_prefix", "security_group_id"]

        add_rules = []
        for rule in neutron_rules:
            name = rule["id"]
            remote_group_id = rule["remote_group_id"]

            fwr = dict()
            for key in attrs:
                fwr[key] = rule[key]

            fwr["local_group_id"] = ipset.id
            fwr["apply_to"] = nsg.id
            if remote_group_id in revs_ips:
                fwr["remote_group_id"] = revs_ips[remote_group_id]

            if name in revs_fwr:
                # If the rule is disabled recreate it
                if not meta_fwr.get(name).get("FirewallRule.disabled"):
                    del revs_fwr[name]
                    continue

            fwr_spec = self.nsxv3.get_security_group_rule_spec(fwr)
            if fwr_spec:
                add_rules.append(fwr_spec)
        del_rules = revs_fwr.values()

        (sg_id, revision) = self.rpc.get_security_group_revision(sg_id)

        self.nsxv3.update_security_group_rules(
            sg_id,
            revision_number=revision,
            add_rules=add_rules,
            del_rules=del_rules)
    
    def _security_group_member_updated_mgmt_api(self, security_group_id):
        sg_id = str(security_group_id)
        LOG.debug("Updating Security Group '{}' members".format(sg_id))
        self.nsxv3.get_or_create_security_group(sg_id)
        ip1 = self.rpc.get_security_group_members_ips(sg_id)
        ip2 = self.rpc.get_security_group_members_address_bindings_ips(
            sg_id)

        members = [str(ip) for ip in netaddr.IPSet(
            [str(ip[0]) for ip in ip1 + ip2]).iter_cidrs()]
        self.nsxv3.update_security_group_members(sg_id, members)

    def _security_group_rule_updated(self, security_group_id, revision):
        sg_id = str(security_group_id)

        neutron_rules = self.rpc.get_rules_for_security_groups_id(sg_id)

        nsxv3_rules = {}

        try:
            nsxv3_rules = self.infra.get_revisions(\
                nsxv3_policy.ResourceContainers.SecurityPolicyRule, sg_id)
        except:
            # Force recreate all rules
            pass
        
        add_rules = []
        for rule in neutron_rules:
            r = nsxv3_policy.Rule()
            r.identifier = rule["id"]
            r.ethertype = rule["ethertype"]
            r.direction = rule["direction"]
            r.remote_group_id = rule["remote_group_id"]
            r.remote_ip_prefix = rule["remote_ip_prefix"]
            r.security_group_id = rule["security_group_id"]
            r.service = nsxv3_policy.Service()

            r.service.identifier = r.identifier
            r.service.port_range_min = rule["port_range_min"]
            r.service.port_range_max = rule["port_range_max"]
            r.service.protocol = rule["protocol"]
            r.service.ethertype = r.ethertype

            add_rules.append(r)
            nsxv3_rules.pop(r.identifier, None)
        
        del_rules = []
        for identifier, _ in nsxv3_rules.items():
            r = nsxv3_policy.Rule()
            r.identifier = identifier
            r.service = nsxv3_policy.Service() 
            r.service.identifier = r.identifier
            del_rules.append(r)
        
        return add_rules, del_rules

    def _do_security_group_update(self, security_group_id, skip_rules=False):
        sg_id = str(security_group_id)
        try:
            _, revision_sg = self.rpc.get_security_group_revision(sg_id)
        except exceptions.ObjectNotFound as e:
                return

        scope = nsxv3_constants.NSXV3_CAPABILITY_TCP_STRICT
        LOG.info("Updating Security Group '{}'".format(sg_id))
        with LockManager.get_lock(sg_id):
            if not self.policy_api_enabled:
                # Will skip the revision check as this will prevent the daily desired state sync

                # Removed tcp_strict, not a valid attribute of the used nsx-t python library
                # self.nsxv3.get_or_create_security_group(sg_id)
                # tcp_strict = self.rpc.has_security_group_tag(sg_id, scope)
                # self.nsxv3.update_security_group_capabilities(sg_id, [tcp_strict])
                self._security_group_member_updated_mgmt_api(sg_id)
                if not skip_rules:
                    self._security_group_rule_updated_mgmt_api(sg_id)
                return

            revision_rule = self.infra.get_revision(
                nsxv3_policy.ResourceContainers.SecurityPolicy, sg_id)

            tcp_strict = None
            add_rules = []
            del_rules = []

            revision_member = revision_sg
            cidrs = self._security_group_member_updated(sg_id)

            if not skip_rules and revision_rule != revision_sg:
                revision_rule = revision_sg
                tcp_strict = self.rpc.has_security_group_tag(sg_id, scope)
                add_rules, del_rules = \
                    self._security_group_rule_updated(sg_id, revision_sg)

            self.infra.update_policy(sg_id, tcp_strict=tcp_strict,
                                     revision_member=revision_member,
                                     revision_rule=revision_rule,
                                     cidrs=cidrs,
                                     add_rules=add_rules, del_rules=del_rules)

    def security_group_delete(self, security_group_id):
        LOG.info("Deleting Security Group '{}'".format(security_group_id))
        with LockManager.get_lock(security_group_id):
            if not self.policy_api_enabled:
                self.nsxv3.delete_security_group(security_group_id)
                return

            sg_id = str(security_group_id)

            nsxv3_rules = self.infra.get_revisions(\
                nsxv3_policy.ResourceContainers.SecurityPolicyRule, sg_id)
            
            del_rules = []
            for identifier, _ in nsxv3_rules.items():
                r = nsxv3_policy.Rule()
                r.identifier = identifier
                del_rules.append(r)

            self.infra.update_policy(security_group_id,
                                     del_rules=del_rules, delete=True)

    # RPC method
    def security_groups_member_updated(self, context, **kwargs):
        o = kwargs["security_groups"]
        self.runner.run(sync.Priority.HIGHEST,
                        o if isinstance(o, list) else [o],
                        self.sync_security_group)

    # RPC method
    def security_groups_rule_updated(self, context, **kwargs):
        o = kwargs["security_groups"]
        self.runner.run(sync.Priority.HIGHEST,
                        o if isinstance(o, list) else [o],
                        self.sync_security_group)

    def sync_security_groups(self):
        revs = self.get_revisions(query=self.rpc.get_security_group_revision_tuples)
        self.runner.run(sync.Priority.LOW, revs.keys(), self.sync_security_group)

    def sync_qos_policies(self):
        self.runner.run(
            sync.Priority.HIGH,
            self.get_revisions(
                query=self.rpc.get_qos_policy_revision_tuples).keys(),
            self.sync_qos)

    def sync_ports(self):
        self.runner.run(sync.Priority.MEDIUM, self.get_revisions(
            query=self.rpc.get_port_revision_tuples).keys(), self.sync_port)

    def _sync_inventory_full(self):
        self.sync_security_groups()
        self.sync_qos_policies()
        self.sync_ports()

    def _sync_inventory_shallow(self):
        sg_query = self.rpc.get_security_group_revision_tuples
        qos_query = self.rpc.get_qos_policy_revision_tuples
        port_query = self.rpc.get_port_revision_tuples

        num_orphans = cfg.CONF.NSXV3.nsxv3_remove_orphan_items_count
        migration_limit = cfg.CONF.NSXV3.nsxv3_policy_migration_limit

        # Security Groups Synchronization
        missing_ips, outdated_ips, orphaned_ips = self._sync_get_content(
            sdk_model=IPSet(), os_query=sg_query)
        # All Groups need to be created before rule creation begins duo to
        # remote group references

        # Migration Magic
        if self.migration_mode:
            if not missing_ips:
                # That's all folks
                self.migration_complete()
                return

            # Get legacy mgmt sections
            mg_ipset, _, _ = self.nsxv3.get_revisions(sdk_model=IPSet(create_user="admin"))
            # Add any newly added sg that not existing at all yet
            outdated_ips |= missing_ips.difference(mg_ipset)
            missing_ips.difference_update(outdated_ips)

            # If there's enough space in the queue, add missing policies (MGMT -> Policy)
            in_progress = int(self.infra.get_inprogress_policies_count()) + len(outdated_ips)
            migrate_to_queue = max(migration_limit - in_progress, 0)
            outdated_ips |= set(itertools.islice(missing_ips, migrate_to_queue))
        else:
            # handle missing same as outdated
            outdated_ips |= missing_ips
        # END Migration Magic

        self.runner.run(
            sync.Priority.HIGH,
            outdated_ips, self.sync_security_group_skip_rules)
        self.runner.run(
            sync.Priority.MEDIUM,
            outdated_ips, self.sync_security_group)
        self.runner.run(
            sync.Priority.LOW,
            set(itertools.islice(orphaned_ips, num_orphans)), self.sync_security_group_orphaned)

        # QoS Policies Synchronization
        missing_qos, outdated_qos, orphaned_qos = self._sync_get_content(
            sdk_model=QosSwitchingProfile(), os_query=qos_query)
        self.runner.run(
            sync.Priority.LOWER,
            outdated_qos | missing_qos, self.sync_qos)

        # Ports Synchronization
        missing_lps, outdated_lps, orphaned_lps = self._sync_get_content(
            sdk_model=LogicalPort(), os_query=port_query)
        self.runner.run(
            sync.Priority.LOW,
            outdated_lps | missing_lps, self.sync_port)
        self.runner.run(
            sync.Priority.LOW,
            set(itertools.islice(orphaned_lps, num_orphans)), self.sync_port_orphaned)

        # TODO - remove after migration completes
        # Clean up the migrated Security Groups from Management to Policy API
        if self.policy_api_enabled:
            orphan_sgs = self._sync_get_orphan_security_groups_mgmt_api(outdated_ips | missing_ips)
            self.runner.run(
                sync.Priority.LOW,
                set(itertools.islice(orphan_sgs, num_orphans)), self.nsxv3.delete_security_group)
            self._sync_report("Security Groups Management API", 0, orphan_sgs)

        self._sync_report("Security Groups", outdated_ips, orphaned_ips)
        self._sync_report("QoS Profiles", outdated_qos| missing_qos, orphaned_qos)
        self._sync_report("Ports", outdated_lps | missing_lps, orphaned_lps)

    def migration_complete(self):
        tz = TransportZone(display_name=self.nsxv3.tz_name)

        timestamp_policy_migration_completed = nsxv3_facada.Timestamp(
            "policy_migration_completed", self.nsxv3, TransportZones, tz, 0)

        timestamp_policy_migration_completed.update()

    def sync_inventory(self):
        m = "Synchronization events pools size HIGHPRIORITY={} LOWPRIORITY={}"

        with LockManager.get_lock(AGENT_SYNCHRONIZATION_LOCK):
            LOG.info(m.format(self.runner.active(), self.runner.passive()))
            tz = TransportZone(display_name=self.nsxv3.tz_name)

            if self.runner.passive() > 0:
                return

            timestamp_policy_migration_completed = nsxv3_facada.Timestamp(
                "policy_migration_completed", self.nsxv3, TransportZones, tz, 0)
            self.migration_mode = self.policy_api_enabled and not timestamp_policy_migration_completed.has_set()

            timestamp = nsxv3_facada.Timestamp(
                "last_full_synchronization", self.nsxv3, TransportZones, tz, cfg.CONF.AGENT.sync_full_schedule)

            # Policy compatbile and migrating?
            # Then only sync shallow to ensure slow migration and low policy-realiziation queue
            if not timestamp.has_expired() or self.migration_mode:
                LOG.info("Starting a shallow inventory synchronization")
                self._sync_inventory_shallow()
            else:
                LOG.info("Starting a full inventory synchronization")
                self._sync_inventory_full()
                timestamp.update()

    def _sync_report(self, object_name, outdated, orphaned):
        report = dict()
        report["outdated"] = outdated
        report["orphaned"] = orphaned
        LOG.info("Synchronizing {} {}".format(object_name, report))

    def _sync_get_content(self, sdk_model, os_query):
        revs_os = self.get_revisions(query=os_query)
        revs_nsx = None

        # Policy API
        if self.policy_api_enabled and isinstance(sdk_model, IPSet):
            rc = nsxv3_policy.ResourceContainers
            revs_nsx = nsxv3_utils.concat_revisions(
                self.infra.get_revisions(rc.SecurityPolicy),
                self.infra.get_revisions(rc.SecurityPolicyGroup)
            )
        # TODO - imperative API - replace with policy
        else:
            revs_nsx, _, _ = self.nsxv3.get_revisions(sdk_model=sdk_model)

        outdated = nsxv3_utils.outdated_revisions(revs_os, revs_nsx)
        missing = set(revs_os.keys()).difference(revs_nsx.keys())
        orphaned = set(revs_nsx.keys()).difference(revs_os.keys())
        return missing, outdated, orphaned

    # TODO - remove after all nsx-t managers > 2.4
    def _sync_get_orphan_services(self):
        rc = nsxv3_policy.ResourceContainers
        revs_rules = self.nsxv3.get_rules_revisions()
        revs_services = self.infra.get_revisions(rc.SecurityPolicyRuleService)

        orphaned = set(revs_services.keys()).difference(revs_rules.keys())
        return orphaned

    # TODO - remove after migration to the Policy API
    def _sync_get_orphan_security_groups_mgmt_api(self, outdated):
        rc = nsxv3_policy.ResourceContainers
        pl = nsxv3_utils.concat_revisions(self.infra.get_revisions(rc.SecurityPolicy),
                                          self.infra.get_revisions(rc.SecurityPolicyGroup))
        mg_nsgroup, _, _ = self.nsxv3.get_revisions(sdk_model=NSGroup(create_user="admin"))
        mg_ipset, _, _ = self.nsxv3.get_revisions(sdk_model=IPSet(create_user="admin"))
        mg_fwsect, _, _ = self.nsxv3.get_revisions(sdk_model=FirewallSection(create_user="admin"))

        # Get all security group IDs 
        # regardless of the fact they could be partially implemented
        # Section object is excluded as it cannot be assigned with tags.
        # Though, the cleanup will try to remove the three objects for each ID
        mg = {}
        mg.update(mg_fwsect)
        mg.update(mg_nsgroup)
        mg.update(mg_ipset)

        def is_valid_uuid(uuid_to_test, version=4):
            try:
                uuid_obj = uuid.UUID(uuid_to_test, version=version)
            except ValueError:
                return False
            return str(uuid_obj) == uuid_to_test

        result = []
        for k,_ in mg.items():
            if k in pl and pl.get(k).isdigit():
                v1 = int(mg_nsgroup.get(k)) if mg_nsgroup.get(k, '').isdigit() else 0
                v2 = int(mg_ipset.get(k)) if mg_ipset.get(k, '').isdigit() else 0
                # Only clean up older entries for now
                if max(v1,v2) < int(pl.get(k)):
                    result.append(k)
                # Cleanup mgmt section of intialized policies
                elif cfg.CONF.AGENT.enable_imperative_security_group_cleanup and self.nsxv3.get_policy_ready(k):
                    result.append(k)
            elif k not in outdated and k not in pl and is_valid_uuid(k) and not self.migration_mode:
                # Cleanup orphans
                result.append(k)
        return result

    def sync_port(self, port_id):
        LOG.debug("Synching port '{}'.".format(port_id))

        id_options = sync.Identifier.decode(port_id)
        port_id = id_options.identifier
        
        try:
            (id, mac, up, status, qos_id, rev, binding_host, vif_details, parent_id) = self.rpc.get_port(port_id)
        except oslo_messaging.RemoteError as err:
            if err.exc_type in ['ObjectNotFound']:
                LOG.warning("Port '{}' not found in Neutron".format(port_id))
                return
        port = {
            "id": id,
            "parent_id": parent_id,
            "mac_address": mac,
            "admin_state_up": up,
            "status": status,
            "qos_policy_id": qos_id,
            "fixed_ips": [],
            "allowed_address_pairs": [],
            "security_groups": [],
            "revision_number": rev,
            "binding:host_id": binding_host,
            portbindings.VNIC_TYPE: portbindings.VNIC_NORMAL,
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS
        }

        for ip, subnet in self.rpc.get_port_addresses(port_id):
            port["fixed_ips"].append(
                {"ip_address": ip, "mac_address": mac, "subnet_id": subnet})

        for (ip, mac) in self.rpc.get_port_allowed_pairs(port_id):
            # TODO - fix in future.
            # NSX-T does not support CIDR as port manual binding
            if "/" in ip:
                continue
            port["allowed_address_pairs"].append(
                {"ip_address": ip, "mac_address": mac})

        for (sg_id,) in self.rpc.get_port_security_groups(port_id):
            port["security_groups"].append(sg_id)
        try:
            self._port_update(context=None, port=port, vif_details=json.loads(vif_details))
        except Exception as e:
            LOG.error(e)
            if id_options.retry_next():
                self.runner.run(sync.Priority.HIGHEST, [id_options.encode()],
                                self.sync_port)


    def sync_port_orphaned(self, port_id):
        LOG.debug("Removing orphaned ports '{}'.".format(
            port_id))
        self.port_delete(context=None, port_id=port_id, sync=True)

    def sync_qos(self, qos_id):
        LOG.debug("Synching QoS porofile '{}'.".format(qos_id))
        id_options = sync.Identifier.decode(qos_id)
        qos_id = id_options.identifier

        (qos_name, qos_revision_number) = self.rpc.get_qos(qos_id)
        bwls_rules = self.rpc.get_qos_bwl_rules(qos_id)
        dscp_rules = self.rpc.get_qos_dscp_rules(qos_id)

        rules = []
        if dscp_rules:
            for (_, dscp_mark) in dscp_rules:
                rules.append({"dscp_mark": dscp_mark})
        if bwls_rules:
            for (direction, max_kbps, max_burst_kbps) in bwls_rules:
                rules.append({
                    "direction": direction,
                    "max_kbps": max_kbps,
                    "max_burst_kbps": max_burst_kbps
                })

        policy = {
            "id": qos_id,
            "name": qos_name,
            "revision_number": qos_revision_number,
            "rules": rules
        }
        try:
            self.create_policy(context=None, policy=policy)
        except Exception as e:
            if "Object exists" not in str(e):
                LOG.error("Unable to create policy '{}'".format(qos_id))
        
        try:
            self.update_policy(context=None, policy=policy)
        except Exception as e:
            LOG.error(e)
            if id_options.retry_next():
                self.runner.run(sync.Priority.HIGHEST, [id_options.encode()],
                                self.sync_qos)

    def sync_qos_orphaned(self, qos_id):
        LOG.debug("Removing orphaned QoS Policy '{}'.".format(qos_id))
        policy = {
            "id": qos_id,
            "name": "ORPHANED-" + qos_id
        }
        self.delete_policy(context=None, policy=policy)

    def get_missing_policies(self, e):
        missing_policies = set()
        try:
            error = json.loads(e.args[1][23:])
            for path_error in error['related_errors']:
                m = re.match(r".*\[/infra/domains/default/groups/(.*)\]", path_error['error_message'])
                if m:
                    missing_policies.add(m.group(1))
        except Exception:
            pass
        return missing_policies

    def sync_security_group_skip_rules(self, security_group_id):
        self.sync_security_group(security_group_id, update_rules=False)

    def sync_security_group(self, security_group_id, update_rules=True):
        LOG.debug("Synching Security Group '{}'.".format(security_group_id))

        id_options = sync.Identifier.decode(security_group_id)

        try:
            self._do_security_group_update(id_options.identifier,
                                           skip_rules=not update_rules)
        except Exception as e:
            if (isinstance(e, oslo_messaging.RemoteError)
                    and e.exc_type == 'ObjectNotFound'
                    or isinstance(e, exceptions.ObjectNotFound)):
                LOG.debug(getattr(e, 'value', 'ObjectNotFound'))
                return

            if not id_options.retry_next():
                LOG.error("Failed updating SG %s skip_rules=%d: %s", security_group_id, not update_rules, e)
                return

            # Ensure circular dependencies are satisfied
            missing_policies = self.get_missing_policies(e)
            if missing_policies:
                self.runner.run(sync.Priority.HIGHEST, self.get_missing_policies(e),
                                self.sync_security_group_skip_rules)
            self.runner.run(sync.Priority.HIGHEST, [id_options.encode()],
                            self.sync_security_group)
            if missing_policies:
                self.runner.run(sync.Priority.MEDIUM, [id_options.encode()],
                                self.sync_security_group)

    def sync_security_group_orphaned(self, security_group_id):
        LOG.debug("Removing orphaned security group '{}'.".format(
            security_group_id))
        self.security_group_delete(security_group_id)

    def get_revisions(self, query):
        limit = cfg.CONF.AGENT.rpc_max_records_per_query
        rev = {}
        created_after = datetime.datetime(1970, 1, 1)
        while True:
            pr_tuples = query(limit=limit, created_after=created_after)
            for port, revision, _ in pr_tuples:
                rev[port] = str(revision)
            if len(pr_tuples) < limit:
                break
            created_after = pr_tuples.pop()[2]
        return rev

    def get_network_bridge(
            self,
            context,
            current,
            network_segments,
            network_current):
        LOG.debug("Trying to map network bridge for networks ...")
        for ns in network_segments:
            seg_id = ns.get("segmentation_id")
            if seg_id:
                LOG.debug("Retrieving bridge for segmentation_id={}"
                          .format(seg_id))
                lock_id = nsxv3_utils.get_segmentation_id_lock(seg_id)
                with LockManager.get_lock(lock_id):
                    id = self.nsxv3.get_switch_id_for_segmentation_id(seg_id)
                    return {
                        'nsx-logical-switch-id': id,
                        'segmentation_id': seg_id
                    }
        return {}

    def port_update(self, context, port=None, network_type=None,
                    physical_network=None, segmentation_id=None):
        LOG.debug("Updating Port='%s' with Segment='%s'", str(port),
                  segmentation_id)
        self.runner.run(sync.Priority.HIGHEST, [port["id"]], self.sync_port)

    def _port_update(self, context, port=None, network_type=None,
                    physical_network=None, vif_details=None):
        vnic_type = port.get(portbindings.VNIC_TYPE)
        vif_type = port.get(portbindings.VIF_TYPE)
        if not ((vnic_type and vnic_type == portbindings.VNIC_NORMAL) and
                (vif_type and vif_type == portbindings.VIF_TYPE_OVS)):
            return

        if 'binding:host_id' in port:
            if not cfg.CONF.host == port.get('binding:host_id'):
                LOG.debug("Skipping Port='%s'. It is not assigned to agent.",
                          str(port))
                return

        address_bindings = []

        for addr in port["fixed_ips"]:
            mac = addr.get("mac_address")
            mac = mac if mac else port["mac_address"]
            address_bindings.append((addr["ip_address"], mac))
        for addr in port["allowed_address_pairs"]:
            address_bindings.append((addr["ip_address"], addr["mac_address"]))

        if port["parent_id"] is None:
            lock = port["id"]
        else:
            lock = port["parent_id"]

        with LockManager.get_lock(lock):
            self.nsxv3.port_update(port, vif_details, address_bindings)
        self.updated_devices.add(port['mac_address'])

    def port_delete(self, context, **kwargs):
        port_id = kwargs["port_id"]
        LOG.debug("Deleting port " + port_id)
        if kwargs.get("sync"):
            with LockManager.get_lock(port_id):
                hours = cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after

                port = self.nsxv3.get_port(\
                    sdk_service=LogicalPorts,
                    sdk_model=LogicalPort(attachment={"id": port_id}))

                timestamp = nsxv3_facada.Timestamp(
                    "marked_for_delete",
                    self.nsxv3, LogicalPorts,
                    port,
                    hours)
                
                if timestamp.has_set():
                    if timestamp.has_expired():
                        self.nsxv3.port_delete(port_id)
                else:
                    timestamp.update()
                    LOG.info("Port {} marked for deletion after {} hours"\
                            .format(port_id, hours))
        # Else, a port is deleted by Nova when destroying the instance

    def create_policy(self, context, policy):
        LOG.debug("Creating policy={}.".format(policy["name"]))
        with LockManager.get_lock(policy["id"]):
            self.nsxv3.create_switch_profile_qos(
                policy["id"], policy["revision_number"])

    def update_policy(self, context, policy):
        LOG.debug("Updating policy={}.".format(policy["name"]))
        with LockManager.get_lock(policy["id"]):
            self.nsxv3.update_switch_profile_qos(context, policy["id"],
                                                 policy["revision_number"],
                                                 policy["rules"])

    def delete_policy(self, context, policy):
        LOG.debug("Deleting policy={}.".format(policy["name"]))
        with LockManager.get_lock(policy["id"]):
            self.nsxv3.delete_switch_profile_qos(policy["id"])

    def validate_policy(self, context, policy):
        LOG.debug("Validating policy={}.".format(policy["name"]))
        self.nsxv3.validate_switch_profile_qos(policy["rules"])


class NSXv3Manager(amb.CommonAgentManagerBase):

    def __init__(self, nsxv3=None, nsxv3_infra=None, vsphere=None, monitoring=True):
        super(NSXv3Manager, self).__init__()
        context = neutron_context.get_admin_context()

        self.nsxv3 = nsxv3
        self.infra = nsxv3_infra
        self.vsphere = vsphere
        self.rpc = None
        self.rpc_plugin = nsxv3_rpc.NSXv3ServerRpcApi(
            context, nsxv3_constants.NSXV3_SERVER_RPC_TOPIC, cfg.CONF.host)
        self.last_sync_time = 0
        self.runner = sync.Runner(
            workers_size=cfg.CONF.NSXV3.nsxv3_concurrent_requests)
        self.sync_inventory = loopingcall.FixedIntervalLoopingCall(
            self.run_sync_inventory)
        self.sync_inventory.start(interval=cfg.CONF.AGENT.polling_interval)

        self.runner.start()
        if monitoring:
            eventlet.greenthread.spawn(exporter.nsxv3_agent_exporter, 
                                       self.runner)

    def shutdown_gracefully(self):
        self.sync_inventory.stop()
        self.runner.stop()

    def run_sync_inventory(self):
        if self.rpc:
            try:
                self.rpc.sync_inventory()
                self.last_sync_time = time.time()
            except Exception:
                LOG.error(traceback.format_exc())

    def get_all_devices(self):
        """Get a list of all devices of the managed type from this host
        A device in this context is a String that represents a network device.
        This can for example be the name of the device or its MAC address.
        This value will be stored in the Plug-in and be part of the
        device_details.
        Typically this list is retrieved from the sysfs. E.g. for linuxbridge
        it returns all names of devices of type 'tap' that start with a certain
        prefix.
        :return: set -- the set of all devices e.g. ['tap1', 'tap2']
        """
        elapsed = (time.time() - self.last_sync_time)
        timeout = 10 * cfg.CONF.AGENT.polling_interval
        if self.last_sync_time and elapsed > timeout:
            raise Exception("Last successful inventory sync {} old > timeout={}, bailing out report state".format(
                elapsed, timeout))
        return set()

    def get_devices_modified_timestamps(self, devices):
        """Get a dictionary of modified timestamps by device
        The devices passed in are expected to be the same format that
        get_all_devices returns.
        :return: dict -- A dictionary of timestamps keyed by device
        """
        return dict()

    def plug_interface(
            self,
            network_id,
            network_segment,
            device,
            device_owner):
        # NSXv3 Agent does not plug standard ports it self, it relies on Nova
        pass

    def ensure_port_admin_state(self, device, admin_state_up):
        """Enforce admin_state for a port
        :param device: The device for which the admin_state should be set
        :param admin_state_up: True for admin_state_up, False for
            admin_state_down
        """

    def get_agent_configurations(self):
        """Establishes the agent configuration map.
        The content of this map is part of the agent state reports to the
        neutron server.
        :return: map -- the map containing the configuration values
        :rtype: dict
        """
        c = cfg.CONF.NSXV3
        return {
            'nsxv3_policy_migration_limit': c.nsxv3_policy_migration_limit,
            'nsxv3_connection_retry_count': c.nsxv3_connection_retry_count,
            'nsxv3_connection_retry_sleep': c.nsxv3_connection_retry_sleep,
            'nsxv3_request_timeout': c.nsxv3_request_timeout,
            'nsxv3_host': c.nsxv3_login_hostname,
            'nsxv3_port': c.nsxv3_login_port,
            'nsxv3_user': c.nsxv3_login_user,
            'nsxv3_password': c.nsxv3_login_password,
            'nsxv3_managed_hosts': c.nsxv3_managed_hosts,
            'nsxv3_transport_zone': c.nsxv3_transport_zone_name}

    def get_agent_id(self):
        """Calculate the agent id that should be used on this host
        :return: str -- agent identifier
        """
        return cfg.CONF.AGENT.agent_id

    def get_extension_driver_type(self):
        """Get the agent extension driver type.
        :return: str -- The String defining the agent extension type
        """
        return nsxv3_constants.NSXV3

    def get_rpc_callbacks(self, context, agent, sg_agent):
        """Returns the class containing all the agent rpc callback methods
        :return: class - the class containing the agent rpc callback methods.
            It must reflect the CommonAgentManagerRpcCallBackBase Interface.
        """
        if not self.rpc:
            self.rpc = NSXv3AgentManagerRpcCallBackBase(
                context=context,
                agent=agent,
                sg_agent=sg_agent,
                nsxv3=self.nsxv3,
                nsxv3_infra = self.infra,
                vsphere=self.vsphere,
                rpc=self.rpc_plugin,
                runner=self.runner)
        return self.rpc

    def get_agent_api(self, **kwargs):
        """Get L2 extensions drivers API interface class.
        :return: instance of the class containing Agent Extension API
        """

    def get_rpc_consumers(self):
        """Get a list of topics for which an RPC consumer should be created
        :return: list -- A list of topics. Each topic in this list is a list
            consisting of a name, an operation, and an optional host param
            keying the subscription to topic.host for plugin calls.
        """
        return [
            [topics.PORT, topics.UPDATE],
            [topics.PORT, topics.DELETE],
            [topics.SECURITY_GROUP, topics.UPDATE],
            [nsxv3_constants.NSXV3, topics.UPDATE]
        ]

    def setup_arp_spoofing_protection(self, device, device_details):
        """Setup the arp spoofing protection for the given port.
        :param device: The device to set up arp spoofing rules for, where
            device is the device String that is stored in the Neutron Plug-in
            for this Port. E.g. 'tap1'
        :param device_details: The device_details map retrieved from the
            Neutron Plugin
        """
        # Spoofguard is handled by port update operation

    def delete_arp_spoofing_protection(self, devices):
        """Remove the arp spoofing protection for the given ports.
        :param devices: List of devices that have been removed, where device
            is the device String that is stored for this port in the Neutron
            Plug-in. E.g. ['tap1', 'tap2']
        """
        # Spoofguard is handled by port delete operation

    def delete_unreferenced_arp_protection(self, current_devices):
        """Cleanup arp spoofing protection entries.
        :param current_devices: List of devices that currently exist on this
            host, where device is the device String that could have been stored
            in the Neutron Plug-in. E.g. ['tap1', 'tap2']
        """


def cli_sync():
    """
    CLI SYNC command force synchronization between Neutron and NSX-T objects
    cfg.CONF.AGENT_CLI for options
    """
    LOG.info("VMware NSXv3 Agent CLI")
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    profiler.setup(nsxv3_constants.NSXV3_BIN, cfg.CONF.host)

    sg_ids = cfg.CONF.AGENT_CLI.neutron_security_group_id
    pt_ids = cfg.CONF.AGENT_CLI.neutron_port_id
    qs_ids = cfg.CONF.AGENT_CLI.neutron_qos_policy_id

    rate=cfg.CONF.NSXV3.nsxv3_requests_per_second
    timeout=cfg.CONF.NSXV3.nsxv3_requests_per_second_timeout
    limit=1

    api_scheduler = sync.Scheduler(rate, limit, timeout)
    nsxv3_client = nsxv3_policy.Client(api_scheduler=api_scheduler)
    nsxv3_infra = nsxv3_policy.InfraService(nsxv3_client)
    nsxv3 = nsxv3_facada.NSXv3Facada(api_scheduler=api_scheduler)
    nsxv3.login()
    vsphere = vsphere_client.VSphereClient()
    manager = NSXv3Manager(nsxv3=nsxv3, nsxv3_infra=nsxv3_infra,
                           vsphere=vsphere, monitoring=False)
    rpc = manager.get_rpc_callbacks(context=None, agent=None, sg_agent=None)

    def execute(sync_single, sync_all, ids):
        sync_all() if '*' in ids else [sync_single(id) for id in ids]

    execute(rpc.sync_security_group, rpc.sync_security_groups, sg_ids)
    execute(rpc.sync_port, rpc.sync_ports, pt_ids)
    execute(rpc.sync_qos, rpc.sync_qos_policies, qs_ids)
    manager.shutdown_gracefully()

    uninitialized = -1
    while uninitialized:
        res = nsxv3.get_uninitalized_policies()
        if res.ok:
            uninitialized = res.json().get('result_count', -1)

        LOG.info("Waiting for %d uninitalized Policies", uninitialized)
        eventlet.sleep(10)


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    profiler.setup(nsxv3_constants.NSXV3_BIN, cfg.CONF.host)
    LOG.info("VMware NSXv3 Agent initializing ...")

    # Enable DEBUG Logging
    try:
        resolution = float(os.getenv('DEBUG_BLOCKING'))
        eventlet.debug.hub_blocking_detection(
            state=True, resolution=resolution)
    except (ValueError, TypeError):
        LOG.error("VMware NSXv3 Agent setting DEBUG configuration has failed.")

    rate=cfg.CONF.NSXV3.nsxv3_requests_per_second
    timeout=cfg.CONF.NSXV3.nsxv3_requests_per_second_timeout
    limit=1

    api_scheduler = sync.Scheduler(rate, limit, timeout)

    nsxv3_client = nsxv3_policy.Client(api_scheduler=api_scheduler)
    nsxv3_infra = nsxv3_policy.InfraService(nsxv3_client)

    nsxv3 = nsxv3_facada.NSXv3Facada(api_scheduler=api_scheduler)
    nsxv3.setup()
    vsphere = vsphere_client.VSphereClient()

    agent = ca.CommonAgentLoop(
        NSXv3Manager(nsxv3=nsxv3, nsxv3_infra=nsxv3_infra, vsphere=vsphere),
        cfg.CONF.AGENT.polling_interval,
        cfg.CONF.AGENT.quitting_rpc_timeout,
        nsxv3_constants.NSXV3_AGENT_TYPE,
        nsxv3_constants.NSXV3_BIN
    )

    LOG.info("Activate runtime migration from ML2 DVS driver=%s",
             is_migration_enabled())
    LOG.info("VMware NSXv3 Agent initialized successfully.")
    service.launch(cfg.CONF, agent, restart_method='mutate').wait()
