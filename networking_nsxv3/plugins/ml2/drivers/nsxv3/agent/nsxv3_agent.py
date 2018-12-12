import os

# Eventlet Best Practices
# https://specs.openstack.org/openstack/openstack-specs/specs/eventlet-best-practices.html
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()

import collections
import signal
import six
import sys
import datetime
import random
import time
import uuid
import math
import json

import oslo_messaging

from collections import defaultdict
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_service import service
from oslo_utils import timeutils
from osprofiler.profiler import trace_cls

from neutron.common import profiler
from neutron.common import config as common_config, topics
from neutron_lib import constants as n_const
from neutron_lib import context as neutron_context
from neutron_lib.utils import helpers
from neutron.db.securitygroups_rpc_base import DIRECTION_IP_PREFIX
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.common import profiler as setup_profiler

from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.common import config as nsxv3_config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_client
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_facada
from networking_nsxv3.db import db as db_queries

from com.vmware.nsx_client import  NsGroups, IpSets
from com.vmware.nsx.model_client import FirewallRule
from com.vmware.nsx.model_client import FirewallService
from com.vmware.nsx.model_client import FirewallSection
from com.vmware.nsx.model_client import FirewallSectionRuleList
from com.vmware.nsx.model_client import ResourceReference
from com.vmware.nsx.model_client import L4PortSetNSService
from com.vmware.nsx.model_client import LogicalPort
from com.vmware.nsx.model_client import VapiStruct
from com.vmware.nsx.model_client import IPSet
from com.vmware.nsx.model_client import NSGroup
from com.vmware.nsx.model_client import ICMPTypeNSService
from com.vmware.nsx.model_client import QosSwitchingProfile
from com.vmware.nsx.firewall_client import Sections

from networking_nsxv3.common.locking import LockManager

LOG = logging.getLogger(__name__)


class NSXv3AgentManagerRpcSecurityGroupCallBackMixin(object):

    # RPC method
    def security_groups_member_updated(self, context, **kwargs):
        # TODO to be provided by Alex
        pass

    # RPC method
    def security_groups_rule_updated(self, context, **kwargs):
        # TODO to be provided by Alex
        pass


class NSXv3AgentManagerRpcCallBackBase(
        NSXv3AgentManagerRpcSecurityGroupCallBackMixin,
        amb.CommonAgentManagerRpcCallBackBase):

    target = oslo_messaging.Target(version=nsxv3_constants.RPC_VERSION)

    """
    Base class for managers RPC callbacks.
    """

    def __init__(self, context, config, agent, sg_agent, nsxv3, db):
        super(NSXv3AgentManagerRpcCallBackBase,self).__init__(
            context,agent,sg_agent)
        self.config = config
        self.nsxv3 = nsxv3
        self.db = db
        self.pool = eventlet.greenpool.GreenPool(config.AGENT.sync_pool_size)
    
    def get_active_workers(self):
        return self.pool.running()

    def sync(self):
        (added, updated, orphaned) = self.get_sync_data(
            sdk_model=QosSwitchingProfile(),
            query=self.db.get_qos_policy_revision_tuples)
        for id in added:
            self.pool.spawn(self.sync_qos, id)
        for id in updated:
            self.pool.spawn(self.sync_qos, id)

        (added, updated, orphaned) = self.get_sync_data(
            sdk_model=LogicalPort(),
            query=self.db.get_port_revision_tuples)
        for id in updated:
            self.pool.spawn(self.sync_port, id)

        (added, updated, orphaned) = self.get_sync_data(
            sdk_model=IPSet(),
            query=self.db.get_security_group_revision_tuples)
        for id in updated:
            self.pool.spawn(self.sync_security_group, id)
        for id in added:
            self.pool.spawn(self.sync_security_group, id)

        self.pool.waitall()

    def get_sync_delta(self, db_dict, ep_dict):
        orphaned = ep_dict.copy()
        added = {}
        updated = {}

        # OpenStack is single source of truth
        for id in db_dict:
            if id in orphaned:
                ep_revision = orphaned.pop(id)
                if db_dict[id] != ep_revision:
                    updated[id] = db_dict[id]
            else:
                added[id] = db_dict[id]
        return (added, updated, orphaned)

    def get_sync_data(self, sdk_model, query):
        sdk_type = sdk_model.__class__.__name__
        db = self.get_name_revision_dict(query=query)
        (name_revision, _) = self.nsxv3.get_name_revision_dict(
            sdk_model=sdk_model)

        (added, updated, orphaned) = self.get_sync_delta(
            db_dict=db, ep_dict=name_revision)
        LOG.info("Neutron -> NSX create {}={}".format(sdk_type, added))
        LOG.info("Neutron -> NSX update {}={}".format(sdk_type, updated))
        LOG.info("Neutron -> NSX orphan {}={}".format(sdk_type, orphaned))
        return (added, updated, orphaned)

    def sync_port(self, port_id):
        LOG.debug("Synching port '{}'.".format(port_id))

        (id, mac, up, status, qos_id, revision) = self.db.get_port(port_id)
        port = {
            "id": id,
            "mac_address": mac,
            "admin_state_up": up,
            "status": status,
            "qos_policy_id": qos_id,
            "fixed_ips": [],
            "allowed_address_pairs": [],
            "security_groups": [],
            "revision_number": revision
        }

        for ip, subnet in self.db.get_port_addresses(port_id):
            port["fixed_ips"].append(
                {"ip_address": ip, "mac_address": mac, "subnet_id": subnet})
        
        for (ip, mac) in self.db.get_port_allowed_pairs(port_id):
            port["allowed_address_pairs"].append(
                {"ip_address": ip,"mac_address": mac})
        
        for (sg_id,) in self.db.get_port_security_groups(port_id):
            port["security_groups"].append(sg_id)

        self.port_update(context=None, port=port)

    def sync_qos(self, qos_id):
        LOG.debug("Synching QoS porofile '{}'.".format(qos_id))
        (qos_name, qos_revision_number) = self.db.get_qos(qos_id)
        bwls_rules = self.db.get_qos_bwl_rules(qos_id)
        dscp_rules = self.db.get_qos_dscp_rules(qos_id)

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
        # try:
        self.update_policy(context=None, policy=policy)
        # except Exception as e:
        #     LOG.error("Unable to update policy '{}'".format(e))

    def sync_security_group(self, security_group_id):
        LOG.debug("Synching security group '{}'.".format(security_group_id))
        self.security_group_member_updated(security_group_id)
        self.security_group_rule_updated(security_group_id)

    def get_name_revision_dict(self, query):
        limit = self.config.AGENT.db_max_records_per_query
        id_rev = {}
        created_after = datetime.datetime(1970, 1, 1)
        while True:
            pr_tuples = query(limit=limit, created_after=created_after)
            for port, revision, _ in pr_tuples:
                id_rev[port] = str(revision)
            if len(pr_tuples) < limit:
                break
            created_after = pr_tuples.pop()[2]
        return id_rev

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
                lock_id = "segmentation_id-{}".format(seg_id)
                with LockManager.get_lock(lock_id):
                    id = self.nsxv3.get_switch_id_for_segmentation_id(seg_id)
                    return {'nsx-logical-switch-id': id}
        return {}

    def port_update(self, context, port=None, network_type=None,
            physical_network=None, segmentation_id=None):
        LOG.debug("Updating port " + str(port))

        address_bindings = []

        for addr in port["fixed_ips"]:
            mac = addr.get("mac_address")
            mac = mac if mac else port["mac_address"]
            address_bindings.append((addr["ip_address"], mac))
        for addr in port["allowed_address_pairs"]:
            address_bindings.append((addr["ip_address"], addr["mac_address"]))

        with LockManager.get_lock(port["id"]):
            self.nsxv3.port_update(
                port["id"],
                port["revision_number"],
                port["security_groups"],
                address_bindings,
                qos_name=port["qos_policy_id"]
            )

    def port_delete(self, context, **kwargs):
        LOG.debug("Deleting port " + str(kwargs))
        with LockManager.get_lock(kwargs["port_id"]):
            self.nsxv3.port_delete(kwargs["port_id"])

    def create_policy(self, context, policy):
        LOG.debug("Creating policy={}.".format(policy["name"]))
        with LockManager.get_lock(policy["id"]):
            self.nsxv3.create_switch_profile_qos(
                policy["id"], policy["revision_number"])

    def update_policy(self, context, policy):
        LOG.debug("Updating policy={}.".format(policy["name"]))
        with LockManager.get_lock(policy["id"]):
            self.nsxv3.update_switch_profile_qos(context, policy["id"], 
                policy["revision_number"], policy["rules"])

    def delete_policy(self, context, policy):
        LOG.debug("Deleting policy={}.".format(policy["name"]))
        with LockManager.get_lock(policy["id"]):
            self.nsxv3.delete_switch_profile_qos(self, policy["id"])

    def validate_policy(self, context, policy):
        LOG.debug("Validating policy={}.".format(policy["name"]))
        self.nsxv3.validate_switch_profile_qos(policy["rules"])


class NSXv3Manager(amb.CommonAgentManagerBase):

    def __init__(self, config=None, nsxv3=None):
        super(NSXv3Manager, self).__init__()
        self.config = config
        self.nsxv3 = nsxv3
        self.rpc = None
        self.db = db_queries.DB(config=config,
                                context=neutron_context.get_admin_context())

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
        
        msg = "FULL SYNCHRONIZATION CYCLE - {}"
        if self.rpc:
            active_workers = self.rpc.get_active_workers()
            if active_workers == 0:
                LOG.info(msg.format("STARTED"))
                self.rpc.sync()
                LOG.info(msg.format("COMPLETED"))
            else:
                LOG.info(msg.format("IN PROGRESS - ACTIVE WORKERS '{}'"
                    .format(active_workers)))
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
        pass

    def get_agent_configurations(self):
        """Establishes the agent configuration map.
        The content of this map is part of the agent state reports to the
        neutron server.
        :return: map -- the map containing the configuration values
        :rtype: dict
        """
        config = self.config.NSXV3
        return {
            'nsxv3_connection_retry_count': config.nsxv3_connection_retry_count,
            'nsxv3_connection_retry_sleep': config.nsxv3_connection_retry_sleep,
            'nsxv3_host': config.nsxv3_login_hostname,
            'nsxv3_port': config.nsxv3_login_port,
            'nsxv3_user': config.nsxv3_login_user,
            'nsxv3_password': config.nsxv3_login_password,
            'nsxv3_managed_hosts': config.nsxv3_managed_hosts,
            'nsxv3_transport_zone': config.nsxv3_transport_zone_name}

    def get_agent_id(self):
        """Calculate the agent id that should be used on this host
        :return: str -- agent identifier
        """
        return self.config.AGENT.agent_id

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
                config=self.config,
                agent=agent,
                sg_agent=sg_agent,
                nsxv3=self.nsxv3,
                db=self.db)
        return self.rpc

    def get_agent_api(self, **kwargs):
        """Get L2 extensions drivers API interface class.
        :return: instance of the class containing Agent Extension API
        """
        pass

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
        pass

    def delete_arp_spoofing_protection(self, devices):
        """Remove the arp spoofing protection for the given ports.
        :param devices: List of devices that have been removed, where device
            is the device String that is stored for this port in the Neutron
            Plug-in. E.g. ['tap1', 'tap2']
        """
        # Spoofguard is handled by port delete operation
        pass

    def delete_unreferenced_arp_protection(self, current_devices):
        """Cleanup arp spoofing protection entries.
        :param current_devices: List of devices that currently exist on this
            host, where device is the device String that could have been stored
            in the Neutron Plug-in. E.g. ['tap1', 'tap2']
        """
        pass


def main():
    LOG.info("VMware NSXv3 Agent initializing ...")
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    profiler.setup(nsxv3_constants.NSXV3_BIN, cfg.CONF.host)

    # Enable DEBUG Logging
    try:
        resolution = float(os.getenv('DEBUG_BLOCKING'))
        eventlet.debug.hub_blocking_detection(
            state=True, resolution=resolution)
    except (ValueError, TypeError):
        LOG.error("VMware NSXv3 Agent setting DEBUG configuration has failed.")

    nsxv3 = nsxv3_facada.NSXv3Facada()
    nsxv3.setup()

    agent = ca.CommonAgentLoop(
        NSXv3Manager(config=cfg.CONF, nsxv3=nsxv3),
        cfg.CONF.AGENT.polling_interval,
        cfg.CONF.AGENT.quitting_rpc_timeout,
        nsxv3_constants.NSXV3_AGENT_TYPE,
        nsxv3_constants.NSXV3_BIN
    )

    LOG.info("VMware NSXv3 Agent initialized successfully.")
    service.launch(cfg.CONF, agent, restart_method='mutate').wait()
