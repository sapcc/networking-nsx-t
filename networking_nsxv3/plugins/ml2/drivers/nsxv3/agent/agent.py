import os
import sys

import oslo_messaging
from neutron.common import config as common_config
from neutron.common import profiler
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall, service

from networking_nsxv3.api import rpc as nsxv3_rpc
from networking_nsxv3.common import config  # noqa
from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.common import synchronization as sync
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import (
    provider_nsx_mgmt, provider_nsx_policy, realization)
from networking_nsxv3.prometheus import exporter
from neutron_lib.agent import topics
from neutron_lib.api.definitions import portbindings

try:
    from neutron.conf.agent import common as agent_config
except ImportError:
    from neutron.agent.common import agent_config

# Eventlet Best Practices
# https://specs.openstack.org/openstack/openstack-specs/specs/eventlet-best-practices.html
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class NSXv3AgentManagerRpcCallBackBase(amb.CommonAgentManagerRpcCallBackBase):

    target = oslo_messaging.Target(version=nsxv3_constants.RPC_VERSION)

    """
    Base class for managers RPC callbacks.
    """

    def __init__(self, context, agent, sg_agent, callback, realizer):
        super(NSXv3AgentManagerRpcCallBackBase, self).__init__(
            context, agent, sg_agent)
        self.callback = callback
        self.realizer = realizer

    def get_network_bridge(self, context, current, network_segments, network_current):
        if current.get('binding:vif_type') == portbindings.VIF_TYPE_UNBOUND and \
                current.get('status') == nsxv3_constants.neutron_constants.ACTIVE:
            # This is a double-bound port with inactive new binding, proactivly sync it
            self.port_update(context, port=current)
        else:
            self.port_create(port=current)
        for ns in network_segments:
            cfg.CONF.NSXV3.nsxv3_transport_zone_name
            seg_id = ns.get("segmentation_id")
            net_type = ns.get("network_type")
            if seg_id and net_type in nsxv3_constants.NSXV3_AGENT_NETWORK_TYPES:
                return self.realizer.network(seg_id)
        return dict()

    def security_groups_member_updated(self, context, **kwargs):
        self.callback(kwargs["security_groups"],
                      self.realizer.security_group_members)

    def security_groups_rule_updated(self, context, **kwargs):
        self.callback(kwargs["security_groups"],
                      self.realizer.security_group_rules)

    def port_create(self, **kwargs):
        self.realizer.port(kwargs["port"]["id"])

    def port_update(self, context, **kwargs):
        # Ensure security groups attached to the port are synced first
        for sg in kwargs["port"].get('security_groups', []):
            self.callback(sg, self.realizer.security_group_rules)
        self.callback(kwargs["port"]["id"], self.realizer.port)

    def port_delete(self, context, **kwargs):
        # Ports removed by the background synchronization
        pass

    def create_policy(self, context, policy):
        self.update_policy(context, policy)

    def delete_policy(self, context, policy):
        self.update_policy(context, policy)

    def update_policy(self, context, policy):
        self.callback(policy["id"], self.realizer.qos)

    def validate_policy(self, context, policy):
        pass


class NSXv3Manager(amb.CommonAgentManagerBase):

    def __init__(self, rpc, synchronization=True, monitoring=True, force_api=None):
        super(NSXv3Manager, self).__init__()

        legacy_provider = provider_nsx_mgmt.Provider()
        provider = provider_nsx_policy.Provider()

        provider_version = provider.client.version
        LOG.info("Detected NSX-T %s version.", provider_version)

        info = "Activating %s API in primary mode and %s API in legacy mode."

        if (force_api == "Management" if force_api else provider_version < (3, 0)):
            LOG.info(info, "Management", "Policy")
            tmp_provider = legacy_provider
            legacy_provider = provider
            provider = tmp_provider
        else:
            LOG.info(info, "Policy", "Management")

        self.runner = sync.Runner(
            workers_size=cfg.CONF.NSXV3.nsxv3_concurrent_requests)
        self.runner.start()

        self.realizer = realization.AgentRealizer(
            rpc=rpc,
            callback=self._sync_delayed,
            kpi=self.kpi,
            provider=provider,
            legacy_provider=legacy_provider)

        self.synchronization = synchronization
        self.synchronizer = loopingcall.FixedIntervalLoopingCall(
            self._sync_all)
        self.reload()

        if monitoring:
            exporter.nsxv3_agent_exporter()

    def _sync_all(self):
        try:
            self.realizer.all()
        except Exception as err:
            LOG.error("Synchronization has failed. Error: %s", err)

    def _sync_immediate(self, os_ids, realizer):
        ids = list(os_ids) if isinstance(os_ids, set) else os_ids
        ids = ids if isinstance(ids, list) else [ids]
        self.runner.run(sync.Priority.HIGHEST, ids, realizer)

    def _sync_delayed(self, os_ids, realizer):
        ids = list(os_ids) if isinstance(os_ids, set) else os_ids
        ids = ids if isinstance(ids, list) else [ids]
        self.runner.run(sync.Priority.HIGH, ids, realizer)

    def kpi(self):
        return {
            "active": self.runner.active(),
            "passive": self.runner.passive()
        }

    def reload(self):
        if self.synchronization:
            self.synchronizer.start(interval=cfg.CONF.AGENT.polling_interval)

    def shutdown(self):
        self.synchronizer.stop()
        LOG.info("Synchronization terminated successfully.")
        self.runner.stop()
        LOG.info("Job Queue terminated successfully.")

    def get_all_devices(self):
        """Get a list of all devices of the managed type from this host
        A device in this context is a String that represents a network device.
        This can for example be the name of the device or its MAC address.
        This value will be stored in the Plug-in and be part of the
        device_details.
        Typically this list is retrieved from the sysfs. E.g. for linuxbridge
        it returns all names of devices of type 'tap' that start with a certain`````
        prefix.
        :return: set -- the set of all devices e.g. ['tap1', 'tap2']
        """
        return set()

    def get_devices_modified_timestamps(self, devices):
        """Get a dictionary of modified timestamps by device
        The devices passed in are expected to be the same format that
        get_all_devices returns.
        :return: dict -- A dictionary of timestamps keyed by device
        """
        return dict()

    def plug_interface(self, network_id, network_segment, device, device_owner):
        # This agent relies on Nova for port plug-in
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
        if not hasattr(self, 'rpc'):
            self.rpc = NSXv3AgentManagerRpcCallBackBase(context, agent,
                sg_agent, callback=self._sync_immediate, realizer=self.realizer)
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
        # Spoofguard is handled by port delete operation


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    agent_config.register_agent_state_opts_helper(cfg.CONF)
    profiler.setup(nsxv3_constants.NSXV3_BIN, cfg.CONF.host)
    LOG.info("VMware NSXv3 Agent initializing ...")

    try:
        resolution = os.getenv('DEBUG_BLOCKING')
        if resolution is not None:
            eventlet.debug.hub_blocking_detection(
                state=True, resolution=float(resolution))
        else:
            LOG.info(
                "Eventlet blocking behavior detection initialization completed.")
    except (ValueError, TypeError):
        LOG.error("Initializing Eventlet blocking behavior detection has failed.")

    agent = ca.CommonAgentLoop(
        NSXv3Manager(rpc=nsxv3_rpc.NSXv3ServerRpcApi()),
        cfg.CONF.AGENT.polling_interval,
        cfg.CONF.AGENT.quitting_rpc_timeout,
        nsxv3_constants.NSXV3_AGENT_TYPE,
        nsxv3_constants.NSXV3_BIN
    )

    LOG.info("VMware NSXv3 Agent initialized successfully.")
    service.launch(cfg.CONF, agent, restart_method='mutate').wait()
