import networking_nsxv3.common.config

from neutron import service
from neutron.agent import securitygroups_rpc
from neutron.db import provisioning_blocks
from neutron.plugins.ml2.drivers import mech_agent
from neutron_lib.services.trunk import constants as trunk_consts
from neutron_lib import context as ctx, rpc
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources, registry, events
from neutron_lib.plugins.ml2 import api
from oslo_log import log
from oslo_config import cfg

from networking_nsxv3.api import rpc as nsxv3_rpc
from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.services.qos.drivers.nsxv3 import qos as nsxv3_qos
from networking_nsxv3.services.trunk.drivers.nsxv3 import trunk as nsxv3_trunk
from networking_nsxv3.services.logapi.drivers.nsxv3 import driver as nsxv3_logging
from neutron.objects import trunk as trunk_objects

from networking_nsxv3.extensions.nsxtoperations import Nsxtoperations  # auto-loads api on neutron server start

from oslo_utils import importutils
from neutron.services.logapi.drivers import manager

LOG = log.getLogger(__name__)

class MaxSecurityGroupsPerPortExceeded(Exception):
    """Not more than 28 security groups per port can be assigned"""
class VMwareNSXv3MechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using vmware nsx-t agent.

    The driver integrates the ml2 plugin with the nsx-t L2 agent via RPC.
    Where the binding:vif_type and binding:vif_details values are the
    same for all bindings.

    Port binding with this driver sends message to a topic, then
    all the agents listening on that topic try to handle the request.
    Only the agent having the same host.id should be able to bind the port.

    Network creation with this driver sends message to a topic, then
    all the agents listening on that topic try to handle the request.
    It is expected that all the agents have to handle the request.

    In case of offline agent, the one has to reconfigure network once
    get back online.
    """

    version = nsxv3_constants.NSXV3_VERSION

    def __init__(self):
        self.agent_type = nsxv3_constants.NSXV3_AGENT_TYPE
        LOG.info("Initializing Mechanism Driver Type=" + str(self.agent_type))

        self.context = ctx.get_admin_context_without_session()

        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        LOG.info("Security Gruop Enabled=" + str(sg_enabled))

        self.vif_type = portbindings.VIF_TYPE_OVS
        self.vif_details = {
            portbindings.CAP_PORT_FILTER: sg_enabled,
            portbindings.VIF_DETAILS_CONNECTIVITY:
                portbindings.CONNECTIVITY_L2
        }

        self.rpc = nsxv3_rpc.NSXv3AgentRpcClient(self.context)
        self.trunk = nsxv3_trunk.NSXv3TrunkDriver.create()
        self.qos = nsxv3_qos.NSXv3QosDriver.create(self.rpc)
        self.logging = nsxv3_logging.NSXv3LogDriver.create(self.rpc)

        # Register the log driver at Neutron logging api drivers manager
        importutils.import_module('neutron.services.logapi.common.sg_validate')
        manager.register(resources.SECURITY_GROUP, self.logging.register_callback_handler)
        LOG.info("Successfully registered NSXV3 log driver.")

        super(VMwareNSXv3MechanismDriver, self).__init__(
                self.agent_type,
                self.vif_type,
                self.vif_details
        )

        LOG.info("Initialized Mechanism Driver Type = " + str(self.agent_type))

    def get_workers(self):
        return [service.RpcWorker([self], worker_process_count=0)]

    def start_rpc_listeners(self):
        """Start the RPC loop to let the plugin communicate with agents."""
        self.conn = rpc.Connection()
        self.conn.create_consumer(nsxv3_constants.NSXV3_SERVER_RPC_TOPIC,
                             [nsxv3_rpc.NSXv3ServerRpcCallback()],
                             fanout=False)
        return self.conn.consume_in_threads()

    # Overwrite
    def get_allowed_network_types(self, agent):
        return nsxv3_constants.NSXV3_AGENT_NETWORK_TYPES

    # Overwrite
    # Network mappings will be dynamic
    # https://specs.openstack.org/openstack/neutron-specs/specs/juno/ml2-hierarchical-port-binding.html
    def get_mappings(self, agent):
        return nsxv3_constants.NSXV3_AGENT_NETWORK_MAPPING

    # Overwrite
    def try_to_bind_segment_for_agent(self, context, segment, agent):
        LOG.debug('Bind Segment={} for Agent={}'.format(segment, agent))

        device = context.current.get('device_owner', '')
        admin_state_up = agent.get('admin_state_up', False)
        agent_alive = agent.get('alive', False)
        agent_type = agent['agent_type']
        host = agent.get('host', None)
        physical_network = segment.get('physical_network')
        transport_zone = agent.get('configurations', {}).get('nsxv3_transport_zone')

        if not (device.startswith('compute') or device.startswith(trunk_consts.TRUNK_SUBPORT_OWNER)):
            LOG.warn(
                "Only compute and trunk subport devices are supported. Device=" +
                str(device))
            return False

        if not admin_state_up:
            LOG.error("Agent is in AdminStateUp=" + str(admin_state_up))
            return False

        if not agent_alive:
            LOG.error("Agent is in Alive=" + str(agent_alive))
            return False

        if not agent_type.lower() == self.agent_type.lower():
            LOG.warn("Unsupported agent type: Type=" + str(agent_type))
            return False

        if not host == context.current['binding:host_id']:
            LOG.warn("Not supported host. Host=" + str(host))
            return False

        if not physical_network:
            LOG.warn("Needs a valid physical network for binding")
            return False

        # We cannot rely on always getting the right segment
        if len(context.segments_to_bind) > 1 and transport_zone:
            # Remove bb
            bb = transport_zone.lstrip('b')
            # remove leading zeros
            bb = bb.lstrip('0')
            # remove -vlan
            if bb.endswith('-vlan'):
                bb = bb[:-5]
            # readd bb
            bb = 'bb{}'.format(bb)

            if not(physical_network in transport_zone or physical_network == bb):
                LOG.warn("No segment found for physical_network=" + str(physical_network))
                return False

        subport = trunk_objects.SubPort.get_object(context=ctx.get_admin_context(), port_id=context.current['id'])
        if bool(subport)\
            and context.current.get("binding:profile") == {}\
                and context.current.get("device:owner") != "trunk:subport":
            # skip binding as this is a binding request for subport without parent binding
            raise Exception(f"Standalone binding of subports not allowed! Subport: {subport}")

        response = self.rpc.get_network_bridge(
            context.current, [segment], context.network.current, context.host
        )

        vif_details = self.vif_details.copy()
        vif_details.update(response)

        if not vif_details.get('nsx-logical-switch-id'):
            LOG.info("Agent {} did not provide nsx-logical-switch-id for network {} of port {}"
                     .format(host, context.network.current.get('id'), context.current.get('id')))
            return False
        else:
            # Bind the port
            context.set_binding(segment[api.ID], self.vif_type, vif_details)

            return True

    def _update_trunk_subports(self, parent, delete=False):
        admin_ctx = ctx.get_admin_context()
        truk_id = parent.get('trunk_details', {}).get('trunk_id')
        sub_ports = parent.get('trunk_details', {}).get('sub_ports', [])

        subports = [trunk_objects.SubPort(
                        context=admin_ctx,
                        port_id=p['port_id'],
                        segmentation_id=p['segmentation_id'],
                        segmentation_type=p['segmentation_type'])
                for p in sub_ports]
        trunk = trunk_objects.Trunk.get_object(context=admin_ctx, id=truk_id)
        payload = events.DBEventPayload(admin_ctx, resource_id=trunk.id,
                                        states=(trunk, trunk,),
                                        metadata={
                                            'subports': subports
                                        })

        if delete:
            registry.publish(resources.SUBPORTS, events.AFTER_DELETE, self, payload=payload)
        else:
            registry.publish(resources.SUBPORTS, events.AFTER_CREATE, self, payload=payload)

    def update_port_postcommit(self, context: api.PortContext):
        """ Set port status to ACTIVE, this is normaly done by
            neutron itself if the device (port) has been added
            to the updated devices, but this won't work because
            get_all_devices is implemented as a empty set.

                self.updated_devices.add(port['mac_address'])

            As a workaround we manually set every updated port
            using our database session to completed.

            As an addition we also bind/unbind subports if the any"""
        port = context.current
        if port[portbindings.VNIC_TYPE] in self.supported_vnic_types:
            sub_ports = port.get('trunk_details', {}).get('sub_ports')
            if port[portbindings.VIF_TYPE] in ['unbound', 'binding_failed']:
                # If we have subports, we need to unbind them also
                if bool(sub_ports):
                    self._update_trunk_subports(port, delete=True)
                provisioning_blocks.remove_provisioning_component(
                    context._plugin_context, port['id'], resources.PORT, provisioning_blocks.L2_AGENT_ENTITY)
            elif port[portbindings.VIF_TYPE] == self.vif_type:
                # If we have subports, we need to bind them also
                if bool(sub_ports):
                    self._update_trunk_subports(port)
                # Set status to ACTIVE
                provisioning_blocks.provisioning_complete(
                    context._plugin_context, port['id'], resources.PORT, provisioning_blocks.L2_AGENT_ENTITY)

    def trigger_sync(self, id, type):
        self.rpc.trigger_manual_update(id=id, type=type)

    def _enforce_max_sg_per_segment_port(self, port):
        if len(port['security_groups']) >= cfg.CONF.AGENT.max_sg_tags_per_segment_port:
            raise MaxSecurityGroupsPerPortExceeded
    def create_port_precommit(self, context):
        """Enforce max number of security groups per port """
        super().create_port_precommit(context)
        self._enforce_max_sg_per_segment_port(context.current)
    def update_port_precommit(self, context):
        """Enforce max number of security groups per port during update"""
        super().update_port_precommit(context)
        self._enforce_max_sg_per_segment_port(context.current)