from neutron_lib.callbacks import resources
from oslo_log import log

from neutron.db import provisioning_blocks
from neutron.plugins.ml2.drivers import mech_agent
from neutron.agent import securitygroups_rpc

from neutron_lib import context
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins.ml2 import api

from neutron_lib import rpc as n_rpc


from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.api import rpc as nsxv3_rpc
from networking_nsxv3.services.trunk.drivers.nsxv3 import trunk as nsxv3_trunk
from networking_nsxv3.services.qos.drivers.nsxv3 import qos as nsxv3_qos

LOG = log.getLogger(__name__)


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

        self.context = context.get_admin_context_without_session()

        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        LOG.info("Security Gruop Enabled=" + str(sg_enabled))

        self.vif_type = portbindings.VIF_TYPE_OVS
        self.vif_details = {
            portbindings.CAP_PORT_FILTER: sg_enabled,
            portbindings.OVS_HYBRID_PLUG: sg_enabled,
        }

        self.rpc = nsxv3_rpc.NSXv3AgentRpcClient(self.context)
        self.trunk = nsxv3_trunk.NSXv3TrunkDriver.create()
        self.qos = nsxv3_qos.NSXv3QosDriver.create(self.rpc)

        conn = n_rpc.Connection()
        conn.create_consumer(nsxv3_constants.NSXV3_SERVER_RPC_TOPIC,
                             [nsxv3_rpc.NSXv3ServerRpcCallback()],
                             fanout=False)
        conn.consume_in_threads()

        super(VMwareNSXv3MechanismDriver, self).__init__(
            self.agent_type,
            self.vif_type,
            self.vif_details
        )

        LOG.info("Initialized Mechanism Driver Type=" + str(self.agent_type))

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

        device = context.current.get('device_owner', "")
        admin_state_up = agent.get('admin_state_up', False)
        agent_alive = agent.get('alive', False)
        agent_type = agent['agent_type']
        host = agent.get('host', None)

        if not device.startswith('compute'):
            LOG.warn(
                "Only compute devices are supported. Device=" +
                str(device))
            return False

        if not admin_state_up:
            LOG.error("Agent is in AdminStateUp=" + str(admin_state_up))
            return False

        if not agent_alive:
            LOG.error("Agent is in Alive=" + str(agent_alive))
            return False

        if not agent_type.lower() == self.agent_type.lower():
            LOG.warn("Un supported agent type Type=" + str(agent_type))
            return False

        if not host == context.current['binding:host_id']:
            LOG.warn("Not supported host. Host=" + str(host))
            return False

        response = self.rpc.get_network_bridge(
            context.current, [segment], context.network.current, context.host
        )

        vif_details = self.vif_details.copy()
        vif_details['nsx-logical-switch-id'] = response.get(
            'nsx-logical-switch-id')
        vif_details['external-id'] = response.get('nsx-logical-switch-id')
        vif_details['segmentation_id'] = response.get('segmentation_id')

        if not vif_details['nsx-logical-switch-id']:
            LOG.error("Agent={} did not provide nsx-logical-switch-id."
                      .format(agent_type))
            return False
        else:
            context.set_binding(segment[api.ID], self.vif_type, vif_details)
            return True

    def update_port_postcommit(self, context):
        """ Set port status to ACTIVE, this is normaly done by
            neutron itself if the device (port) has been added
            to the updated devices, but this won't work because
            get_all_devices is implemented as a empty set.

                self.updated_devices.add(port['mac_address'])

            As a workaround we manually set every updated port
            using our database session to completed."""
        port = context.current
        if (port[portbindings.VNIC_TYPE] in self.supported_vnic_types and
                port[portbindings.VIF_TYPE] == self.vif_type):
            provisioning_blocks.provisioning_complete(
                context._plugin_context, port['id'], resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)
