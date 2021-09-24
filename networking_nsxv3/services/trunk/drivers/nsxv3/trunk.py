from networking_nsxv3.common import constants as nsxv3_constants
from neutron.services.trunk.drivers import base
from neutron_lib import constants, context
from neutron_lib.api.definitions import port, portbindings
from neutron_lib.callbacks import events, registry, resources
from neutron_lib.plugins import directory
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NSXv3TrunkDriver(base.DriverBase):
    """
    NSXv3 dummy trunk driver to register neutron's trunk extension.

    Driver is dummy as ML2 NSXv3 is supposed to work in a multy NSXv3 Manager
    environment and a port will not be created until port-bind is called.
    """

    @property
    def is_loaded(self):
        try:
            return cfg.CONF.core_plugin.lower() == 'ml2'
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls):
        SUPPORTED_INTERFACES = (portbindings.VIF_TYPE_OVS,)
        SUPPORTED_SEGMENTATION_TYPES = (trunk_consts.SEGMENTATION_TYPE_VLAN,)
        return cls(
            nsxv3_constants.NSXV3,
            SUPPORTED_INTERFACES,
            SUPPORTED_SEGMENTATION_TYPES,
            agent_type=None,
            can_trunk_bound_port=True
        )

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        LOG.info("NSXv3 trunk driver initializing ...")
        super(
            NSXv3TrunkDriver,
            self).register(
                resource,
                event,
                trigger,
                payload=payload)

        self.core_plugin = directory.get_plugin()

        registry.subscribe(self.trunk_create, resources.TRUNK, events.AFTER_CREATE)
        registry.subscribe(self.trunk_delete, resources.TRUNK, events.AFTER_DELETE)
        registry.subscribe(self.subport_create, resources.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.subport_delete, resources.SUBPORTS, events.AFTER_DELETE)

        LOG.info("NSXv3 trunk driver initialized.")

    def _get_context_and_parent_port(self, parent_port_id):
        """Get admin context and parent port

        Return None, None if this driver is not responsible for this trunk/port
        """
        ctx = context.get_admin_context()
        parent = self.core_plugin.get_port(ctx, parent_port_id)
        if not self.is_interface_compatible(parent[portbindings.VIF_TYPE]):
            return None, None
        return ctx, parent

    def trunk_create(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.current_trunk.port_id)
        if not parent:
            return

        LOG.info("Trunk create called, resource %s payload %s trunk id %s",
                 resource, payload, payload.trunk_id)
        self._bind_subports(ctx, parent, payload.current_trunk, payload.current_trunk.sub_ports)
        payload.current_trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)

    def trunk_delete(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.original_trunk.port_id)
        if not parent:
            return

        LOG.info("Trunk %s delete called", payload.trunk_id)
        self._bind_subports(ctx, parent, payload.original_trunk, payload.original_trunk.sub_ports, delete=True)

    def subport_create(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.current_trunk.port_id)
        if not parent:
            return

        self._bind_subports(ctx, parent, payload.current_trunk, payload.subports)

    def subport_delete(self, resource, event, trunk_plugin, payload):
        ctx, parent = self._get_context_and_parent_port(payload.current_trunk.port_id)
        if not parent:
            return

        self._bind_subports(ctx, parent, payload.current_trunk, payload.subports, delete=True)

    def _bind_subports(self, ctx, parent, trunk, subports, delete=False):
        for subport in subports:
            LOG.debug("%s parent %s for subport %s on trunk %s",
                      "Setting" if not delete else "Unsetting",
                      trunk.port_id, subport.port_id, trunk.id)
            if not delete:
                binding_profile = parent.get(portbindings.PROFILE)
                binding_profile['nsxv3_trunk'] = {
                    'port_parent_id': trunk.port_id
                }

                port_data = {
                    port.RESOURCE_NAME: {
                        portbindings.HOST_ID: parent.get(portbindings.HOST_ID),
                        portbindings.VNIC_TYPE: parent.get(portbindings.VNIC_TYPE),
                        portbindings.PROFILE: binding_profile,
                        # 'device_owner': parent.get('device_owner'),
                        'device_owner': trunk_consts.TRUNK_SUBPORT_OWNER,
                        'device_id': parent.get('device_id'),
                        # do not set port to active, the driver can do this!
                        # 'status': constants.PORT_STATUS_ACTIVE,
                    },
                }
            else:
                port_data = {
                    port.RESOURCE_NAME: {
                        portbindings.HOST_ID: None,
                        portbindings.VNIC_TYPE: None,
                        portbindings.PROFILE: None,
                        'device_owner': '',
                        'device_id': '',
                        'status': constants.PORT_STATUS_DOWN,
                    },
                }
            self.core_plugin.update_port(ctx, subport.port_id, port_data)

        if len(trunk.sub_ports) > 0:
            trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)
        else:
            # trunk is automatically set to DOWN on change. if we don't change that it will stay that way
            LOG.info("Last subport was removed from trunk %s, setting it to state DOWN", trunk.id)
