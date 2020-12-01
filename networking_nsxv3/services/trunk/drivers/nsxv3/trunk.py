from oslo_config import cfg
from oslo_log import log as logging

from neutron_lib.callbacks import resources
from neutron_lib.services.trunk import constants as trunk_consts

from neutron.services.trunk.drivers import base
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import port
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.plugins import directory
from neutron_lib import context
from neutron_lib import constants

from networking_nsxv3.common import constants as nsxv3_constants

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

        registry.subscribe(self.trunk_create, trunk_consts.TRUNK, events.AFTER_CREATE)
        registry.subscribe(self.trunk_update, trunk_consts.TRUNK, events.AFTER_UPDATE)
        registry.subscribe(self.trunk_delete, trunk_consts.TRUNK, events.AFTER_DELETE)
        registry.subscribe(self.subport_create, trunk_consts.SUBPORTS, events.AFTER_CREATE)
        registry.subscribe(self.subport_delete, trunk_consts.SUBPORTS, events.AFTER_DELETE)
    
        LOG.info("NSXv3 trunk driver initialized.")


    def trunk_create(self, resource, event, trunk_plugin, payload):
        LOG.info("Trunk create called, resource %s payload %s trunk id %s",
                 resource, payload, payload.trunk_id)
        self._bind_subports(payload.current_trunk, payload.current_trunk.sub_ports)
        payload.current_trunk.update(status=trunk_consts.ACTIVE_STATUS)

    def trunk_update(self, resource, event, trunk_plugin, payload):
        LOG.info("Trunk %s update called", payload.trunk_id)

    def trunk_delete(self, resource, event, trunk_plugin, payload):
        LOG.info("Trunk %s delete called", payload.trunk_id)
        self._bind_subports(payload.original_trunk, payload.original_trunk.sub_ports, delete=True)

    def subport_create(self, resource, event, trunk_plugin, payload):
        self._bind_subports(payload.current_trunk, payload.subports)

    def subport_delete(self, resource, event, trunk_plugin, payload):
        self._bind_subports(payload.current_trunk, payload.subports, delete=True)

    def _bind_subports(self, trunk, subports, delete=False):
        ctx = context.get_admin_context()
        parent = self.core_plugin.get_port(ctx, trunk.port_id)

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
            trunk.update(status=trunk_consts.ACTIVE_STATUS)
        else:
            # trunk is automatically set to DOWN on change. if we don't change that it will stay that way
            LOG.info("Last subport was removed from trunk %s, setting it to state DOWN", trunk.id)