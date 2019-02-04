from oslo_config import cfg
from oslo_log import log as logging

from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry

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
        SUPPORTED_SEGMENTATION_TYPES = (trunk_consts.VLAN,)
        return cls(
            nsxv3_constants.NSXV3,
            SUPPORTED_INTERFACES,
            SUPPORTED_SEGMENTATION_TYPES,
            agent_type=None,
            can_trunk_bound_port=True
        )

    @registry.receives(trunk_consts.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        LOG.info("NSXv3 dummy trunk driver initializing ...")
        super(
            NSXv3TrunkDriver,
            self).register(
                resource,
                event,
                trigger,
                payload=payload)
        LOG.info("NSXv3 dummy trunk driver initialized.")
