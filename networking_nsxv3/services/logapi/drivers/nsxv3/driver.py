from neutron_lib.api.definitions import portbindings
from oslo_log import log as logging
from neutron.services.logapi.drivers import base

LOG = logging.getLogger(__name__)

DRIVER = None

SUPPORTED_LOGGING_TYPES = ['security_group']
SUPPORTED_VIF_TYPES = [portbindings.VIF_TYPE_OVS]


class NSXv3LogDriver(base.DriverBase):

    @staticmethod
    def create(agent_rpc):
        LOG.debug("Initializing NSXV3 Logging driver")
        # TODO - list vif and vnic 
        driver_base_args = {
            "name": 'NSXv3QosDriver',
            "vif_types": SUPPORTED_VIF_TYPES,
            "vnic_types": None,
            "supported_logging_types": SUPPORTED_LOGGING_TYPES,
            "requires_rpc": True
        }

        return NSXv3LogDriver(
            driver_base_args=driver_base_args,
            rpc=agent_rpc
        )

    def __init__(self, driver_base_args, rpc):
        self.rpc = rpc
        if not rpc:
            raise Exception(
                "Unable to load Logging driver as Agent RCP client is missing.")
        super(NSXv3LogDriver, self).__init__(**driver_base_args)

    def create_log(self, context, log_obj):
        LOG.info("Create a log_obj invocation.")
        self.rpc.create_log(context, log_obj)

    def create_log_precommit(self, context, log_obj):
        self.rpc.create_log_precommit(context, log_obj)

    def update_log(self, context, log_obj):
        LOG.info("Update a log_obj invocation")
        self.rpc.update_log(context, log_obj)

    def update_log_precommit(self, context, log_obj):
        self.rpc.update_log_precommit(context, log_obj)

    def delete_log(self, context, log_obj):
        LOG.info("Delete a log_obj invocation")
        self.rpc.delete_log(context, log_obj)

    def delete_log_precommit(self, context, log_obj):
        self.rpc.delete_log_precommit(context, log_obj)

    def resource_update(self, context, log_objs):
        self.rpc.resource_update(context, log_objs)

    def is_vnic_compatible(self, vnic_type):
        # TODO - Add the supported vnic types and remove the overwrite method
        return True

def register():
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = NSXv3LogDriver.create(agent_rpc=None)
    LOG.debug('NSXv3LogDriver logging driver registered')