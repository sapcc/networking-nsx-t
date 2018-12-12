from neutron_lib import constants
from neutron_lib.db import constants as db_constants
from neutron_lib.services.qos import base
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

DRIVER = None

SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, db_constants.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, db_constants.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': [constants.EGRESS_DIRECTION,
                            constants.INGRESS_DIRECTION]}
    },
    qos_consts.RULE_TYPE_DSCP_MARKING: {
        qos_consts.DSCP_MARK: {'type:values': constants.VALID_DSCP_MARKS}
    }
}


class NSXv3QosDriver(base.DriverBase):

    @staticmethod
    def create(agent_rpc):
        driver_base_args = {
            "name": 'NSXv3QosDriver',
            "vif_types": None,
            "vnic_types": None,
            "supported_rules": SUPPORTED_RULES,
            "requires_rpc_notifications": False
        }
        return NSXv3QosDriver(
            driver_base_args=driver_base_args,
            rpc=agent_rpc
        )

    def __init__(self, driver_base_args, rpc):
        self.rpc = rpc
        if not rpc:
            raise Exception(
                "Unable to load QoS driver as Agent RCP client is missing.")
        super(NSXv3QosDriver, self).__init__(**driver_base_args)

    def is_vif_type_compatible(self, vif_type):
        return True

    def is_vnic_compatible(self, vnic_type):
        return True

    def create_policy(self, context, policy):
        self.rpc.create_policy(context, policy)

    def update_policy(self, context, policy):
        self.rpc.update_policy(context, policy)

    def delete_policy(self, context, policy):
        self.rpc.delete_policy(context, policy)

    def update_policy_precommit(self, context, policy):
        self.rpc.update_policy_precommit(context, policy)


def register():
    """Register the NSX-V3 QoS driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = NSXv3QosDriver.create(agent_rpc=None)
    LOG.debug('NSXv3QosDriver QoS driver registered')
