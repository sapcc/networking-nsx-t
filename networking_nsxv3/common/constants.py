from enum import Enum
from neutron_lib import constants as neutron_constants

# Driver
NSXV3 = 'nsxv3'
NSXV3_VERSION = '2.3'
NSXV3_BIN = 'neutron-nsxv3-agent'
NSXV3_AGENT_TYPE = 'NSXv3 Agent'
NSXV3_AGENT_LOGIN_RETRIES = 3
NSXV3_AGENT_NETWORK_TYPES = [
    neutron_constants.TYPE_VLAN,
    neutron_constants.TYPE_FLAT
]
NSXV3_AGENT_NETWORK_MAPPING = dict()

NSXV3_SECURITY_GROUP_SCOPE = "security_group"
NSXV3_SECURITY_GROUP_REMOTE_SCOPE = "security_group_remote_id"
NSXV3_SECURITY_GROUP_RULE_BATCH_SIZE = 265
NSXV3_REVISION_SCOPE = "revision_number"
NSXV3_AGE_SCOPE = "age"
DEFAULT_MALICIOUS_GROUP_NAME = "DefaultMaliciousIpGroup"

# DFW Logging
NSXV3_LOGGING_SCOPE = "logging"
NSXV3_LOGGING_ENABLED = "enabled"
NSXV3_DEFAULT_POLICY_ID = "DefaultML2Policy"
NSXV3_DEFAULT_LOGGING_ID = "DefaultLoggingRule"

NSXV3_MP_MIGRATION_SCOPE = "mp2policy_migr_status"
NSXV3_HOSTSWITCH_MIGRATION_SCOPE = "hostswitch_migr_status"
NSXV3_MIGRATION_SUCCESS_TAG = "success"

NSXV3_CAPABILITY_TCP_STRICT = "capability_tcp_strict"
# If TCP strict is enabled on a section and a packet matches rule in it,
# Will check to see if the SYN flag of the packet is set.
# If it is not, then it will drop the packet.

# Set RPC API version to 1.0 by default.
# history
#   1.1 Support Security Group RPC
#   1.3 Added param devices_to_update to security_groups_provider_updated
#   1.4 Added support for network_update
#   1.5 Added binding_activate and binding_deactivate
RPC_VERSION = '1.5'
NSXV3_SERVER_RPC_VERSION = '1.0'
NSXV3_SERVER_RPC_TOPIC = "nsxv3"

MP2POLICY_NSX_MIN_VERSION = (3, 2, 2)
ONLY_POLICY_API_NSX_VERSION = (4, 0, 0)


class MP2POLICY_STATES(Enum):  # NOSONAR
    PROMOTION_NOT_IN_PROGRESS = "PROMOTION_NOT_IN_PROGRESS"
    PROMOTION_IN_PROGRESS = "PROMOTION_IN_PROGRESS"


class MP2POLICY_PROMOTION_STATUS(Enum):  # NOSONAR
    UNINITIALIZED = "UNINITIALIZED"
    NOT_POSSIBLE = "NOT_POSSIBLE"
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESSFUL = "SUCCESSFUL"
    CANCELED = "CANCELED"
    CANCEL_FAILED = "CANCEL_FAILED"


class MIGR_COORD_STATE(Enum):  # NOSONAR
    RUNNING = "running"


class RUNNING_MIGR_STATUS(Enum):  # NOSONAR
    FAIL = "FAIL"
    FAILED = "FAILED"
    PAUSING = "PAUSING"
    PAUSED = "PAUSED"
    SUCCESS = "SUCCESS"
