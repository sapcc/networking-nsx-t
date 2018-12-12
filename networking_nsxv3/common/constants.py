import attr
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
NSXV3_AGENT_NETWORK_MAPPING = {}

NSXV3_SECURITY_GROUP_SCOPE = "security_group"
NSXV3_SECURITY_GROUP_RULE_BATCH_SIZE = 265
NSXV3_REVISION_SCOPE = "revision_number"

# Set RPC API version to 1.0 by default.
# history
#   1.1 Support Security Group RPC
#   1.3 Added param devices_to_update to security_groups_provider_updated
#   1.4 Added support for network_update
#   1.5 Added binding_activate and binding_deactivate
RPC_VERSION = '1.5'

