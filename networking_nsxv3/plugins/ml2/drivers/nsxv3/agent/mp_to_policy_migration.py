# import re

# import eventlet
# from oslo_config import cfg
from oslo_log import log as logging
# from oslo_utils import excutils

from networking_nsxv3.common.constants import *
# from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_policy
# from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *

LOG = logging.getLogger(__name__)


class API(provider_nsx_policy.API):
    pass

class PolicyResourceMeta(provider_nsx_policy.PolicyResourceMeta):
    pass


class PolicyResource(provider_nsx_policy.PolicyResource):
    pass


class Payload(provider_nsx_policy.Payload):
    pass


class Provider(provider_nsx_policy.Provider):
    pass