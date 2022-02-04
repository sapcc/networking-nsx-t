# import re

# import eventlet
from oslo_config import cfg
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

    def __init__(self, payload=Payload):
        super(Provider, self).__init__(payload=payload)
        self.provider = "MP-TO-POLICY"
        self.migration_on = cfg.CONF.AGENT.force_mp_to_policy
        self.plcy_provider = super(Provider, self)
        self.mgmt_provider = super(provider_nsx_policy.Provider, self)
        self._ensure_switching_profiles()

    def migration_enabled(method):
        def wrapper(self, *args, **kwargs):
            if self.migration_on:
                return method(self, *args, **kwargs)
            else:
                LOG.info("Migration to Policy disabled.")
        return wrapper

    def _ensure_switching_profiles(self):
        self.mgmt_sw_profiles = self.mgmt_provider.get_all_switching_profiles()
        self.policy_sw_profiles = self.plcy_provider.get_non_default_switching_profiles()

        mgmt_profile_ids = [p.get("id") for p in self.mgmt_sw_profiles if p]
        plcy_profile_ids = [p.get("id") for p in self.policy_sw_profiles if p]

        not_migrated_ids = [p_id for p_id in mgmt_profile_ids if p_id not in plcy_profile_ids]

        if not_migrated_ids:
            LOG.info(f"Not migrated to policy switching profiles: {not_migrated_ids}")
            try:
                self._migrate_sw_profiles(not_migrated_ids)
            except Exception as e:
                LOG.warning(str(e))
                self.migration_enabled = False

    @migration_enabled
    def _migrate_sw_profiles(self, not_migrated_ids):
        LOG.info(f"Trying to migrate the missing switching profiles ...")
        for p_id in not_migrated_ids:
            # TODO: do migration
            pass
        raise NotImplementedError()
