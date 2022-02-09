# import re

# import eventlet
from time import sleep
from oslo_config import cfg
from oslo_log import log as logging
# from oslo_utils import excutils

from networking_nsxv3.common.constants import *
# from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_policy
# from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *

LOG = logging.getLogger(__name__)


class API(provider_nsx_policy.API):
    MIGR_BASE = "/api/v1/migration"
    MIGR_PLAN = MIGR_BASE + "/plan"
    MIGR_STATUS_SUM = MIGR_BASE + "/status-summary"
    MP_TO_POLICY = MIGR_BASE + "/mp-to-policy"
    MP_TO_POLICY_WORKFLOW = MP_TO_POLICY + "/workflow"

    MP_TO_POLICY_INIT = MP_TO_POLICY_WORKFLOW + "?action=INITIATE"
    MP_TO_POLICY_END = MP_TO_POLICY_WORKFLOW + "?action=DONE"
    MIGRATION_START = MIGR_PLAN + "?action=start"
    MIGRATION_CONTINUE = MIGR_PLAN + "?action=continue"
    MIGRATION_ABORT = MIGR_PLAN + "?action=abort"


class PolicyResourceMeta(provider_nsx_policy.PolicyResourceMeta):
    pass


class PolicyResource(provider_nsx_policy.PolicyResource):
    pass


class Payload(provider_nsx_policy.Payload):
    def mp2p_mapping(resource_type: str) -> str or None:
        """Maps Manager Resource types with MP-TO-POLICY types

        Args:
            resource_type (str): Manager API Resource Type

        Returns:
            str or None: MP-TO-POLICY API Object Type
        """
        resource_map = {
                "SwitchSecuritySwitchingProfile": "SEGMENT_SECURITY_PROFILES",
                "SpoofGuardSwitchingProfile": "SPOOFGUARD_PROFILES",
                "IpDiscoverySwitchingProfile": "IPDISCOVERY_PROFILES",
                "MacManagementSwitchingProfile": "MACDISCOVERY_PROFILES",
                "QosSwitchingProfile": "QOS_PROFILES",
                # "PortMirroringSwitchingProfile": "NOT SUPPORTED"
                "LogicalSwitch": "LOGICAL_SWITCH",
                "LogicalPort": "LOGICAL_PORT"
        }
        return resource_map.get(resource_type, None)

    class MigrationData(object):
        def __init__(self):
            self._resource_ids = {}

        def add(self, resource_type: str, resource_id: str):
            r_ids: list = self._resource_ids.setdefault(resource_type, list())
            r_ids.append(resource_id)

        def clear(self):
            self._resource_ids = {}

        def json(self) -> dict or None:
            """Build up and returns the added migration data

            Returns:
                dict or None: JSON structured migration data. None - if no resource_ids added
            """
            migr_data = []
            for r_t, r_ids in self._resource_ids.items():
                r_type = Payload.mp2p_mapping(r_t)
                if not r_type:
                    LOG.warn(f"Not supported resource type for migration ({r_t}).")
                else:
                    migr_data.append({"type": r_type, "resource_ids": [
                                    {"manager_id": r_id, "policy_id": r_id} for r_id in set(r_ids)
                                    ]})
            return {"migration_data": migr_data} if len(migr_data) > 0 else None


class Provider(provider_nsx_policy.Provider):
    def __init__(self, payload=Payload):
        super(Provider, self).__init__(payload=payload)
        self.provider = "MP-TO-POLICY"
        self.migration_on = cfg.CONF.AGENT.force_mp_to_policy
        self.plcy_provider = super(Provider, self)
        self.mgmt_provider = super(provider_nsx_policy.Provider, self)
        self._ensure_switching_profiles()

    def migration(build_migr_data):
        def wrapper(self, *args, **kwargs):
            if self.migration_on:
                try:
                    self._initiate_migration()
                    migr_data: Payload.MigrationData = build_migr_data(self, *args, **kwargs)
                    json_migdata = migr_data.json() if migr_data else None
                    if not json_migdata:
                        LOG.warn("No migration data provided. Migration skiped.")
                        return
                    self._set_migration(json_migdata)
                    self._start_migration(json_migdata)
                    self._await_migration(json_migdata)
                finally:
                    self._end_migration()
            else:
                LOG.info("Migration to Policy is disabled.")
        return wrapper

    def _ensure_switching_profiles(self):
        self.mgmt_sw_profiles = self.mgmt_provider.get_all_switching_profiles()
        self.policy_sw_profiles = self.plcy_provider.get_non_default_switching_profiles()

        mgmt_profile_ids = [p.get("id") for p in self.mgmt_sw_profiles if p]
        plcy_profile_ids = [p.get("id") for p in self.policy_sw_profiles if p]

        LOG.info(mgmt_profile_ids)
        LOG.info(plcy_profile_ids)

        not_migrated_ids = [p_id for p_id in mgmt_profile_ids if p_id not in plcy_profile_ids]

        if len(not_migrated_ids) > 0:
            not_migrated = [(p.get("id"), p.get("resource_type"))
                            for p in self.mgmt_sw_profiles if p and p.get("id") in not_migrated_ids]
            LOG.info(f"Not migrated to policy switching profiles: {not_migrated}")
            try:
                self._migrate_sw_profiles(not_migrated)
            except Exception as e:
                LOG.warning(str(e))
                self.migration_on = False

    @migration
    def _migrate_sw_profiles(self, not_migrated: tuple) -> Payload.MigrationData:
        LOG.info("Trying to migrate the missing switching profiles ...")
        data = Payload.MigrationData()
        for p_id, p_type in not_migrated:
            data.add(resource_type=p_type, resource_id=p_id)
        return data

    @migration
    def _migrate_port(self, port_id: str) -> Payload.MigrationData:
        # TODO: Do port migration
        pass

    def _initiate_migration(self):
        LOG.debug("Initiating migration window ...")
        self.client.post(path=API.MP_TO_POLICY_INIT, data=None)

    def _end_migration(self):
        LOG.debug("Closing migration window ...")
        self.client.post(path=API.MP_TO_POLICY_END, data=None)

    def _set_migration(self, migr_data: dict):
        LOG.debug("Setting migration data ...")
        try:
            self.client.post(path=API.MP_TO_POLICY, data=migr_data)
        except Exception as e:
            self._try_rollback(migr_data=None)
            raise e

    def _start_migration(self, migr_data: dict):
        LOG.debug("Starting migration ...")
        try:
            self.client.post(path=API.MIGRATION_START, data=None)
            # TODO: do prechecks
            sleep(2)  # TODO remove
            # TODO: split and retry or poll due to: (None, 'Error Code=400 Message=b\'{\\n  "httpStatus" : "BAD_REQUEST",\\n  "error_code" : 30722,\\n  "module_name" : "migration-coordinator",\\n  "error_message" : "Migration coordinator backend is busy. Please try again after some time."\\n}\'')
            self.client.post(path=API.MIGRATION_CONTINUE, data=None)
        except Exception as e:
            # TODO
            self._try_rollback(migr_data)
            raise e

    def _await_migration(self, migr_data: dict):
        try:
            # TODO
            pass
        except Exception as e:
            # TODO
            self._try_rollback(migr_data)
            raise e

    # TODO: retry or poll due to: (None, 'Error Code=400 Message=b\'{\\n  "httpStatus" : "BAD_REQUEST",\\n  "error_code" : 30722,\\n  "module_name" : "migration-coordinator",\\n  "error_message" : "Migration coordinator backend is busy. Please try again after some time."\\n}\'')
    def _try_rollback(self, migr_data: dict):
        try:
            sleep(3)  # TODO remove when retry is implemented
            self.client.post(path=API.MIGRATION_ABORT, data=None)
            # TODO check the status
            if migr_data is not None:
                # TODO actual rollback
                pass
        except Exception as e:
            LOG.error(str(e))
