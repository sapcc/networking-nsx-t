# import re

import eventlet
from array import array
from time import sleep
from unittest.mock import patch
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
    MIGR_PLAN = f"{MIGR_BASE}/plan"

    MIGR_STATUS_SUM = f"{MIGR_BASE}/status-summary"
    MIGR_STATUS_PRE = f"{MIGR_STATUS_SUM}?component_type=MP_TO_POLICY_PRECHECK"
    MIGR_STATUS_POS = f"{MIGR_STATUS_SUM}?component_type=MP_TO_POLICY_MIGRATION"

    MP_TO_POLICY = f"{MIGR_BASE}/mp-to-policy"
    MP_TO_POLICY_WORKFLOW = f"{MP_TO_POLICY}/workflow"

    MP_TO_POLICY_INIT = f"{MP_TO_POLICY_WORKFLOW}?action=INITIATE"
    MP_TO_POLICY_DONE = f"{MP_TO_POLICY_WORKFLOW}?action=DONE"
    MIGRATION_START = f"{MIGR_PLAN}?action=start"
    MIGRATION_CONTINUE = f"{MIGR_PLAN}?action=continue"
    MIGRATION_ABORT = f"{MIGR_PLAN}?action=abort"

    MIGRATION_ROLLBACK = f"{MP_TO_POLICY}/rollback"


class PolicyResourceMeta(provider_nsx_policy.PolicyResourceMeta):
    pass


class PolicyResource(provider_nsx_policy.PolicyResource):
    pass


class Payload(provider_nsx_policy.Payload):
    SUPPORTED_RESOURCE_TYPES = {
        "SwitchSecuritySwitchingProfile": "SEGMENT_SECURITY_PROFILES",
        "SpoofGuardSwitchingProfile": "SPOOFGUARD_PROFILES",
        "IpDiscoverySwitchingProfile": "IPDISCOVERY_PROFILES",
        "MacManagementSwitchingProfile": "MACDISCOVERY_PROFILES",
        "QosSwitchingProfile": "QOS_PROFILES",
        # "PortMirroringSwitchingProfile": "NOT SUPPORTED"
        "LogicalSwitch": "LOGICAL_SWITCH",
        "LogicalPort": "LOGICAL_PORT"
    }

    def mp2p_mapping(resource_type: str) -> str or None:
        """Maps Manager Resource types with MP-TO-POLICY types

        Args:
            resource_type (str): Manager API Resource Type

        Returns:
            str or None: MP-TO-POLICY API Object Type
        """
        return Payload.SUPPORTED_RESOURCE_TYPES.get(resource_type, None)

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

    def migration(build_migr_data_func):
        def wrapper(self, *args, **kwargs):
            if self.migration_on:
                try:
                    self._initiate_migration()
                    m_data: Payload.MigrationData = build_migr_data_func(self, *args, **kwargs)
                    json_migdata = m_data.json() if m_data else None
                    if not json_migdata:
                        LOG.warn("No migration data provided. Migration skiped.")
                        return
                    self._set_migration(migr_data=json_migdata)
                    self._start_migration(migr_data=json_migdata)
                    self._precheck_migration(migr_data=json_migdata)
                    self._continue_migration(migr_data=json_migdata)
                    self._await_migration(migr_data=json_migdata)
                    LOG.info("Migration completed.")
                finally:
                    self._end_migration()
            else:
                LOG.info("Migration to Policy is disabled.")
        return wrapper

    def rollback(migration_func):
        def wrapper(self, *args, **kwargs):
            try:
                return migration_func(self, *args, **kwargs)
            except Exception as e:
                LOG.error(str(e))
                m_data = kwargs['migr_data'] if (migration_func.__name__ != "_set_migration") else None
                self._try_rollback(migr_data=m_data)
                raise e
        return wrapper

    def await_status(seconds):
        def decorator(status_func):
            def wrapper(*args, **kwargs):
                res = {}
                r = seconds
                while r > 0:
                    res = status_func(*args, **kwargs)
                    overal_status = res.get("overall_migration_status", "FAILED")
                    results = res.get("component_status", [])

                    if overal_status == "FAILED" or len(results) < 1 or results[0].get("status") == "FAILED":
                        raise RuntimeError(f"Migration status check FAILED! Result: {res}")

                    if results[0].get("status") != "SUCCESS" and results[0].get("percent_complete") < 100:
                        r = r - 1
                        eventlet.sleep(1)
                    else:
                        return
                raise RuntimeError(f"Migration status check FAILED! Result: {res}")
            return wrapper
        return decorator

    def _ensure_switching_profiles(self):
        self.mgmt_sw_profiles = self.mgmt_provider.get_all_switching_profiles()
        self.policy_sw_profiles = self.plcy_provider.get_non_default_switching_profiles()

        mgmt_profile_ids = [p.get("id") for p in self.mgmt_sw_profiles
                            if p and p.get("resource_type") in Payload.SUPPORTED_RESOURCE_TYPES]
        plcy_profile_ids = [p.get("id") for p in self.policy_sw_profiles if p]

        not_migrated_ids = [p_id for p_id in mgmt_profile_ids if p_id not in plcy_profile_ids]

        if len(not_migrated_ids) > 0:
            not_migrated = [(p.get("id"), p.get("resource_type"), p.get("_system_owned"))
                            for p in self.mgmt_sw_profiles if p and p.get("id") in not_migrated_ids]
            LOG.info(f"Not migrated to policy switching profiles: {not_migrated}")
            try:
                # migrate first system owned
                not_migrated_sys_owned = [(p_id, p_type) for p_id, p_type, sys_owned in not_migrated if sys_owned]
                if len(not_migrated_sys_owned) > 0:
                    self._migrate_sw_profiles(not_migrated_sys_owned)
                # migrate non system owned
                not_migrated_not_sys_owned = [(p_id, p_type)
                                              for p_id, p_type, sys_owned in not_migrated if not sys_owned]
                if len(not_migrated_not_sys_owned) > 0:
                    self._migrate_sw_profiles(not_migrated_not_sys_owned)
            except Exception as e:
                LOG.warning(str(e))
                self.migration_on = False

    @migration
    def _migrate_sw_profiles(self, not_migrated: list) -> Payload.MigrationData:
        LOG.info("Trying to migrate the missing switching profiles ...")
        data = Payload.MigrationData()
        for p_id, p_type in not_migrated:
            data.add(resource_type=p_type, resource_id=p_id)
        return data

    @migration
    def _migrate_port(self, port_id: str) -> Payload.MigrationData:
        # TODO: Do port migration
        pass

    @rollback
    def _set_migration(self, migr_data: dict):
        LOG.debug("Setting migration data ...")
        self.client.post(path=API.MP_TO_POLICY, data=migr_data)

    @rollback
    def _start_migration(self, migr_data: dict):
        LOG.debug("Starting migration ...")
        self.client.post(path=API.MIGRATION_START, data=None)

    @rollback
    @await_status(seconds=5)
    def _precheck_migration(self, migr_data: dict) -> dict:
        LOG.debug("Pre-checking migration ...")
        return self.client.get(path=API.MIGR_STATUS_PRE).json()

    @rollback
    def _continue_migration(self, migr_data: dict):
        LOG.debug("Continuing migration ...")
        self.client.post(path=API.MIGRATION_CONTINUE, data=None)

    @rollback
    @await_status(seconds=10)
    def _await_migration(self, migr_data: dict):
        LOG.debug("Post-checking migration ...")
        return self.client.get(path=API.MIGR_STATUS_POS).json()

    def _initiate_migration(self):
        LOG.debug("Initiating migration window ...")
        self.client.post(path=API.MP_TO_POLICY_INIT, data=None)

    def _end_migration(self):
        LOG.debug("Closing migration window ...")
        self.client.post(path=API.MP_TO_POLICY_DONE, data=None)

    def _try_rollback(self, migr_data: dict):
        LOG.debug("Rolling back the migration ...")
        try:
            self.client.post(path=API.MIGRATION_ABORT, data=None)
            if migr_data is not None:
                self.client.post(path=API.MIGRATION_ROLLBACK, data=migr_data)
        except Exception as e:
            LOG.error(str(e))
