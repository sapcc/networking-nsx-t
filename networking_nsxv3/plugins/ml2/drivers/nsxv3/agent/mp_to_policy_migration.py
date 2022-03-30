from typing import List, Tuple
import eventlet
from oslo_config import cfg
from oslo_log import log as logging

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import Client
from networking_nsxv3.common.locking import LockManager

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class API(object):
    MIGR_BASE = "/api/v1/migration"
    MIGR_PLAN = f"{MIGR_BASE}/plan"

    MIGR_UNIT = "MP_TO_POLICY_MIGRATION"
    SERVICE_STATUS = f"{MIGR_BASE}/migration-unit-groups/{MIGR_UNIT}?summary=true"

    MIGR_STATUS_SUM = f"{MIGR_BASE}/status-summary"
    MIGR_STATUS_PRE = f"{MIGR_STATUS_SUM}?component_type=MP_TO_POLICY_PRECHECK"
    MIGR_STATUS_POS = f"{MIGR_STATUS_SUM}?component_type={MIGR_UNIT}"

    MP_TO_POLICY = f"{MIGR_BASE}/mp-to-policy"
    MP_TO_POLICY_WORKFLOW = f"{MP_TO_POLICY}/workflow"

    MP_TO_POLICY_INIT = f"{MP_TO_POLICY_WORKFLOW}?action=INITIATE"
    MP_TO_POLICY_DONE = f"{MP_TO_POLICY_WORKFLOW}?action=DONE"
    MIGRATION_START = f"{MIGR_PLAN}?action=start"
    MIGRATION_CONTINUE = f"{MIGR_PLAN}?action=continue"
    MIGRATION_ABORT = f"{MIGR_PLAN}?action=abort"

    MIGRATION_ROLLBACK = f"{MP_TO_POLICY}/rollback"
    MIGRATED_RESOURCES = f"{MIGR_BASE}/migrated-resources"
    MIGRATED_QOS_PROFILES = f"{MIGRATED_RESOURCES}?resource_type=QOS_PROFILES"


class Payload(object):
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

    def mp2p_mapping(resource_type: str) -> str:
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

        def __len__(self):
            return len(self._resource_ids)

        def add(self, resource_type: str, resource_id: str):
            r_ids: list = self._resource_ids.setdefault(resource_type, list())
            r_ids.append(resource_id)

        def clear(self):
            self._resource_ids = {}

        def json(self) -> dict:
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


class PayloadBuilder(object):
    def __init__(self):
        self.__payload: Payload.MigrationData = Payload.MigrationData()

    def sw_profiles(self, profiles: List[Tuple[str, str]]):
        for p_id, p_type in profiles:
            if p_type in Payload.SUPPORTED_RESOURCE_TYPES:
                self.__payload.add(resource_type=p_type, resource_id=p_id)
            else:
                LOG.warning(f"ResourceType '{p_type}' not supported for MP-to-Policy promotion")
        return self

    def ports(self, port_ids: List[str]):
        for p_id in port_ids:
            self.__payload.add(resource_type="LogicalPort", resource_id=p_id)
        return self

    def switch(self, switch_id: str):
        self.__payload.add(resource_type="LogicalSwitch", resource_id=switch_id)
        return self

    def build(self) -> Payload.MigrationData:
        return self.__payload


class Provider(object):
    def __init__(self, payload: Payload = Payload()):
        self.payload: Payload = payload
        self.client: Client = Client()
        self.check_service_availability()
        LOG.info("Activating MP-TO-POLICY API Provider.")

    def check_service_availability(self):
        with LockManager.get_lock(API.MIGR_UNIT):
            try:
                self.client.post(path=API.MP_TO_POLICY, data={}).raise_for_status()
                self.client.post(path=API.MIGRATION_ABORT, data=None).raise_for_status()
                stat = self.client.get(path=API.SERVICE_STATUS)
                srvc_stat = stat.json()
                if not srvc_stat or not srvc_stat.get("enabled"):
                    raise RuntimeError(f"{stat.content}")
            except Exception as e:
                raise RuntimeError(f"MP-TO-POLICY API not enabled or service down. ({e})")

    def migration(build_migr_data_func):
        def wrapper(self, *args, **kwargs):
            with LockManager.get_lock(API.MIGR_UNIT):
                initiated = False
                try:
                    m_data: Payload.MigrationData = build_migr_data_func(self, *args, **kwargs)
                    json_migdata = m_data.json() if m_data else None
                    if not json_migdata:
                        LOG.warn("No migration data provided. Migration skiped.")
                        return
                    self._initiate_migration()
                    initiated = True
                    self._set_migration(migr_data=json_migdata)
                    self._start_migration(migr_data=json_migdata)
                    LOG.debug("Pre-checking migration ...")
                    self._precheck_migration(migr_data=json_migdata)
                    self._continue_migration(migr_data=json_migdata)
                    LOG.debug("Post-checking migration ...")
                    self._await_migration(migr_data=json_migdata)
                    LOG.info("Migration completed.")
                finally:
                    if initiated:
                        self._end_migration()
                return m_data
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

    def await_status(timeout):
        def decorator(status_func):
            def wrapper(*args, **kwargs):
                res = {}
                t = timeout
                while t > 0:
                    res = status_func(*args, **kwargs)
                    overal_status = res.get("overall_migration_status", "FAILED")
                    results = res.get("component_status", [])

                    if overal_status == "FAILED" or len(results) < 1 or results[0].get("status") == "FAILED":
                        raise RuntimeError(f"Migration status check FAILED! Result: {res}")

                    if results[0].get("status") != "SUCCESS" and results[0].get("percent_complete") < 100:
                        t = t - 2
                        eventlet.sleep(2)
                    else:
                        LOG.info("Result: " + results[0].get("status") +
                                 ", Percentage: " + str(results[0].get("percent_complete")))
                        return
                raise RuntimeError(f"Migration status check FAILED! Result: {res}")
            return wrapper
        return decorator

    def get_migrated_qos(self) -> List[dict]:
        return self.client.get_all(path=API.MIGRATED_QOS_PROFILES)

    @migration
    def migrate_sw_profiles(self, not_migrated: List[tuple], data: Payload.MigrationData = None) -> Payload.MigrationData:
        """Promote switching profiles to segment profiles

        Args:
            not_migrated (list): List of tupples (sw_profile_id, sw_profile_type) to be promoted
            data (Payload.MigrationData, optional): Append existing data. Defaults to None.

        Returns:
            Payload.MigrationData: Payload used by the migration wrapper for the actual migration.
        """
        LOG.info("Trying to migrate the missing switching profiles ...")
        data = Payload.MigrationData() if not data else data
        for p_id, p_type in not_migrated:
            if p_type in Payload.SUPPORTED_RESOURCE_TYPES:
                data.add(resource_type=p_type, resource_id=p_id)
            else:
                LOG.warning(f"ResourceType '{p_type}' not supported for MP-to-Policy promotion")
        return data

    @migration
    def migrate_ports(self, port_ids: List[str], data: Payload.MigrationData = None) -> Payload.MigrationData:
        """Promote switching ports to segment ports

        Args:
            port_ids (list): List of strings (port_ids) to be promoted
            data (Payload.MigrationData, optional): Append existing data. Defaults to None.

        Returns:
            Payload.MigrationData: Payload used by the migration wrapper for the actual migration.
        """
        LOG.info(f"Trying to migrate ports: {port_ids}")
        data = Payload.MigrationData() if not data else data
        for p_id in port_ids:
            data.add(resource_type="LogicalPort", resource_id=p_id)
        return data

    @migration
    def migrate_switch(self, switch_id: str, data: Payload.MigrationData = None) -> Payload.MigrationData:
        """Promote switch to segment

        Args:
            switch_id (str): Switch ID to be promoted
            data (Payload.MigrationData, optional): Append existing data. Defaults to None.

        Returns:
            Payload.MigrationData: Payload used by the migration wrapper for the actual migration.
        """
        LOG.info(f"Trying to migrate switch: {switch_id}")
        data = Payload.MigrationData() if not data else data
        data.add(resource_type="LogicalSwitch", resource_id=switch_id)
        return data

    @migration
    def migrate_bulk(self, payload: Payload.MigrationData) -> Payload.MigrationData:
        """Promote bulk of objects

        Args:
            payload (Payload.MigrationData): Provided migration payload (builded externally).

        Returns:
            Payload.MigrationData: Payload used by the migration wrapper for the actual migration.
        """
        LOG.info(f"Trying to migrate bulk of objects")
        if not payload or len(payload) < 1:
            raise RuntimeError("Empty or no Migration Payload provided.")
        return payload

    @rollback
    def _set_migration(self, migr_data: dict):
        LOG.debug("Setting migration data ...")
        self.client.post(path=API.MP_TO_POLICY, data=migr_data)

    @rollback
    def _start_migration(self, migr_data: dict):
        LOG.debug("Starting migration ...")
        self.client.post(path=API.MIGRATION_START, data=None)

    @rollback
    @await_status(timeout=6000)
    def _precheck_migration(self, migr_data: dict) -> dict:
        return self.client.get(path=API.MIGR_STATUS_PRE).json()

    @rollback
    def _continue_migration(self, migr_data: dict):
        LOG.debug("Continuing migration ...")
        self.client.post(path=API.MIGRATION_CONTINUE, data=None)

    @rollback
    @await_status(timeout=6000)
    def _await_migration(self, migr_data: dict):
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
