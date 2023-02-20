from typing import List, Set, Tuple
import eventlet
import json
from networking_nsxv3.common.constants import MP2POLICY_NSX_MIN_VERSION
from oslo_config import cfg
from oslo_log import log as logging

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import Client
from networking_nsxv3.common.locking import LockManager

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class API(object):
    MIGR_BASE = "/api/v1/migration"
    MIGR_PLAN = f"{MIGR_BASE}/plan"
    MIGR_SERVICE_STATUS = "/api/v1/node/services/migration-coordinator/status"

    MIGR_UNIT = "MP_TO_POLICY_MIGRATION"
    SERVICE_STATUS = f"{MIGR_BASE}/migration-unit-groups/{MIGR_UNIT}?summary=true"

    MIGR_STATUS_SUM = f"{MIGR_BASE}/status-summary"
    MIGR_STATUS_PRE = f"{MIGR_STATUS_SUM}?component_type=MP_TO_POLICY_PRECHECK"
    MIGR_STATUS_POS = f"{MIGR_STATUS_SUM}?component_type={MIGR_UNIT}"

    MP_TO_POLICY = f"{MIGR_BASE}/mp-to-policy"
    MP_TO_POLICY_WORKFLOW = f"{MP_TO_POLICY}/workflow"
    MIGR_FEEDBACK = f"{MP_TO_POLICY}/feedback"
    MIGR_STATS_PRE = f"{MP_TO_POLICY}/stats?pre_promotion=true"
    MIGR_STATS_POST = f"{MP_TO_POLICY}/stats?pre_promotion=false"

    MP_TO_POLICY_INIT = f"{MP_TO_POLICY_WORKFLOW}?action=INITIATE"
    MP_TO_POLICY_DONE = f"{MP_TO_POLICY_WORKFLOW}?action=DONE"
    MIGRATION_START = f"{MIGR_PLAN}?action=start"
    MIGRATION_CONTINUE = f"{MIGR_PLAN}?action=continue"
    MIGRATION_ABORT = f"{MIGR_PLAN}?action=abort"

    MIGRATION_CANCEL = f"{MP_TO_POLICY}/cancel"
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

    @staticmethod
    def generic(resource_types: Set[str] = None, skip_failed=False) -> dict:
        """Supports the following resource types:\n
            - SEGMENT_SECURITY_PROFILES\n
            - SPOOFGUARD_PROFILES\n
            - IPDISCOVERY_PROFILES\n
            - MACDISCOVERY_PROFILES\n
            - QOS_PROFILES\n
            - LOGICAL_SWITCH\n
            - LOGICAL_PORT
        """
        if resource_types:
            return {
                "mode": "GENERIC",
                "skip_failed_resources": skip_failed,
                "migration_data": [{"type": r_t, "resource_ids": []} for r_t in resource_types]
            }
        return {"mode": "GENERIC", "skip_failed_resources": skip_failed}


class Provider(object):
    def __init__(self, payload: Payload = Payload()):
        self.payload: Payload = payload
        self.client: Client = Client()
        self.check_service_availability()
        LOG.info("Activating MP-TO-POLICY API Provider.")

    def check_service_availability(self):
        with LockManager.get_lock(API.MIGR_UNIT):
            try:
                if self.client.version < MP2POLICY_NSX_MIN_VERSION:
                    raise RuntimeError(f"MP-TO-POLICY API not supported for NSX version {self.client.version}.")
                mp_service_status = self.client.get(path=API.MIGR_SERVICE_STATUS).json()
                if (mp_service_status.get("monitor_runtime_state") == "running") and (
                        mp_service_status.get("runtime_state") == "running"):
                    LOG.info("Migration coordinator is UP and RUNNING.")
            except Exception as e:
                raise RuntimeError(f"MP-TO-POLICY API not enabled or service down. ({e})")

    def migration(build_migr_data_func):
        def wrapper(self, *args, **kwargs):
            with LockManager.get_lock(API.MIGR_UNIT):
                try:
                    m_data: Payload.MigrationData = build_migr_data_func(self, *args, **kwargs)
                    json_migdata = m_data.json() if m_data else None
                    if not json_migdata:
                        LOG.warn("No migration data provided. Migration skiped.")
                        return
                    self._initiate_migration()
                    self._set_migration(migr_data=json_migdata)
                    self._start_migration(migr_data=json_migdata)
                    LOG.debug("Pre-checking migration ...")
                    self._precheck_migration(migr_data=json_migdata)
                    self._continue_migration(migr_data=json_migdata)
                    LOG.debug("Post-checking migration ...")
                    self._await_migration(migr_data=json_migdata)
                    LOG.info("Migration completed.")
                finally:
                    self._end_migration()
                return m_data
        return wrapper

    def rollback(migration_func):
        def wrapper(self, *args, **kwargs):
            try:
                return migration_func(self, *args, **kwargs)
            except Exception as e:
                LOG.error(str(e))
                m_data = kwargs.get('migr_data')
                self._try_rollback(migr_data=m_data)
                raise e
        return wrapper

    def cancel(migration_func):
        def wrapper(self, *args, **kwargs):
            try:
                return migration_func(self, *args, **kwargs)
            except Exception as e:
                LOG.error(str(e))
                self._cancel_migration()
                raise e
        return wrapper

    def await_status(timeout, interval=10, title_msg="Migration status check."):
        def decorator(status_func):
            def wrapper(self, *args, **kwargs):
                status_msg = lambda r: f" - Status for component '{r.get('component_type')}': {r.get('status')}, {r.get('percent_complete')}%"
                res = {}
                t = timeout
                while t > 0:
                    res = status_func(self, *args, **kwargs)
                    overal_status = res.get("overall_migration_status", "")
                    results = res.get("component_status", [])

                    if len(results) < 1 and overal_status == "FAILED":
                        raise RuntimeError(f"{title_msg} Status: FAILED! Result: {res}")

                    LOG.info(f"Overall migration status: {overal_status}")
                    migr_incomplete = False
                    for r in results:
                        if r.get("status") == "FAILED":
                            fdbk = self.get_migration_feedback()
                            if overal_status == "PAUSING":
                                LOG.warning(r.get("details"))
                            elif overal_status == "PAUSED" and cfg.CONF.AGENT.continue_on_failed_promotions:
                                LOG.info(status_msg(r))
                                # raise if port aways, despite of continue_on_failed_promotions
                                self._raise_for_port(migr_feedback=fdbk)

                                self._display_last_migr_feedback(fdbk)
                                self._continue_migration()
                            else:
                                raise RuntimeError(f"{title_msg} Status:  FAILED! Result: {res}")
                        else:
                            LOG.info(status_msg(r))
                        if r.get("status") != "SUCCESS" and r.get("percent_complete") < 100:
                            migr_incomplete = True

                    if migr_incomplete:
                        t = t - interval
                        LOG.info(f"Waiting {interval} seconds for migration to complete. {t} seconds left.")
                        eventlet.sleep(interval)
                    else:
                        LOG.info(f"{title_msg} Finished with SUCCESS. Result:\n{json.dumps(res,indent=4)}")
                        return
                raise RuntimeError(f"{title_msg}, Status:  FAILED! Result: {res}")
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

    def migrate_generic(self) -> Tuple[bool, dict, dict]:
        """Start generic migration
        Returns:
            Tuple[bool, dict, dict]: Migration status, stats, errors
        """
        success = False
        migr_stats = {}
        fdbk = {}
        with LockManager.get_lock(API.MIGR_UNIT):
            try:
                LOG.info("Starting Generic migration ...")
                self._set_generic_migration()
                self._await_generic_migration()
                LOG.info("Migration completed.")
                self._end_migration()
                LOG.info("Migration window closed.")
                success = True
            finally:
                fdbk = self.get_migration_feedback()
                while fdbk and len(fdbk.get("results", [])) > 0:
                    self._display_last_migr_feedback(fdbk)
                migr_stats = self.get_migration_stats(pre=False)
        return success, migr_stats, fdbk

    def get_migration_feedback(self) -> dict:
        """Get migration feedback

        Returns:
            dict: Migration feedback
        """
        return self.client.get(path=API.MIGR_FEEDBACK).json()

    def get_migration_stats(self, pre=True) -> dict:
        try:
            if pre:
                return self.client.get(path=API.MIGR_STATS_PRE).json()
            return self.client.get(path=API.MIGR_STATS_POST).json()
        except Exception as e:
            LOG.warning(f"Failed to get migration stats: {e}")
            return {}

    def _set_generic_migration(self):
        LOG.info("Setting Generic migration data ...")
        skip_failed = cfg.CONF.AGENT.continue_on_failed_promotions
        self.client.post(path=API.MP_TO_POLICY, data=PayloadBuilder.generic(skip_failed=skip_failed))

    @rollback
    def _set_migration(self, migr_data: dict):
        LOG.info("Setting migration data ...")
        resp = self.client.post(path=API.MP_TO_POLICY, data=migr_data)
        if not resp.ok:
            error = resp.json().get("error_message", resp.text)
            LOG.warning(f"Failed to set migration data: {error}")

    @rollback
    def _start_migration(self, migr_data: dict = None):
        LOG.info("Starting migration ...")
        self.client.post(path=API.MIGRATION_START, data=None)

    @rollback
    @await_status(timeout=6000)
    def _precheck_migration(self, migr_data: dict = None) -> dict:
        return self.client.get(path=API.MIGR_STATUS_PRE).json()

    @rollback
    def _continue_migration(self, migr_data: dict = None):
        LOG.info("Continuing migration ...")
        self.client.post(path=API.MIGRATION_CONTINUE, data=None)

    @rollback
    @await_status(timeout=6000)
    def _await_migration(self, migr_data: dict = None):
        return self.client.get(path=API.MIGR_STATUS_POS).json()

    @cancel
    @await_status(timeout=1200, interval=10, title_msg="Generic migration.")
    def _await_generic_migration(self, migr_data: dict = None):
        return self.client.get(path=API.MIGR_STATUS_SUM).json()

    def _initiate_migration(self):
        LOG.info("Initiating migration window ...")
        self.client.post(path=API.MP_TO_POLICY_INIT, data=None)

    def _end_migration(self):
        LOG.info("Closing migration window ...")
        self.client.post(path=API.MP_TO_POLICY_DONE, data=None)

    def _try_rollback(self, migr_data: dict):
        LOG.info("Rolling back the migration ...")
        try:
            self.client.post(path=API.MIGRATION_ABORT, data=None)
            if migr_data is not None:
                self.client.post(path=API.MIGRATION_ROLLBACK, data=migr_data)
        except Exception as e:
            LOG.error(str(e))

    def _cancel_migration(self):
        LOG.info("Canceling Generic migration ...")
        try:
            self.client.post(path=API.MIGRATION_CANCEL, data=None)
        except Exception as e:
            pass

    def _display_last_migr_feedback(self, migr_feedback):
        if migr_feedback and migr_feedback.get("result_count", 0) > 0:
            LOG.warning(f"Migration feedback:")
            l = len(migr_feedback.get("results"))
            try:
                feedback_res = migr_feedback.get("results").pop(0)  # LIFO
                LOG.warning(
                    f" {l}. display_name: '{feedback_res.get('mp_display_name')}', type: '{feedback_res.get('type')}', id: '{feedback_res.get('mp_id')}':")
                for err in feedback_res.get("error_list", []):
                    LOG.warning(f"   - {err.get('error_id')}: {err.get('error_desc')}")
            except IndexError:
                return

    def _raise_for_port(self, migr_feedback):
        if migr_feedback and migr_feedback.get("result_count", 0) > 0:
            for res in migr_feedback.get("results", []):
                if res.get('type') == 'LOGICAL_PORT' or res.get('type') == 'SEGMENT_PORT':
                    raise RuntimeError(
                        f"Migration failed for port: display_name: '{res.get('mp_display_name')}', id: '{res.get('mp_id')}':")
