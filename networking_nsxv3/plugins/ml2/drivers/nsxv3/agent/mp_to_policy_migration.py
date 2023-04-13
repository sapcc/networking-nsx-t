from typing import List, Set, Tuple
import eventlet
import json

from networking_nsxv3.common.constants import MP2POLICY_NSX_MIN_VERSION, MP2POLICY_PROMOTION_STATUS, MIGR_COORD_STATE, RUNNING_MIGR_STATUS
from oslo_config import cfg
from oslo_log import log as logging

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import Client
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.prometheus import exporter

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class API(object):
    MIGR_UNIT = "MP_TO_POLICY_MIGRATION"
    MIGR_BASE = "/api/v1/migration"
    MIGR_SERVICE_STATUS = "/api/v1/node/services/migration-coordinator/status"

    MIGR_STATE = f"{MIGR_BASE}/mp-policy-promotion/state"
    MIGR_STATUS_SUM = f"{MIGR_BASE}/status-summary"

    MP_TO_POLICY = f"{MIGR_BASE}/mp-to-policy"
    MIGR_FEEDBACK = f"{MP_TO_POLICY}/feedback"
    MIGR_STATS_PRE = f"{MP_TO_POLICY}/stats?pre_promotion=true"
    MIGR_STATS_POST = f"{MP_TO_POLICY}/stats?pre_promotion=false"

    MP_TO_POLICY_WORKFLOW = f"{MP_TO_POLICY}/workflow"
    MP_TO_POLICY_DONE = f"{MP_TO_POLICY_WORKFLOW}?action=DONE"

    MIGRATION_CANCEL = f"{MP_TO_POLICY}/cancel"
    MIGRATION_CONTINUE = f"{MIGR_BASE}/plan?action=continue"

    MIGRATED_RESOURCES = f"{MIGR_BASE}/migrated-resources"
    MIGRATED_QOS_PROFILES = f"{MIGRATED_RESOURCES}?resource_type=QOS_PROFILES"


class PayloadBuilder(object):
    @staticmethod
    def generic(resource_types: Set[str] = None) -> dict:
        """Supports the following resource types:\n
            - SEGMENT_SECURITY_PROFILES\n
            - SPOOFGUARD_PROFILES\n
            - IPDISCOVERY_PROFILES\n
            - MACDISCOVERY_PROFILES\n
            - QOS_PROFILES\n
            - LOGICAL_SWITCH\n
            - LOGICAL_PORT
        """
        return {"mode": "GENERIC", "skip_failed_resources": cfg.CONF.AGENT.continue_on_failed_promotions}


class MpPolicyException(Exception):
    pass


class Provider(object):
    def __init__(self):
        self.client: Client = Client()
        self.check_service_availability()
        LOG.info("Activating MP-TO-POLICY API Provider.")

    def check_service_availability(self):
        with LockManager.get_lock(API.MIGR_UNIT):
            try:
                if self.client.version < MP2POLICY_NSX_MIN_VERSION:
                    raise MpPolicyException(f"MP-TO-POLICY API not supported for NSX version {self.client.version}.")
                mp_service_status = self.client.get(path=API.MIGR_SERVICE_STATUS).json()
                if (mp_service_status.get("monitor_runtime_state") == MIGR_COORD_STATE.RUNNING.value) and (
                        mp_service_status.get("runtime_state") == MIGR_COORD_STATE.RUNNING.value):
                    LOG.info("Migration coordinator is UP and RUNNING.")
                    exporter.MP2POLICY_PROM_STATUS.state(MP2POLICY_PROMOTION_STATUS.NOT_STARTED.value)
                else:
                    raise MpPolicyException(
                        f"monitor_runtime_state: {mp_service_status.get('monitor_runtime_state')}, runtime_state: {mp_service_status.get('runtime_state')}")
            except Exception as e:
                exporter.MP2POLICY_PROM_STATUS.state(MP2POLICY_PROMOTION_STATUS.NOT_POSSIBLE.value)
                raise MpPolicyException(f"MP-TO-POLICY API not enabled or service down. ({e})")

    def await_status(timeout, interval=10,):
        def decorator(status_func):
            def wrapper(self, *args, **kwargs):
                res = {}
                t = timeout
                while t > 0:
                    res, migr_incomplete = self._handle_migr_status(args, kwargs, status_func)

                    if migr_incomplete:
                        t = t - interval
                        LOG.info(f"Waiting {interval} seconds for migration to complete. {t} seconds left.")
                        eventlet.sleep(interval)
                    else:
                        LOG.info(f"MP-Policy Migration. Finished with SUCCESS. Result:\n{json.dumps(res,indent=4)}")
                        return
                raise MpPolicyException(f"MP-Policy Migration, Status: FAILED! Result: {res}")

            return wrapper
        return decorator

    def migrate_generic(self, only_await=False) -> Tuple[bool, dict, dict]:
        """Start generic migration
        Returns:
            Tuple[bool, dict, dict]: Migration status, stats, errors
        """
        success = False
        migr_stats = {}
        fdbk = {}
        with LockManager.get_lock(API.MIGR_UNIT):
            try:
                exporter.MP2POLICY_PROM_STATUS.state(MP2POLICY_PROMOTION_STATUS.IN_PROGRESS.value)
                if not only_await:
                    LOG.info("Starting Generic migration ...")
                    self._set_generic_migration()
                self._await_generic_migration()
                LOG.info("Migration completed.")
            except Exception as e:
                LOG.error(str(e))
                try:
                    self._cancel_migration()
                    LOG.info("Migration canceled.")
                    exporter.MP2POLICY_PROM_STATUS.state(MP2POLICY_PROMOTION_STATUS.CANCELED.value)
                except Exception as e:
                    exporter.MP2POLICY_PROM_STATUS.state(MP2POLICY_PROMOTION_STATUS.CANCEL_FAILED.value)
                    LOG.error(f"Failed to cancel migration: {e}")
            else:
                self._end_migration()
                LOG.info("Migration window closed.")
                success = True
                exporter.MP2POLICY_PROM_STATUS.state(MP2POLICY_PROMOTION_STATUS.SUCCESSFUL.value)
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

    def get_migration_state(self) -> str or None:
        state = self.client.get(path=API.MIGR_STATE).json()
        return state.get("mp_policy_promotion") if state else None

    def _set_generic_migration(self):
        LOG.info("Setting Generic migration data ...")
        self.client.post(path=API.MP_TO_POLICY, data=PayloadBuilder.generic())

    @await_status(timeout=1200, interval=5)
    def _await_generic_migration(self):
        return self.client.get(path=API.MIGR_STATUS_SUM).json()

    def _end_migration(self):
        LOG.info("Closing migration window ...")
        self.client.post(path=API.MP_TO_POLICY_DONE, data=None)

    def _continue_migration(self, migr_data: dict = None):
        LOG.info("Continuing migration ...")
        self.client.post(path=API.MIGRATION_CONTINUE, data=None)

    def _cancel_migration(self):
        LOG.info("Canceling Generic migration ...")
        self.client.post(path=API.MIGRATION_CANCEL, data=None)
        LOG.info("Migration canceled.")

    def _handle_migr_status(self, args, kwargs, status_func) -> Tuple[dict, bool]:
        status_msg = lambda r: f" - Status for component '{r.get('component_type')}': {r.get('status')}, {r.get('percent_complete')}%"
        res = status_func(self, *args, **kwargs)

        overal_status = res.get("overall_migration_status", "")
        results = res.get("component_status", [])
        failed_statuses = [RUNNING_MIGR_STATUS.FAIL.value, RUNNING_MIGR_STATUS.FAILED.value]

        if len(results) < 1 and overal_status in failed_statuses:
            raise MpPolicyException(f"MP-Policy Migration Status: FAILED! Result: {res}")

        LOG.info(f"Overall migration status: {overal_status}")
        migr_incomplete = False
        for r in results:
            if r.get("status") in failed_statuses:
                fdbk = self.get_migration_feedback()
                if overal_status == RUNNING_MIGR_STATUS.PAUSING.value:
                    LOG.warning(r.get("details"))
                elif overal_status == RUNNING_MIGR_STATUS.PAUSED.value and cfg.CONF.AGENT.continue_on_failed_promotions:
                    LOG.info(status_msg(r))
                    # raise if port aways, despite of continue_on_failed_promotions
                    self._raise_for_port(migr_feedback=fdbk)

                    self._display_last_migr_feedback(fdbk)
                    self._continue_migration()
                else:
                    raise MpPolicyException(f"MP-Policy Migration Status:  FAILED! Result: {res}")
            else:
                LOG.info(status_msg(r))
            if r.get("status") != RUNNING_MIGR_STATUS.SUCCESS.value and r.get("percent_complete") < 100:
                migr_incomplete = True
        return res, migr_incomplete

    def _display_last_migr_feedback(self, migr_feedback):
        if migr_feedback and migr_feedback.get("result_count", 0) > 0:
            LOG.info(f"Migration feedback:")
            l = len(migr_feedback.get("results"))
            try:
                feedback_res = migr_feedback.get("results").pop(0)  # LIFO
                LOG.info(
                    f" {l}. display_name: '{feedback_res.get('mp_display_name')}', type: '{feedback_res.get('type')}', id: '{feedback_res.get('mp_id')}':")
                for err in feedback_res.get("error_list", []):
                    LOG.warning(f"   - {err.get('error_id')}: {err.get('error_desc')}")
            except IndexError:
                return

    def _raise_for_port(self, migr_feedback):
        if migr_feedback and migr_feedback.get("result_count", 0) > 0:
            for res in migr_feedback.get("results", []):
                if res.get('type') == 'LOGICAL_PORT' or res.get('type') == 'SEGMENT_PORT':
                    raise MpPolicyException(
                        f"Migration failed for port: display_name: '{res.get('mp_display_name')}', id: '{res.get('mp_id')}'")
