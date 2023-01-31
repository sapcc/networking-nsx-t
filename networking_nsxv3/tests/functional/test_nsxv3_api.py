import math
import os
import time
import eventlet
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt, provider_nsx_policy, client_nsx

from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.tests.environment import Environment
from neutron.tests import base

LOG = logging.getLogger(__name__)


class BaseNsxTest(base.BaseTestCase):
    cleanup_on_teardown = True
    cleanup_on_setup = True
    cleanup_sleep = 30

    CONF_CLEANUP_SLEEP_ON_TEARDOWN = 320
    CONF_CLEANUP_SLEEP_ON_SETUP = 180
    CONF_SLEEP_AFTER_TEST_EXECUTION = 580

    @classmethod
    def load_env_variables(cls):
        LOG.info(f"Load Env Variables")

        cls.dummy_class = "load_env_variables"
        g = os.environ.get

        if g("DEBUG") == True:
            cfg.CONF.set_override('debug', True)
        logging.setup(cfg.CONF, "demo")
        cfg.CONF.set_override("lock_path", "/tmp/", "oslo_concurrency")

        # LOG.error(f"Login user {g('NSXV3_LOGIN_HOSTNAME')} - {cfg.CONF.NSXV3.nsxv3_login_user}")

        cfg.CONF.set_override("nsxv3_login_hostname", g("NSXV3_LOGIN_HOSTNAME"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_port", g("NSXV3_LOGIN_PORT"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_user", g("NSXV3_LOGIN_USER"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_password", g("NSXV3_LOGIN_PASSWORD"), "NSXV3")
        cfg.CONF.set_override("nsxv3_transport_zone_name", g("NSXV3_TRANSPORT_ZONE_NAME"), "NSXV3")
        cfg.CONF.set_override("nsxv3_connection_retry_count", "3", "NSXV3")
        cfg.CONF.set_override("nsxv3_remove_orphan_ports_after", "0", "NSXV3")

    def _cleanup(self, sleep_time):
        LOG.info("==>>>>>>>>>>>>>>>>>>> cleanup")
        env = Environment(name="Cleanup")

        with env:
            eventlet.sleep(sleep_time)
            mngr_meta, plcy_meta = env.dump_provider_inventory(printable=False)
            for type, meta in plcy_meta.items():
                p = env.manager.realizer.plcy_provider
                if type != p.SEGMENT and type != p.SG_RULES_REMOTE_PREFIX:
                    self.assertEquals(expected=dict(), observed=meta["meta"])
            for type, meta in mngr_meta.items():
                p = env.manager.realizer.mngr_provider
                if type != p.NETWORK and type != p.SG_RULES_REMOTE_PREFIX:
                    self.assertEquals(expected=dict(), observed=meta["meta"])

    @staticmethod
    def get_transport_zone_id():
        cl = client_nsx.Client()
        zone_name = cfg.CONF.NSXV3.nsxv3_transport_zone_name
        for zone in cl.get_all(path="/api/v1/transport-zones"):
            if zone.get("display_name") == zone_name:
                return zone.get("id")
        raise RuntimeError("Not found Transport Zone {}".format(zone_name))

    @staticmethod
    def clean_all_from_nsx():
        """Clean all NSX-T environment objects"""
        BaseNsxTest.clean_domain_objects("SecurityPolicy")
        BaseNsxTest.clean_domain_objects("Group")
        BaseNsxTest.clean_segment_ports()
        BaseNsxTest.clean_logical_ports()
        BaseNsxTest.clean_segments()
        BaseNsxTest.clean_logical_switches()
        BaseNsxTest.clean_all_segment_profiles()
        BaseNsxTest.clean_switching_profiles()

    @staticmethod
    def clean_domain_objects(obj_type: str):
        """Clean all objects of type: obj_type

        Args:
            obj_type (str): object type to clean (e.g. SecurityPolicy, Group)
        """
        LOG.info(f"Cleaning all objects of type: {obj_type} ...")
        cl = client_nsx.Client()
        infra = cl.get(path=provider_nsx_policy.API.INFRA, params={"type_filter": obj_type}).json()
        obj_to_update = []
        children = infra.get("children", [])
        if children:
            children = children[0].get("Domain", {}).get("children", [])
            for o in children:
                obj = o.get(obj_type)
                if obj and not obj.get("_system_owned")\
                    and not obj.get("marked_for_delete")\
                        and obj.get("_create_user") != "system":
                    o[obj_type]["marked_for_delete"] = True
                    o["marked_for_delete"] = True
                    obj_to_update.append(o)

        if obj_to_update:
            l = len(obj_to_update)
            if l < 1000:
                infra["children"][0]["Domain"]["children"] = obj_to_update
                cl.patch(path=provider_nsx_policy.API.INFRA, data=infra)
            else:
                for i in range(0, math.ceil(l / 1000)):
                    idx_from = i * 1000
                    idx_to = (i + 1) * 1000
                    infra["children"][0]["Domain"]["children"] = obj_to_update[idx_from:l if idx_to > l else idx_to]
                    cl.patch(path=provider_nsx_policy.API.INFRA, data=infra)
            return BaseNsxTest._await_clean(obj_type)

        LOG.info(f"No objects of type: {obj_type} found")

    @staticmethod
    def clean_logical_ports():
        zone_id = BaseNsxTest.get_transport_zone_id()
        LOG.info("Cleaning logical ports ...")
        cl = client_nsx.Client()
        ports = cl.get_all(path=provider_nsx_mgmt.API.PORTS, params={"transport_zone_id": zone_id})
        for p in ports:
            cl.delete(path=provider_nsx_mgmt.API.PORT.format(p.get("id")), params={"detach": True})

    @staticmethod
    def clean_logical_switches():
        zone_id = BaseNsxTest.get_transport_zone_id()
        LOG.info("Cleaning logical switches ...")
        cl = client_nsx.Client()
        switches = cl.get_all(path=provider_nsx_mgmt.API.SWITCHES, params={"transport_zone_id": zone_id})
        for sw in switches:
            cl.delete(path=provider_nsx_mgmt.API.SWITCH.format(sw.get("id")), params={"cascade": True, "detach": True})

    @staticmethod
    def clean_segments():
        LOG.info("Cleaning segments ...")
        cl = client_nsx.Client()
        infra = cl.get(path=provider_nsx_policy.API.INFRA, params={"type_filter": "Segment"}).json()
        update_infra = False
        for child in infra.get("children", []):
            segment = child.get("Segment")
            if segment:
                child["marked_for_delete"] = True
                update_infra = True
        if update_infra:
            cl.patch(path=provider_nsx_policy.API.INFRA, data=infra)
            # Sleep until the infra is not clean of Segments
            BaseNsxTest._await_clean("Segment")

    @staticmethod
    def clean_segment_profiles(prfl_type: str):
        LOG.info(f"Cleaning segment profiles of type {prfl_type} ...")
        cl = client_nsx.Client()
        infra = cl.get(path=provider_nsx_policy.API.INFRA, params={"type_filter": prfl_type}).json()
        update_infra = False
        for child in infra.get("children", []):
            p = child.get(prfl_type)
            if p and not p.get("_system_owned")\
                    and not p.get("marked_for_delete")\
            and p.get("_create_user") != "system":
                p["marked_for_delete"] = True
                child["marked_for_delete"] = True
                update_infra = True
        if update_infra:
            cl.patch(path=provider_nsx_policy.API.INFRA, data=infra)
            # Sleep until the infra is not clean
            BaseNsxTest._await_clean(prfl_type)

    @staticmethod
    def clean_segment_ports():
        LOG.info("Cleaning segment ports ...")
        cl = client_nsx.Client()
        infra = cl.get(path=provider_nsx_policy.API.INFRA, params={"type_filter": "SegmentPort"}).json()
        update_infra = False
        for child in infra.get("children", []):
            segment = child.get("Segment")
            if segment:
                for seg_child in segment.get("children", []):
                    if seg_child.get("SegmentPort"):
                        seg_child["marked_for_delete"] = True
                        update_infra = True
        if update_infra:
            cl.patch(path=provider_nsx_policy.API.INFRA, data=infra)
            # Sleep until the infra is not clean of SegmentPorts
            BaseNsxTest._await_clean("SegmentPort")

    @staticmethod
    def clean_all_segment_profiles():
        LOG.info("Cleaning segment profiles ...")
        BaseNsxTest.clean_segment_profiles("QoSProfile")
        # BaseNsxTest.clean_segment_profiles("MacDiscoveryProfile")
        # BaseNsxTest.clean_segment_profiles("SegmentSecurityProfile")
        # BaseNsxTest.clean_segment_profiles("IPDiscoveryProfile")
        # BaseNsxTest.clean_segment_profiles("SpoofGuardProfile")

    @staticmethod
    def clean_switching_profiles():
        LOG.info("Cleaning switching profiles ...")
        cl = client_nsx.Client()
        qos_profiles = cl.get_all(path=provider_nsx_mgmt.API.PROFILES,
                                  params=provider_nsx_mgmt.API.PARAMS_GET_QOS_PROFILES)

        for p in qos_profiles:
            cl.delete(path=f"{provider_nsx_mgmt.API.PROFILES}/{p.get('id')}", params={"unbind": True})

    @staticmethod
    def _await_clean(obj_type: str, system_owned: bool = False):
        cl = client_nsx.Client()
        while True:
            time.sleep(15)
            query_str = f"resource_type:{obj_type}{' AND _system_owned:False AND NOT _create_user:system' if not system_owned else ''}"
            q = cl.get(path=provider_nsx_policy.API.SEARCH_QUERY, params={"query": query_str}).json()
            if not q.get("result_count"):
                break
            LOG.info(f"Waiting for infra to be cleaned from objects of type: {obj_type} ...")
