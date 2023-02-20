import functools
import os
import time
import typing
import unittest
import eventlet
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt, provider_nsx_policy, client_nsx

from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.tests.environment import Environment

LOG = logging.getLogger(__name__)


class NsxPolicyInfraApiProvider(object):

    def __init__(self):
        self.client = client_nsx.Client()

    def chunked_update(update_func: typing.Callable, chunk_size=1000) -> typing.Callable:
        chunk_size = 2000 if chunk_size > 2000 else chunk_size  # total max

        @functools.wraps(update_func)
        def decorated(cls, obj_to_update, obj_type, parent_obj_type=None):
            child_sizes = [cls._calculate_child_sizes(
                o, parent_obj_type, obj_type) for o in obj_to_update]

            idx = 0
            while idx < len(obj_to_update):
                ch_size = 1
                chunks = []
                for i in range(idx, len(obj_to_update)):
                    ch_size += 1 + child_sizes[i]
                    if ch_size >= chunk_size:
                        break
                    chunks.append(obj_to_update[i])
                    idx += 1
                update_func(cls, chunks, obj_type)
        return decorated

    def get_infra_children(self, obj_type: str) -> list:
        infra = self.client.get(path=provider_nsx_policy.API.INFRA, params={"type_filter": obj_type}).json()
        return infra.get("children", [])

    @chunked_update
    def update_infra(self, obj_to_update: list, obj_type: str, parent_obj_type: str = None):
        infra = {
            "resource_type": "Infra",
            "path": "/infra",
            "parent_path": "/infra",
            "children": obj_to_update
        }
        LOG.info(
            f"Updating {len(obj_to_update)} objects of type '{obj_type}', parent: '{parent_obj_type}'")
        self.client.patch(path=provider_nsx_policy.API.INFRA, data=infra)

    @chunked_update
    def update_domain_infra(self, obj_to_update: list, obj_type: str):
        infra = {
            "resource_type": "Infra",
            "path": "/infra",
            "parent_path": "/infra",
            "children": [{
                "Domain": {
                    "resource_type": "Domain",
                    "id": "default",
                    "path": "/infra/domains/default",
                    "parent_path": "/infra",
                    "children": obj_to_update
                },
                "id": "default",
                "resource_type": "ChildDomain"
            }]
        }
        LOG.info(f"Updating {len(obj_to_update)} objects of type '{obj_type}', parent: 'Domain'")
        self.client.patch(path=provider_nsx_policy.API.INFRA, data=infra)

    def _calculate_child_sizes(self, obj, parent_obj_type, obj_type):
        if parent_obj_type:
            size = 0
            parent = obj.get(parent_obj_type, {})
            if parent:
                parent_children = parent.get("children", [])
                size = len(parent_children)
                for parent_child in parent_children:
                    children = parent_child.get(obj_type, {}).get("children", [])
                    size += len(children)
            return size
        else:
            children = obj.get(obj_type, {}).get("children", [])
            return len(children)


class BaseNsxTest(unittest.TestCase):
    cleanup_on_teardown = True
    cleanup_on_setup = True
    cleanup_sleep = 30

    CONF_CLEANUP_SLEEP_ON_TEARDOWN = 320
    CONF_CLEANUP_SLEEP_ON_SETUP = 180
    CONF_SLEEP_AFTER_TEST_EXECUTION = 580

    INFRA_PROVIDER: NsxPolicyInfraApiProvider = None

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
        # Infra api calls needs more time when dealing with large number of objects used in the test polution
        cfg.CONF.set_override("nsxv3_request_timeout", "320", "NSXV3")
        BaseNsxTest.INFRA_PROVIDER = NsxPolicyInfraApiProvider()

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
        children = BaseNsxTest.INFRA_PROVIDER.get_infra_children(obj_type)
        if children:
            children = children[0].get("Domain", {}).get("children", [])
            obj_to_update = BaseNsxTest._mark_for_delete(obj_type, children)

        if obj_to_update:
            BaseNsxTest.INFRA_PROVIDER.update_domain_infra(obj_to_update, obj_type)
            return BaseNsxTest._await_clean(obj_type)

        LOG.info(f"No objects of type: {obj_type} found")

    @staticmethod
    def clean_segments():
        LOG.info("Cleaning segments ...")
        obj_type = "Segment"
        children = BaseNsxTest.INFRA_PROVIDER.get_infra_children(obj_type)
        obj_to_update = BaseNsxTest._mark_for_delete(obj_type, children)

        if obj_to_update:
            BaseNsxTest.INFRA_PROVIDER.update_infra(obj_to_update, obj_type)
            return BaseNsxTest._await_clean(obj_type)

        LOG.info(f"No objects of type: {obj_type} found")

    @staticmethod
    def clean_segment_ports():
        LOG.info("Cleaning segment ports ...")
        obj_type = "SegmentPort"
        children = BaseNsxTest.INFRA_PROVIDER.get_infra_children(obj_type)
        update_infra = False
        for child in children:
            segment = child.get("Segment")
            if segment:
                obj_to_update = BaseNsxTest._mark_for_delete(obj_type, segment.get("children", []))
                segment["children"] = obj_to_update
                update_infra = True
        if update_infra:
            BaseNsxTest.INFRA_PROVIDER.update_infra(children, obj_type, "Segment")
            return BaseNsxTest._await_clean(obj_type)

        LOG.info(f"No objects of type: {obj_type} found")

    @staticmethod
    def clean_segment_profiles(obj_type: str):
        LOG.info(f"Cleaning segment profiles of type {obj_type} ...")
        children = BaseNsxTest.INFRA_PROVIDER.get_infra_children(obj_type)
        obj_to_update = BaseNsxTest._mark_for_delete(obj_type, children)

        if obj_to_update:
            BaseNsxTest.INFRA_PROVIDER.update_infra(obj_to_update, obj_type)
            return BaseNsxTest._await_clean(obj_type)

        LOG.info(f"No objects of type: {obj_type} found")

    @staticmethod
    def clean_all_segment_profiles():
        LOG.info("Cleaning segment profiles ...")
        BaseNsxTest.clean_segment_profiles("QoSProfile")
        # BaseNsxTest.clean_segment_profiles("MacDiscoveryProfile")
        # BaseNsxTest.clean_segment_profiles("SegmentSecurityProfile")
        # BaseNsxTest.clean_segment_profiles("IPDiscoveryProfile")
        # BaseNsxTest.clean_segment_profiles("SpoofGuardProfile")

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

    @staticmethod
    def _is_updatable(obj):
        return obj and not obj.get("_system_owned") and not obj.get("marked_for_delete") and obj.get("_create_user") != "system"

    @staticmethod
    def _mark_for_delete(obj_type, children):
        obj_to_update = []
        for o in children:
            obj = o.get(obj_type)
            if BaseNsxTest._is_updatable(obj):
                o[obj_type]["marked_for_delete"] = True
                o["marked_for_delete"] = True
                obj_to_update.append(o)
        return obj_to_update
