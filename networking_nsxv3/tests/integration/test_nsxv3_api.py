import copy
import os
import eventlet


from oslo_config import cfg
from oslo_log import log as logging

from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.environment import Environment
from neutron.tests import base

LOG = logging.getLogger(__name__)


class TestNSXTApi(base.BaseTestCase):
    cleanup_on_teardown = True
    cleanup_on_setup = True
    cleanup_sleep = 30

    CONF_CLEANUP_SLEEP_ON_TEARDOWN = 320
    CONF_CLEANUP_SLEEP_ON_SETUP = 180
    CONF_SLEEP_AFTER_TEST_EXECUTION = 580

    o = cfg.CONF.set_override

    def printconfg(self):
        nsxt = cfg.CONF.get("NSXV3")
        for key, value in nsxt.items():
            LOG.info(f"{key} --> {value}")

    @classmethod
    def load_env_variables(cls):
        LOG.info(f"Load Env Variables")

        g = os.environ.get

        if g("DEBUG") == True:
            cls.o('debug', True)
        logging.setup(cfg.CONF, "demo")
        cls.o("lock_path", "/tmp/", "oslo_concurrency")

        # LOG.error(f"Login user {g('NSXV3_LOGIN_HOSTNAME')} - {cfg.CONF.NSXV3.nsxv3_login_user}")

        cls.o("nsxv3_login_hostname", g("NSXV3_LOGIN_HOSTNAME"), "NSXV3")
        cls.o("nsxv3_login_port", g("NSXV3_LOGIN_PORT"), "NSXV3")
        cls.o("nsxv3_login_user", g("NSXV3_LOGIN_USER"), "NSXV3")
        cls.o("nsxv3_login_password", g("NSXV3_LOGIN_PASSWORD"), "NSXV3")
        cls.o("nsxv3_transport_zone_name", g("NSXV3_TRANSPORT_ZONE_NAME"), "NSXV3")
        cls.o("nsxv3_connection_retry_count", "3", "NSXV3")
        cls.o("nsxv3_remove_orphan_ports_after", "0", "NSXV3")

    def setup_networks(self, env: Environment, inventory):
        for port_id in inventory.get("port"):
            net = env.openstack_inventory.network_create(inventory["port"][port_id]["vif_details"]["segmentation_id"])
            inventory["port"][port_id]["vif_details"]["nsx-logical-switch-id"] = net.get("nsx-logical-switch-id")
        env.openstack_inventory.reload_inventory(inventory)

    def _setup_enviroment(self):
        migration_inventory = copy.deepcopy(coverage.OPENSTACK_INVENTORY_MIGRATION)
        env = Environment(inventory=migration_inventory)

        return env, migration_inventory

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
