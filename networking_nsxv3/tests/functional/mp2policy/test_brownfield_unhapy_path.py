from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx, provider_nsx_mgmt, provider_nsx_policy
from networking_nsxv3.common.constants import MP2POLICY_NSX_MIN_VERSION

from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.tests.functional.base_nsxv3_api import BaseNsxTest

LOG = logging.getLogger(__name__)


class TestMp2PolicyMigr(BaseNsxTest):

    MIGR_INVENTORY = None
    TEST_ENV = None

    @classmethod
    def setUpClass(cls):
        LOG.info(f"Global setup - READ Enviroment Variables, Activate Migration")
        cls.load_env_variables()
        if client_nsx.Client().version < MP2POLICY_NSX_MIN_VERSION:
            cls.skipTest(
                cls, f"Migration Functional Tests skipped. Migration is not supported for NSX-T < {MP2POLICY_NSX_MIN_VERSION}")
        cls.clean_all_from_nsx()
        cls.enable_nsxtside_m2policy_migration()

        LOG.info(f"Activate migration on driver side")

        cfg.CONF.set_override("force_mp_to_policy", True, "AGENT")
        cfg.CONF.set_override("continue_on_failed_promotions", True, "AGENT")
        cfg.CONF.set_override("migration_tag_count_trigger", 1, "AGENT")
        cfg.CONF.set_override("migration_tag_count_max", 6, "AGENT")
        cfg.CONF.set_override("max_sg_tags_per_segment_port", 2, "AGENT")
        cfg.CONF.set_override("polling_interval", 20, "AGENT")

        cls.MIGR_INVENTORY = cls._polute_environment(
            num_nets=1,  # 100
            num_ports_per_net=5,  # 20
            num_groups=10,  # 1000
            num_qos=1,  # 100
            sg_gt_27=True)

        cls._start_agent_with_migration()

    @classmethod
    def tearDownClass(cls):
        LOG.info(f"Global Teardwon")

    def setUp(self):
        super().setUp()
        LOG.info(f"Setup before running test")
        self.cleanup_on_setup = False

        self.mngr_meta, self.plcy_meta = TestMp2PolicyMigr.TEST_ENV.dump_provider_inventory(printable=False)
        self.mngr: provider_nsx_mgmt.Provider = TestMp2PolicyMigr.TEST_ENV.manager.realizer.mngr_provider
        self.plcy: provider_nsx_policy.Provider = TestMp2PolicyMigr.TEST_ENV.manager.realizer.plcy_provider

    def tearDown(self):
        super().tearDown()
        LOG.info(f"Teardown after running test")
        LOG.info("NO cleanup on tearDown")

    def test_netowrk(self):
        pass

    def test_port(self):
        pass

    def test_qos(self):
        pass

    def test_security_group(self):
        pass
