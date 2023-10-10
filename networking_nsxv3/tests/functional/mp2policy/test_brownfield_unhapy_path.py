import eventlet
eventlet.monkey_patch()

from networking_nsxv3.tests.functional.base_nsxv3_api import BaseNsxTest
from oslo_log import log as logging
from oslo_config import cfg
from networking_nsxv3.common.constants import MP2POLICY_NSX_MIN_VERSION, ONLY_POLICY_API_NSX_VERSION
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx, provider_nsx_mgmt, provider_nsx_policy
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.unit import openstack


LOG = logging.getLogger(__name__)


class TestMp2PolicyMigr(BaseNsxTest):
    """ TODO: Describe the scenario
    """

    MIGR_INVENTORY = None
    TEST_ENV = None
    TEST_CONFIG = cfg.CONF

    @classmethod
    def setUpClass(cls):
        LOG.info(f"Global setup - READ Enviroment Variables, Activate Migration")
        cls.load_env_variables()
        if client_nsx.Client().version < MP2POLICY_NSX_MIN_VERSION:
            cls.skipTest(
                cls, f"Migration Functional Tests skipped. Migration is NOT supported for NSX-T < {MP2POLICY_NSX_MIN_VERSION}")
        if client_nsx.Client().version >= ONLY_POLICY_API_NSX_VERSION:
            cls.skipTest(
                cls, f"Migration Functional Tests skipped for NSX-T >= 4.0.0")
        cls.clean_all_from_nsx()
        cls.unpersist_migration_status()
        cls.enable_nsxtside_m2policy_migration()

        LOG.info(f"Activate migration on driver side")

        cls.TEST_CONFIG.set_override("force_mp_to_policy", True, "AGENT")
        cls.TEST_CONFIG.set_override("ports_tag_number_decrease_workaround", False, "AGENT")
        cls.TEST_CONFIG.set_override("continue_on_failed_promotions", False, "AGENT")
        cls.TEST_CONFIG.set_override("max_sg_tags_per_segment_port", 2, "AGENT")
        cls.TEST_CONFIG.set_override("polling_interval", 10, "AGENT")
        cls.TEST_CONFIG.set_override("sync_skew", 0, "AGENT")

        cls.MIGR_INVENTORY = cls._polute_environment(
            num_nets=5,  # 100
            num_ports_per_net=5,  # 20
            num_groups=30,  # 1000
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

    def test_network(self):
        # Case 1: Assert that all objects are rolled-back as before the migration
        nets = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.NETWORK).items()
        self.assertTrue(len(nets) > 0, "No Networks found in the inventory!")

        for k, v in nets:
            vlan_id = v.get("segmentation_id")
            self.assertTrue(str(vlan_id) in self.mngr_meta[self.mngr.NETWORK]["meta"],
                            f"Network '{k}' with vlan '{vlan_id}' must exists in the manager metadata!")
            self.assertFalse(str(vlan_id) in self.plcy_meta[self.plcy.NETWORK]["meta"],
                            f"Network '{k}' with vlan '{vlan_id}' must NOT exists in the policy metadata!")

    def test_port(self):
        # Case 1: Assert that all objects are rolled-back as before the migration
        ports = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.PORT).items()
        self.assertTrue(len(ports) > 0, "No Ports found in the inventory!")

        for k, v in ports:
            self.assertTrue(k in self.mngr_meta[self.mngr.PORT]["meta"],
                            f"Port '{k}' must exists in the manager metadata!")
            self.assertFalse(k in self.plcy_meta[self.plcy.PORT]["meta"],
                            f"Port '{k}' must NOT exists in the policy metadata!")

    def test_qos(self):
        # Case 1: Assert that all objects are rolled-back as before the migration
        qos = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.QOS).items()
        self.assertTrue(len(qos) > 0, "No QoS found in the inventory!")

        for k, v in qos:
            self.assertTrue(k in self.mngr_meta[self.mngr.QOS]["meta"],
                            f"QoS '{k}' must exists in the manager metadata!")
            self.assertFalse(k in self.plcy_meta[self.plcy.QOS]["meta"],
                            f"QoS '{k}' must NOT exists in the policy metadata!")

    def test_security_group(self):
        # Case 1: Assert that all objects are rolled-back as before the migration
        sgs = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.SECURITY_GROUP).items()
        self.assertTrue(len(sgs) > 0, "No Security Groups found in the inventory!")

        for k, v in sgs:
            self.assertFalse(k in self.mngr_meta[self.mngr.SG_MEMBERS]["meta"],
                             f"SG Members '{k}' must NOT exists in the manager metadata!")
            self.assertTrue(k in self.plcy_meta[self.plcy.SG_MEMBERS]["meta"],
                            f"SG Members '{k}' must exists in the policy metadata!")
            self.assertFalse(k in self.mngr_meta[self.mngr.SG_RULES]["meta"],
                             f"SG Rules '{k}' must NOT exists in the manager metadata!")
            self.assertTrue(k in self.plcy_meta[self.plcy.SG_RULES]["meta"],
                            f"SG Rules '{k}' must exists in the policy metadata!")

        self.assertFalse(coverage.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in self.plcy_meta[self.plcy.SG_RULES]["meta"],
                         f"SG Rules '{coverage.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED['id']}' must NOT exists in the policy metadata!")
        for id in self.plcy_meta[self.plcy.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertTrue("0.0.0.0/" in id or "::/" in id, f"SG Rules '{id}' must be a remote prefix!")

    def test_security_group_members(self):
        # Case 1: Assert that all objects are rolled-back as before the migration
        ports = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.PORT).items()
        self.assertTrue(len(ports) > 0, "No Ports found in the inventory!")

        # Assert port's group membership
        for k, v in ports:
            os_sgs = v.get("security_groups")
            for sg in os_sgs:
                self.assertTrue(sg in self.plcy_meta[self.plcy.SG_MEMBERS]["meta"],
                                f"SG Members '{sg}' must exists in the policy metadata!")
                self.assertEqual(0, len(self.plcy_meta[self.plcy.SG_MEMBERS]["meta"][sg]["sg_members"]),
                                 f"SG '{sg}' must have no static members in the policy metadata!")

