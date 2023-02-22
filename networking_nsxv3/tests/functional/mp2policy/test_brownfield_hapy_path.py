from networking_nsxv3.tests.unit import openstack
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
            sg_gt_27=False)

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
        # Case 1: Assert that all objects are migrated as expected
        nets = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.NETWORK).items()
        self.assertTrue(len(nets) > 0, "No Networks found in the inventory!")

        for k, v in nets:
            vlan_id = v.get("segmentation_id")
            self.assertFalse(str(vlan_id) in self.mngr_meta[self.mngr.NETWORK]["meta"],
                             f"Network '{k}' with vlan '{vlan_id}' must not exists in the manager metadata!")
            self.assertTrue(str(vlan_id) in self.plcy_meta[self.plcy.SEGMENT]["meta"],
                            f"Network '{k}' with vlan '{vlan_id}' must exists in the policy metadata!")

    def test_port(self):
        # Case 1: Assert that all objects are migrated as expected
        ports = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.PORT).items()
        self.assertTrue(len(ports) > 0, "No Ports found in the inventory!")

        for k, v in ports:
            self.assertFalse(k in self.mngr_meta[self.mngr.PORT]["meta"],
                             f"Port '{k}' must not exists in the manager metadata!")
            self.assertTrue(k in self.plcy_meta[self.plcy.SEGM_PORT]["meta"],
                            f"Port '{k}' must exists in the policy metadata!")

    def test_qos(self):
        # Case 1: Assert that all objects are migrated as expected
        qos = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.QOS).items()
        self.assertTrue(len(qos) > 0, "No QoS found in the inventory!")

        for k, v in qos:
            self.assertFalse(k in self.mngr_meta[self.mngr.QOS]["meta"],
                             f"QoS '{k}' must not exists in the manager metadata!")
            self.assertTrue(k in self.plcy_meta[self.plcy.SEGM_QOS]["meta"],
                            f"QoS '{k}' must exists in the policy metadata!")

    def test_security_group(self):
        # Case 1: Assert that all objects are migrated as expected
        sgs = TestMp2PolicyMigr.MIGR_INVENTORY.get(openstack.NeutronMock.SECURITY_GROUP).items()
        self.assertTrue(len(sgs) > 0, "No Security Groups found in the inventory!")

        for k, v in sgs:
            self.assertFalse(k in self.mngr_meta[self.mngr.SG_MEMBERS]["meta"],
                             f"SG Members '{k}' must not exists in the manager metadata!")
            self.assertTrue(k in self.plcy_meta[self.plcy.SG_MEMBERS]["meta"],
                            f"SG Members '{k}' must exists in the policy metadata!")
            self.assertFalse(k in self.mngr_meta[self.mngr.SG_RULES]["meta"],
                             f"SG Rules '{k}' must not exists in the manager metadata!")
            self.assertTrue(k in self.plcy_meta[self.plcy.SG_RULES]["meta"],
                            f"SG Rules '{k}' must exists in the policy metadata!")

    """
    # Assert group membership
    migrated_port1_path = plcy_meta[plcy.SEGM_PORT]["meta"][c.PORT_FOR_MIGRATION_1['id']].get("path")
    migrated_port2_path = plcy_meta[plcy.SEGM_PORT]["meta"][c.PORT_FOR_MIGRATION_2['id']].get("path")

    self.assertEquals(
        migrated_port1_path in plcy_meta[plcy.SG_MEMBERS]["meta"][c.MP_TO_POLICY_GRP_1["id"]]["sg_members"], False)
    self.assertEquals(
        migrated_port2_path in plcy_meta[plcy.SG_MEMBERS]["meta"][c.MP_TO_POLICY_GRP_1["id"]]["sg_members"], True)
    self.assertEquals(
        1, len(plcy_meta[plcy.SG_MEMBERS]["meta"][c.MP_TO_POLICY_GRP_1["id"]]["sg_members"]))
    self.assertEquals(
        1, len(plcy_meta[plcy.SG_MEMBERS]["meta"][c.MP_TO_POLICY_GRP_2["id"]]["sg_members"]))
    self.assertEquals(
        1, len(plcy_meta[plcy.SG_MEMBERS]["meta"][c.MP_TO_POLICY_GRP_3["id"]]["sg_members"]))
    self.assertEquals(
        1, len(plcy_meta[plcy.SG_MEMBERS]["meta"][c.MP_TO_POLICY_GRP_4["id"]]["sg_members"]))
    self.assertEquals(
        0, len(plcy_meta[plcy.SG_MEMBERS]["meta"][c.MP_TO_POLICY_GRP_5["id"]]["sg_members"]))

    # Validate Security Group Rules Sections
    self.assertEquals(c.MP_TO_POLICY_GRP_1["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
    self.assertEquals(c.MP_TO_POLICY_GRP_2["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
    self.assertEquals(c.MP_TO_POLICY_GRP_3["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
    self.assertEquals(c.MP_TO_POLICY_GRP_4["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
    self.assertEquals(c.MP_TO_POLICY_GRP_5["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
    self.assertEquals(
        c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[plcy.SG_RULES]["meta"], False)

    # Validate Security Group Remote Prefix IPSets
    for id in plcy_meta[plcy.SG_RULES_REMOTE_PREFIX]["meta"].keys():
        self.assertEquals("0.0.0.0/" in id or "::/" in id, True)
    """
