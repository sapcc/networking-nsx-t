import eventlet
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx
from networking_nsxv3.tests.datasets import coverage

from oslo_config import cfg
from oslo_log import log as logging
from test_nsxv3_api import TestNSXTApi

LOG = logging.getLogger(__name__)


class TestManagement2PolicyApi(TestNSXTApi):

    @classmethod
    def setup_class(cls):
        LOG.info(f"Global setup - READ Enviroment Variables, Activate Migration")
        cls.load_env_variables()
        cls.enable_nsxtside_m2policy_migration()
        cls.enable_driverside_mp2policy_migation()

    @classmethod
    def enable_nsxtside_m2policy_migration(cls):
        LOG.info(f"Enable Driver Side MP2Policy Migration")
        cl = client_nsx.Client()
        mp_service_status = cl.get(path="/api/v1/node/services/migration-coordinator/status").json()
        if (mp_service_status.get("monitor_runtime_state") == "running") and (
                mp_service_status.get("runtime_state") == "running"):
            LOG.info("Migration coordinator is UP and RUNNING.")
        else:
            LOG.info("Migration coordinator is NOT running. Enabling ...")
            cl.post(path="/api/v1/node/services/migration-coordinator?action=start", data={})
            eventlet.sleep(240)

    @classmethod
    def enable_driverside_mp2policy_migation(cls):
        LOG.info(f"Activate migration on driver side")

        cfg.CONF.set_override("force_mp_to_policy", True, "AGENT")
        cfg.CONF.set_override("migration_tag_count_trigger", 5, "AGENT")
        cfg.CONF.set_override("migration_tag_count_max", 6, "AGENT")
        cfg.CONF.set_override("max_sg_tags_per_segment_port", 4, "AGENT")
        cfg.CONF.set_override("polling_interval", 20, "AGENT")

    def setUp(self):
        super(TestManagement2PolicyApi, self).setUp()
        LOG.info(f"Setup before running test")

        # cleanup only during startup
        if self.cleanup_on_setup:
            self._cleanup(self.CONF_CLEANUP_SLEEP_ON_SETUP)
        self.cleanup_on_setup = False

    @classmethod
    def teardown_class(cls):
        LOG.info(f"Global Teardwon")

    def tearDown(self):
        super(TestManagement2PolicyApi, self).tearDown()
        LOG.info(f"Teardown after running test")
        if self.cleanup_on_teardown:
            LOG.info("cleanup on tearDown")
            self._cleanup(self.CONF_CLEANUP_SLEEP_ON_TEARDOWN)
        else:
            LOG.info("NO cleanup on tearDown")

    def _assert_migrate(self, os_inventory, environment):
        c = os_inventory
        mngr_meta, plcy_meta = environment.dump_provider_inventory(printable=False)
        mngr = environment.manager.realizer.mngr_provider
        plcy = environment.manager.realizer.plcy_provider

        # Validate Networks
        self.assertEquals("1000" in mngr_meta[mngr.NETWORK]["meta"], True)
        self.assertEquals("3200" in mngr_meta[mngr.NETWORK]["meta"], True)
        self.assertEquals("1000" in plcy_meta[plcy.SEGMENT]["meta"], True)
        self.assertEquals("3200" in plcy_meta[plcy.SEGMENT]["meta"], True)

        # Validate Ports migrated
        self.assertEquals(c.PORT_FOR_MIGRATION_1["id"] in mngr_meta[mngr.PORT]["meta"], False)
        self.assertEquals(c.PORT_FOR_MIGRATION_2["id"] in mngr_meta[mngr.PORT]["meta"], False)
        self.assertEquals(c.SUBPORT_FOR_MIGRATION_1["id"] in mngr_meta[mngr.PORT]["meta"], False)
        self.assertEquals(c.PORT_FOR_NOT_MIGRATION_1["id"] in mngr_meta[mngr.PORT]["meta"], True)
        self.assertEquals(c.PORT_FOR_NOT_MIGRATION_2["id"] in mngr_meta[mngr.PORT]["meta"], True)
        self.assertEquals(
            c.PORT_FOR_NOT_MIGRATION_1["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], False)
        self.assertEquals(
            c.PORT_FOR_NOT_MIGRATION_2["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], False)
        self.assertEquals(
            c.SUBPORT_FOR_MIGRATION_1["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], True)
        self.assertEquals(
            c.PORT_FOR_MIGRATION_1["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], True)
        self.assertEquals(
            c.PORT_FOR_MIGRATION_2["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], True)

        # Validate QoS State
        self.assertEquals(c.MP_QOS_EXTERNAL["id"] in plcy_meta[plcy.SEGM_QOS]["meta"], True)
        self.assertEquals(c.MP_QOS_EXTERNAL["id"] in mngr_meta[mngr.QOS]["meta"], True)

        # Validate Security Groups Members
        self.assertEquals(c.MP_TO_POLICY_GRP_1["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.MP_TO_POLICY_GRP_2["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.MP_TO_POLICY_GRP_3["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.MP_TO_POLICY_GRP_4["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.MP_TO_POLICY_GRP_5["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(
            c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], False)
        self.assertEquals(len(plcy_meta[plcy.SG_MEMBERS]["meta"].keys()), 5)

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

    def test_policy_migration(self):
        LOG.info(f"Run Test Policy Migration")

        self.cleanup_on_teardown = True

        env, migration_inventory = self._setup_enviroment()

        with env:
            self.setup_networks(env, migration_inventory)
            i = env.openstack_inventory
            # QOS
            i.qos_create(coverage.MP_QOS_EXTERNAL["id"])

            eventlet.sleep(self.CONF_SLEEP_AFTER_TEST_EXECUTION)
            self._assert_migrate(coverage, env)
