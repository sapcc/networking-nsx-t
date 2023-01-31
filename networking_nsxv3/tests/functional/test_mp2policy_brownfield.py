import eventlet
import pytest
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.environment import Environment
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx, provider_nsx_mgmt, provider_nsx_policy
from networking_nsxv3.common.constants import MP2POLICY_NSX_MIN_VERSION

from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.tests.functional.test_nsxv3_api import BaseNsxTest

LOG = logging.getLogger(__name__)


def is_nsx_min_ver() -> bool:
    BaseNsxTest.load_env_variables()
    cl = client_nsx.Client()
    return cl.version >= MP2POLICY_NSX_MIN_VERSION


class TestMp2PolicyMigr(BaseNsxTest):

    @classmethod
    def setup_class(cls):
        LOG.info(f"Global setup - READ Enviroment Variables, Activate Migration")
        cls.load_env_variables()
        cls.clean_all_from_nsx()
        cls.enable_nsxtside_m2policy_migration()
        cls.enable_driverside_mp2policy_migation()

    @classmethod
    def teardown_class(cls):
        LOG.info(f"Global Teardwon")

    def setUp(self):
        super(TestMp2PolicyMigr, self).setUp()
        LOG.info(f"Setup before running test")
        self.number_of_networks = 2  # 200
        self.number_of_ports_per_network = 7  # 12
        self.total_number_of_security_groups = 6  # 6000
        self.total_number_of_qos_policies = 5  # 100
        self.cleanup_on_setup = False

    def tearDown(self):
        super(TestMp2PolicyMigr, self).tearDown()
        LOG.info(f"Teardown after running test")
        LOG.info("NO cleanup on tearDown")

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
        cfg.CONF.set_override("migration_tag_count_trigger", 1, "AGENT")
        cfg.CONF.set_override("migration_tag_count_max", 6, "AGENT")
        cfg.CONF.set_override("max_sg_tags_per_segment_port", 2, "AGENT")
        cfg.CONF.set_override("polling_interval", 20, "AGENT")

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

    @pytest.mark.skipif(not is_nsx_min_ver(), reason="Migration Functional Tests skipped. Migration is not supported for NSX-T < 3.2.2")
    def test_policy_migration(self):
        LOG.info("Starting end to end tests ...")

        MIGR_INVENTORY = self._polute_environment(
            num_nets=self.number_of_networks,
            num_ports_per_net=self.number_of_ports_per_network,
            num_groups=self.total_number_of_security_groups,
            num_qos=self.total_number_of_qos_policies)

        eventlet.sleep(10)

        # env = Environment(inventory=MIGR_INVENTORY)
        # with env:
        #     i = env.openstack_inventory
        #     eventlet.sleep(580)
        # LOG.info(f"Inventories: {i}")

    def _polute_environment(self, num_nets=500, num_ports_per_net=5, num_groups=3000, num_qos=100) -> dict:
        """Polutes the environment with the given number of networks, ports and security groups.
        """
        os_inventory = coverage.generate_os_inventory(num_nets, num_ports_per_net, num_groups, num_qos)
        self.polute_nsx(os_inventory)

        return os_inventory

    def polute_nsx(self, os_inventory):
        cl = client_nsx.Client()
        mngr_payload = provider_nsx_mgmt.Payload()
        plcy_payload = provider_nsx_policy.Payload()
        mngr_api = provider_nsx_mgmt.API
        plcy_api = provider_nsx_policy.API
        zone_id = self.get_transport_zone_id()

        nets = os_inventory.get("network", {})
        grps = os_inventory.get("security-group", {})
        rules = os_inventory.get("security-group-rule", {})
        qos = os_inventory.get("qos", {})
        ports = os_inventory.get("port", {})

        LOG.info(f"Poluting with {len(nets)} Logical Switches ...")
        for k in nets:
            seg_id = nets[k].get("segmentation_id")
            _id = f"{cfg.CONF.NSXV3.nsxv3_transport_zone_name}-{seg_id}"
            net_payload = mngr_payload.network(os_net={"id": _id, "segmentation_id": seg_id},
                                        provider_net={"transport_zone_id": zone_id})
            net_payload["_revision"] = 0
            sw = cl.post(path=mngr_api.SWITCHES, data=net_payload).json()
            nets[k]["nsx_id"] = sw["id"]

        LOG.info(f"Poluting with {len(grps)} Security Groups ...")
        for k in grps:
            grp_payload = plcy_payload.sg_members_container(os_sg=grps[k], provider_sg={})
            cl.put(path=plcy_api.GROUP.format(k), data=grp_payload)

        LOG.info(f"Poluting with {len(rules)} Security Rules ...")
        for k in rules:
            r = rules[k]
            rules_payload = plcy_payload.sg_rule(os_rule=r,
                                                 provider_rule={"_revision": None},
                                                 sp_id=r.get("security_group_id"),
                                                 logged=r.get("logged")
                                                 )
            secp_payload = plcy_payload.sg_rules_container(
                os_sg={"id": r.get("security_group_id")},
                provider_sg={"scope": r.get("security_group_id"), "rules": [rules_payload], "_revision": None}
            )
            cl.put(path=plcy_api.POLICY.format(r.get("security_group_id")), data=secp_payload)

        LOG.info(f"Poluting with {len(qos)} QOS Profiles ...")
        for k in qos:
            qos_payload = mngr_payload.qos(os_qos=qos[k], provider_qos={})
            q = cl.post(path=mngr_api.PROFILES, data=qos_payload).json()
            qos[k]["nsx_id"] = q.get("id")

        LOG.info(f"Poluting with {len(ports)} Logical Ports ...")
        for k in ports:
            p = ports[k]
            p["vif_details"]["nsx-logical-switch-id"] = nets[p.get("network_id")]["nsx_id"]
            port_payload = mngr_payload.port(os_port=p, provider_port={
                    "switching_profile_ids": [],
                    "qos_policy_id": qos[p.get("qos_policy_id")]["nsx_id"],
                    "parent_id": p.get("parent_id"),
                    })
            p = cl.post(path=mngr_api.PORTS, data=port_payload).json()
            p["nsx_id"] = p.get("id")
