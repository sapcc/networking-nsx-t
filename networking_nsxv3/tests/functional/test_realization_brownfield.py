import eventlet
eventlet.monkey_patch()

from oslo_log import log as logging
from oslo_config import cfg
from neutron.tests import base
from networking_nsxv3.tests.environment import Environment
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_policy as pp
import copy
import os
import re

LOG = logging.getLogger(__name__)

# TODO - replace static wait/sleep with active polling


class TestAgentRealizer(base.BaseTestCase):

    cleanup_on_teardown = False
    cleanup_sleep = 30

    def setUp(self):
        super(TestAgentRealizer, self).setUp()

        LOG.info("==>>>>>>>>>>>>>>>>>>> setUp")

        o = cfg.CONF.set_override
        g = os.environ.get

        if g("DEBUG") == True:
            o('debug', True)
        logging.setup(cfg.CONF, "demo")

        o("nsxv3_login_hostname", g("NSXV3_LOGIN_HOSTNAME"), "NSXV3")
        o("nsxv3_login_port", g("NSXV3_LOGIN_PORT"), "NSXV3")
        o("nsxv3_login_user", g("NSXV3_LOGIN_USER"), "NSXV3")
        o("nsxv3_login_password", g("NSXV3_LOGIN_PASSWORD"), "NSXV3")
        o("nsxv3_transport_zone_name", g("NSXV3_TRANSPORT_ZONE_NAME"), "NSXV3")
        o("nsxv3_connection_retry_count", 3, "NSXV3")
        o("nsxv3_remove_orphan_ports_after", 0, "NSXV3")
        o("sync_skew", 0, "AGENT")

        TestAgentRealizer.instance = self

    @staticmethod
    def cleanup():
        LOG.info("==>>>>>>>>>>>>>>>>>>> cleanup")
        env = Environment(name="Cleanup")
        with env:
            eventlet.sleep(TestAgentRealizer.cleanup_sleep)
            mngr_meta, plcy_meta = env.dump_provider_inventory(printable=False)
            for type, meta in plcy_meta.items():
                p = env.manager.realizer.nsx_provider
                if type != p.NETWORK and type != p.SG_RULES_REMOTE_PREFIX:
                    TestAgentRealizer.instance.assertEquals(dict(), meta["meta"])

    def tearDown(self):
        super(TestAgentRealizer, self).tearDown()
        LOG.info("==>>>>>>>>>>>>>>>>>>> tearDown")
        if TestAgentRealizer.cleanup_on_teardown:
            LOG.info("cleanup on tearDown")
            TestAgentRealizer.cleanup()
        else:
            LOG.info("NO cleanup on tearDown")

    @staticmethod
    def setup_networks(env: Environment, inventory):
        for port_id in inventory.get("port"):
            net = env.openstack_inventory.network_create(inventory["port"][port_id]["vif_details"]["segmentation_id"])
            inventory["port"][port_id]["vif_details"]["nsx-logical-switch-id"] = net.get("nsx-logical-switch-id")
        env.openstack_inventory.reload_inventory(inventory)

    def test_01_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_01_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_02_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_02_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_03_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_03_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_04_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_04_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_05_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_05_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_06_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_06_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_07_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_07_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_08_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_08_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_09_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_09_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_10_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_10_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_11_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_11_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    @staticmethod
    def end_to_end_test_generator():
        LOG.info("Starting end to end tests ...")
        TestAgentRealizer.cleanup_sleep = 80
        TestAgentRealizer.cleanup()
        TestAgentRealizer.cleanup_sleep = 30
        c = coverage

        ################ PORT-BIND FUNCTIONAL TESTS ##############

        LOG.info("Create inventory with the provider")
        inventory = copy.deepcopy(coverage.OPENSTACK_INVENTORY)

        env = Environment(inventory=inventory)
        with env:
            TestAgentRealizer.setup_networks(env, inventory)
            i = env.openstack_inventory
            LOG.info("Binding port \"PORT_FRONTEND_EXTERNAL\"")
            i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")

            # Test split point
            yield 1

            LOG.info("Binding port \"PORT_FRONTEND_INTERNAL\"")
            i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")

            # Test split point
            yield 2

            LOG.info("Binding port \"PORT_BACKEND\"")
            i.port_bind(c.PORT_BACKEND["name"], "3200")

            # Test split point
            yield 3

            LOG.info("Binding port \"PORT_DB\"")
            i.port_bind(c.PORT_DB["name"], "3200")

            # Test split point
            yield 4

            LOG.info("Binding port \"PORT_WITH_3_SG\"")
            i.port_bind(c.PORT_WITH_3_SG["name"], "1000")

            eventlet.sleep(30)
            # Test split point
            yield 5

        LOG.info("Checking \"_assert_create\"")
        TestAgentRealizer._assert_create(c, env)
        eventlet.sleep(10)
        yield 6  # Test split point

        # ################ PORT-UNBIND FUNCTIONAL TESTS ##############
        LOG.info("Create inventory with the provider")

        env = Environment(inventory=inventory)
        with env:
            TestAgentRealizer.setup_networks(env, inventory)
            i = env.openstack_inventory
            eventlet.sleep(10)

            LOG.info("Polluting ...")
            for index in range(1, 10):
                TestAgentRealizer._pollute(env, index)

            # Test split point
            yield 7

            # Remove parent
            LOG.info("Deleting port \"PORT_FRONTEND_INTERNAL\"")
            i.port_delete(c.PORT_FRONTEND_INTERNAL["name"])

            # Test split point
            yield 8

            LOG.info("Deleting port \"PORT_WITH_3_SG\"")
            i.port_delete(c.PORT_WITH_3_SG["name"])

            # Test split point
            yield 9

            # Remove child
            LOG.info("Deleting port \"PORT_FRONTEND_EXTERNAL\"")
            i.port_delete(c.PORT_FRONTEND_EXTERNAL["name"])

            eventlet.sleep(60)
            # Test split point
            yield 10

        LOG.info("Checking \"_assert_update\"")
        TestAgentRealizer._assert_update(c, env)
        TestAgentRealizer.cleanup_on_teardown = True
        TestAgentRealizer.cleanup_sleep = 120
        eventlet.sleep(10)
        yield 11

    @staticmethod
    def _assert_create(os_inventory: coverage, environment: Environment):
        c = os_inventory
        mgmt_meta, plcy_meta = environment.dump_provider_inventory(printable=False)
        m = {**mgmt_meta, **plcy_meta}

        p = environment.manager.realizer.nsx_provider

        # Validate network creation
        TestAgentRealizer.instance.assertEquals("1000" in m[p.NETWORK]["meta"], True)
        TestAgentRealizer.instance.assertEquals("3200" in m[p.NETWORK]["meta"], True)

        # Validate QoS State
        TestAgentRealizer.instance.assertEquals(c.QOS_INTERNAL["id"] in m[p.QOS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.QOS_EXTERNAL["id"] in m[p.QOS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.QOS_NOT_REFERENCED["id"] in m[p.QOS]["meta"], False)
        
        # Validate QoS Bindings
        internal_qos_id = m[p.QOS]["meta"][c.QOS_INTERNAL["id"]]["id"]
        internal_qos_meta = m[p.QOS]["meta"][c.QOS_INTERNAL["id"]]
        internal_port_meta = m[p.PORT]["meta"][c.PORT_FRONTEND_INTERNAL["id"]]

        external_qos_id = m[p.QOS]["meta"][c.QOS_EXTERNAL["id"]]["id"]
        external_qos_meta = m[p.QOS]["meta"][c.QOS_EXTERNAL["id"]]
        external_port_meta = m[p.PORT]["meta"][c.PORT_FRONTEND_EXTERNAL["id"]]

        internal_qos_query = pp.API.SEARCH_Q_QOS_BIND.format(internal_qos_id)
        internal_qos_mappings = p.client.get_all(path=pp.API.SEARCH_QUERY, params={"query": internal_qos_query})

        external_qos_query = pp.API.SEARCH_Q_QOS_BIND.format(external_qos_id)
        external_qos_mappings = p.client.get_all(path=pp.API.SEARCH_QUERY, params={"query": external_qos_query})

        internal_qos_data = {
            "display_name": internal_qos_meta["real_id"],
            "id": internal_qos_meta["real_id"],
            "marked_for_delete": False,
            "parent_path": internal_port_meta["path"],
            "path": internal_port_meta["path"] + f"/port-qos-profile-binding-maps/{internal_qos_id}",
            "qos_profile_path": internal_qos_meta["path"],
            "resource_type": "PortQoSProfileBindingMap"
        }
        external_qos_data = {
            "display_name": external_qos_meta["real_id"],
            "id": external_qos_meta["real_id"],
            "marked_for_delete": False,
            "parent_path": external_port_meta["path"],
            "path": external_port_meta["path"] + f"/port-qos-profile-binding-maps/{external_qos_id}",
            "qos_profile_path": external_qos_meta["path"],
            "resource_type": "PortQoSProfileBindingMap"
        }

        TestAgentRealizer.instance.assertEqual(1, len(external_qos_mappings))
        TestAgentRealizer.instance.assertEqual(1, len(internal_qos_mappings))
        TestAgentRealizer.instance.assertDictSupersetOf(external_qos_data, external_qos_mappings[0])
        TestAgentRealizer.instance.assertDictSupersetOf(internal_qos_data, internal_qos_mappings[0])

        # Validate Security Groups Members
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(
            c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_MEMBERS]["meta"], False)

        # Validate Security Group Rules Sections
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES]["meta"], False)
        TestAgentRealizer.instance.assertEquals(
            c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES]["meta"], False)

        if environment.is_management_api_mode():
            # Validate Security Group Rules NSGroups
            TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES_EXT]["meta"], True)
            TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES_EXT]["meta"], True)
            TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES_EXT]["meta"], True)
            TestAgentRealizer.instance.assertEquals(
                c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES_EXT]["meta"], True)
            TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES_EXT]["meta"], False)
            TestAgentRealizer.instance.assertEquals(
                c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES_EXT]["meta"], False)

        # Validate Security Group Remote Prefix IPSets
        for id in m[p.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            TestAgentRealizer.instance.assertEquals("0.0.0.0/" in id or "::/" in id, True)

    @staticmethod
    def _assert_update(os_inventory: coverage, environment: Environment):
        c = os_inventory
        mgmt_meta, plcy_meta = environment.dump_provider_inventory(printable=False)
        m = {**mgmt_meta, **plcy_meta}
        p = environment.manager.realizer.nsx_provider

        # Validate network creation
        TestAgentRealizer.instance.assertEquals("1000" in m[p.NETWORK]["meta"], True)
        TestAgentRealizer.instance.assertEquals("3200" in m[p.NETWORK]["meta"], True)

        # Validate QoS State
        TestAgentRealizer.instance.assertEquals(c.QOS_INTERNAL["id"] in m[p.QOS]["meta"], False)
        TestAgentRealizer.instance.assertEquals(c.QOS_EXTERNAL["id"] in m[p.QOS]["meta"], False)
        TestAgentRealizer.instance.assertEquals(c.QOS_NOT_REFERENCED["id"] in m[p.QOS]["meta"], False)
        TestAgentRealizer.instance.assertEquals(len(m[p.QOS]["meta"].keys()), 0)

        # Validate Security Groups Members
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_MEMBERS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_MEMBERS]["meta"], False)
        TestAgentRealizer.instance.assertEquals(
            c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_MEMBERS]["meta"], False)
        TestAgentRealizer.instance.assertEquals(len(m[p.SG_MEMBERS]["meta"].keys()), 4)

        # Validate Security Group Rules Sections
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES]["meta"], False)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES]["meta"], False)
        TestAgentRealizer.instance.assertEquals(
            c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES]["meta"], False)
        TestAgentRealizer.instance.assertEquals(len(m[p.SG_RULES]["meta"].keys()), 3)

        if environment.is_management_api_mode():
            # Validate Security Group Rules NSGroups
            TestAgentRealizer.instance.assertEquals(
                c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES_EXT]["meta"], False)
            TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES_EXT]["meta"], True)
            TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES_EXT]["meta"], True)
            TestAgentRealizer.instance.assertEquals(
                c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES_EXT]["meta"], True)
            TestAgentRealizer.instance.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES_EXT]["meta"], False)
            TestAgentRealizer.instance.assertEquals(
                c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES_EXT]["meta"], False)
            TestAgentRealizer.instance.assertEquals(len(m[p.SG_RULES_EXT]["meta"].keys()), 3)

        # Validate Security Group Remote Prefix IPSets
        for id in m[p.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            TestAgentRealizer.instance.assertEquals("0.0.0.0/" in id or "::/" in id, True)

        params = {"default_service": False}  # User services only
        services = p.client.get_all(path=pp.API.SERVICES, params=params)
        services = [s for s in services if not s.get("is_default")]
        TestAgentRealizer.instance.assertEquals(len(services), 0)

    @staticmethod
    def _pollute(env, index):
        p = env.manager.realizer.nsx_provider
        _id = "00000000-0000-0000-0000-00000000000{}".format(index)

        ipv4 = "192.168.0.0/{}".format(index)
        ipv6 = "::ffff/{}".format(index)

        ipv4_id = re.sub(r"\.|:|\/", "-", ipv4)
        ipv6_id = re.sub(r"\.|:|\/", "-", ipv6)

        ppp = pp.Payload()
        api = pp.API

        p.client.put(path=api.GROUP.format(ipv4_id), data=ppp.sg_rule_remote(ipv4))
        p.client.put(path=api.GROUP.format(ipv6_id), data=ppp.sg_rule_remote(ipv6))

        p.client.put(path=api.GROUP.format(_id), data=ppp.sg_members_container({"id": _id}, dict()))
        data = ppp.sg_rules_container({"id": _id}, {"rules": [], "scope": _id})
        p.client.put(path=api.POLICY.format(_id), data=data)


# Initialize end to end tests generator
TestAgentRealizer.tests_generator = TestAgentRealizer.end_to_end_test_generator()
