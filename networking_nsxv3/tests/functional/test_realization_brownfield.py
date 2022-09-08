import copy
import os
import re

import eventlet
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import (
    agent, provider_nsx_mgmt, provider_nsx_policy, client_nsx)
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.environment import Environment
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# TODO - replace static wait/sleep with active polling


class TestAgentRealizer(base.BaseTestCase):

    cleanup_on_teardown = False

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
        o("nsxv3_connection_retry_count", "3", "NSXV3")
        o("nsxv3_remove_orphan_ports_after", "0", "NSXV3")

        TestAgentRealizer.instance = self
        TestAgentRealizer.cleanup_on_teardown = False

    @staticmethod
    def cleanup():
        LOG.info("==>>>>>>>>>>>>>>>>>>> cleanup")
        env = Environment(name="Cleanup")
        with env:
            eventlet.sleep(30)

        provider = env.manager.realizer.plcy_provider
        _, plcy_meta = env.dump_provider_inventory(printable=False)
        for type, meta in plcy_meta.items():
            if type != provider.SEGMENT and type != provider.SG_RULES_REMOTE_PREFIX:
                TestAgentRealizer.instance.assertEquals(meta["meta"], dict())

    def tearDown(self):
        super(TestAgentRealizer, self).tearDown()
        LOG.info("==>>>>>>>>>>>>>>>>>>> tearDown")
        if TestAgentRealizer.cleanup_on_teardown:
            LOG.info("cleanup on tearDown")
            TestAgentRealizer.cleanup()
        else:
            LOG.info("NO cleanup on tearDown")

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

    def test_12_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_12_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_13_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_13_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    def test_14_functional_generated(self):
        LOG.info(f"==> Starting \"{TestAgentRealizer.test_14_functional_generated.__name__}\" ...")
        y = next(self.tests_generator)
        LOG.info(f"==> End \"test_{y}_functional_generated\". Finished yield = {y}")

    @staticmethod
    def functional_test_generator():
        LOG.info("Starting end to end tests ...")
        TestAgentRealizer.cleanup()
        c = coverage

        ################ PORT-BIND FUNCTIONAL TESTS ##############

        LOG.info("Create inventory with the provider")
        inventory = copy.deepcopy(coverage.OPENSTACK_INVENTORY)

        env = Environment(inventory=inventory)
        with env:
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

            eventlet.sleep(30)
            # Test split point
            yield 10

        LOG.info("Checking \"_assert_update\"")
        TestAgentRealizer._assert_update(c, env)

        # Test split point
        TestAgentRealizer.cleanup_on_teardown = True
        eventlet.sleep(10)
        yield 11

        ################ MP-TO-POLICY FUNCTIONAL TESTS ##############
        cl = client_nsx.Client()
        mp_service_status = cl.get(path="/api/v1/node/services/migration-coordinator/status").json()
        if (mp_service_status.get("monitor_runtime_state") == "running") and (mp_service_status.get("runtime_state") == "running"):
            LOG.info("Migration coordinator is UP and RUNNING.")
        else:
            LOG.info("Migration coordinator is NOT running. Enabling ...")
            cl.post(path="/api/v1/node/services/migration-coordinator?action=start", data={})
            eventlet.sleep(120)

        yield 12

        cfg.CONF.set_override("force_mp_to_policy", True, "AGENT")
        cfg.CONF.set_override("migration_tag_count_trigger", 2, "AGENT")
        cfg.CONF.set_override("migration_tag_count_max", 5, "AGENT")
        cfg.CONF.set_override("max_sg_tags_per_segment_port", 2, "AGENT")

        migration_inventory = copy.deepcopy(coverage.OPENSTACK_INVENTORY_MIGRATION)
        env = Environment(inventory=migration_inventory)

        with env:
            i = env.openstack_inventory
            i.port_bind(c.PORT_FOR_MIGRATION_1["name"], "1000")
            i.port_bind(c.PORT_FOR_MIGRATION_2["name"], "1000")
            i.port_bind(c.PORT_FOR_NOT_MIGRATION_1["name"], "1000")
            i.port_bind(c.PORT_FOR_NOT_MIGRATION_2["name"], "1000")

            eventlet.sleep(60)
            # Test split point
            yield 13

        LOG.info("Checking \"_assert_migrate\"")
        TestAgentRealizer._assert_migrate(c, env)

        LOG.info("End of end to end tests.")
        TestAgentRealizer.cleanup_on_teardown = True
        eventlet.sleep(10)
        yield 14

    @staticmethod
    def _assert_create(os_inventory, environment):
        c = os_inventory
        mgmt_meta, plcy_meta = environment.dump_provider_inventory(printable=False)
        m = {**mgmt_meta, **plcy_meta}
        p = environment.manager.realizer.mngr_provider

        # Validate network creation
        TestAgentRealizer.instance.assertEquals("1000" in m[p.NETWORK]["meta"], True)
        TestAgentRealizer.instance.assertEquals("3200" in m[p.NETWORK]["meta"], True)

        # Validate QoS State
        TestAgentRealizer.instance.assertEquals(c.QOS_INTERNAL["id"] in m[p.QOS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.QOS_EXTERNAL["id"] in m[p.QOS]["meta"], True)
        TestAgentRealizer.instance.assertEquals(c.QOS_NOT_REFERENCED["id"] in m[p.QOS]["meta"], False)

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
    def _assert_update(os_inventory, environment):
        c = os_inventory
        mgmt_meta, plcy_meta = environment.dump_provider_inventory(printable=False)
        m = {**mgmt_meta, **plcy_meta}
        p = environment.manager.realizer.mngr_provider

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
        services = p.client.get_all(path=provider_nsx_policy.API.SERVICES, params=params)
        services = [s for s in services if not s.get("is_default")]
        TestAgentRealizer.instance.assertEquals(len(services), 0)

    @staticmethod
    def _assert_migrate(os_inventory, environment):
        # TODO: do test comparisons
        pass

    @staticmethod
    def _pollute(env, index):
        p = env.manager.realizer.mngr_provider
        id = "00000000-0000-0000-0000-00000000000{}".format(index)

        ipv4 = "192.168.0.0/{}".format(index)
        ipv6 = "::ffff/{}".format(index)

        ipv4_id = re.sub(r"\.|:|\/", "-", ipv4)
        ipv6_id = re.sub(r"\.|:|\/", "-", ipv6)

        pp = provider_nsx_policy.Payload()
        api = provider_nsx_policy.API

        p.client.put(path=api.GROUP.format(ipv4_id), data=pp.sg_rule_remote(ipv4))
        p.client.put(path=api.GROUP.format(ipv6_id), data=pp.sg_rule_remote(ipv6))

        p.client.put(path=api.GROUP.format(id), data=pp.sg_members_container({"id": id}, dict()))
        data = pp.sg_rules_container({"id": id}, {"rules": [], "scope": id})
        p.client.put(path=api.POLICY.format(id), data=data)


# Initialize end to end tests generator
TestAgentRealizer.tests_generator = TestAgentRealizer.functional_test_generator()
