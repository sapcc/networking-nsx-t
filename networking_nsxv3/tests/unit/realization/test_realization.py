import copy
import os
import re

import eventlet
import responses
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.environment import Environment
from networking_nsxv3.tests.unit import provider
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


# TODO - replace static wait/sleep with active polling
# TODO - split into more granual functional tests

def set_logging_levels():
    cfg.CONF.set_override("default_log_levels", [
        # Test Provider
        'networking_nsxv3.tests.unit.provider=WARNING',

        # Agent
        'networking_nsxv3.common.synchronization=WARNING',
        'networking_nsxv3.common.synchronization=WARNING',
        'networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.realization=WARNING',
        'networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy=WARNING',
        'networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_mgmt=WARNING',

        # Other packages
        'sqlalchemy=WARNING',
        'oslo.messaging=WARNING',
        'oslo_messaging=WARNING',
        'requests.packages.urllib3.connectionpool=WARNING',
        'urllib3.connectionpool=WARNING',
        'requests.packages.urllib3.util.retry=WARNING',
        'urllib3.util.retry=WARNING',
        'oslo.cache=WARNING',
        'oslo_policy=WARNING',
    ])


class TestAgentRealizer(base.BaseTestCase):
    def setUp(self):
        super(TestAgentRealizer, self).setUp()

        hostname = "nsxm-l-01a.corp.local"
        port = "443"

        o = cfg.CONF.set_override
        g = os.environ.get

        # o('debug', True)
        set_logging_levels()
        logging.setup(cfg.CONF, "demo")

        o("nsxv3_login_hostname", hostname, "NSXV3")
        o("nsxv3_login_port", port, "NSXV3")
        o("nsxv3_remove_orphan_ports_after", 0, "NSXV3")

        self.url = "https://{}:{}".format(hostname, port)

    def _mock(self, r):
        self.inventory = provider.Inventory(base_url=self.url, version="3.0.0")
        for m in [r.GET, r.POST, r.PUT, r.DELETE, r.PATCH]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    def test_creation(self):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as resp:
            self._mock(resp)
            c = coverage

            env = Environment(inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY))
            with env:
                # LOG.info("Begin - OpenStack Inventory: %s", env.dump_openstack_inventory())
                # LOG.info("Begin - NSX-T Inventory: %s", env.dump_provider_inventory())

                i = env.openstack_inventory
                i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
                i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
                i.port_bind(c.PORT_BACKEND["name"], "3200")
                i.port_bind(c.PORT_DB["name"], "3200")

                eventlet.sleep(10)

                # LOG.info("End - OpenStack Inventory: %s", env.dump_openstack_inventory())
                # LOG.info("End - NSX-T Inventory: %s", env.dump_provider_inventory())

        plcy = env.manager.realizer.plcy_provider
        mngr = env.manager.realizer.mngr_provider

        mngr_meta, plcy_meta = env.dump_provider_inventory(printable=False)

        # Validate network creation
        self.assertEquals("1000" in mngr_meta[mngr.NETWORK]["meta"], True)
        self.assertEquals("3200" in mngr_meta[mngr.NETWORK]["meta"], True)
        self.assertEquals(plcy_meta[plcy.SEGMENT]["meta"], {})
        self.assertEquals(plcy_meta[plcy.SEGM_PORT]["meta"], {})

        # Validate QoS State
        self.assertEquals(c.QOS_INTERNAL["id"] in mngr_meta[mngr.QOS]["meta"], True)
        self.assertEquals(c.QOS_EXTERNAL["id"] in mngr_meta[mngr.QOS]["meta"], True)
        self.assertEquals(c.QOS_NOT_REFERENCED["id"] in mngr_meta[mngr.QOS]["meta"], False)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(
            c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], False)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[plcy.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[plcy.SG_RULES]["meta"], False)

        # Validate Security Group Remote Prefix IPSets
        for id in plcy_meta[plcy.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)

    def test_synchronous_creation(self):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as resp:
            self._mock(resp)
            c = coverage

            env = Environment(inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY))
            with env:
                i = env.openstack_inventory
                i.test_synchronous_port_create(c.PORT_FRONTEND_EXTERNAL["name"], "1001")
                eventlet.sleep(10)

        pp = env.manager.realizer.plcy_provider
        mp = env.manager.realizer.mngr_provider
        mngr_meta, plcy_meta = env.dump_provider_inventory(printable=False)

        # Validate network creation
        self.assertEquals("1001" in mngr_meta[mp.NETWORK]["meta"], True)

        # Validate QoS State
        self.assertEquals(c.QOS_EXTERNAL["id"] in mngr_meta[mp.QOS]["meta"], True)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[pp.SG_RULES]["meta"], True)

        # Validate Security Group Remote Prefix IPSets
        for id in plcy_meta[pp.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)

    def test_cleanup(self):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as resp:
            self._mock(resp)

            c = coverage

            env = Environment(inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY))
            with env:
                i = env.openstack_inventory

                i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
                i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
                i.port_bind(c.PORT_BACKEND["name"], "3200")
                i.port_bind(c.PORT_DB["name"], "3200")

                eventlet.sleep(10)

                # LOG.info("Begin - OpenStack Inventory: %s", env.dump_openstack_inventory())
                # LOG.info("Begin - NSX-T Inventory: %s", env.dump_provider_inventory())

                # Add orphan IPSets
                # pp.client.post(path="/api/v1/ip-sets", data=pp.payload.sg_rule_remote("192.168.0.0/12"))
                # pp.client.post(path="/api/v1/ip-sets", data=pp.payload.sg_rule_remote("::ffff/64"))

                i.port_delete(c.PORT_FRONTEND_INTERNAL["name"])
                eventlet.sleep(1)
                i.port_delete(c.PORT_FRONTEND_EXTERNAL["name"])
                eventlet.sleep(10)

                # LOG.info("End - OpenStack Inventory: %s", env.dump_openstack_inventory())
                # LOG.info("End - NSX-T Inventory: %s", env.dump_provider_inventory())

        pp = env.manager.realizer.plcy_provider
        mp = env.manager.realizer.mngr_provider
        mngr_meta, plcy_meta = env.dump_provider_inventory(printable=False)

        # Validate network creation
        self.assertEquals("1000" in mngr_meta[mp.NETWORK]["meta"], True)
        self.assertEquals("3200" in mngr_meta[mp.NETWORK]["meta"], True)

        # Validate Ports
        self.assertEquals(c.PORT_FRONTEND_EXTERNAL["id"] in mngr_meta[mp.PORT]["meta"], False)
        self.assertEquals(c.PORT_FRONTEND_INTERNAL["id"] in mngr_meta[mp.PORT]["meta"], False)
        self.assertEquals(c.PORT_BACKEND["id"] in mngr_meta[mp.PORT]["meta"], True)
        self.assertEquals(c.PORT_DB["id"] in mngr_meta[mp.PORT]["meta"], True)

        # Validate QoS State
        self.assertEquals(c.QOS_INTERNAL["id"] in mngr_meta[mp.QOS]["meta"], False)
        self.assertEquals(c.QOS_EXTERNAL["id"] in mngr_meta[mp.QOS]["meta"], False)
        self.assertEquals(c.QOS_NOT_REFERENCED["id"] in mngr_meta[mp.QOS]["meta"], False)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], False)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[pp.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[pp.SG_RULES]["meta"], False)

        # Validate Security Group Rules NSGroups
        # self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[mp.SG_RULES_EXT]["meta"], False)
        # self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[mp.SG_RULES_EXT]["meta"], True)
        # self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[mp.SG_RULES_EXT]["meta"], True)
        # self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[mp.SG_RULES_EXT]["meta"], True)
        # self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[mp.SG_RULES_EXT]["meta"], False)
        # self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[mp.SG_RULES_EXT]["meta"], False)

        # Validate Security Group Remote Prefix IPSets
        for id in plcy_meta[pp.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)


class TestMigrationRealization(base.BaseTestCase):
    def setUp(self):
        super(TestMigrationRealization, self).setUp()

        hostname = "nsxm-l-01a.corp.local"
        port = "443"

        o = cfg.CONF.set_override
        g = os.environ.get

        # o('debug', True)
        set_logging_levels()
        logging.setup(cfg.CONF, "demo")

        o("nsxv3_login_hostname", hostname, "NSXV3")
        o("nsxv3_login_port", port, "NSXV3")
        o("nsxv3_remove_orphan_ports_after", 0, "NSXV3")
        o("nsxv3_remove_orphan_ports_after", 0, "NSXV3")

        o("force_mp_to_policy", True, "AGENT")
        o("migration_tag_count_trigger", 4, "AGENT")
        o("migration_tag_count_max", 6, "AGENT")
        o("max_sg_tags_per_segment_port", 5, "AGENT")

        self.url = "https://{}:{}".format(hostname, port)

    def _mock(self, r):
        self.inventory = provider.Inventory(base_url=self.url, version="3.1.3")
        for m in [r.GET, r.POST, r.PUT, r.DELETE, r.PATCH]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    def test_migration(self):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as resp:
            self._mock(resp)
            c = coverage

            env = Environment(inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY))
            with env:
                i = env.openstack_inventory
                i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
                i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
                i.port_bind(c.PORT_BACKEND["name"], "3200")
                i.port_bind(c.PORT_DB["name"], "3200")
                eventlet.sleep(10)

                # LOG.info("End - NSX-T Inventory: %s", env.dump_provider_inventory())

        plcy = env.manager.realizer.plcy_provider
        mngr = env.manager.realizer.mngr_provider

        mngr_meta, plcy_meta = env.dump_provider_inventory(printable=False)

        # Validate Networks
        self.assertEquals("1000" in mngr_meta[mngr.NETWORK]["meta"], True)
        self.assertEquals("3200" in mngr_meta[mngr.NETWORK]["meta"], True)
        self.assertEquals("1000" in plcy_meta[plcy.SEGMENT]["meta"], True)
        self.assertEquals("3200" in plcy_meta[plcy.SEGMENT]["meta"], True)

        # Validate Ports
        self.assertEquals(c.PORT_FRONTEND_EXTERNAL["id"] in mngr_meta[mngr.PORT]["meta"], True)
        self.assertEquals(c.PORT_FRONTEND_INTERNAL["id"] in mngr_meta[mngr.PORT]["meta"], True)
        self.assertEquals(c.PORT_BACKEND["id"] in mngr_meta[mngr.PORT]["meta"], True)
        self.assertEquals(c.PORT_DB["id"] in mngr_meta[mngr.PORT]["meta"], True)
        self.assertEquals(c.PORT_FRONTEND_EXTERNAL["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], False)
        self.assertEquals(c.PORT_FRONTEND_INTERNAL["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], True)
        self.assertEquals(c.PORT_BACKEND["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], True)
        self.assertEquals(c.PORT_DB["id"] in plcy_meta[plcy.SEGM_PORT]["meta"], True)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], True)
        self.assertEquals(
            c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[plcy.SG_MEMBERS]["meta"], False)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[plcy.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[plcy.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[plcy.SG_RULES]["meta"], False)

        # Validate Security Group Remote Prefix IPSets
        for id in plcy_meta[plcy.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)

    def test_cleanup(self):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as resp:
            self._mock(resp)

            c = coverage

            env = Environment(inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY))
            with env:
                i = env.openstack_inventory
                i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
                i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
                i.port_bind(c.PORT_BACKEND["name"], "3200")
                i.port_bind(c.PORT_DB["name"], "3200")
                eventlet.sleep(10)

                i.port_delete(c.PORT_FRONTEND_INTERNAL["name"])
                eventlet.sleep(1)
                i.port_delete(c.PORT_FRONTEND_EXTERNAL["name"])
                eventlet.sleep(10)

        pp = env.manager.realizer.plcy_provider
        mp = env.manager.realizer.mngr_provider
        mngr_meta, plcy_meta = env.dump_provider_inventory(printable=False)

        # Validate network creation
        self.assertEquals("1000" in mngr_meta[mp.NETWORK]["meta"], True)
        self.assertEquals("3200" in mngr_meta[mp.NETWORK]["meta"], True)
        self.assertEquals("1000" in plcy_meta[pp.SEGMENT]["meta"], True)
        self.assertEquals("3200" in plcy_meta[pp.SEGMENT]["meta"], True)

        # Validate Ports
        self.assertEquals(c.PORT_FRONTEND_EXTERNAL["id"] in mngr_meta[mp.PORT]["meta"], False)
        self.assertEquals(c.PORT_FRONTEND_INTERNAL["id"] in mngr_meta[mp.PORT]["meta"], False)
        self.assertEquals(c.PORT_BACKEND["id"] in mngr_meta[mp.PORT]["meta"], True)
        self.assertEquals(c.PORT_DB["id"] in mngr_meta[mp.PORT]["meta"], True)
        self.assertEquals(c.PORT_FRONTEND_EXTERNAL["id"] in plcy_meta[pp.SEGM_PORT]["meta"], False)
        self.assertEquals(c.PORT_FRONTEND_INTERNAL["id"] in plcy_meta[pp.SEGM_PORT]["meta"], False)
        self.assertEquals(c.PORT_BACKEND["id"] in plcy_meta[pp.SEGM_PORT]["meta"], True)
        self.assertEquals(c.PORT_DB["id"] in plcy_meta[pp.SEGM_PORT]["meta"], True)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[pp.SG_MEMBERS]["meta"], False)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in plcy_meta[pp.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in plcy_meta[pp.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in plcy_meta[pp.SG_RULES]["meta"], False)

        # Validate Security Group Remote Prefix IPSets
        for id in plcy_meta[pp.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)
