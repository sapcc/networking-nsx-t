import copy
import os
import re

import eventlet
import responses
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import agent
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.environment import Environment
from networking_nsxv3.tests.unit import provider
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


# TODO - replace static wait/sleep with active polling

class TestAgentRealizer(base.BaseTestCase):
    
    def setUp(self):
        super(TestAgentRealizer, self).setUp()

        hostname = "nsxm-l-01a.corp.local"
        port = "443"

        o = cfg.CONF.set_override
        g = os.environ.get

        o('debug', True)
        logging.setup(cfg.CONF, "demo")

        o("nsxv3_login_hostname", hostname, "NSXV3")
        o("nsxv3_login_port", port, "NSXV3")
        o("nsxv3_remove_orphan_ports_after", "0", "NSXV3")

        self.url = "https://{}:{}".format(hostname, port)


    def _mock(self, r):
        self.inventory = provider.Inventory(self.url)
        for m in [r.GET, r.POST, r.PUT, r.DELETE]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    
    def test_creation(self):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as resp:
            self._mock(resp)
            c = coverage

            env = Environment(inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY))
            with env:
                LOG.info("Begin - OpenStack Inventory: %s", env.dump_openstack_inventory())
                LOG.info("Begin - NSX-T Inventory: %s", env.dump_provider_inventory())

                i = env.openstack_inventory
                i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
                i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
                i.port_bind(c.PORT_BACKEND["name"], "3200")
                i.port_bind(c.PORT_DB["name"], "3200")

                eventlet.sleep(30)

                LOG.info("End - OpenStack Inventory: %s", env.dump_openstack_inventory())
                LOG.info("End - NSX-T Inventory: %s", env.dump_provider_inventory())

        provider = p = env.manager.realizer.provider

        metadata = m = env.dump_provider_inventory(printable=False)

        # Validate network creation
        self.assertEquals("1000" in m[p.NETWORK]["meta"], True)
        self.assertEquals("3200" in m[p.NETWORK]["meta"], True)

        # Validate QoS State
        self.assertEquals(c.QOS_INTERNAL["id"] in m[p.QOS]["meta"], True)
        self.assertEquals(c.QOS_EXTERNAL["id"] in m[p.QOS]["meta"], True)
        self.assertEquals(c.QOS_NOT_REFERENCED["id"] in m[p.QOS]["meta"], False)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_MEMBERS]["meta"], False)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES]["meta"], False)

        if env.is_management_api_mode():
            # Validate Security Group Rules NSGroups
            self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES_EXT]["meta"], True)
            self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES_EXT]["meta"], True)
            self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES_EXT]["meta"], True)
            self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES_EXT]["meta"], True)
            self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES_EXT]["meta"], False)
            self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES_EXT]["meta"], False)
        
        # Validate Security Group Remote Prefix IPSets
        for id in m[p.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)


    def test_cleanup(self):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as resp:
            self._mock(resp)

            c = coverage

            env = Environment(inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY))
            with env:
                inventory = i = env.openstack_inventory
                provider = p = env.manager.realizer.provider

                i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
                i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
                i.port_bind(c.PORT_BACKEND["name"], "3200")
                i.port_bind(c.PORT_DB["name"], "3200")

                eventlet.sleep(30)

                LOG.info("Begin - OpenStack Inventory: %s", env.dump_openstack_inventory())
                LOG.info("Begin - NSX-T Inventory: %s", env.dump_provider_inventory())

                # Add orphan IPSets
                p.client.post(path="/api/v1/ip-sets",
                            data=p.payload.sg_rule_remote("192.168.0.0/12"))
                p.client.post(path="/api/v1/ip-sets",
                            data=p.payload.sg_rule_remote("::ffff/64"))

                i.port_delete(c.PORT_FRONTEND_INTERNAL["name"])
                eventlet.sleep(10)
                i.port_delete(c.PORT_FRONTEND_EXTERNAL["name"])
                eventlet.sleep(40)

                LOG.info("End - OpenStack Inventory: %s", env.dump_openstack_inventory())
                LOG.info("End - NSX-T Inventory: %s", env.dump_provider_inventory())
    
        metadata = m = env.dump_provider_inventory(printable=False)

        # Validate network creation
        self.assertEquals("1000" in m[p.NETWORK]["meta"], True)
        self.assertEquals("3200" in m[p.NETWORK]["meta"], True)

        # Validate QoS State
        self.assertEquals(c.QOS_INTERNAL["id"] in m[p.QOS]["meta"], False)
        self.assertEquals(c.QOS_EXTERNAL["id"] in m[p.QOS]["meta"], False)
        self.assertEquals(c.QOS_NOT_REFERENCED["id"] in m[p.QOS]["meta"], False)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_MEMBERS]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_MEMBERS]["meta"], False)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES]["meta"], False)

        # Validate Security Group Rules NSGroups
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES_EXT]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES_EXT]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES_EXT]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES_EXT]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES_EXT]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES_EXT]["meta"], False)

        # Validate Security Group Remote Prefix IPSets
        for id in m[p.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)

