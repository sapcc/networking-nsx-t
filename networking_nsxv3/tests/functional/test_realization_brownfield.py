import copy
import os
import re

import eventlet
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import (
    agent, provider_nsx_mgmt, provider_nsx_policy)
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.environment import Environment
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


# TODO - replace static wait/sleep with active polling

class TestAgentRealizer(base.BaseTestCase):
    
    def setUp(self):
        super(TestAgentRealizer, self).setUp()

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
        

    def cleanup(self):
        env = Environment(name="Cleanup")
        with env:
            eventlet.sleep(30)
        
        provider = env.manager.realizer.provider
        for type,meta in env.dump_provider_inventory(printable=False).items():
            if type != provider.NETWORK and type != provider.SG_RULES_REMOTE_PREFIX:
                self.assertEquals(meta["meta"], dict())

    def tearDown(self):
        super(TestAgentRealizer, self).tearDown()
        self.cleanup() 
    

    def test_end_to_end(self):
        self.cleanup()
        c = coverage

        LOG.info("Create inventory with the legacy provider")
        inventory=copy.deepcopy(coverage.OPENSTACK_INVENTORY)
        env = Environment(name="Management API", inventory=inventory, force_api="Management")
        with env:
            i = env.openstack_inventory
            i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
            i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
            i.port_bind(c.PORT_BACKEND["name"], "3200")
            i.port_bind(c.PORT_DB["name"], "3200")

            eventlet.sleep(30)
        
        self._assert_create(c, env)

        LOG.info("Create inventory with the provider")

        env = Environment(inventory=inventory)
        with env:
            inventory = i = env.openstack_inventory
            provider = p = env.manager.realizer.provider

            eventlet.sleep(30)

            for index in range(1,10):
                self._pollute(env, index)            

            # Remove parent
            i.port_delete(c.PORT_FRONTEND_INTERNAL["name"])
            eventlet.sleep(10)
            # Remove child
            i.port_delete(c.PORT_FRONTEND_EXTERNAL["name"])
            eventlet.sleep(60)

        self._assert_update(c, env)

    
    def _assert_create(self, os_inventory, environment):
        c = os_inventory
        m = environment.dump_provider_inventory(printable=False)
        p = environment.manager.realizer.provider

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

        if environment.is_management_api_mode():
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
    
    def _assert_update(self, os_inventory, environment):
        c = os_inventory
        m = environment.dump_provider_inventory(printable=False)
        p = environment.manager.realizer.provider

        # Validate network creation
        self.assertEquals("1000" in m[p.NETWORK]["meta"], True)
        self.assertEquals("3200" in m[p.NETWORK]["meta"], True)

        # Validate QoS State
        self.assertEquals(c.QOS_INTERNAL["id"] in m[p.QOS]["meta"], False)
        self.assertEquals(c.QOS_EXTERNAL["id"] in m[p.QOS]["meta"], False)
        self.assertEquals(c.QOS_NOT_REFERENCED["id"] in m[p.QOS]["meta"], False)
        self.assertEquals(len(m[p.QOS]["meta"].keys()), 0)

        # Validate Security Groups Members
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_MEMBERS]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_MEMBERS]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_MEMBERS]["meta"], False)
        self.assertEquals(len(m[p.SG_MEMBERS]["meta"].keys()), 4)

        # Validate Security Group Rules Sections
        self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES]["meta"], True)
        self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES]["meta"], False)
        self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES]["meta"], False)
        self.assertEquals(len(m[p.SG_RULES]["meta"].keys()), 3)

        if environment.is_management_api_mode():
            # Validate Security Group Rules NSGroups
            self.assertEquals(c.SECURITY_GROUP_FRONTEND["id"] in m[p.SG_RULES_EXT]["meta"], False)
            self.assertEquals(c.SECURITY_GROUP_BACKEND["id"] in m[p.SG_RULES_EXT]["meta"], True)
            self.assertEquals(c.SECURITY_GROUP_DB["id"] in m[p.SG_RULES_EXT]["meta"], True)
            self.assertEquals(c.SECURITY_GROUP_OPERATIONS["id"] in m[p.SG_RULES_EXT]["meta"], True)
            self.assertEquals(c.SECURITY_GROUP_AUTH["id"] in m[p.SG_RULES_EXT]["meta"], False)
            self.assertEquals(c.SECURITY_GROUP_OPERATIONS_NOT_REFERENCED["id"] in m[p.SG_RULES_EXT]["meta"], False)
            self.assertEquals(len(m[p.SG_RULES_EXT]["meta"].keys()), 3)

        # Validate Security Group Remote Prefix IPSets
        for id in m[p.SG_RULES_REMOTE_PREFIX]["meta"].keys():
            self.assertEquals("0.0.0.0/" in id or "::/" in id, True)
        
        params = {"default_service": False} # User services only
        services = p.client.get_all(path=provider_nsx_policy.API.SERVICES, params=params)
        services = [s for s in services if not s.get("is_default")]
        self.assertEquals(len(services), 0)
        

    def _pollute(self, env, index):
        p = env.manager.realizer.provider
        id = "00000000-0000-0000-0000-00000000000{}".format(index)

        ipv4 = "192.168.0.0/{}".format(index)
        ipv6 = "::ffff/{}".format(index)

        ipv4_id = re.sub(r"\.|:|\/", "-", ipv4)
        ipv6_id = re.sub(r"\.|:|\/", "-", ipv6)

        mp = provider_nsx_mgmt.Payload()
        pp = provider_nsx_policy.Payload()
        api = provider_nsx_policy.API

        p.client.post(path=api.IPSETS, data=mp.sg_rule_remote(ipv4))
        p.client.post(path=api.IPSETS, data=mp.sg_rule_remote(ipv6))

        p.client.put(path=api.GROUP.format(ipv4_id), data=pp.sg_rule_remote(ipv4))
        p.client.put(path=api.GROUP.format(ipv6_id), data=pp.sg_rule_remote(ipv6))

        p.client.put(path=api.GROUP.format(id), data=pp.sg_members_container({"id": id}, dict()))
        data=pp.sg_rules_container({"id": id}, {"rules": [], "scope": id})
        if env.version < (3, 0):
            del data["scope"] # No scope property before 3.0
        p.client.put(path=api.POLICY.format(id), data=data)

        o = p.client.post(path=api.NSGROUPS, data=mp.sg_rules_ext_container({"id": id}, dict())).json()
        p.client.post(path=api.SECTIONS, data=mp.sg_rules_container({"id": id}, {"applied_tos": o.get("id")}))

        p.client.put(path=api.SERVICE.format(id), data={
            "service_entries": [
                {
                    "l4_protocol": "TCP",
                    "source_ports": [],
                    "destination_ports": ["1024"],
                    "resource_type": "L4PortSetServiceEntry",
                    "display_name": id
                }
            ],
            "resource_type": "Service",
            "display_name": id
        })
