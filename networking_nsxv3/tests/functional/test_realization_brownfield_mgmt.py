import json
import os

import eventlet
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import agent
from networking_nsxv3.tests.datasets import coverage
from networking_nsxv3.tests.unit import openstack, provider
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class Environment(object):

    def __init__(self, inventory=None):
        self.openstack_inventory = openstack.NeutronMock()
        if inventory:
            self.openstack_inventory.reload_inventory(inventory)

    def __enter__(self):
        self.rpc = openstack.TestNSXv3ServerRpcApi(self.openstack_inventory)
        self.manager = agent.NSXv3Manager(rpc=self.rpc, synchronization=True, monitoring=False)
        rpc = self.manager.get_rpc_callbacks(None, None, None)
        notifier = openstack.TestNSXv3AgentManagerRpcCallBackBase(rpc)
        self.openstack_inventory.register(notifier)
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.manager.shutdown()
    
    def dump_openstack_inventory(self, printable=True):
        o = self.openstack_inventory.inventory
        return json.dumps(o, indent=4) if printable else o

    def dump_provider_inventory(self, printable=True):
        def provider_dict(meta_provider):
            mt = meta_provider.meta.meta_transaction
            return {
                "endpoint": meta_provider.endpoint,
                "meta": meta_dict(meta_provider.meta.meta),
                "meta_transaction": meta_dict(mt) if mt else {}
            }
        def meta_dict(meta):
            return {
                k:{
                    "id": v.id, 
                    "rev": v.rev, 
                    "age": v.age, 
                    "_revision": v._revision
                } for k,v in meta.items()
            }

        metadata = self.manager.realizer.provider._metadata
        o = {r:provider_dict(m)  for r,m in metadata.items()}
        return json.dumps(o, indent=4) if printable else o

# TODO - replace static wait/sleep with active polling

class TestAgentRealizer(base.BaseTestCase):
    
    def setUp(self):
        super(TestAgentRealizer, self).setUp()

        logging.setup(cfg.CONF, "demo")
        
        o = cfg.CONF.set_override
        g = os.environ.get

        o("nsxv3_login_hostname", g("NSXV3_LOGIN_HOSTNAME"), "NSXV3")
        o("nsxv3_login_port", g("NSXV3_LOGIN_PORT"), "NSXV3")
        o("nsxv3_login_user", g("NSXV3_LOGIN_USER"), "NSXV3")
        o("nsxv3_login_password", g("NSXV3_LOGIN_PASSWORD"), "NSXV3")
        o("nsxv3_connection_retry_count", "3", "NSXV3")

        environment = Environment()
        with environment:
            eventlet.sleep(30)
        
        provider = environment.manager.realizer.provider
        for type,meta in util.metadata_serializer(provider._metadata).items():
            if type != provider.NETWORK and type != provider.SG_RULES_REMOTE_PREFIX:
                self.assertEquals(meta["meta"], dict())


    def test_creation(self):
        c = coverage

        environment = Environment(inventory=coverage.OPENSTACK_INVENTORY)
        with environment:
            LOG.info("Begin - OpenStack Inventory: %s", environment.dump_openstack_inventory())
            LOG.info("Begin - NSX-T Inventory: %s", environment.dump_provider_inventory())

            i = environment.openstack_inventory
            i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
            i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
            i.port_bind(c.PORT_BACKEND["name"], "3200")
            i.port_bind(c.PORT_DB["name"], "3200")

            eventlet.sleep(30)

            LOG.info("End - OpenStack Inventory: %s", environment.dump_openstack_inventory())
            LOG.info("End - NSX-T Inventory: %s", environment.dump_provider_inventory())

        
        provider = p = environment.manager.realizer.provider

        metadata = m = environment.dump_provider_inventory(printable=False)

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
        c = coverage

        environment = Environment(inventory=coverage.OPENSTACK_INVENTORY)
        with environment:
            inventory = i = environment.openstack_inventory
            provider = p = environment.manager.realizer.provider

            i.port_bind(c.PORT_FRONTEND_EXTERNAL["name"], "1000")
            i.port_bind(c.PORT_FRONTEND_INTERNAL["name"], "3200")
            i.port_bind(c.PORT_BACKEND["name"], "3200")
            i.port_bind(c.PORT_DB["name"], "3200")

            eventlet.sleep(30)

            LOG.info("Begin - OpenStack Inventory: %s", environment.dump_openstack_inventory())
            LOG.info("Begin - NSX-T Inventory: %s", environment.dump_provider_inventory())

            # Add orphan IPSets
            p.client.post(path="/api/v1/ip-sets",
                          data=p.payload.sg_rules_remote("192.168.0.0/12"))
            p.client.post(path="/api/v1/ip-sets",
                          data=p.payload.sg_rules_remote("::ffff/64"))

            i.port_delete(c.PORT_FRONTEND_INTERNAL["name"])
            eventlet.sleep(10)
            i.port_delete(c.PORT_FRONTEND_EXTERNAL["name"])
            eventlet.sleep(40)


        LOG.info("End - OpenStack Inventory: %s", environment.dump_openstack_inventory())
        LOG.info("End - NSX-T Inventory: %s", environment.dump_provider_inventory())        
        metadata = m = environment.dump_provider_inventory(printable=False)

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

