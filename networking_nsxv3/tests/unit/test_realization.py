import sys

import mock
import responses
import testtools
from mock import patch
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.realization import \
    AgentRealizer
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging


from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import agent
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import realization

from networking_nsxv3.tests.unit import provider
from networking_nsxv3.tests.unit import openstack

import re
import json
import eventlet
import requests


LOG = logging.getLogger(__name__)


NSX_URL="https://nsxm-l-01a.corp.local:443"


def nova_port_creation(os_port_id):
    requests.post("{}/api/v1/logical-ports".format(NSX_URL), data=json.dumps({
        "logical_switch_id": "419e0f47-7ff5-40c8-8256-0bd9173a4e1f",
        "attachment": {
            "attachment_type": "VIF",
            "id": "machine@{}".format(os_port_id)
        },
        "admin_state": "UP",
        "address_bindings": [],
        "switching_profile_ids": [
            {
                "key": "SwitchSecuritySwitchingProfile",
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888"
            },
            {
                "key": "SpoofGuardSwitchingProfile",
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1"
            },
            {
                "key": "IpDiscoverySwitchingProfile",
                "value": "0c403bc9-7773-4680-a5cc-847ed0f9f52e"
            },
            {
                "key": "MacManagementSwitchingProfile",
                "value": "1e7101c8-cfef-415a-9c8c-ce3d8dd078fb"
            },
            {
                "key": "PortMirroringSwitchingProfile",
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09"
            },
            {
                "key": "QosSwitchingProfile",
                "value": "f313290b-eba8-4262-bd93-fab5026e9495"
            }
        ],
        "ignore_address_bindings": [],
        "resource_type": "LogicalPort",
        "display_name": os_port_id,
        "description": "",
        "tags": []
    }))


class TestAgentRealizer(base.BaseTestCase):
    
    def setUp(self):
        super(TestAgentRealizer, self).setUp()

        # How To Overwrite cfg
        # cfg.CONF.set_override("nsxv3_login_user", "admin", "NSXV3")

        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])
        cfg.CONF.set_override("nsxv3_cache_refresh_window", 0, "NSXV3")

        self.provider_inventory = provider.Inventory("https://nsxm-l-01a.corp.local:443")
        self.openstack_inventory = openstack.Inventory()

        r = responses
        for m in [r.GET, r.POST, r.PUT, r.DELETE]:
            r.add_callback(m, re.compile(r".*"), callback=self.provider_inventory.api)

    def setUpResponsesActivated(self):
        self.rpc = openstack.TestNSXv3ServerRpcApi(self.openstack_inventory)
        self.manager = agent.NSXv3Manager(rpc=self.rpc, monitoring=False)
        rpc = self.manager.get_rpc_callbacks(None, None, None)
        notifier = openstack.TestNSXv3AgentManagerRpcCallBackBase(rpc)
        self.openstack_inventory.register(notifier)


    @responses.activate
    def test_child_port_update(self):
        self.setUpResponsesActivated()

        # Simulate Port Binding
        port = self.openstack_inventory.port_create("p1", "3200")
        nova_port_creation(port.get("id"))
        
        port = self.openstack_inventory.port_update("p1", security_group_names=[])
        child_port = self.openstack_inventory.port_create("p1-1", "3201", parent_name="p1")
        child_port = self.openstack_inventory.port_update("p1-1", security_group_names=[])

        eventlet.sleep(5.0)

        p_inv = self.provider_inventory
        LOG.info(json.dumps(p_inv.inventory, indent=4))
        LOG.info(json.dumps(p_inv.inventory, indent=4))



        provider_ports = [o.get("display_name") for _,o in p_inv.inventory.get(p_inv.PORTS).items()]
        self.assertEqual(set(provider_ports), set([port.get("id"), child_port.get("id")]))

        self.manager.shutdown()

    @responses.activate
    def test_ports_add_remove_end_to_end(self):
        self.setUpResponsesActivated()

        qos_01 = self.openstack_inventory.qos_create("qos-01")
        sg_01 = self.openstack_inventory.security_group_create("sg-01", tags=["capability_tcp_strict"])
        sg_02 = self.openstack_inventory.security_group_create("sg-02", tags=["capability_tcp_strict"])
        self.openstack_inventory.security_group_rule_add(
            sg_02.get("name"), "1", 
            protocol="tcp", ethertype="IPv4", direction="ingress", 
            remote_ip_prefix="192.168.0.0/16", port_range_min=443)
        self.openstack_inventory.security_group_rule_add(
            sg_02.get("name"), "2", 
            protocol="tcp", ethertype="IPv4", direction="ingress",
            remote_group_id=sg_01.get("id"), port_range_min=443)
        sg_02_rule = self.openstack_inventory.security_group_rule_add(
            sg_02.get("name"), "3", 
            protocol="tcp", ethertype="IPv4", direction="ingress", 
            remote_ip_prefix="0.0.0.0/16", port_range_min=443)

        # Simulate Port Binding
        port = self.openstack_inventory.port_create("p1", "3200")
        nova_port_creation(port.get("id"))
        
        self.openstack_inventory.port_update("p1", qos_name=qos_01.get("name"), security_group_names=[sg_02.get("name")])

        # Wait for async jobs to apply the desired state
        eventlet.sleep(10)

        p_inv = self.provider_inventory
        # o_inv = self.openstack_inventory.inventory
        # c_inv = self.manager.realizer.provider._cache

        LOG.info(json.dumps(self.provider_inventory.inventory, indent=4))
        LOG.info(json.dumps(self.openstack_inventory.inventory, indent=4))
        LOG.info(json.dumps(self.manager.realizer.provider._cache, indent=4))

        self.assertNotEqual(p_inv.lookup(p_inv.NSGROUPS, sg_02.get("id")), None)
        self.assertNotEqual(p_inv.lookup(p_inv.SECTIONS, sg_02.get("id")), None)
        self.assertNotEqual(p_inv.lookup(p_inv.IPSETS, sg_01.get("id")), None)
        self.assertNotEqual(p_inv.lookup(p_inv.IPSETS, sg_02_rule.get("id")), None)
        self.assertEqual(len(p_inv.lookup(p_inv.SECTIONS, sg_02.get("id")).get("_").get("rules").keys()), 3)
        self.assertEqual(len(p_inv.inventory.get(p_inv.IPSETS).keys()), 3)
        self.assertNotEqual(p_inv.lookup(p_inv.PROFILES, qos_01.get("id")), None)

        sgs = []
        for i in range(1,3):
            name = "sg-{}".format(i)
            sgs.append(self.openstack_inventory.security_group_create(name, tags=[]).get("name"))
            self.openstack_inventory.security_group_rule_add(
                name, str(i), 
                protocol="tcp", ethertype="IPv4", direction="ingress", 
                remote_ip_prefix="192.168.{}.0/24".format(i), port_range_min=1000+i)
        

        self.openstack_inventory.port_update("p1", qos_name=qos_01.get("name"), security_group_names=sgs)

        eventlet.sleep(10)

        self.openstack_inventory.port_delete("p1")
        
        eventlet.sleep(10)

        LOG.info(json.dumps(self.provider_inventory.inventory, indent=4))
        LOG.info(json.dumps(self.openstack_inventory.inventory, indent=4))
        LOG.info(json.dumps(self.manager.realizer.provider._cache, indent=4))        
        
        self.assertEqual(p_inv.inventory.get(p_inv.NSGROUPS).keys(), [])
        self.assertEqual(p_inv.inventory.get(p_inv.SECTIONS).keys(), [])
        self.assertEqual(p_inv.inventory.get(p_inv.IPSETS).keys(), [])
        self.assertEqual(p_inv.inventory.get(p_inv.PORTS).keys(), [])
        # Default IP-Discovery and Spoofguard
        self.assertEqual(len(p_inv.inventory.get(p_inv.PROFILES).keys()), 2)

        self.manager.shutdown()

