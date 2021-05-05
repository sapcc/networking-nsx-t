import requests
import responses
import re
import json
import hashlib
import copy
from urlparse import urlparse, parse_qs
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt
from oslo_config import cfg
from neutron.tests import base
from networking_nsxv3.tests.unit.provider import Inventory

from oslo_log import log as logging
LOG = logging.getLogger(__name__)


# TODO - introduce responses.add_passthru(re.compile('https://percy.io/\\w+'))

def get_url(path):
    return "https://nsxm-l-01a.corp.local:443{}".format(path)



class TestProvider(base.BaseTestCase):

    def get_result_by_name(self, payload, display_name):
        r = [o for o in payload.get("results", []) if o.get("display_name") == display_name]
        if len(r) > 1:
            raise Exception("Ambiguous {}".format(display_name))
        return r.pop(0) if len(r) == 1 else None

    def get_by_name(self, container, name):
        result = [obj for id,obj in container.items() if obj.get("display_name") == name]
        return result.pop(0) if result else None

    def get_tag(self, resource, scope):
        for item in resource.get("tags", {}):
            if item.get("scope") == scope:
                return item.get("tag")

    def setUp(self):
        super(TestProvider, self).setUp()

        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])
        cfg.CONF.set_override("nsxv3_cache_refresh_window", 0, "NSXV3")

        self.inventory = Inventory("https://nsxm-l-01a.corp.local:443")
        r = responses

        for m in [r.GET, r.POST, r.PUT, r.DELETE]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    @responses.activate
    def test_provider_initialization(self):
        provider_nsx_mgmt.Provider()

        profiles = self.inventory.inventory.get(Inventory.PROFILES)

        sgp = "{}-{}".format(cfg.CONF.AGENT.agent_id, "SpoofGuard")
        ipp = "{}-{}".format(cfg.CONF.AGENT.agent_id, "IpDiscovery")

        self.assertEquals(len(profiles), 2)

        keys = profiles.keys()

        self.assertEquals(profiles.get(keys[0]).get("display_name"), sgp)
        self.assertEquals(profiles.get(keys[1]).get("display_name"), ipp)


    @responses.activate
    def test_security_group_members_creation_diverse_cidrs(self):
        sg = ({
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.5.0/24"],
            "revision_number": 0
        },{
            "resource_type": "IPSet",
            "ip_addresses": ["172.16.1.1", "172.16.1.2", "172.16.2.0/24", "172.16.5.0/24"]
        })

        provider_nsx_mgmt.Provider().sg_members_realize(sg[0])
        
        inv = self.inventory.inventory
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg[0]["id"])
        for k,v in sg[1].items():
            self.assertEquals(sg_ipset.get(k), sg[1].get(k))


    @responses.activate
    def test_security_group_members_creation_compact_cidrs(self):
        sg = ({
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.0.0/16"],
            "revision_number": 2
        },{
            "resource_type": "IPSet",
            "ip_addresses": ["172.16.0.0/16"]
        })

        provider_nsx_mgmt.Provider().sg_members_realize(sg[0])
        inv = self.inventory.inventory
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg[0]["id"])
        for k,v in sg[1].items():
            self.assertEquals(sg_ipset.get(k), sg[1].get(k))
    
    @responses.activate
    def test_security_group_members_update(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32"],
            "revision_number": 2
        }

        sgu = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.2/16"],
            "revision_number": 3
        }
        
        provider = provider_nsx_mgmt.Provider()
        provider.sg_members_realize(sg)
        provider.sg_members_realize(sgu)

        inv = self.inventory.inventory
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg["id"])
        self.assertEquals(sg_ipset.get("ip_addresses"), ["172.16.1.2/16"])


    @responses.activate
    def test_security_group_members_delete(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32"],
            "revision_number": 2
        }
        
        inv = self.inventory.inventory

        provider = provider_nsx_mgmt.Provider()

        provider.sg_members_realize(sg)
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg["id"])
        self.assertNotEqual(sg_ipset, None)

        provider.sg_members_realize(sg, delete=True)
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg["id"])
        self.assertEquals(sg_ipset, None)


    @responses.activate
    def test_security_group_rules_create(self):

        sg = ({
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        },{
            "resource_type": "FirewallSection",
            "display_name": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "tags": [
                {
                    "scope": "agent_id", 
                    "tag": "nsxm-l-01a.corp.local"
                }, 
                {
                    "scope": "revision_number", 
                    "tag": 2
                }
            ],
            "tcp_strict": True
        },
        {
            "resource_type": "NSGroup",
            "display_name": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "membership_criteria": [
                {
                    "target_type": "LogicalPort", 
                    "tag_op": "EQUALS", 
                    "scope_op": "EQUALS", 
                    "tag": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19", 
                    "scope": "security_group", 
                    "resource_type": "NSGroupTagExpression"
                }
            ],
            "tags": [
                {
                    "scope": "agent_id", 
                    "tag": "nsxm-l-01a.corp.local"
                }, 
                {
                    "scope": "revision_number", 
                    "tag": 2
                }
            ]
        })

        provider_nsx_mgmt.Provider().sg_rules_realize(sg[0], dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg[0]["id"])
        for k,v in sg[1].items():
            if k == "tags":
                tags = set([(t["scope"],t["tag"]) for t in sg_section.get(k)])
                tags_exp = set([(t["scope"],t["tag"]) for t in sg[1].get(k)])
                self.assertEquals(tags_exp.intersection(tags), tags_exp)
            else:
                self.assertEquals(sg_section.get(k), sg[1].get(k))

        sg_nsgroup = self.get_by_name(inv[Inventory.NSGROUPS], sg[0]["id"])
        for k,v in sg[2].items():
            if k == "tags":
                tags = set([(t["scope"],t["tag"]) for t in sg_nsgroup.get(k)])
                tags_exp = set([(t["scope"],t["tag"]) for t in sg[2].get(k)])
                self.assertEquals(tags_exp.intersection(tags), tags_exp)
            else:
                self.assertEquals(sg_nsgroup.get(k), sg[2].get(k))


    @responses.activate
    def test_security_group_rules_update(self):

        sg = {
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule1 = {
            "id": "1",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "5",
            "port_range_max": "1",
            "protocol": "icmp",
        }

        rule2 = {
            "id": "2",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "",
            "port_range_max": "",
            "protocol": "hopopt",
        }

        rule1_u = {
            "id": "1",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "5",
            "port_range_max": "2",
            "protocol": "icmp",
        }

        rule3 = {
            "id": "3",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "",
            "port_range_max": "",
            "protocol": "1",
        }

        # Add two new rules
        sg1 = copy.deepcopy(sg)
        sg1["id"] = "1"
        sg1["rules"].append(copy.deepcopy(rule1))
        sg1["rules"].append(copy.deepcopy(rule2))
    

        # Add new, update existing, delete existing
        sg2 = copy.deepcopy(sg)
        sg2["id"] = "2"
        sg2["rules"].append(copy.deepcopy(rule1_u))
        sg2["rules"].append(copy.deepcopy(rule3))

        sg3 = copy.deepcopy(sg)
        sg3["id"] = "3"

        inv = self.inventory.inventory
        provider = provider_nsx_mgmt.Provider()
        
        provider.sg_rules_realize(sg1, dict())
        provider.sg_rules_realize(sg2, dict())
        provider.sg_rules_realize(sg3, dict())

        LOG.info(json.dumps(inv, indent=4))

        sg_meta_rules = provider.metadata(provider.SG_RULE, sg1.get("id"))
        self.assertEquals(len(sg_meta_rules.keys()), 2)

        provider.sg_rules_realize(sg2, provider_rules_meta=sg_meta_rules)
        sg_meta_rules = provider.metadata(provider.SG_RULE, sg2.get("id"))
        LOG.info(json.dumps(sg_meta_rules, indent=4))
        self.assertEquals(len(sg_meta_rules.keys()), 2)

        rule1_u_expected = [
            {
                "service": {
                    "icmp_code": "2", 
                    "icmp_type": "5", 
                    "protocol": "ICMPv4", 
                    "resource_type": "ICMPTypeNSService"
                }
            }
        ]
        rule3_expected = [
            {
                "service": {
                    "protocol_number": 1, 
                    "resource_type": "IPProtocolNSService"
                }
            }
        ]
        self.assertEquals(sg_meta_rules.get(rule1_u.get("id")).get("services"), rule1_u_expected)
        self.assertEquals(sg_meta_rules.get(rule3.get("id")).get("services"), rule3_expected)
        
        provider.sg_rules_realize(sg3, provider_rules_meta=sg_meta_rules)
        sg_meta_rules = provider.metadata(provider.SG_RULE, sg3.get("id"))
        self.assertEquals(len(sg_meta_rules.keys()), 0)


    @responses.activate
    def test_security_group_rules_delete(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
        }

        provider = provider_nsx_mgmt.Provider()
        
        provider.sg_rules_realize(sg, dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg.get("id"))

        self.assertEquals(sg_section.get("display_name"), sg.get("id"))

        provider.sg_rules_realize(sg, dict(), delete=True)

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg.get("id"))

        self.assertEquals(sg_section, None)


    @responses.activate
    def test_security_group_rules_remote_ip_prefix_ipset(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule = {
            "id": "1",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "0.0.0.0/16",
            "security_group_id": sg.get("id"),
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp",
        }

        sg["rules"].append(rule)

        p = provider_nsx_mgmt.Provider()
        p.sg_rules_realize(sg, dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule["id"])
        sg_rule_ipset = self.get_by_name(inv[Inventory.IPSETS], sg_rule.get("sources")[0].get("target_display_name"))

        self.assertEquals(self.get_tag(sg_rule_ipset, "security_group_remote_id"), sg.get("id"))
        self.assertEquals(self.get_tag(sg_rule_ipset, "agent_id"), "nsxm-l-01a.corp.local")
        self.assertEquals(self.get_tag(sg_rule_ipset, "revision_number"), None)
        self.assertEquals(sg_rule_ipset.get("ip_addresses"), [rule.get("remote_ip_prefix")])

    @responses.activate
    def test_security_group_rules_remote_ip_prefix_ip(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule = {
            "id": "1",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp",
        }

        sg["rules"].append(rule)

        p = provider_nsx_mgmt.Provider()
        p.sg_rules_realize(sg, dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule["id"])
        sg_rule_source = sg_rule.get("sources")[0]

        self.assertEquals(sg_rule_source.get("target_display_name"), rule.get("remote_ip_prefix"))
        self.assertEquals(sg_rule_source.get("target_id"), rule.get("remote_ip_prefix"))
        self.assertEquals(sg_rule_source.get("target_type"), "IPv4Address")
        
        
    @responses.activate
    def test_security_group_rules_remote_group(self):

        sg_remote = ({
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": [],
            "revision_number": 0
        })

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule = {
            "id": "1",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": sg_remote.get("id"),
            "remote_ip_prefix": "",
            "security_group_id": sg.get("id"),
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp",
        }

        sg["rules"].append(rule)

        provider = provider_nsx_mgmt.Provider()
        provider.sg_members_realize(sg_remote)
        provider.sg_rules_realize(sg, dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule["id"])
        sg_rule_ipset = self.get_by_name(inv[Inventory.IPSETS], sg_rule.get("sources")[0].get("target_display_name"))

        self.assertEquals(sg_rule_ipset.get("display_name"), sg_remote.get("id"))


    @responses.activate
    def test_security_group_rules_service_l4(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule = {
            "id": "1",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp",
        }

        sg["rules"].append(rule)

        provider_nsx_mgmt.Provider().sg_rules_realize(sg, dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule["id"])
        sg_rule_service = sg_rule.get("services")[0].get("service")

        self.assertEquals(sg_rule.get("action"), "ALLOW")
        self.assertEquals(sg_rule.get("ip_protocol"), "IPV4")
        self.assertEquals(sg_rule.get("direction"), "IN")
        self.assertEquals(sg_rule.get("destinations"), [])
        self.assertEquals(sg_rule.get("disabled"), False)
        self.assertEquals(sg_rule_service, {
            "resource_type": "L4PortSetNSService", 
            "l4_protocol": "TCP", 
            "source_ports": [
                "1-65535"
            ],
            "destination_ports": [
                "443"
            ] 
        })

    @responses.activate
    def test_security_group_rules_service_ip_protocol(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule_hopopt = {
            "id": "1",
            "ethertype": "",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "",
            "port_range_max": "",
            "protocol": "hopopt",
        }

        rule_0 = {
            "id": "2",
            "ethertype": "",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "",
            "port_range_max": "",
            "protocol": "0",
        }

        sg["rules"].append(rule_hopopt)
        sg["rules"].append(rule_0)

        provider_nsx_mgmt.Provider().sg_rules_realize(sg, dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule_hopopt = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule_hopopt["id"])
        sg_rule_hopopt_service = sg_rule_hopopt.get("services")[0].get("service")

        self.assertEquals(sg_rule_hopopt_service, {
            "resource_type": "IPProtocolNSService", 
            "protocol_number": 0
        })

        sg_rule_0 = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule_0["id"])
        sg_rule_0_service = sg_rule_0.get("services")[0].get("service")

        self.assertEquals(sg_rule_0_service, {
            "resource_type": "IPProtocolNSService", 
            "protocol_number": 0
        })

    @responses.activate
    def test_security_group_rules_service_icmp(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule_valid = {
            "id": "1",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "5",
            "port_range_max": "1",
            "protocol": "icmp",
        }

        rule_invalid = {
            "id": "2",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "5",
            "port_range_max": "",
            "protocol": "icmp",
        }

        sg["rules"].append(rule_valid)
        sg["rules"].append(rule_invalid)

        provider_nsx_mgmt.Provider().sg_rules_realize(sg, dict())

        inv = self.inventory.inventory

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule_valid = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule_valid["id"])
        sg_rule_valid_service = sg_rule_valid.get("services")[0].get("service")

        self.assertEquals(sg_rule_valid_service, {
            "resource_type": "ICMPTypeNSService",
            "protocol": "ICMPv4",
            "icmp_code": "1", 
            "icmp_type": "5"
        })

        sg_rule_invalid = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule_invalid["id"])

        self.assertEquals(sg_rule_invalid, None)


    def port_fixture(self):
        provider_port = {
            "logical_switch_id": "419e0f47-7ff5-40c8-8256-0bd9173a4e1f",
            "attachment": {
                "attachment_type": "VIF",
                "id": "something@80372EA3-5F58-4B06-8456-3067D60B3023"
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
            "display_name": "someid",
            "description": "",
            "tags": []
        }

        os_sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [{
                "id": "1",
                "ethertype": "IPv4",
                "direction": "ingress",
                "remote_group_id": "",
                "remote_ip_prefix": "192.168.10.0/24",
                "security_group_id": "",
                "port_range_min": "5",
                "port_range_max": "1",
                "protocol": "icmp"
            }]
        }

        os_qos = {
            "id": "628722EC-B0AA-4AF8-8045-3071BEE00EB2",
            "revision_number": "3",
            "name": "test",
            "rules": [{"dscp_mark": "5"}]
        }

        os_port_parent = {
            "id": "80372EA3-5F58-4B06-8456-3067D60B3023",
            "revision_number": "2",
            "parent_id": "",
            "mac_address": "fa:16:3e:e4:11:f1",
            "admin_state_up": "UP",
            "qos_policy_id": os_qos.get("id"),
            "security_groups": [os_sg.get("id")],
            "address_bindings": ["172.24.4.3", "172.24.4.4"],
            "vif_details": {
                "nsx-logical-switch-id": "712CAD71-B3F5-4AA0-8C3F-8D453DCBF2F2",
                "segmentation_id": "3200"
            }
        }

        os_port_child = {
            "id": "CAB0602E-6E2D-4483-A7A8-E0FCDBF5E49D",
            "revision_number": "4",
            "parent_id": os_port_parent.get("id"),
            "mac_address": "fa:16:3e:e4:11:f1",
            "admin_state_up": "UP",
            "qos_policy_id": os_qos.get("id"),
            "security_groups": [os_sg.get("id")],
            "address_bindings": ["172.24.4.3", "172.24.4.4"],
            "vif_details": {
                "nsx-logical-switch-id": "712CAD71-B3F5-4AA0-8C3F-8D453DCBF2F2",
                "segmentation_id": "3400"
            }
        }

        return (provider_port, os_sg, os_qos, os_port_parent, os_port_child)
    
    @responses.activate
    def test_port_parent_create(self):
        provider_port, os_sg, os_qos, os_port_parent, _ = self.port_fixture()
        provider_port_attachment = provider_port.get("attachment")

        # Port crated via Nova machine provisioning
        provider_port = requests.post(get_url("/api/v1/logical-ports"), data=json.dumps(provider_port)).json()

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(os_sg, dict())
        provider.qos_realize(os_qos, dict())
        provider.port_realize(os_port_parent, dict())

        meta_port = provider.metadata(provider.PORT, os_port_parent.get("id")).get(os_port_parent.get("id"))

        self.assertEquals(meta_port.get("rev"), os_port_parent.get("revision_number"))

        provider_port = requests.get(get_url("/api/v1/logical-ports/{}".format(provider_port.get("id")))).json()
        
        self.assertEquals(provider_port.get("attachment"), provider_port_attachment)
        self.assertEquals(provider_port.get("address_bindings"), os_port_parent.get("address_bindings"))

        self.assertEquals(self.get_tag(provider_port, "security_group"), os_port_parent.get("security_groups")[0])
        self.assertEquals(self.get_tag(provider_port, "agent_id"), "nsxm-l-01a.corp.local")
        self.assertEquals(self.get_tag(provider_port, "revision_number"), os_port_parent.get("revision_number"))

    @responses.activate
    def test_port_child_create(self):
        provider_port, os_sg, os_qos, os_port_parent, os_port_child = self.port_fixture()
        provider_port_attachment = provider_port.get("attachment")

        # Port crated via Nova machine provisioning
        provider_port = requests.post(get_url("/api/v1/logical-ports"), data=json.dumps(provider_port)).json()

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(os_sg, dict())
        provider.qos_realize(os_qos, dict())
        provider.port_realize(os_port_parent, dict())
        provider.port_realize(os_port_child, dict())

        meta_port = provider.metadata(provider.PORT, os_port_child.get("id")).get(os_port_child.get("id"))

        self.assertEquals(meta_port.get("rev"), os_port_child.get("revision_number"))
        provider_port = requests.get(get_url("/api/v1/logical-ports/{}".format(meta_port.get("id")))).json()
        
        self.assertEquals(provider_port.get("attachment").get("id"), os_port_child.get("id"))
        self.assertEquals(provider_port.get("address_bindings"), os_port_child.get("address_bindings"))

        self.assertEquals(self.get_tag(provider_port, "security_group"), os_port_child.get("security_groups")[0])
        self.assertEquals(self.get_tag(provider_port, "agent_id"), "nsxm-l-01a.corp.local")
        self.assertEquals(self.get_tag(provider_port, "revision_number"), os_port_child.get("revision_number"))
    
    @responses.activate
    def test_port_delete(self):
        provider_port, os_sg, os_qos, os_port_parent, os_port_child = self.port_fixture()
        provider_port_attachment = provider_port.get("attachment")

        # Port crated via Nova machine provisioning
        provider_port = requests.post(get_url("/api/v1/logical-ports"), data=json.dumps(provider_port)).json()

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(os_sg, dict())
        provider.qos_realize(os_qos, dict())
        provider.port_realize(os_port_parent, dict())
        provider.port_realize(os_port_child, dict())

        meta_parent_port = provider.metadata(provider.PORT, os_port_parent.get("id")).get(os_port_parent.get("id"))
        meta_child_port = provider.metadata(provider.PORT, os_port_child.get("id")).get(os_port_child.get("id"))

        self.assertEquals(len(self.inventory.inventory[Inventory.PORTS].keys()), 2)
        self.assertNotEqual(meta_parent_port, None)
        self.assertNotEqual(meta_child_port, None)

        provider.port_realize(os_port_parent, dict(), delete=True)
        provider.port_realize(os_port_child, dict(), delete=True)

        self.assertEquals(self.inventory.inventory[Inventory.PORTS].keys(), [])


    @responses.activate
    def test_qos_create(self):
        os_qos = {
            "id": "628722EC-B0AA-4AF8-8045-3071BEE00EB2",
            "revision_number": "3",
            "name": "test",
            "rules": [
                {
                    "dscp_mark": "5"
                },
                {
                    "direction": "ingress", 
                    "max_kbps": "6400", 
                    "max_burst_kbps": "128000"
                },
                {
                    "direction": "egress", 
                    "max_kbps": "7200", 
                    "max_burst_kbps": "256000"
                },
            ]
        }
        provider = provider_nsx_mgmt.Provider()
        provider.qos_realize(os_qos, dict())

        result = requests.get(get_url("/{}".format(Inventory.PROFILES))).json()

        qos = self.get_result_by_name(result, os_qos.get("id"))

        self.assertEquals(qos.get("dscp"), {
            "priority": 5, 
            "mode": "UNTRUSTED"
        })

        self.assertEquals(qos.get("shaper_configuration"), [
            {
                "average_bandwidth_mbps": 6, 
                "peak_bandwidth_mbps": 12, 
                "enabled": True, 
                "burst_size_bytes": 16384000, 
                "resource_type": "IngressRateShaper"
            }, 
            {
                "average_bandwidth_mbps": 7, 
                "peak_bandwidth_mbps": 14, 
                "enabled": True, 
                "burst_size_bytes": 32768000, 
                "resource_type": "EgressRateShaper"
            }
        ])


    @responses.activate
    def test_qos_update(self):
        os_qos = {
            "id": "628722EC-B0AA-4AF8-8045-3071BEE00EB2",
            "revision_number": "3",
            "name": "test",
            "rules": [
                {
                    "dscp_mark": "5"
                }
            ]
        }

        rule = {
            "direction": "ingress", 
            "max_kbps": "6400", 
            "max_burst_kbps": "128000"
        }

        provider = provider_nsx_mgmt.Provider()
        provider.qos_realize(os_qos, dict())
        
        os_qos.get("rules").append(rule)
        provider.qos_realize(os_qos, dict())

        result = requests.get(get_url("/{}".format(Inventory.PROFILES))).json()

        qos = self.get_result_by_name(result, os_qos.get("id"))

        self.assertEquals(qos.get("dscp"), {
            "priority": 5, 
            "mode": "UNTRUSTED"
        })

        self.assertEquals(qos.get("shaper_configuration"), [
            {
                "average_bandwidth_mbps": 6, 
                "peak_bandwidth_mbps": 12, 
                "enabled": True, 
                "burst_size_bytes": 16384000, 
                "resource_type": "IngressRateShaper"
            }
        ])

    @responses.activate
    def test_qos_delete(self):
        os_qos = {
            "id": "628722EC-B0AA-4AF8-8045-3071BEE00EB2",
            "revision_number": "3",
            "name": "test",
            "rules": [
                {
                    "dscp_mark": "5"
                }
            ]
        }

        provider = provider_nsx_mgmt.Provider()

        provider.qos_realize(os_qos, dict())
        result = requests.get(get_url("/{}".format(Inventory.PROFILES))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))
        self.assertNotEqual(qos, None)

        provider.qos_realize(os_qos, dict(), delete=True)
        result = requests.get(get_url("/{}".format(Inventory.PROFILES))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))
        self.assertEquals(qos, None)

    @responses.activate
    def test_outdated(self):
        sg = [
            {"id": "1", "revision_number": 1, "tags": [], "rules": []},
            {"id": "2", "revision_number": 2, "tags": [], "rules": []},
            {"id": "3", "revision_number": 3, "tags": [], "rules": []},
            {"id": "4", "revision_number": 4, "tags": [], "rules": []}
        ]

        meta = {
            "1": "1", # same
            "2": "3", # updated
            "3": "8" # updated
            # 4 was removed => orphaned
        }

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(sg[0], dict())
        provider.sg_rules_realize(sg[1], dict())
        provider.sg_rules_realize(sg[2], dict())
        provider.sg_rules_realize(sg[3], dict())

        outdated,current = provider.outdated(provider.SG_RULES, meta)

        self.assertEquals(outdated, set(["2","3","4"]))
        self.assertEquals(current, set(["1"]))
