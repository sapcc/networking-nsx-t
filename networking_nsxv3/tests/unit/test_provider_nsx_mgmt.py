import copy
import hashlib
import json
import re
import time
import uuid

import requests
import responses
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt
from networking_nsxv3.tests.unit.provider import Inventory
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


# INFO - Can introduce responses to directly run the tests against live NSX-T
# responses.add_passthru(re.compile('https://nsxm-l-01a.corp.local/\\w+'))

def get_url(path):
    return "https://nsxm-l-01a.corp.local:443{}".format(path)


class TestProviderMgmt(base.BaseTestCase):

    def get_result_by_name(self, payload, display_name):
        r = [o for o in payload.get("results", []) if o.get("display_name") == display_name]
        if len(r) > 1:
            raise Exception("Ambiguous {}".format(display_name))
        return r.pop(0) if len(r) == 1 else None

    def get_by_name(self, container, name):
        result = [obj for id, obj in container.items() if obj.get("display_name") == name]
        return result.pop(0) if result else None

    def get_tag(self, resource, scope):
        return provider_nsx_mgmt.Resource(resource).tags.get(scope)

    def setUp(self):
        super(TestProviderMgmt, self).setUp()

        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])

        self.inventory = Inventory("https://nsxm-l-01a.corp.local:443", version="3.2.2")
        r = responses

        for m in [r.GET, r.POST, r.PUT, r.DELETE]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    @responses.activate
    def test_provider_initialization(self):
        provider_nsx_mgmt.Provider()

        profiles = self.inventory.inv.get(Inventory.PROFILES)

        sgp = cfg.CONF.NSXV3.nsxv3_spoof_guard_switching_profile
        ipp = cfg.CONF.NSXV3.nsxv3_ip_discovery_switching_profile

        self.assertEquals(len(profiles), 2)
        realized_profiles = [profiles.get(key).get("display_name") for key in profiles.keys()]
        self.assertIn(sgp, realized_profiles)
        self.assertIn(ipp, realized_profiles)

    @responses.activate
    def test_security_group_members_creation_diverse_cidrs(self):
        sg = ({
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.5.0/24"],
            "revision_number": 0
        }, {
            "resource_type": "IPSet",
            "ip_addresses": ["172.16.1.1", "172.16.1.2", "172.16.2.0/24", "172.16.5.0/24"]
        })

        provider_nsx_mgmt.Provider().sg_members_realize(sg[0])

        inv = self.inventory.inv
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg[0]["id"])
        for k, v in sg[1].items():
            self.assertEquals(sg_ipset.get(k), sg[1].get(k))

    @responses.activate
    def test_security_group_members_creation_compact_ipv4_cidrs(self):
        sg = ({
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.0.0/16"],
            "revision_number": 2
        }, {
            "resource_type": "IPSet",
            "ip_addresses": ["172.16.0.0/16"]
        })

        provider_nsx_mgmt.Provider().sg_members_realize(sg[0])
        inv = self.inventory.inv
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg[0]["id"])
        for k, v in sg[1].items():
            self.assertEquals(sg_ipset.get(k), sg[1].get(k))

    @responses.activate
    def test_security_group_members_creation_compact_ipv6_cidrs(self):
        sg = ({
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["fd2e:faa4:fe14:e370:fd2e:faa4:fe14:e370/128"],
            "revision_number": 2
        }, {
            "resource_type": "IPSet",
            "ip_addresses": ["fd2e:faa4:fe14:e370:fd2e:faa4:fe14:e370"]
        })

        provider_nsx_mgmt.Provider().sg_members_realize(sg[0])
        inv = self.inventory.inv
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg[0]["id"])
        for k, v in sg[1].items():
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

        inv = self.inventory.inv
        sg_ipset = self.get_by_name(inv[Inventory.IPSETS], sg["id"])
        self.assertEquals(sg_ipset.get("ip_addresses"), ["172.16.1.2/16"])

    @responses.activate
    def test_security_group_members_delete(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32"],
            "revision_number": 2
        }

        inv = self.inventory.inv

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
        }, {
            "resource_type": "FirewallSection",
            "display_name": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "tags": [
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
                    "scope": "revision_number",
                    "tag": 2
                }
            ]
        })

        provider_nsx_mgmt.Provider().sg_rules_realize(sg[0])

        inv = self.inventory.inv

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg[0]["id"])
        for k, v in sg[1].items():
            if k == "tags":
                tags = set([(t["scope"], t["tag"]) for t in sg_section.get(k, dict())])
                tags_exp = set([(t["scope"], t["tag"]) for t in sg[1].get(k)])
                self.assertEquals(tags_exp.intersection(tags), tags_exp)
            else:
                self.assertEquals(sg_section.get(k), sg[1].get(k))

        sg_nsgroup = self.get_by_name(inv[Inventory.NSGROUPS], sg[0]["id"])
        for k, v in sg[2].items():
            if k == "tags":
                tags = set([(t["scope"], t["tag"]) for t in sg_nsgroup.get(k)])
                # NS Group should not have revision tag
                tags_exp = set([(t["scope"], t["tag"]) for t in sg[2].get(k) if t["scope"] != "revision_number"])
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
            "id": str(uuid.uuid4()),
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
            "id": str(uuid.uuid4()),
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
            "id": str(uuid.uuid4()),
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
            "id": str(uuid.uuid4()),
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
        sg1["id"] = str(uuid.uuid4())
        sg1["rules"].append(copy.deepcopy(rule1))
        sg1["rules"].append(copy.deepcopy(rule2))

        # Add new, update existing, delete existing
        sg2 = copy.deepcopy(sg)
        sg2["id"] = str(uuid.uuid4())
        sg2["rules"].append(copy.deepcopy(rule1_u))
        sg2["rules"].append(copy.deepcopy(rule3))

        sg3 = copy.deepcopy(sg)
        sg3["id"] = str(uuid.uuid4())

        inv = self.inventory.inv
        provider = provider_nsx_mgmt.Provider()

        provider.sg_rules_realize(sg1)
        provider.sg_rules_realize(sg2)
        provider.sg_rules_realize(sg3)

        LOG.info(json.dumps(inv, indent=4))

        sg_meta_rules = provider.metadata(provider.SG_RULE, sg1.get("id"))
        self.assertEquals(len(sg_meta_rules.keys()), 2)

        provider.sg_rules_realize(sg2)
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

        provider.sg_rules_realize(sg3)
        sg_meta_rules = provider.metadata(provider.SG_RULE, sg3.get("id"))
        self.assertEquals(len(sg_meta_rules.keys()), 0)

    @responses.activate
    def test_security_group_icmp_generic_rules(self):

        sg = {
            "id": str(uuid.uuid4()),
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule1 = {
            "id": str(uuid.uuid4()),
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": None,
            "port_range_max": None,
            "protocol": "icmp",
        }

        rule2 = {
            "id": str(uuid.uuid4()),
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "5",
            "port_range_max": None,
            "protocol": "icmp",
        }

        rule3 = {
            "id": str(uuid.uuid4()),
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "192.168.10.0/24",
            "security_group_id": "",
            "port_range_min": "3",
            "port_range_max": "1",
            "protocol": "icmp",
        }

        # Add rules
        sg["rules"].append(copy.deepcopy(rule1))
        sg["rules"].append(copy.deepcopy(rule2))
        sg["rules"].append(copy.deepcopy(rule3))

        inv = self.inventory.inv
        provider = provider_nsx_mgmt.Provider()

        provider.sg_rules_realize(sg)

        LOG.info(json.dumps(inv, indent=4))

        sg_meta_rules = provider.metadata(provider.SG_RULE, sg.get("id"))
        self.assertEquals(len(sg_meta_rules.keys()), 3)

        generic_icmp_expected = [
            {
                "service": {
                    "icmp_code": "",
                    "icmp_type": "",
                    "protocol": "ICMPv4",
                    "resource_type": "ICMPTypeNSService"
                }
            },
            {
                "service": {
                    "icmp_code": "",
                    "icmp_type": "5",
                    "protocol": "ICMPv4",
                    "resource_type": "ICMPTypeNSService"
                }
            },
            {
                "service": {
                    "icmp_code": "1",
                    "icmp_type": "3",
                    "protocol": "ICMPv4",
                    "resource_type": "ICMPTypeNSService"
                }
            },
        ]

        self.assertDictContainsSubset(sg_meta_rules.get(rule1.get("id")).get("services")[0], generic_icmp_expected[0])
        self.assertDictContainsSubset(sg_meta_rules.get(rule2.get("id")).get("services")[0], generic_icmp_expected[1])
        self.assertDictContainsSubset(sg_meta_rules.get(rule3.get("id")).get("services")[0], generic_icmp_expected[2])

    @responses.activate
    def test_security_group_rules_delete(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
        }

        provider = provider_nsx_mgmt.Provider()

        provider.sg_rules_realize(sg)

        inv = self.inventory.inv

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg.get("id"))

        self.assertEquals(sg_section.get("display_name"), sg.get("id"))

        provider.sg_rules_realize(sg, delete=True)

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg.get("id"))

        self.assertEquals(sg_section, None)

    @responses.activate
    def test_security_group_rules_remote_ip_prefix_constant_ipset(self):

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
        p.sg_rules_realize(sg)

        inv = self.inventory.inv

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule["id"])
        sg_rule_ipset = self.get_by_name(inv[Inventory.IPSETS], sg_rule.get("sources")[0].get("target_display_name"))

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
        p.sg_rules_realize(sg)

        inv = self.inventory.inv

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
        provider.sg_rules_realize(sg)

        inv = self.inventory.inv

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

        provider_nsx_mgmt.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

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

        provider_nsx_mgmt.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

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
            "port_range_max": "5",
            "protocol": "icmp",
        }

        sg["rules"].append(rule_valid)
        sg["rules"].append(rule_invalid)

        provider_nsx_mgmt.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

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

    @responses.activate
    def test_security_group_rules_service_udp_any_port(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": []
        }

        rule = {
            "id": "9961B0AE-53EC-4E54-95B6-2F440D243F7B",
            "ethertype": "IPv6",
            "direction": "egress",
            "remote_ip_prefix": "",
            "remote_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "protocol": "udp"
        }

        sg["rules"].append(rule)

        provider_nsx_mgmt.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

        sg_section = self.get_by_name(inv[Inventory.SECTIONS], sg["id"])
        sg_rule = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule["id"])

        self.assertEquals(sg_rule["services"][0]["service"]["destination_ports"], ["1-65535"])

    def port_fixture(self):
        provider_port = {
            "logical_switch_id": "419e0f47-7ff5-40c8-8256-0bd9173a4e1f",
            "attachment": {
                "attachment_type": "VIF",
                "id": "80372EA3-5F58-4B06-8456-3067D60B3023"
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

        os_sg_second = {
            "id": "FB8B899A-2DAF-4DFA-9E6A-D2869C16BCD0",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [{
                "id": "1",
                "ethertype": "IPv4",
                "direction": "ingress",
                "remote_group_id": "",
                "remote_ip_prefix": "192.168.11.0/24",
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
            "security_groups": [os_sg.get("id"), os_sg_second.get("id")],
            "address_bindings": ["172.24.4.3", "172.24.4.4"],
            "vif_details": {
                "nsx-logical-switch-id": "712CAD71-B3F5-4AA0-8C3F-8D453DCBF2F2",
                "segmentation_id": "3200"
            },
            "_last_modified_time": time.time()
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

        return (provider_port, os_sg, os_sg_second, os_qos, os_port_parent, os_port_child)

    @responses.activate
    def test_port_parent_create(self):
        provider_port, os_sg, os_sg_second, os_qos, os_port_parent, _ = self.port_fixture()
        provider_port_attachment = provider_port.get("attachment")

        # Port created via Nova machine provisioning
        provider_port = requests.post(get_url("/api/v1/logical-ports"), data=json.dumps(provider_port)).json()

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(os_sg)
        provider.qos_realize(os_qos)
        provider.port_realize(os_port_parent)

        meta_port = provider.metadata(provider.PORT, os_port_parent.get("id"))

        self.assertEquals(meta_port.rev, os_port_parent.get("revision_number"))

        provider_port = requests.get(get_url("/api/v1/logical-ports/{}".format(provider_port.get("id")))).json()

        provider_port_attachment.update({
            "context": {
                "resource_type": "VifAttachmentContext",
                "traffic_tag": "3200",
                "vif_type": "PARENT"
            }
        })

        self.assertEquals(provider_port_attachment, provider_port.get("attachment"))
        self.assertEquals(provider_port.get("address_bindings"), os_port_parent.get("address_bindings"))

        self.assertEquals(self.get_tag(provider_port, "security_group"), os_port_parent.get("security_groups"))
        self.assertEquals(self.get_tag(provider_port, "revision_number"), os_port_parent.get("revision_number"))

    @responses.activate
    def test_port_child_create(self):
        provider_port, os_sg, _, os_qos, os_port_parent, os_port_child = self.port_fixture()

        # Port crated via Nova machine provisioning
        provider_port = requests.post(get_url("/api/v1/logical-ports"), data=json.dumps(provider_port)).json()

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(os_sg)
        provider.qos_realize(os_qos)
        provider.port_realize(os_port_parent)
        provider.port_realize(os_port_child)

        meta_port = provider.metadata(provider.PORT, os_port_child.get("id"))

        self.assertEquals(meta_port.rev, os_port_child.get("revision_number"))
        provider_port = requests.get(get_url("/api/v1/logical-ports/{}".format(meta_port.id))).json()

        self.assertEquals(provider_port.get("attachment").get("id"), os_port_child.get("id"))
        self.assertEquals(provider_port.get("address_bindings"), os_port_child.get("address_bindings"))

        self.assertEquals([self.get_tag(provider_port, "security_group")], os_port_child.get("security_groups"))
        self.assertEquals(self.get_tag(provider_port, "revision_number"), os_port_child.get("revision_number"))

    @responses.activate
    def test_port_bound_multiple_security_groups(self):
        provider_port, _, _, _, os_port_parent, _ = self.port_fixture()

        # Port created via Nova machine provisioning
        provider_port = requests.post(get_url("/api/v1/logical-ports"), data=json.dumps(provider_port)).json()

        provider = provider_nsx_mgmt.Provider()
        provider.port_realize(os_port_parent)

        provider_port = requests.get(get_url("/api/v1/logical-ports/{}".format(provider_port.get("id")))).json()
        self.assertEquals(self.get_tag(provider_port, "security_group"), os_port_parent.get("security_groups"))
        self.assertEquals(len(self.get_tag(provider_port, "security_group")), 2)

    @responses.activate
    def test_port_delete(self):
        provider_port, os_sg, _, os_qos, os_port_parent, os_port_child = self.port_fixture()

        # Port crated via Nova machine provisioning
        provider_port = requests.post(get_url("/api/v1/logical-ports"), data=json.dumps(provider_port)).json()

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(os_sg)
        provider.qos_realize(os_qos)
        provider.port_realize(os_port_parent)
        provider.port_realize(os_port_child)

        meta_parent_port = provider.metadata(provider.PORT, os_port_parent.get("id")).id
        meta_child_port = provider.metadata(provider.PORT, os_port_child.get("id")).id

        self.assertEquals(len(self.inventory.inv[Inventory.PORTS].keys()), 2)
        self.assertNotEqual(meta_parent_port, None)
        self.assertNotEqual(meta_child_port, None)

        provider.port_realize(os_port_child, delete=True)
        provider.port_realize(os_port_parent, delete=True)

        self.assertEquals(list(self.inventory.inv[Inventory.PORTS].keys()), [meta_parent_port])

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
        provider.qos_realize(os_qos)

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
        provider.qos_realize(os_qos)

        os_qos.get("rules").append(rule)
        provider.qos_realize(os_qos)

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

        provider.qos_realize(os_qos)
        result = requests.get(get_url("/{}".format(Inventory.PROFILES))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))
        self.assertNotEqual(qos, None)

        provider.qos_realize(os_qos, delete=True)
        result = requests.get(get_url("/{}".format(Inventory.PROFILES))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))
        self.assertEquals(qos, None)

    @responses.activate
    def test_create_network(self):
        segmentation_id = "3200"
        provider = provider_nsx_mgmt.Provider()
        meta = provider.network_realize(segmentation_id)

        inv = self.inventory.inv
        net = inv[Inventory.SWITCHES].get(meta.id)
        self.assertEquals(net.get("vlan"), segmentation_id)
        self.assertEquals(net.get("transport_zone_id"), provider.zone_id)
        self.assertEquals(net.get("display_name"), "{}-{}".format(provider.zone_name, segmentation_id))

    @responses.activate
    def test_reuse_network(self):
        segmentation_id = "3200"
        segmentation_id2 = "3201"
        provider = provider_nsx_mgmt.Provider()

        inv = self.inventory.inv

        meta = provider.network_realize(segmentation_id)
        self.assertEquals(len(inv[Inventory.SWITCHES]), 1)

        meta1 = provider.network_realize(segmentation_id)
        self.assertEquals(len(inv[Inventory.SWITCHES]), 1)

        self.assertEquals(meta.id, meta1.id)

        meta = provider.network_realize(segmentation_id2)
        self.assertEquals(len(inv[Inventory.SWITCHES]), 2)

    @responses.activate
    def test_outdated(self):
        sg = [
            {"id": str(uuid.uuid4()), "revision_number": 1, "tags": [], "rules": []},
            {"id": str(uuid.uuid4()), "revision_number": 2, "tags": [], "rules": []},
            {"id": str(uuid.uuid4()), "revision_number": 3, "tags": [], "rules": []},
            {"id": str(uuid.uuid4()), "revision_number": 4, "tags": [], "rules": []}
        ]

        meta = {
            sg[0]['id']: "1",  # same
            sg[1]['id']: "3",  # updated
            sg[2]['id']: "8"  # updated
            # 4th was removed => orphaned
        }

        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(sg[0])
        provider.sg_rules_realize(sg[1])
        provider.sg_rules_realize(sg[2])
        provider.sg_rules_realize(sg[3])

        outdated, current = provider.outdated(provider.SG_RULES, meta)

        LOG.info(json.dumps(self.inventory.inv, indent=4))

        self.assertItemsEqual(outdated, [sg[1]['id'], sg[2]['id'], sg[3]['id']])
        self.assertItemsEqual(current, [sg[0]['id']])

    @responses.activate
    def test_remote_prefix_orphan_cleanup(self):
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
        inv = self.inventory.inv

        for i in range(1, 10):
            data = {
                "resource_type": "IPSet",
                "display_name": "0.0.0.0/{}".format(i),
                "ip_addresses": ["0.0.0.0/{}".format(i)]
            }
            p.client.post(path=provider_nsx_mgmt.API.IPSETS, data=data)

        self.assertEquals(len(inv[self.inventory.IPSETS]), 9)

        for i in range(1, 3):
            data = {
                "resource_type": "IPSet",
                "display_name": "192.168.0.{}".format(i),
                "ip_addresses": ["192.168.0/{}".format(i)]
            }
            p.client.post(path=provider_nsx_mgmt.API.IPSETS, data=data)

        self.assertEquals(len(inv[self.inventory.IPSETS]), 11)

        p.sg_rules_realize(sg)

        for id, cleanup in p.sanitize(100):
            cleanup(id)

        # /16 from the rule and /1-9
        self.assertEquals(len(inv[self.inventory.IPSETS]), 10)

        sg_section = self.get_by_name(inv[self.inventory.SECTIONS], sg["id"])
        sg_rule = self.get_by_name(sg_section.get("_", {}).get("rules", {}), rule["id"])
        sg_rule_ipset = self.get_by_name(inv[Inventory.IPSETS], sg_rule.get("sources")[0].get("target_display_name"))

        self.assertNotEqual(sg_rule_ipset, None)

    @responses.activate
    def test_security_group_stateful(self):
        sg1 = {"id": str(uuid.uuid4()), "revision_number": 2, "rules": []}
        sg2 = dict(sg1, **{'id': str(uuid.uuid4()), "stateful": False})
        provider = provider_nsx_mgmt.Provider()
        provider.sg_rules_realize(sg1)
        provider.sg_rules_realize(sg2)
        inv = self.inventory.inv
        self.assertTrue(self.get_by_name(inv[Inventory.SECTIONS], sg1["id"]).get("stateful"))
        self.assertFalse(self.get_by_name(inv[Inventory.SECTIONS], sg2["id"]).get("stateful"))

    @responses.activate
    def test_outdated_with_filtered_deletions(self):
        _, _, _, _, os_port_parent, _ = self.port_fixture()

        provider = provider_nsx_mgmt.Provider()
        meta = provider.network_realize(os_port_parent['vif_details']['segmentation_id'])
        os_port_parent['vif_details']['nsx-logical-switch-id'] = meta.id
        provider.port_realize(os_port_parent)

        meta_p = provider.meta_provider(provider.PORT)
        provider.port_realize(os_port_parent, delete=True)

        cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after = 1000
        outdated, _ = provider.outdated(provider.PORT, {os_port_parent['id']: os_port_parent['revision_number']})
        self.assertEquals(len(outdated), 0)

        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 0)

        cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after = 0
        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 1)

        provider.port_realize(os_port_parent, delete=True)
        self.assertEquals(len(meta_p.meta.keys()), 0)

    @responses.activate
    def test_priveleged_ports(self):
        cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after = 0
        _, _, _, _, os_port_parent, _ = self.port_fixture()

        provider = provider_nsx_mgmt.Provider()

        # Create non-agent managed port/switch
        meta = provider.network_realize('vmotion')
        os_port_parent['vif_details']['nsx-logical-switch-id'] = meta.id
        provider.port_realize(os_port_parent)

        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 0)

        # Create agent-managed port/switch
        meta = provider.network_realize('1234')
        os_port_parent['vif_details']['nsx-logical-switch-id'] = meta.id
        provider.port_realize(os_port_parent)

        # Assume to clean it up
        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 1)
