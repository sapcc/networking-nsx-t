import copy
import json
import re
import time
import uuid
import requests

import responses
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_policy
from networking_nsxv3.tests.unit.provider import Inventory
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


# INFO - Can introduce responses to directly run the tests against live NSX-T
# responses.add_passthru(re.compile('https://nsxm-l-01a.corp.local/\\w+'))


def get_url(path):
    return "https://nsxm-l-01a.corp.local:443{}".format(path)


class TestProviderPolicy(base.BaseTestCase):
    def get_result_by_name(self, payload, display_name):
        r = [o for o in payload.get("results", []) if o.get("display_name") == display_name]
        if len(r) > 1:
            raise Exception("Ambiguous {}".format(display_name))
        return r.pop(0) if len(r) == 1 else None

    def get_by_name(self, container, name):
        result = [obj for id, obj in container.items() if obj.get("display_name") == name]
        return result.pop(0) if result else None

    def get_tag(self, resource, scope):
        for item in resource.get("tags", {}):
            if item.get("scope") == scope:
                return item.get("tag")

    def get_all_tags_from_scope(self, resource, scope):
        l = []
        for item in resource.get("tags", {}):
            if item.get("scope") == scope:
                l.append(item.get("tag"))
        return l

    def setUp(self):
        super(TestProviderPolicy, self).setUp()

        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])

        self.inventory = Inventory("https://nsxm-l-01a.corp.local:443", version="3.2.2")
        r = responses

        for m in [r.GET, r.POST, r.PUT, r.DELETE, r.PATCH]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    def tearDown(self):
        super(TestProviderPolicy, self).tearDown()
        responses.reset()

    @responses.activate
    def test_provider_initialization(self):
        provider_nsx_policy.Provider()
        self.assertTrue(True, "Provider initialization successful")

    @responses.activate
    def test_security_group_members_creation_diverse_cidrs(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.5.0/24"],
            "revision_number": 0,
        }

        provider_nsx_policy.Provider().sg_members_realize(sg)

        inv = self.inventory.inv
        sg_group = self.get_by_name(inv[Inventory.GROUPS], sg["id"])

        ip_addresses = []
        for e in sg_group.get("expression"):
            if e.get("ip_addresses"):
                ip_addresses = e.get("ip_addresses")
                break
        self.assertEquals(ip_addresses, ["172.16.1.1", "172.16.1.2", "172.16.2.0/24", "172.16.5.0/24"])

    @responses.activate
    def test_security_group_members_creation_compact_ipv4_cidrs(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.0.0/16"],
            "revision_number": 0,
        }

        provider_nsx_policy.Provider().sg_members_realize(sg)

        inv = self.inventory.inv
        sg_group = self.get_by_name(inv[Inventory.GROUPS], sg["id"])

        ip_addresses = []
        for e in sg_group.get("expression"):
            if e.get("ip_addresses"):
                ip_addresses = e.get("ip_addresses")
                break
        self.assertEquals(ip_addresses, ["172.16.0.0/16"])

    @responses.activate
    def test_security_group_members_creation_compact_ipv6_cidrs(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["fd2e:faa4:fe14:e370:fd2e:faa4:fe14:e370/128"],
            "revision_number": 0,
        }

        provider_nsx_policy.Provider().sg_members_realize(sg)

        inv = self.inventory.inv
        sg_group = self.get_by_name(inv[Inventory.GROUPS], sg["id"])

        ip_addresses = []
        for e in sg_group.get("expression"):
            if e.get("ip_addresses"):
                ip_addresses = e.get("ip_addresses")
                break
        self.assertEquals(ip_addresses, ["fd2e:faa4:fe14:e370:fd2e:faa4:fe14:e370"])

    @responses.activate
    def test_security_group_members_update(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.0.0/16"],
            "revision_number": 0,
        }

        sgu = {"id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19", "cidrs": ["172.16.1.2/16"], "revision_number": 3}

        provider = provider_nsx_policy.Provider()

        provider.sg_members_realize(sg)
        provider.sg_members_realize(sgu)

        inv = self.inventory.inv
        sg_group = self.get_by_name(inv[Inventory.GROUPS], sg["id"])

        ip_addresses = []
        for e in sg_group.get("expression"):
            if e.get("ip_addresses"):
                ip_addresses = e.get("ip_addresses")
                break
        self.assertEquals(ip_addresses, ["172.16.1.2/16"])

    @responses.activate
    def test_security_group_members_delete(self):
        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "cidrs": ["172.16.1.1/32", "172.16.1.2", "172.16.2.0/24", "172.16.0.0/16"],
            "revision_number": 0,
        }

        inv = self.inventory.inv
        provider = provider_nsx_policy.Provider()

        provider.sg_members_realize(sg)
        sg_group = self.get_by_name(inv[Inventory.GROUPS], sg["id"])
        self.assertNotEqual(sg_group, None)

        provider.sg_members_realize(sg, delete=True)
        sg_group = self.get_by_name(inv[Inventory.GROUPS], sg["id"])
        self.assertEquals(sg_group, None)

    @responses.activate
    def test_security_group_rules_create(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
        }

        provider_nsx_policy.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

        policy = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        LOG.info(json.dumps(policy, indent=4))

        tags = {t["scope"]: t["tag"] for t in policy.get("tags")}

        self.assertEquals(policy.get("display_name"), sg.get("id"))
        self.assertEquals(tags["revision_number"], sg.get("revision_number"))
        self.assertNotEqual(tags.get("age"), None)
        self.assertEquals(policy.get("scope"), ["/infra/domains/default/groups/{}".format(sg["id"])])
        self.assertEquals(policy.get("rules"), [])

    @responses.activate
    def test_security_group_rules_update(self):

        sg = {
            "id": "7FBE1798-65F6-43E9-A7BB-3DFA63450818",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
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
            "remote_ip_prefix": "0.0.0.0/16",
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
        sg1["rules"].append(copy.deepcopy(rule1))
        sg1["rules"].append(copy.deepcopy(rule2))

        # Add new, update existing, delete existing
        sg2 = copy.deepcopy(sg)
        sg2["rules"].append(copy.deepcopy(rule1_u))
        sg2["rules"].append(copy.deepcopy(rule3))

        sg3 = copy.deepcopy(sg)

        inv = self.inventory.inv
        provider = provider_nsx_policy.Provider()

        provider.sg_rules_realize(sg1)
        LOG.info(json.dumps(inv, indent=4))
        policy1 = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        rules = {r.get("id"): r for r in policy1.get("rules")}

        self.assertEquals(len(policy1.get("rules")), 2)
        self.assertEquals(rules[rule1["id"]].get("source_groups"), [rule1.get("remote_ip_prefix")])
        self.assertEquals(rules[rule1["id"]].get("service_entries")[0].get("icmp_type"), "5")
        self.assertEquals(rules[rule1["id"]].get("service_entries")[0].get("icmp_code"), "1")
        self.assertEquals(rules[rule2["id"]].get("service_entries")[0].get("protocol_number"), 0)

        provider.sg_rules_realize(sg2)
        LOG.info(json.dumps(inv, indent=4))
        policy2 = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        rules = {r.get("id"): r for r in policy2.get("rules")}

        self.assertEquals(len(policy2.get("rules")), 2)
        self.assertEquals(rules.get(rule2["id"]), None)
        self.assertEquals(rules[rule1["id"]].get("service_entries")[0].get("icmp_code"), "2")
        self.assertEquals(rules[rule3["id"]].get("service_entries")[0].get("protocol_number"), 1)

        provider.sg_rules_realize(sg3)
        LOG.info(json.dumps(inv, indent=4))
        policy3 = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        rules = {r.get("id"): r for r in policy3.get("rules")}

        self.assertEquals(len(policy3.get("rules")), 0)

    @responses.activate
    def test_security_group_logging(self):

        sg = {
            "id": "7FBE1798-65F6-43E9-A7BB-3DFA63450818",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
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
            "remote_ip_prefix": "0.0.0.0/16",
            "security_group_id": "",
            "port_range_min": "",
            "port_range_max": "",
            "protocol": "hopopt",
        }

        # Add two new rules
        sg1 = copy.deepcopy(sg)
        sg1["rules"].append(copy.deepcopy(rule1))
        sg1["rules"].append(copy.deepcopy(rule2))

        inv = self.inventory.inv
        provider = provider_nsx_policy.Provider()

        provider.sg_rules_realize(sg1, logged=True)
        rules_logged = [r["logged"] for r in self.get_by_name(inv[Inventory.POLICIES], sg["id"])["rules"]]
        self.assertEquals(all(rules_logged), True)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(1, len(drop_rules))
        self._assertDropLoggedRules(sg, drop_rules)

        provider.sg_rules_realize(sg1, logged=False)
        rules_logged = [r["logged"] for r in self.get_by_name(inv[Inventory.POLICIES], sg["id"])["rules"]]
        self.assertEquals(any(rules_logged), False)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(0, len(drop_rules))

        provider.sg_rules_realize(sg1, logged=True)
        rules_logged = [r["logged"] for r in self.get_by_name(inv[Inventory.POLICIES], sg["id"])["rules"]]
        self.assertEquals(all(rules_logged), True)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(1, len(drop_rules))
        self._assertDropLoggedRules(sg1, drop_rules)

        log_obj = {
            "resource_type": "security_group",
            "resource_id": sg["id"]
        }

        provider.disable_policy_logging(log_obj)
        rules_logged = [r["logged"] for r in inv[Inventory.POLICIES][sg["id"]]["rules"]]
        self.assertEquals(any(rules_logged), False)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(0, len(drop_rules))

        provider.enable_policy_logging(log_obj)
        rules_logged = [r["logged"] for r in inv[Inventory.POLICIES][sg["id"]]["rules"]]
        self.assertEquals(all(rules_logged), True)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(1, len(drop_rules))
        self._assertDropLoggedRules(sg, drop_rules)

        provider.disable_policy_logging(log_obj)
        rules_logged = [r["logged"] for r in inv[Inventory.POLICIES][sg["id"]]["rules"]]
        self.assertEquals(any(rules_logged), False)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(0, len(drop_rules))

        log_obj["enabled"] = True
        provider.update_policy_logging(log_obj)
        rules_logged = [r["logged"] for r in inv[Inventory.POLICIES][sg["id"]]["rules"]]
        self.assertEquals(all(rules_logged), True)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(1, len(drop_rules))
        self._assertDropLoggedRules(sg, drop_rules)

        log_obj["enabled"] = False
        provider.update_policy_logging(log_obj)
        rules_logged = [r["logged"] for r in inv[Inventory.POLICIES][sg["id"]]["rules"]]
        self.assertEquals(any(rules_logged), False)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(0, len(drop_rules))

        log_obj["enabled"] = True
        provider.update_policy_logging(log_obj)
        rules_logged = [r["logged"] for r in inv[Inventory.POLICIES][sg["id"]]["rules"]]
        self.assertEquals(all(rules_logged), True)
        drop_rules = inv[Inventory.POLICIES]["default-layer3-logged-drop-section"]["_"]["rules"]
        self.assertEqual(1, len(drop_rules))
        self._assertDropLoggedRules(sg, drop_rules)

        LOG.info("FINISHED: test_security_group_logging")

    @responses.activate
    def test_security_group_rules_remote_group(self):

        sg_remote = {"id": "36BC1A8F-C62C-4327-9FD5-AEC49E941467", "cidrs": [], "revision_number": 0}

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
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

        provider = provider_nsx_policy.Provider()
        provider.sg_members_realize(sg_remote)
        provider.sg_rules_realize(sg)

        inv = self.inventory.inv

        LOG.info(json.dumps(inv, indent=4))
        policy = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        group = self.get_by_name(inv[Inventory.GROUPS], sg["id"])
        rules = {r.get("id"): r for r in policy.get("rules")}

        self.assertEquals(
            rules[rule["id"]].get("source_groups"),
            ["/infra/domains/default/groups/{}".format(sg_remote["id"])])

    @responses.activate
    def test_security_group_rules_service_l4(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
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

        provider_nsx_policy.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

        policy = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        rules = {r.get("id"): r for r in policy.get("rules")}

        self.assertEquals(rules[rule["id"]].get("service_entries")[0], {
            "resource_type": "L4PortSetServiceEntry",
            "l4_protocol": "TCP",
            "source_ports": [
                "1-65535"
            ],
            "destination_ports": [
                "443"
            ]
        })

        self.assertEquals(rules[rule["id"]].get("action"), "ALLOW")
        self.assertEquals(rules[rule["id"]].get("ip_protocol"), "IPV4")
        self.assertEquals(rules[rule["id"]].get("direction"), "IN")
        self.assertEquals(rules[rule["id"]].get("destination_groups"), ["ANY"])
        self.assertEquals(rules[rule["id"]].get("disabled"), False)

    @responses.activate
    def test_security_group_rules_service_ip_protocol(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
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

        provider_nsx_policy.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

        policy = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        rules = {r.get("id"): r for r in policy.get("rules")}

        self.assertEquals(rules[rule_hopopt["id"]].get("service_entries")[0], {
            "resource_type": "IPProtocolServiceEntry",
            "protocol_number": 0
        })

        self.assertEquals(rules[rule_0["id"]].get("service_entries")[0], {
            "resource_type": "IPProtocolServiceEntry",
            "protocol_number": 0
        })

        self.assertEquals(
            rules[rule_0["id"]].get("service_entries")[0],
            {"resource_type": "IPProtocolServiceEntry", "protocol_number": 0},
        )

    @responses.activate
    def test_security_group_rules_service_icmp(self):

        sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [],
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
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "icmp",
        }

        sg["rules"].append(rule_valid)
        sg["rules"].append(rule_invalid)

        provider_nsx_policy.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

        policy = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        rules = {r.get("id"): r for r in policy.get("rules")}

        self.assertEquals(rules[rule_valid["id"]].get("service_entries")[0], {
            "resource_type": "ICMPTypeServiceEntry",
            "protocol": "ICMPv4",
            "icmp_code": "1",
            "icmp_type": "5"
        })

        self.assertEquals(len(rules), 1)

    @responses.activate
    def test_outdated(self):
        sg = [
            {"id": str(uuid.uuid4()), "revision_number": 1, "tags": [], "rules": []},
            {"id": str(uuid.uuid4()), "revision_number": 2, "tags": [], "rules": []},
            {"id": str(uuid.uuid4()), "revision_number": 3, "tags": [], "rules": []},
            {"id": str(uuid.uuid4()), "revision_number": 4, "tags": [], "rules": []},
        ]

        meta = {
            sg[0]['id']: "1",  # same
            sg[1]['id']: "3",  # updated
            sg[2]['id']: "8"  # updated
            # 4 was removed => orphaned
        }

        provider = provider_nsx_policy.Provider()
        provider.sg_rules_realize(sg[0])
        provider.sg_rules_realize(sg[1])
        provider.sg_rules_realize(sg[2])
        provider.sg_rules_realize(sg[3])

        LOG.info(json.dumps(self.inventory.inv, indent=4))

        outdated, current = provider.outdated(provider.SG_RULES, meta)

        self.assertItemsEqual(outdated, [sg[1]['id'], sg[2]['id'], sg[3]['id']])
        self.assertItemsEqual(current, [sg[0]['id']])

    @responses.activate
    def test_security_group_stateful(self):
        sg1 = {"id": "1", "revision_number": 2, "rules": []}
        sg2 = dict(sg1, **{'id': '2', 'stateful': False})
        provider = provider_nsx_policy.Provider()
        provider.sg_rules_realize(sg1)
        provider.sg_rules_realize(sg2)
        inv = self.inventory.inv
        self.assertTrue(self.get_by_name(inv[Inventory.POLICIES], sg1["id"]).get("stateful"))
        self.assertFalse(self.get_by_name(inv[Inventory.POLICIES], sg2["id"]).get("stateful"))

    @responses.activate
    def test_security_group_revision_retry(self):
        sg1 = {"id": "1904e541-7fa0-475a-99dc-00ff03c7489f", "revision_number": 2, "rules": []}
        provider = provider_nsx_policy.Provider()
        provider.sg_rules_realize(sg1)
        inv = self.inventory.inv
        inv[Inventory.POLICIES]["1904e541-7fa0-475a-99dc-00ff03c7489f"]["_revision"] = 100
        provider.sg_rules_realize(sg1)
        self.assertEqual(101, inv[Inventory.POLICIES].get("1904e541-7fa0-475a-99dc-00ff03c7489f").get("_revision"))

    @responses.activate
    def test_double_creation_of_default_group(self):
        r = responses
        r.reset()

        # Simulate default group exists response
        r.add(
            r.PUT,
            re.compile("(.*)" + provider_nsx_policy.API.GROUP.format("0-0-0-0-0")),
            status=400,
            json={
                "httpStatus": "BAD_REQUEST",
                "error_code": 500127,
                "module_name": "Policy",
                "error_message": "Cannot create an object with path=[/infra/domains/default/groups/0-0-0-0-0] as it already exists.",
            },
        )
        # Add the rest of the callbacks
        for m in [r.GET, r.POST, r.DELETE, r.PATCH]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

        provider = provider_nsx_policy.Provider()
        o = provider._create_sg_provider_rule_remote_prefix("0.0.0.0/0")

        expected = {
            "display_name": "0.0.0.0/0",
            "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["0.0.0.0/0"]}],
            "tags": [{"scope": "agent_id", "tag": "nsxm-l-01a.corp.local"}, {"scope": "age", "tag": 1637251144}],
        }

        self.assertEqual(o["display_name"], expected["display_name"])
        self.assertEqual(o["expression"][0]["ip_addresses"][0], expected["expression"][0]["ip_addresses"][0])

    @responses.activate
    def test_security_group_rules_skip_ipv4_mapped_ipv6s(self):
        sg = {
            "id": "53C33143-3607-4CB2-B6E4-FA5F5C9E3C21",
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
            "port_range_min": "65535",
            "port_range_max": "1",
            "protocol": "tcp",
        }

        rule_invalid = {
            "id": "2",
            "ethertype": "IPv6",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "::ffff:10.180.0.0/112",
            "security_group_id": "",
            "port_range_min": "1",
            "port_range_max": "65535",
            "protocol": "tcp",
        }

        sg["rules"].append(rule_valid)
        sg["rules"].append(rule_invalid)

        provider_nsx_policy.Provider().sg_rules_realize(sg)

        inv = self.inventory.inv

        policy = self.get_by_name(inv[Inventory.POLICIES], sg["id"])
        rules = {r.get("id"): r for r in policy.get("rules")}

        self.assertEquals(len(rules), 1)
        self.assertEquals(rules[rule_valid["id"]].get("source_groups"), ['192.168.10.0/24'])

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

        p = provider_nsx_policy.Provider()
        inv = self.inventory.inv

        for i in range(1, 10):
            cidr = f"192.168.{i}.0/24"
            id = re.sub(r"\.|:|\/", "-", cidr)
            data = {
                "display_name": cidr,
                "expression": [{
                    "resource_type": "IPAddressExpression",
                    "ip_addresses": [cidr]
                }],
                "tags": []
            }
            p.client.put(path=provider_nsx_policy.API.GROUP.format(id), data=data)

        p.sg_rules_realize(sg)

        self.assertEquals(len(inv[self.inventory.GROUPS]), 10)
        self.assertEquals(inv[self.inventory.GROUPS].get("192-168-1-0-24", {}).get("display_name"), "192.168.1.0/24")

        for id, cleanup in p.sanitize(100):
            cleanup(id)

        self.assertEquals(len(inv[self.inventory.GROUPS]), 1)
        self.assertEquals(inv[self.inventory.GROUPS].get("0-0-0-0-16", {}).get("display_name"), "0.0.0.0/16")

    def _assertDropLoggedRules(self, sg, drop_rules):
        self.assertEqual(sg["id"] in drop_rules, True)
        self.assertEqual(drop_rules[sg["id"]]["action"], "DROP")
        self.assertEqual(drop_rules[sg["id"]]["id"], sg["id"])
        self.assertEqual(drop_rules[sg["id"]]["display_name"], sg["id"])
        self.assertEqual(drop_rules[sg["id"]]["sequence_number"], 2147483647)
        self.assertEqual(drop_rules[sg["id"]]["direction"], "IN_OUT")
        self.assertEqual(drop_rules[sg["id"]]["ip_protocol"], "IPV4_IPV6")
        self.assertEqual(drop_rules[sg["id"]]["logged"], True)
        self.assertEqual(drop_rules[sg["id"]]["source_groups"], ["ANY"])
        self.assertEqual(drop_rules[sg["id"]]["destination_groups"], ["ANY"])
        self.assertEqual(drop_rules[sg["id"]]["services"], ["ANY"])
        self.assertEqual(drop_rules[sg["id"]]["scope"], ["/infra/domains/default/groups/{}".format(sg["id"])])

    def port_fixture(self):
        vlan = "1000"
        zone_name = cfg.CONF.NSXV3.nsxv3_transport_zone_name
        segment_id = str(uuid.uuid5(uuid.NAMESPACE_OID, "1234"))
        port_id = str(uuid.uuid5(uuid.NAMESPACE_OID, "12345"))

        provider_network = {
            "type": "DISCONNECTED",
            "vlan_ids": [
                vlan
            ],
            # "transport_zone_path": API.TRANSPORT_ZONES_PATH.format(tr_zone_id),
            "advanced_config": {
                "hybrid": False
            },
            "admin_state": "UP",
            "resource_type": "Segment",
            "id": segment_id,
            "display_name": f"{zone_name}-{vlan}",
            "path": provider_nsx_policy.API.SEGMENT_PATH.format(segment_id),
            # "_revision": provider_net.get("_revision")
        }

        provider_port = {
            "id": port_id,
            "display_name": port_id,
            "resource_type": "SegmentPort",
            "admin_state": "UP",
            "attachment": {
                "id": port_id,
                "type": "PARENT",
                "traffic_tag": vlan
            },
            "address_bindings": ["172.24.4.3", "172.24.4.4"],
            "tags": [],
            "parent_path": provider_nsx_policy.API.SEGMENT_PATH.format(segment_id),
            "path": provider_nsx_policy.API.SEGMENT_PORT_PATH.format(segment_id, port_id),
            "_revision": None
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
            "id": port_id,
            "revision_number": "2",
            "parent_id": "",
            "mac_address": "fa:16:3e:e4:11:f1",
            "admin_state_up": "UP",
            "qos_policy_id": os_qos.get("id"),
            "security_groups": [os_sg.get("id"), os_sg_second.get("id")],
            "address_bindings": ["172.24.4.3", "172.24.4.4"],
            "vif_details": {
                "nsx-logical-switch-id": segment_id,
                "segmentation_id": vlan
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
                "nsx-logical-switch-id": segment_id,
                "segmentation_id": vlan
            }
        }

        return (provider_network, provider_port, os_sg, os_sg_second, os_qos, os_port_parent, os_port_child)

    @responses.activate
    def test_port_parent_create(self):
        provider_network, _, os_sg, _, os_qos, os_port_parent, _ = self.port_fixture()

        # Precreate network
        provider_network = requests.put(get_url(provider_nsx_policy.API.SEGMENT.format(
            provider_network.get("id"))), data=json.dumps(provider_network)).json()

        provider = provider_nsx_policy.Provider()
        provider.metadata_refresh(provider_nsx_policy.Provider.NETWORK)
        provider.sg_rules_realize(os_sg)
        provider.qos_realize(os_qos)
        provider.port_realize(os_port_parent)

        meta_port = provider.metadata(provider.PORT, os_port_parent.get("id"))

        self.assertEquals(meta_port.rev, os_port_parent.get("revision_number"))
        self.assertEquals(meta_port.id, os_port_parent.get("id"))
        self.assertEquals(meta_port.real_id, os_port_parent.get("id"))
        self.assertEquals(meta_port.unique_id, os_port_parent.get("id"))

        provider_port_results = requests.get(get_url(
            f"{provider_nsx_policy.API.SEARCH_QUERY}?query={provider_nsx_policy.API.SEARCH_Q_SEG_PORT.format(os_port_parent.get('id'))}")).json()
        self.assertEquals(1, len(provider_port_results.get("results", [])))
        provider_port = provider_port_results.get("results")[0]
        LOG.critical(json.dumps(provider_port, indent=4))

        self.assertListEqual(provider_port.get("address_bindings"), os_port_parent.get("address_bindings"))
        self.assertEqual(provider_port.get("attachment").get("type"), "PARENT")
        self.assertEqual(provider_port.get("attachment").get("traffic_tag"),
                         os_port_parent.get("vif_details").get("segmentation_id"))

        self.assertListEqual(os_port_parent.get("security_groups"),
                             self.get_all_tags_from_scope(provider_port, "security_group"))

    @responses.activate
    def test_port_child_create(self):
        p_net, p_port, os_sg, _, os_qos, os_port_parent, os_port_child = self.port_fixture()
        api = provider_nsx_policy.API

        # Port crated via Nova machine provisioning
        p_net = requests.put(get_url(api.SEGMENT.format(p_net.get("id"))), json=p_net).json()
        p_port = requests.put(get_url(api.SEGMENT_PORT.format(p_net.get("id"), p_net.get("id"))), json=p_port).json()

        provider = provider_nsx_policy.Provider()
        provider.metadata_refresh(provider_nsx_policy.Provider.NETWORK)

        provider.sg_rules_realize(os_sg)
        provider.qos_realize(os_qos)
        provider.port_realize(os_port_parent)
        provider.port_realize(os_port_child)

        meta_port = provider.metadata(provider.PORT, os_port_child.get("id"))

        self.assertEquals(meta_port.rev, os_port_child.get("revision_number"))
        _, provider_port = provider.get_port(os_port_child.get("id"))

        self.assertEquals(provider_port.get("attachment").get("id"), os_port_child.get("id"))
        self.assertEquals(provider_port.get("address_bindings"), os_port_child.get("address_bindings"))

        self.assertEquals([self.get_tag(provider_port, "security_group")], os_port_child.get("security_groups"))
        self.assertEquals(self.get_tag(provider_port, "revision_number"), os_port_child.get("revision_number"))

    @responses.activate
    def test_port_bound_multiple_security_groups(self):
        p_net, p_port, _, _, _, os_port, _ = self.port_fixture()
        api = provider_nsx_policy.API

        p_net = requests.put(get_url(api.SEGMENT.format(p_net.get("id"))), json=p_net).json()

        provider = provider_nsx_policy.Provider()
        provider.metadata_refresh(provider_nsx_policy.Provider.NETWORK)
        provider.port_realize(os_port)

        _, p_port = provider.get_port(os_port.get("id"))

        self.assertEquals(len(self.get_all_tags_from_scope(p_port, "security_group")), 2)
        self.assertLessEqual(self.get_all_tags_from_scope(p_port, "security_group"), os_port.get("security_groups"))

    @responses.activate
    def test_port_delete(self):
        p_net, p_port, os_sg, _, os_qos, os_port_parent, os_port_child = self.port_fixture()
        api = provider_nsx_policy.API

        p_net = requests.put(get_url(api.SEGMENT.format(p_net.get("id"))), json=p_net).json()

        provider = provider_nsx_policy.Provider()
        provider.metadata_refresh(provider_nsx_policy.Provider.NETWORK)

        provider.sg_rules_realize(os_sg)
        provider.qos_realize(os_qos)
        provider.port_realize(os_port_parent)
        provider.port_realize(os_port_child)

        meta_parent_port = provider.metadata(provider.PORT, os_port_parent.get("id")).id
        meta_child_port = provider.metadata(provider.PORT, os_port_child.get("id")).id

        self.assertListEqual(list(self.inventory.inv[Inventory.SEGMENT_PORTS].keys()), [
                             meta_parent_port, meta_child_port])

        provider.port_realize(os_port_child, delete=True)
        provider.port_realize(os_port_parent, delete=True)

        self.assertEquals(list(self.inventory.inv[Inventory.SEGMENT_PORTS].keys()), [])

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
        provider = provider_nsx_policy.Provider()
        provider.qos_realize(os_qos)

        result = requests.get(get_url("/{}".format(Inventory.SEGMENT_QOS))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))

        self.assertDictEqual(qos.get("dscp"), {'mode': 'UNTRUSTED', 'priority': 5})
        self.assertListEqual(qos.get("shaper_configurations"), [
            {
                'resource_type': 'IngressRateLimiter',
                'enabled': True,
                'average_bandwidth': 6,
                'peak_bandwidth': 12,
                'burst_size': 16384000
            },
            {
                'resource_type': 'EgressRateLimiter',
                'enabled': True, 'average_bandwidth': 7,
                'peak_bandwidth': 14,
                'burst_size': 32768000
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

        provider = provider_nsx_policy.Provider()
        provider.qos_realize(os_qos)

        os_qos.get("rules").append(rule)
        provider.qos_realize(os_qos)

        result = requests.get(get_url("/{}".format(Inventory.SEGMENT_QOS))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))

        self.assertDictEqual(qos.get("dscp"), {"priority": 5, "mode": "UNTRUSTED"})

        self.assertListEqual(qos.get("shaper_configurations"), [
            {
                "average_bandwidth": 6,
                "peak_bandwidth": 12,
                "enabled": True,
                "burst_size": 16384000,
                "resource_type": "IngressRateLimiter"
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

        provider = provider_nsx_policy.Provider()

        provider.qos_realize(os_qos)
        result = requests.get(get_url("/{}".format(Inventory.SEGMENT_QOS))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))
        self.assertNotEqual(qos, None)

        provider.qos_realize(os_qos, delete=True)
        result = requests.get(get_url("/{}".format(Inventory.SEGMENT_QOS))).json()
        qos = self.get_result_by_name(result, os_qos.get("id"))
        self.assertEquals(qos, None)

    @responses.activate
    def test_create_network(self):
        segmentation_id = "3200"
        provider = provider_nsx_policy.Provider()
        meta = provider.network_realize(segmentation_id)

        inv = self.inventory.inv
        net = inv[Inventory.SEGMENTS].get(meta.id)

        self.assertListEqual(net.get("vlan_ids"), [segmentation_id])
        self.assertEquals(net.get("transport_zone_path"),
                          f"/infra/sites/default/enforcement-points/default/transport-zones/{provider.zone_id}")
        self.assertEquals(net.get("display_name"), "{}-{}".format(provider.zone_name, segmentation_id))

    @responses.activate
    def test_reuse_network(self):
        segmentation_id = "3200"
        segmentation_id2 = "3201"
        provider = provider_nsx_policy.Provider()

        inv = self.inventory.inv

        meta = provider.network_realize(segmentation_id)
        self.assertEquals(len(inv[Inventory.SEGMENTS]), 1)

        meta1 = provider.network_realize(segmentation_id)
        self.assertEquals(len(inv[Inventory.SEGMENTS]), 1)

        self.assertEquals(meta.id, meta1.id)

        provider.network_realize(segmentation_id2)
        self.assertEquals(len(inv[Inventory.SEGMENTS]), 2)

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

        provider = provider_nsx_policy.Provider()
        provider.sg_rules_realize(sg[0])
        provider.sg_rules_realize(sg[1])
        provider.sg_rules_realize(sg[2])
        provider.sg_rules_realize(sg[3])

        outdated, current = provider.outdated(provider.SG_RULES, meta)

        LOG.info(json.dumps(self.inventory.inv, indent=4))

        self.assertItemsEqual(outdated, [sg[1]['id'], sg[2]['id'], sg[3]['id']])
        self.assertItemsEqual(current, [sg[0]['id']])

    @responses.activate
    def test_outdated_with_filtered_deletions(self):
        _, _, _, _, _, os_port_parent, _ = self.port_fixture()

        provider = provider_nsx_policy.Provider()
        meta = provider.network_realize(os_port_parent['vif_details']['segmentation_id'])
        os_port_parent['vif_details']['nsx-logical-switch-id'] = meta.id
        provider.port_realize(os_port_parent)

        cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after = 1000
        outdated, _ = provider.outdated(provider.PORT, {os_port_parent['id']: os_port_parent['revision_number']})
        self.assertEquals(len(outdated), 0)

        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 0)

        cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after = 0
        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 1)

        provider.port_realize(os_port_parent, delete=True)
        self.assertIsNone(provider.metadata(provider.PORT, os_port_parent.get("id")))

    @responses.activate
    def test_priveleged_ports(self):
        cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after = 0
        vmk_n, vmk_p, _, _, _, os_port_parent, _ = self.port_fixture()
        api = provider_nsx_policy.API

        # Create non-agent managed port/segment
        vmk_n["id"] = vmk_n["display_name"] = "vmotion"
        vmk_n = requests.post(url=get_url(api.SEGMENTS), json=vmk_n).json()
        vmk_p["parent_path"] = provider_nsx_policy.API.SEGMENT_PATH.format(vmk_n['id'])
        vmk_p["path"] = provider_nsx_policy.API.SEGMENT_PORT_PATH.format(vmk_n['id'], vmk_p["id"])
        vmk_p = requests.put(url=get_url(api.SEGMENT_PORT.format(vmk_n["id"], vmk_p["id"])), json=vmk_p).json()

        provider = provider_nsx_policy.Provider()
        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 0)

        # Create agent-managed port/switch
        meta = provider.network_realize("1234")
        os_port_parent['id'] = str(uuid.uuid1())
        os_port_parent['vif_details']['nsx-logical-switch-id'] = meta.id
        os_port_parent['vif_details']['segmentation_id'] = "1234"
        provider.port_realize(os_port_parent)

        # Assert to clean it up
        outdated, _ = provider.outdated(provider.PORT, {})
        self.assertEquals(len(outdated), 1)

        vmk_port = requests.get(get_url(api.SEGMENT_PORT.format(vmk_n["id"], vmk_p["id"]))).json()
        self.assertIsNotNone(vmk_port)
