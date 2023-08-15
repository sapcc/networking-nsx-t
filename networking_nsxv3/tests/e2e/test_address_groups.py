import eventlet
eventlet.monkey_patch()

from networking_nsxv3.common import config  # noqa
from oslo_log import log as logging
import re
import uuid
from networking_nsxv3.tests.e2e import base
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API


LOG = logging.getLogger(__name__)


class TestAddressGroups(base.E2ETestCase):

    def setUp(self):
        super().setUp()
        self.new_addr_grp_rules = []
        self.new_grp_ids = []
        self.assertGreater(len(self.nova_client.servers.list()), 0, "At least one server should exist!")
        self.def_os_sg = self._get_os_default_sg()

    def tearDown(self):
        super().tearDown()
        # Clean up & Assert cleanup
        LOG.info("Tearing down test case...")
        addr_grp_ids = [ag.get("security_group_rule", {}).get("id") for ag in self.new_addr_grp_rules]
        self._clean_neutron_sg_rules()
        self._clean_addr_groups()
        self._assert_nsx_cleanup(rule_ids=addr_grp_ids)

    def test_create_ipv4_address_groups(self):
        LOG.info("Testing creation of IPv4 address groups...")
        unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
                 "address_group": {
                     "addresses": ["192.168.0.1/32", "192.168.0.2/32", "192.168.0.3/32"],
                     "name": unique_addr_grp_name,
                     "description": "e2e test group"
                 }
             })
        
        new_grp_id = self._get_new_grp_id(unique_addr_grp_name, new_addr_grp)

        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "ingress",
                "ethertype": "IPv4",
                "port_range_max": "80",
                "port_range_min": "80",
                "protocol": "tcp",
                "remote_address_group_id": new_grp_id,
                "security_group_id": self.def_os_sg['id']
            }
        }))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "egress",
                "ethertype": "IPv4",
                "port_range_max": "80",
                "port_range_min": "80",
                "protocol": "tcp",
                "remote_address_group_id": new_grp_id,
                "security_group_id": self.def_os_sg['id']
            }
        }))
        self.new_addr_grp_rules.extend(new_addr_grp_rules)

        # Verify that the rules were created
        self.assertTrue(new_addr_grp_rules[0] and new_addr_grp_rules[0].get(
            'security_group_rule', {}).get('id'))
        self.assertTrue(new_addr_grp_rules[1] and new_addr_grp_rules[1].get(
            'security_group_rule', {}).get('id'))

        # Verify NSX-T side
        nsx_sg_policy = self._fetch_nsx_policy(self.def_os_sg)

        # Get all rules from the NSX-T Security Policy
        nsx_addr_grp_rule1, nsx_addr_grp_rule2 = self._get_rules_after_create(new_addr_grp_rules)

        self.assertEqual(len(nsx_addr_grp_rule1), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            new_addr_grp_rules[0].get("security_group_rule", {}).get("id")))
        self.assertEqual(len(nsx_addr_grp_rule2), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            new_addr_grp_rules[1].get("security_group_rule", {}).get("id")))

        nsx_addr_grp_rule1 = nsx_addr_grp_rule1[0]
        nsx_addr_grp_rule2 = nsx_addr_grp_rule2[0]

        LOG.debug("NSX-T Security Policy Rule 1: {}".format(nsx_addr_grp_rule1))
        LOG.debug("NSX-T Security Policy Rule 2: {}".format(nsx_addr_grp_rule2))

        # Assert the rules have the expected source and destination address groups
        self.assertItemsEqual(nsx_addr_grp_rule1.get("source_groups"), new_addr_grp["address_group"]["addresses"])
        self.assertItemsEqual(nsx_addr_grp_rule2.get("destination_groups"), new_addr_grp["address_group"]["addresses"])

    def test_create_ipv6_address_groups(self):
        LOG.info("Testing creation of IPv6 address groups...")
        unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
            "address_group": {
                "name": unique_addr_grp_name,
                "addresses": ["2001:db8::/64", "2001:db8:1::/64", "2001:db8:2::/64"],
                "description": "e2e IPv6 Address Group"
            }
        })
        
        new_grp_id = self._get_new_grp_id(unique_addr_grp_name, new_addr_grp)

        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "ingress",
                "ethertype": "IPv6",
                "port_range_max": "8080",
                "port_range_min": "8080",
                "protocol": "tcp",
                "remote_address_group_id": new_grp_id,
                "security_group_id": self.def_os_sg['id']
            }
        }))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "egress",
                "ethertype": "IPv6",
                "port_range_max": "8080",
                "port_range_min": "8080",
                "protocol": "tcp",
                "remote_address_group_id": new_grp_id,
                "security_group_id": self.def_os_sg['id']
            }
        }))
        self.new_addr_grp_rules.extend(new_addr_grp_rules)

        # Verify that the rules were created
        self.assertTrue(new_addr_grp_rules[0] and new_addr_grp_rules[0].get(
            'security_group_rule', {}).get('id'))
        self.assertTrue(new_addr_grp_rules[1] and new_addr_grp_rules[1].get(
            'security_group_rule', {}).get('id'))

        # Verify NSX-T side
        nsx_sg_policy = self._fetch_nsx_policy(self.def_os_sg)

        # Get all rules from the NSX-T Security Policy
        nsx_addr_grp_rule1, nsx_addr_grp_rule2 = self._get_rules_after_create(new_addr_grp_rules)

        self.assertEqual(len(nsx_addr_grp_rule1), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            new_addr_grp_rules[0].get("security_group_rule", {}).get("id")))
        self.assertEqual(len(nsx_addr_grp_rule2), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            new_addr_grp_rules[1].get("security_group_rule", {}).get("id")))

        nsx_addr_grp_rule1 = nsx_addr_grp_rule1[0]
        nsx_addr_grp_rule2 = nsx_addr_grp_rule2[0]

        LOG.debug("NSX-T Security Policy Rule 1: {}".format(nsx_addr_grp_rule1))
        LOG.debug("NSX-T Security Policy Rule 2: {}".format(nsx_addr_grp_rule2))

        # Assert the rules have the expected source and destination address groups
        self.assertItemsEqual(nsx_addr_grp_rule1.get("source_groups"), new_addr_grp["address_group"]["addresses"])
        self.assertItemsEqual(nsx_addr_grp_rule2.get("destination_groups"), new_addr_grp["address_group"]["addresses"])

    def test_create_mixed_ipv4_ipv6_members(self):
        LOG.info("Testing creation of mixed IPv4 and IPv6 address groups...")
        unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
            "address_group": {
                "name": unique_addr_grp_name,
                "addresses": ["192.168.0.1/32", "192.168.0.2/32", "192.168.0.3/32", "2001:db8::/64", "2001:db8:1::/64", "2001:db8:2::/64"],
                "description": "e2e IPv4 Address Group with IPv6 members"
            }
        })
        
        new_grp_id = self._get_new_grp_id(unique_addr_grp_name, new_addr_grp)

        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "ingress",
                "ethertype": "IPv4",
                "port_range_max": "8081",
                "port_range_min": "8081",
                "protocol": "tcp",
                "remote_address_group_id": new_grp_id,
                "security_group_id": self.def_os_sg['id']
            }
        }))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "egress",
                "ethertype": "IPv6",
                "port_range_max": "8081",
                "port_range_min": "8081",
                "protocol": "tcp",
                "remote_address_group_id": new_grp_id,
                "security_group_id": self.def_os_sg['id']
            }
        }))
        self.new_addr_grp_rules.extend(new_addr_grp_rules)

        # Verify that the rules were created
        self.assertTrue(new_addr_grp_rules[0] and new_addr_grp_rules[0].get(
            'security_group_rule', {}).get('id'))
        self.assertTrue(new_addr_grp_rules[1] and new_addr_grp_rules[1].get(
            'security_group_rule', {}).get('id'))

        # Verify NSX-T side
        nsx_sg_policy = self._fetch_nsx_policy(self.def_os_sg)

        # Assert TimeoutError raised prooving that the rules were not created in NSX-T
        self.assertRaisesRegex(TimeoutError, "Failed to fetch the desired result", self._get_rules_after_create, new_addr_grp_rules)
        

    def test_update_address_groups(self):
        # TODO: Implement

        # Add addresses to the address group
        # self.n_client.add_address_group_addresses(self.new_grp_id, body={
        #     "addresses": ["192.168.0.4/32"]
        # })
        self.skipTest("Not implemented")

    ######################################################################################
    ####################################### Private Methods ##############################
    ######################################################################################

    def _assert_nsx_cleanup(self, rule_ids=[]):
        LOG.debug("Asserting NSX-T cleanup rule_ids={}".format(rule_ids))

        # Get the default security group
        lsg = self.neutron_client.list_security_groups()
        default_sg = [sg for sg in lsg['security_groups'] if sg['name'] == 'default'][0]

        # Ensure NSX-T Security Policy has no Address Groups rules
        nsx_addr_grp_rules = self._get_rules_after_clean(rule_ids, default_sg)

        self.assertListEqual(nsx_addr_grp_rules, [],
                             "NSX-T Security Policy should have exactly 0 address group rules.")

    def _clean_addr_groups(self):
        if len(self.new_grp_ids) > 0:
            for new_grp_id in self.new_grp_ids:
                self.neutron_client.delete_address_group(new_grp_id)
                self.assertNotIn(new_grp_id, [ag['id']
                        for ag in self.neutron_client.list_address_groups()['address_groups']])

    def _clean_neutron_sg_rules(self):
        if len(self.new_addr_grp_rules) > 0:
            for new_addr_grp_rule in self.new_addr_grp_rules:
                self.neutron_client.delete_security_group_rule(new_addr_grp_rule['security_group_rule']['id'])
                self.assertNotIn(new_addr_grp_rule['security_group_rule']['id'], [r['id']
                            for r in self.neutron_client.list_security_group_rules()['security_group_rules']])

    def _get_os_default_sg(self):
        # Get the default security group
        lsg = self.neutron_client.list_security_groups()
        default_sg = [sg for sg in lsg['security_groups'] if sg['name'] == 'default'][0]

        # Assert that the default security group exists and has active member ports
        self.assertIsNotNone(default_sg, "Default security group should exist")
        sg_ports = self.neutron_client.list_ports(security_groups=[default_sg['id']])
        self.assertGreater(len(sg_ports), 0, "Default security group should have at least one port")
        self.assertGreater(len(sg_ports['ports']), 0, "Default security group should have at least one port")
        self.assertTrue(any([p['status'] == 'ACTIVE' and p['admin_state_up'] for p in sg_ports['ports']]),
                        "Default security group should have at least one active port")

        return default_sg
    
    def _get_new_grp_id(self, unique_addr_grp_name, new_addr_grp):
        new_grp_id = None
        if new_addr_grp:
            new_grp_id = new_addr_grp.get('address_group', {}).get('id')
            self.new_grp_ids.append(new_grp_id)

        # Verify that the address group was created
        self.assertIn(unique_addr_grp_name, [ag['name']
                      for ag in self.neutron_client.list_address_groups()['address_groups']])
                      
        return new_grp_id

    @base.E2ETestCase.retry(max_retries=5, sleep_duration=5)
    def _fetch_nsx_policy(self, default_sg):
        nsx_sg_policy = self.nsx_client.get_unique(
            f"{API.SEARCH_QUERY}?query=resource_type:SecurityPolicy AND category:Application AND display_name:{default_sg['id']}")
        self.assertTrue(nsx_sg_policy, "NSX-T Security Policy should exist")
        if nsx_sg_policy.get("status", {}).get("publish_status") == "REALIZED" and nsx_sg_policy.get("status", {}).get("consolidated_status", {}).get("consolidated_status") == "SUCCESS":
            return nsx_sg_policy
        return None

    @base.E2ETestCase.retry(max_retries=5, sleep_duration=5)
    def _get_rules_after_clean(self, rule_ids, default_sg):
        rules = self.nsx_client.get_all(
            "/policy/api/v1/infra/domains/default/security-policies/{}/rules".format(default_sg['id']))
        nsx_addr_grp_rules = [r for r in rules if r.get("display_name") in rule_ids]
        if len(nsx_addr_grp_rules) > 0:
            return None
        return nsx_addr_grp_rules

    @base.E2ETestCase.retry(max_retries=3, sleep_duration=5)
    def _get_rules_after_create(self, new_addr_grp_rules):
        rules = self.nsx_client.get_all(
            "/policy/api/v1/infra/domains/default/security-policies/{}/rules".format(self.def_os_sg['id']))

        # Assert that the NSX-T Security Policy has rules
        self.assertTrue(rules, "NSX-T Security Policy should have rules")
        self.assertGreater(len(rules), 0, "NSX-T Security Policy should have at least one rule")

        # Assert that the NSX-T Security Policy has the expected address group rule
        nsx_addr_grp_rule1 = [r for r in rules if r.get(
            "display_name") == new_addr_grp_rules[0].get("security_group_rule", {}).get("id")]
        nsx_addr_grp_rule2 = [r for r in rules if r.get(
            "display_name") == new_addr_grp_rules[1].get("security_group_rule", {}).get("id")]

        if len(nsx_addr_grp_rule1) == 0 or len(nsx_addr_grp_rule2) == 0:
            return None

        return nsx_addr_grp_rule1, nsx_addr_grp_rule2
