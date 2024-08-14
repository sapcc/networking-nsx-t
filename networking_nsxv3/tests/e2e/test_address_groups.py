from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
from networking_nsxv3.tests.e2e import base
import uuid
from oslo_log import log as logging
import eventlet
eventlet.monkey_patch()

from networking_nsxv3.common import config  # noqa


LOG = logging.getLogger(__name__)


class TestAddressGroups(base.E2ETestCase):

    def setUp(self):
        super().setUp()
        # self.skipTest("Skipping test temporarily.")

        self.new_addr_grp_rules = []
        self.new_grp_ids = []
        self.new_sg_ids = []
        self.existing_updated_ports = []
        servers = self.nova_client.servers.list(search_opts={"availability_zone": self.availability_zone})
        self.assertGreater(len(servers), 0, "At least one server should exist in the specified availability zone!")
        self.def_os_sg = self.get_os_default_security_group()

    def tearDown(self):
        super().tearDown()
        # Clean up & Assert cleanup
        LOG.info("Tearing down test case...")
        addr_grp_ids = [ag.get("security_group_rule", {}).get("id") for ag in self.new_addr_grp_rules]
        self._revert_updated_ports()
        self._clean_neutron_sg_rules()
        self._clean_addr_groups()
        self._clean_sec_groups()
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

        new_grp_id = self._get_assert_new_grp_id(unique_addr_grp_name, new_addr_grp)

        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "ingress")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "egress")))

        # Verify that the rules were created
        self._assert_and_append_new_grp_rules(new_addr_grp_rules)

        # Verify NSX-T side
        self._verify_nsx_addr_grp(new_addr_grp, new_addr_grp_rules)

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

        new_grp_id = self._get_assert_new_grp_id(unique_addr_grp_name, new_addr_grp)

        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "ingress", "IPv6")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "egress", "IPv6")))

        # Verify that the rules were created
        self._assert_and_append_new_grp_rules(new_addr_grp_rules)

        # Verify NSX-T side
        self._verify_nsx_addr_grp(new_addr_grp, new_addr_grp_rules)

    def test_create_mixed_ipv4_ipv6_members(self):
        LOG.info("Testing creation of mixed IPv4 and IPv6 address groups...")
        unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
            "address_group": {
                "name": unique_addr_grp_name,
                "addresses": ["192.168.0.1/32", "192.168.0.2/32", "2001:db8::/64", "2001:db8:1::/64"],
                "description": "e2e IPv4 Address Group with IPv6 members"
            }
        })

        new_grp_id = self._get_assert_new_grp_id(unique_addr_grp_name, new_addr_grp)

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "ingress")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "egress")))

        # Verify that the rules were created
        self._assert_and_append_new_grp_rules(new_addr_grp_rules)

        # Verify NSX-T side
        self._verify_nsx_addr_grp(new_addr_grp, new_addr_grp_rules)

    def test_update_address_groups(self):
        LOG.info("Testing update of address groups...")
        unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
            "address_group": {
                "name": unique_addr_grp_name,
                "addresses": ["192.168.0.1/32", "192.168.0.2/32", "192.168.0.3/32"],
                "description": "e2e IPv4 Address Group with IPv6 members"
            }
        })

        new_grp_id = self._get_assert_new_grp_id(unique_addr_grp_name, new_addr_grp)

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "ingress")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "egress")))

        # Verify that the rules were created
        self._assert_and_append_new_grp_rules(new_addr_grp_rules)

        # wait some time before updating the address group for simulating the real world scenario
        eventlet.sleep(15)

        # Add addresses to the address group
        self.neutron_client.add_address_group_addresses(new_grp_id, body={
            "addresses": ["192.168.0.4/32"]
        })

        eventlet.sleep(5)

        # Verify NSX-T side
        new_addr_grp = self.neutron_client.show_address_group(new_grp_id)  # update the record with the new addresses
        self._verify_nsx_addr_grp(new_addr_grp, new_addr_grp_rules)

    def test_address_group_in_multiple_security_groups(self):
        LOG.info("Testing address group in multiple security groups...")

        # Check that there are active ports
        ports = self._get_assert_active_ports()

        unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
            "address_group": {
                "name": unique_addr_grp_name,
                "addresses": ["192.168.1.1/24"],
                "description": "e2e IPv4 Address Group used in multiple security groups"
            }
        })
        new_grp_id = self._get_assert_new_grp_id(unique_addr_grp_name, new_addr_grp)

        # Create two new security groups
        new_sg_1 = self.neutron_client.create_security_group(body={
            "security_group": {
                "name": str(uuid.uuid4()),
                "description": "e2e security group 1"
            }
        })
        new_sg_2 = self.neutron_client.create_security_group(body={
            "security_group": {
                "name": str(uuid.uuid4()),
                "description": "e2e security group 2"
            }
        })

        # Attach the new SGs to an active port
        self.existing_updated_ports.append(ports[0])
        self.neutron_client.update_port(ports[0]['id'], body={
            "port": {
                "security_groups": [new_sg_1['security_group']['id'], new_sg_2['security_group']['id']]
            }
        })

        # Verify that the security groups were created
        self.assertTrue(new_sg_1 and new_sg_1.get('security_group', {}).get('id'))
        self.assertTrue(new_sg_2 and new_sg_2.get('security_group', {}).get('id'))

        self.new_sg_ids.append(new_sg_1['security_group']['id'])
        self.new_sg_ids.append(new_sg_2['security_group']['id'])

        # Create new rule with the new address group to each of the new security groups
        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, new_sg_1['security_group']['id'], "ingress")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, new_sg_1['security_group']['id'], "egress")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, new_sg_2['security_group']['id'], "ingress")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, new_sg_2['security_group']['id'], "egress")))

        # Verify that the rules were created
        self._assert_and_append_new_grp_rules(new_addr_grp_rules)

        # Verify NSX-T side
        self._verify_nsx_addr_grp(new_addr_grp, new_addr_grp_rules[0:2], new_sg_1['security_group']['id'])
        self._verify_nsx_addr_grp(new_addr_grp, new_addr_grp_rules[2:4], new_sg_2['security_group']['id'])

    def test_delete_address_group(self):
        LOG.info("Testing delete address group...")

        unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
            "address_group": {
                "addresses": ["192.168.0.1/32", "192.168.0.2/32", "192.168.0.3/32"],
                "name": unique_addr_grp_name,
                "description": "e2e test group"
            }
        })

        new_grp_id = self._get_assert_new_grp_id(unique_addr_grp_name, new_addr_grp)

        new_addr_grp_rules = []

        # Create new rule with the new address group to the default security group
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "ingress")))
        new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(
            body=self._sg_rule_template(new_grp_id, self.def_os_sg['id'], "egress")))

        # Verify that the rules were created
        self._assert_and_append_new_grp_rules(new_addr_grp_rules)

        # Verify NSX-T side
        self._verify_nsx_addr_grp(new_addr_grp, new_addr_grp_rules)

        # Delete the rules and the address group
        self._clean_neutron_sg_rules()
        self._clean_addr_groups()

        eventlet.sleep(5)

        # Verify NSX-T side cleanup
        self._verify_nsx_addr_grp_cleanup([new_grp_id], new_addr_grp_rules)

    ######################################################################################
    ####################################### Private Methods ##############################
    ######################################################################################

    def _sg_rule_template(self, ag_id, sg_id, direction, eth_type="IPv4", port="8080") -> dict:
        return {
            "security_group_rule": {
                "direction": direction,
                "ethertype": eth_type,
                "port_range_max": port,
                "port_range_min": port,
                "protocol": "tcp",
                "remote_address_group_id": ag_id,
                "security_group_id": sg_id
            }
        }

    def _verify_nsx_addr_grp(self, new_addr_grp, new_addr_grp_rules, sg_id=None):
        sg_id = sg_id or self.def_os_sg['id']
        nsx_sg_policy = self._fetch_nsx_policy(sg_id)
        self.assertTrue(nsx_sg_policy, "NSX-T Security Policy should exist")

        # Get all rules from the NSX-T Security Policy
        nsx_addr_grp_rule1, nsx_addr_grp_rule2 = self._get_rules_after_create(new_addr_grp_rules, sg_id)

        self.assertEqual(len(nsx_addr_grp_rule1), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            new_addr_grp_rules[0].get("security_group_rule", {}).get("id")))
        self.assertEqual(len(nsx_addr_grp_rule2), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            new_addr_grp_rules[1].get("security_group_rule", {}).get("id")))

        nsx_addr_grp_rule1 = nsx_addr_grp_rule1[0]
        nsx_addr_grp_rule2 = nsx_addr_grp_rule2[0]

        LOG.debug("NSX-T Security Policy Rule 1: {}".format(nsx_addr_grp_rule1))
        LOG.debug("NSX-T Security Policy Rule 2: {}".format(nsx_addr_grp_rule2))

        # Assert the rules have the expected source and destination address groups
        self.assertListEqual(nsx_addr_grp_rule1.get("source_groups"), [
                             API.GROUP_PATH.format(new_addr_grp["address_group"]["id"])])
        self.assertListEqual(nsx_addr_grp_rule1.get("destination_groups"), ["ANY"])
        self.assertListEqual(nsx_addr_grp_rule2.get("destination_groups"), [
                             API.GROUP_PATH.format(new_addr_grp["address_group"]["id"])])
        self.assertListEqual(nsx_addr_grp_rule2.get("source_groups"), ["ANY"])

        # Get groups from NSX-T and assert they contain the expected addresses
        nsx_addr_grp = self._fetch_nsx_group(new_addr_grp)
        nsx_ip_addrs: list = nsx_addr_grp["expression"][0]["ip_addresses"]
        os_ip_addrs: list = new_addr_grp["address_group"]["addresses"]
        nsx_ip_addrs.sort()
        os_ip_addrs.sort()
        self.assertListEqual(nsx_ip_addrs, os_ip_addrs)

    def _verify_nsx_addr_grp_cleanup(self, new_addr_grp_ids, new_addr_grp_rules, sg_id=None):
        sg_id = sg_id or self.def_os_sg['id']

        r = self._get_rules_after_clean(new_addr_grp_rules, sg_id)
        self.assertListEqual(r, [], "NSX-T Security Policy should have exactly 0 address group rules.")

        g = self._get_addr_grps_after_clean(new_addr_grp_ids)
        self.assertListEqual(g, [], "NSX-T should have exactly 0 address groups.")

    def _assert_nsx_cleanup(self, rule_ids=[], sg_id=None):
        LOG.debug("Asserting NSX-T cleanup rule_ids={}".format(rule_ids))

        sg_id = sg_id or self.def_os_sg['id']

        # Ensure NSX-T Security Policy has no Address Groups rules
        nsx_addr_grp_rules = self._get_rules_after_clean(rule_ids, sg_id)

        self.assertListEqual(nsx_addr_grp_rules, [],
                             "NSX-T Security Policy should have exactly 0 address group rules.")

    def _clean_addr_groups(self):
        if len(self.new_grp_ids) > 0:
            for new_grp_id in self.new_grp_ids:
                self.neutron_client.delete_address_group(new_grp_id)
                self.assertNotIn(new_grp_id, [ag['id']
                                              for ag in self.neutron_client.list_address_groups()['address_groups']])
            self.new_grp_ids = []

    def _revert_updated_ports(self):
        # Revert back the updated ports
        if self.existing_updated_ports and len(self.existing_updated_ports) > 0:
            for port in self.existing_updated_ports:
                self.neutron_client.update_port(
                    port.get("id"), {"port": {"security_groups": port.get("security_groups")}})

    def _clean_neutron_sg_rules(self):
        if len(self.new_addr_grp_rules) > 0:
            for new_addr_grp_rule in self.new_addr_grp_rules:
                self.neutron_client.delete_security_group_rule(new_addr_grp_rule['security_group_rule']['id'])
                self.assertNotIn(new_addr_grp_rule['security_group_rule']['id'], [r['id']
                                                                                  for r in self.neutron_client.list_security_group_rules()['security_group_rules']])
            self.new_addr_grp_rules = []

    def _clean_sec_groups(self):
        if len(self.new_sg_ids) > 0:
            for sg_id in self.new_sg_ids:
                self.neutron_client.delete_security_group(sg_id)
                self.assertNotIn(sg_id, [sg['id']
                                         for sg in self.neutron_client.list_security_groups()['security_groups']])
            self.new_sg_ids = []

    def _get_assert_new_grp_id(self, unique_addr_grp_name, new_addr_grp):
        new_grp_id = None
        if new_addr_grp:
            new_grp_id = new_addr_grp.get('address_group', {}).get('id')
            addresses = new_addr_grp.get('address_group', {}).get('addresses')
            self.new_grp_ids.append(new_grp_id)

        # Verify that the address group was created
        self.assertIn(unique_addr_grp_name, [ag['name']
                      for ag in self.neutron_client.list_address_groups()['address_groups']])
        LOG.info("Address Group created: {} with addresses: {}".format(new_grp_id, addresses))

        return new_grp_id

    def _get_assert_active_ports(self):
        ports = self.neutron_client.list_ports(
            device_owner="compute:nova", admin_state_up="True", status="ACTIVE").get('ports', [])
        self.assertTrue(ports and len(ports) > 0, "No active ports found")
        return ports

    def _assert_and_append_new_grp_rules(self, new_addr_grp_rules):
        for rule in new_addr_grp_rules:
            self.assertTrue(rule and rule.get('security_group_rule', {}).get('id'))
            self.new_addr_grp_rules.append(rule)

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def _fetch_nsx_policy(self, sg_id):
        nsx_sg_policy = self.nsx_client.get_unique(
            f"{API.SEARCH_QUERY}?query=resource_type:SecurityPolicy AND category:Application AND display_name:{sg_id}")
        if nsx_sg_policy and nsx_sg_policy.get("status", {}).get("publish_status") == "REALIZED" and nsx_sg_policy.get("status", {}).get("consolidated_status", {}).get("consolidated_status") == "SUCCESS":
            return nsx_sg_policy
        return None

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def _get_rules_after_clean(self, rule_ids, sg_id):
        rules = self.nsx_client.get_all(
            "/policy/api/v1/infra/domains/default/security-policies/{}/rules".format(sg_id))
        nsx_addr_grp_rules = [r for r in rules if r.get("display_name") in rule_ids]
        if len(nsx_addr_grp_rules) > 0:
            return None
        return nsx_addr_grp_rules

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=30)
    def _get_addr_grps_after_clean(self, addr_grp_ids):
        grps = self.nsx_client.get_all(API.GROUPS)
        nsx_addr_grps = [r for r in grps if r.get("display_name") in addr_grp_ids]
        if len(nsx_addr_grps) > 0:
            return None
        return nsx_addr_grps

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def _get_rules_after_create(self, new_addr_grp_rules, sg_id=None):
        sg_id = sg_id or self.def_os_sg['id']
        rules = self.nsx_client.get_all(
            "/policy/api/v1/infra/domains/default/security-policies/{}/rules".format(sg_id))

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

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def _fetch_nsx_group(self, new_addr_grp):
        resp = self.nsx_client.get(API.GROUP.format(new_addr_grp["address_group"]["id"]))
        if resp.ok:
            return resp.json()
        return None
