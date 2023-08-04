import eventlet
eventlet.monkey_patch()

from networking_nsxv3.common import config  # noqa
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx
from oslo_config import cfg
from oslo_log import log as logging
import os
import uuid
from neutron.tests import base
from novaclient import client as nova
from novaclient.v2.client import Client as NovaClient
from networking_nsxv3.tests.e2e import neutron
from keystoneauth1 import session
from keystoneauth1 import identity


LOG = logging.getLogger(__name__)


class TestAddressGroups(base.BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        g = os.environ.get

        logging.setup(cfg.CONF, "demo")

        cfg.CONF.set_override('debug', True)
        cfg.CONF.set_override("lock_path", "/tmp/", "oslo_concurrency")
        cfg.CONF.set_override("nsxv3_login_hostname", g("NSXV3_LOGIN_HOSTNAME"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_port", g("NSXV3_LOGIN_PORT"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_user", g("NSXV3_LOGIN_USER"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_password", g("NSXV3_LOGIN_PASSWORD"), "NSXV3")
        cfg.CONF.set_override("nsxv3_transport_zone_name", g("NSXV3_TRANSPORT_ZONE_NAME"), "NSXV3")
        cfg.CONF.set_override("nsxv3_connection_retry_count", "3", "NSXV3")
        cfg.CONF.set_override("nsxv3_request_timeout", "320", "NSXV3")

        http_p = "https" if g("OS_HTTPS") == 'true' else "http"
        os_auth_url = f"{http_p}://{g('OS_HOSTNAME')}/identity"
        cls.auth = identity.Password(auth_url=os_auth_url,
                                username=g("OS_USERNAME"),
                                password=g("OS_PASSWORD"),
                                project_name=g("OS_PROJECT_NAME"),
                                project_domain_id=g("OS_PROJECT_DOMAIN_ID"),
                                user_domain_id=g("OS_USER_DOMAIN_ID"))
        cls.sess = session.Session(auth=cls.auth, verify=False)

        cls.nova_client: NovaClient = nova.Client('2.1', session=cls.sess)
        cls.neutron_client = neutron.CustomNeutronClient(session=cls.sess)
        cls.nsx_client = client_nsx.Client()
        cls.nsx_client.version  # This will force the client to login

    def setUp(self):
        super().setUp()
        self.new_addr_grp_rules = []
        self.new_grp_ids = []

    def tearDown(self):
        super().tearDown()
        # Clean up & Assert cleanup
        if len(self.new_addr_grp_rules) > 0:
            for new_addr_grp_rule in self.new_addr_grp_rules:
                self.neutron_client.delete_security_group_rule(new_addr_grp_rule['security_group_rule']['id'])
                self.assertNotIn(new_addr_grp_rule['security_group_rule']['id'], [r['id']
                            for r in self.neutron_client.list_security_group_rules()['security_group_rules']])
        if len(self.new_grp_ids) > 0:
            for new_grp_id in self.new_grp_ids:
                self.neutron_client.delete_address_group(new_grp_id)
                self.assertNotIn(new_grp_id, [ag['id']
                        for ag in self.neutron_client.list_address_groups()['address_groups']])

    def test_create_ipv4_address_groups(self):
        self.unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.neutron_client.create_address_group(body={
                 "address_group": {
                     "addresses": ["192.168.0.1/32", "192.168.0.2/32", "192.168.0.3/32"],
                     "name": self.unique_addr_grp_name,
                     "description": "e2e test group"
                 }
             })
        if new_addr_grp:
            self.new_grp_ids.append(new_addr_grp.get('address_group', {}).get('id'))

        self.assertGreater(len(self.nova_client.servers.list()), 0, "At least one server should exist!")

        # Verify that the address group was created
        self.assertIn(self.unique_addr_grp_name, [ag['name']
                      for ag in self.neutron_client.list_address_groups()['address_groups']])

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

        # Create new rule with the new address group to the default security group
        self.new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "ingress",
                "ethertype": "IPv4",
                "port_range_max": "80",
                "port_range_min": "80",
                "protocol": "tcp",
                "remote_address_group_id": self.new_grp_ids[0],
                "security_group_id": default_sg['id']
            }
        }))
        self.new_addr_grp_rules.append(self.neutron_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "egress",
                "ethertype": "IPv4",
                "port_range_max": "80",
                "port_range_min": "80",
                "protocol": "tcp",
                "remote_address_group_id": self.new_grp_ids[0],
                "security_group_id": default_sg['id']
            }
        }))

        # Verify that the rule was created
        self.assertTrue(self.new_addr_grp_rules[0] and self.new_addr_grp_rules[0].get(
            'security_group_rule', {}).get('id'))
        self.assertTrue(self.new_addr_grp_rules[1] and self.new_addr_grp_rules[1].get(
            'security_group_rule', {}).get('id'))

        nsx_sg_policy = None
        retry_counter = 5
        while retry_counter > 0:
            eventlet.sleep(5)  # Wait for NSX-T to sync
            # Verify NSX-T side
            nsx_sg_policy = self.nsx_client.get_unique(
                f"/policy/api/v1/search/query?query=resource_type:SecurityPolicy AND category:Application AND display_name:{default_sg['id']}")
            self.assertTrue(nsx_sg_policy, "NSX-T Security Policy should exist")
            if nsx_sg_policy.get("status", {}).get("publish_status") == "REALIZED" and nsx_sg_policy.get("status", {}).get("consolidated_status", {}).get("consolidated_status") == "SUCCESS":
                break
            LOG.info(f"{retry_counter} Retrying until NSX-T Security Policy is realized: {nsx_sg_policy}")
            retry_counter -= 1

        if not nsx_sg_policy or not retry_counter:
            self.fail(f"NSX-T Security Policy with Name: {default_sg['id']} was not realized in time: {nsx_sg_policy}")

        # Get all rules from the NSX-T Security Policy
        rules = self.nsx_client.get_all(
            "/policy/api/v1/infra/domains/default/security-policies/{}/rules".format(default_sg['id']))

        # Assert that the NSX-T Security Policy has rules
        self.assertTrue(rules, "NSX-T Security Policy should have rules")
        self.assertGreater(len(rules), 0, "NSX-T Security Policy should have at least one rule")

        # Assert that the NSX-T Security Policy has the expected address group rule
        nsx_addr_grp_rule1 = [r for r in rules if r.get(
            "display_name") == self.new_addr_grp_rules[0].get("security_group_rule", {}).get("id")]
        nsx_addr_grp_rule2 = [r for r in rules if r.get(
            "display_name") == self.new_addr_grp_rules[1].get("security_group_rule", {}).get("id")]

        self.assertEqual(len(nsx_addr_grp_rule1), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            self.new_addr_grp_rules[0].get("security_group_rule", {}).get("id")))
        self.assertEqual(len(nsx_addr_grp_rule2), 1, "NSX-T Security Policy should have exactly one address group rule with name: {}".format(
            self.new_addr_grp_rules[1].get("security_group_rule", {}).get("id")))

        nsx_addr_grp_rule1 = nsx_addr_grp_rule1[0]
        nsx_addr_grp_rule2 = nsx_addr_grp_rule2[0]

        LOG.debug("NSX-T Security Policy Rule 1: {}".format(nsx_addr_grp_rule1))
        LOG.debug("NSX-T Security Policy Rule 2: {}".format(nsx_addr_grp_rule2))

        # Assert the rules have the expected source and destination address groups
        self.assertItemsEqual(nsx_addr_grp_rule1.get("source_groups"), new_addr_grp["address_group"]["addresses"])
        self.assertItemsEqual(nsx_addr_grp_rule2.get("destination_groups"), new_addr_grp["address_group"]["addresses"])

    def test_create_ipv6_address_groups(self):
        # TODO: Implement
        self.skipTest("Not implemented")

    def test_create_ipv4_address_groups_with_ipv6_members(self):
        # TODO: Implement
        self.skipTest("Not implemented")

    def test_create_ipv6_address_groups_with_ipv4_members(self):
        # TODO: Implement
        self.skipTest("Not implemented")

    def test_update_address_groups(self):
        # TODO: Implement

        # Add addresses to the address group
        # self.n_client.add_address_group_addresses(self.new_grp_id, body={
        #     "addresses": ["192.168.0.4/32"]
        # })
        self.skipTest("Not implemented")
