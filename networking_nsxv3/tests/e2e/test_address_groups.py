from keystoneauth1 import identity
from keystoneauth1 import session
from networking_nsxv3.tests.e2e import neutron
from neutron.tests import base
import uuid
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class TestAddressGroups(base.BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.username = 'admin'
        cls.password = 'admin'
        cls.project_name = 'admin'
        cls.project_domain_id = 'default'
        cls.user_domain_id = 'default'
        cls.auth_url = 'http://192.168.32.2/identity'
        cls.auth = identity.Password(auth_url=cls.auth_url,
                                username=cls.username,
                                password=cls.password,
                                project_name=cls.project_name,
                                project_domain_id=cls.project_domain_id,
                                user_domain_id=cls.user_domain_id)
        cls.sess = session.Session(auth=cls.auth, verify=False)
        cls.n_client = neutron.CustomNeutronClient(session=cls.sess)

    def setUp(self):
        super().setUp()
        self.new_addr_grp_rule = None
        self.new_grp_id = None
        self.unique_addr_grp_name = None

    def tearDown(self):
        super().tearDown()
        # Clean up & Assert cleanup
        if self.new_addr_grp_rule:
            self.n_client.delete_security_group_rule(self.new_addr_grp_rule['security_group_rule']['id'])
            self.assertNotIn(self.new_addr_grp_rule['security_group_rule']['id'], [r['id']
                        for r in self.n_client.list_security_group_rules()['security_group_rules']])
        if self.unique_addr_grp_name and self.new_grp_id:
            self.n_client.delete_address_group(self.new_grp_id)
            self.assertNotIn(self.unique_addr_grp_name, [ag['name']
                      for ag in self.n_client.list_address_groups()['address_groups']])

    def test_create_ipv4_address_groups(self):
        self.unique_addr_grp_name = str(uuid.uuid4())
        new_addr_grp = self.n_client.create_address_group(body={
                 "address_group": {
                     "addresses": ["192.168.0.1/32", "192.168.0.2/32", "192.168.0.3/32"],
                     "name": self.unique_addr_grp_name,
                     "description": "e2e test group"
                 }
             })
        self.new_grp_id = new_addr_grp.get('address_group', {}).get('id') if new_addr_grp else None

        # Verify that the address group was created
        self.assertTrue(self.new_grp_id)
        self.assertIn(self.unique_addr_grp_name, [ag['name']
                      for ag in self.n_client.list_address_groups()['address_groups']])

        # Get the default security group
        lsg = self.n_client.list_security_groups()
        default_sg = [sg for sg in lsg['security_groups'] if sg['name'] == 'default'][0]

        # Create new rule with the new address group to the default security group
        self.new_addr_grp_rule = self.n_client.create_security_group_rule(body={
            "security_group_rule": {
                "direction": "ingress",
                "ethertype": "IPv4",
                "port_range_max": "80",
                "port_range_min": "80",
                "protocol": "tcp",
                "remote_address_group_id": self.new_grp_id,
                "security_group_id": default_sg['id']
            }
        })

        # Verify that the rule was created
        self.assertTrue(self.new_addr_grp_rule and self.new_addr_grp_rule.get('security_group_rule', {}).get('id'))

        # TODO: Verify NSX-T side
        pass

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
