import eventlet
eventlet.monkey_patch()

from neutronclient.common.exceptions import NotFound
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
import random
import ipaddress
from oslo_log import log as logging
import uuid
import os
from networking_nsxv3.tests.e2e import base
from novaclient.v2.servers import Server

from networking_nsxv3.common import config  # noqa

LOG = logging.getLogger(__name__)


class TestSecurityGroups(base.E2ETestCase):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self.test_network1_name = os.environ.get("E2E_NETWORK_NAME", None)
        self.test_server1_name = os.environ.get("E2E_SERVER_NAME", None)

    def setUp(self):
        super().setUp()
        # self.skipTest("Skipping test temporarily.")

        if not self.test_network1_name:
            self.fail("E2E_NETWORK_NAME is not set. Please set it to the name of the network to use for testing.")
        if not self.test_server1_name:
            self.fail("E2E_SERVER_NAME is not set. Please set it to the name of the server to use for testing.")

        # Get the server with the name defined in the class
        self.set_test_server(self.test_server1_name)

        # Get the network with the name defined in the class
        self.set_test_network(self.test_network1_name)

        ports = self.neutron_client.list_ports(network_id=self.test_network['id'])['ports']
        if ports and len(ports) > 0:
            self.fail(f"Network '{self.test_network['name']}' has ports. Please use a network without ports.")

        self.test_network['subnets'] = [s['id'] for s in self.neutron_client.list_subnets(
            network_id=self.test_network['id'])['subnets']]
        if not self.test_network['subnets'] or len(self.test_network['subnets']) < 1:
            self.fail(f"Network '{self.test_network['name']}' has no subnets. Please use a network with subnets.")

        # Generate a random names for ports
        self.test_ports = [
            {"name": "e2e-sg-port-" + str(uuid.uuid4()), "id": None},
            {"name": "e2e-sg-port-" + str(uuid.uuid4()), "id": None},
            {"name": "e2e-sg-port-" + str(uuid.uuid4()), "id": None}
        ]

        self.test_sgs = []
        self.def_os_sg = self.get_os_default_security_group()

        self.new_server: Server = None

    def tearDown(self):
        super().tearDown()

        # Clean up & Assert cleanup
        LOG.info("Tearing down test case.")
        self.doCleanups()
        self.assert_security_groups_deleted()

    def test_create_security_group(self):
        LOG.info("Testing Create Security Groups")

        # Create some Security Groups and store their IDs
        self.create_security_groups()

        # Add all types of rules to the security groups
        LOG.info("Adding rules to the Security Groups")
        self.add_rules_to_security_groups()

        # Assert the Security Groups are NOT created in NSX, as there are no ports associated with them
        LOG.info("Verifying Security Groups are NOT created in NSX, as there are no ports associated with them.")
        for sg in self.test_sgs:
            nsx_sg = self.get_nsx_sg_by_os_id(sg['id'])
            self.assertIsNone(nsx_sg, f"Security Group {sg['id']} was created in NSX, but it should not have been.")

    def test_add_port_to_security_group_tag_membership_remote_ip_prefix(self):
        LOG.info("Testing Add Port to Security Group with Tag Membership and Remote IP Prefix Rules")
        self._test_add_port_to_security_group(rules=['remote_ip_prefix'], sg_count=4)

    def test_add_port_to_security_group_static_membership_remote_ip_prefix(self):
        LOG.info("Testing Add Port to Security Group with Static Membership and Remote IP Prefix Rules")
        self._test_add_port_to_security_group(rules=['remote_ip_prefix'], sg_count=60)

    def _test_add_port_to_security_group(self, rules, sg_count):
        # Create some Security Groups and store their IDs
        LOG.info(f"Creating {sg_count} Security Groups")
        self.create_security_groups(sg_count=sg_count)

        # Add Remote IP Prefix rules to the security groups
        LOG.info("Adding Remote IP Prefix rules to the Security Groups")
        self.add_rules_to_security_groups(rules=rules)

        # Create a port and associate it with the Security Groups
        LOG.info(f"Creating {len(self.test_ports)} Ports")
        self.create_test_ports()

        LOG.info("Adding Ports to the Security Groups")
        for i, port in enumerate(self.test_ports):
            sgs_slice = self.get_sgs_slice(stateful=i % 2 == 0)
            self.neutron_client.update_port(port['id'], {'port': {'security_groups': [sg['id'] for sg in sgs_slice]}})

        # Sleep for a few seconds to allow the ports to be added to the Security Groups
        eventlet.sleep(10)

        # Assert the ports are added to the Security Groups in OpenStack
        LOG.info("Verifying Ports are added to the Security Groups in OpenStack")
        for i, port in enumerate(self.test_ports):
            sgs_slice = self.get_sgs_slice(stateful=i % 2 == 0)
            os_port = self.neutron_client.show_port(port['id'])['port']
            self.assertIsNotNone(os_port, f"Port {port['id']} not found in OpenStack.")
            self.assertEqual(len(os_port['security_groups']), len(sgs_slice),
                             f"Port {port['id']} is not in the correct number of Security Groups.")
            for sg in sgs_slice:
                self.assertIn(sg['id'], os_port['security_groups'],
                              f"Port {port['id']} is not in Security Group {sg['id']}.")

        # Attach the ports to the server
        LOG.info(f"Attaching Ports to the Test Server '{self.test_server1_name}'")
        self.attach_test_ports_to_test_server()

        # Sleep for a few seconds to allow the ports to be attached to the server
        eventlet.sleep(10)

        # Assert Security Groups are created in NSX and the ports are associated with them
        LOG.info("Verifying Security Groups are created in NSX and the ports are associated with them")
        attached_ports = self.test_server.interface_list()
        for p in self.test_ports:
            self.assertIn(p['id'], [p.id for p in attached_ports], f"Port {p['id']} not attached to the server.")
        self.assert_os_ports_nsx_sg_membership(attached_ports)

    ##############################################################################################
    ##############################################################################################

    def get_sgs_slice(self, stateful=True):
        if stateful:
            return [sg for sg in self.test_sgs if sg['stateful']]
        return [sg for sg in self.test_sgs if not sg['stateful']]

    def add_rules_to_security_groups(self, rules=['all']):
        """
        Adds rules to the security groups.

        This method clears all the existing rules in the security groups and then adds rules to each security group.
        The rules include ingress and egress rules for both IPv4 and IPv6, ICMP rules, remote group rules,
        and remote IP prefix rules.

        Parameters:
        rule_types (lsit[str]): The types of rules to add. Default is 'all'.
                                Other options are 'icmp', 'remote_group', 'remote_ip_prefix', 'port_range'

        Returns:
            None
        """

        # First clear all the rules in the security group
        for sg in self.test_sgs:
            sg_os = self.neutron_client.show_security_group(sg['id'])['security_group']
            self.assertIsNotNone(sg_os, f"Security Group {sg['id']} not found in OpenStack.")
            for rule in sg_os['security_group_rules']:
                self.neutron_client.delete_security_group_rule(rule['id'])

        # Assert the rules are deleted in OpenStack by checking the number of rules in each Security Group
        for sg in self.test_sgs:
            sg_os = self.neutron_client.show_security_group(sg['id'])['security_group']
            self.assertIsNotNone(sg_os, f"Security Group {sg['id']} not found in OpenStack.")
            self.assertEqual(len(sg_os['security_group_rules']), 0)

        for sg in self.test_sgs:
            LOG.info(f"Adding rules to Security Group {sg['id']} ({sg['name']})")
            # Define the rule parameters
            rule_params = {
                "security_group_rule": {}
            }
            # Define the list of rule types to create
            remote_ip_prefix_rules, remote_group_rules, icmp_rules, port_range_rules = self.sg_rules_fixture()
            rules = []

            # 1. Remote IP Prefix rule types
            if 'all' in rules or 'remote_ip_prefix' in rules:
                rules.extend(remote_ip_prefix_rules)

            # 2. Remote Group rule types
            if 'all' in rules or 'remote_group' in rules:
                rules.extend(remote_group_rules)

            # 3. ICMP rule types
            if 'all' in rules or 'icmp' in rules:
                rules.extend(icmp_rules)

            # 4. Port range rule types
            if 'all' in rules or 'port_range' in rules:
                rules.extend(port_range_rules)

            # Create the rules
            for rule_type in rules:
                LOG.info(f"Creating rule: {rule_type['description']}")
                rule_params["security_group_rule"] = {
                    "security_group_id": sg['id']
                }
                rule_params["security_group_rule"].update(rule_type)
                self.neutron_client.create_security_group_rule(rule_params)

        # Assert the rules are created in OpenStack by checking the number of rules in each Security Group
        for sg in self.test_sgs:
            sg_os = self.neutron_client.show_security_group(sg['id'])['security_group']
            self.assertIsNotNone(sg_os, f"Security Group {sg['id']} not found in OpenStack.")
            self.assertGreaterEqual(len(sg_os['security_group_rules']), len(rules))

    def create_security_groups(self, sg_count=10):
        """
        Create multiple security groups and store their IDs in the self.test_sgs list.
        The method creates a number of security groups with half of them being stateful and the other half stateless.

        Args:
            sg_count (int): The number of security groups to create. Default is 10.

        Returns:
            None
        """
        self.test_sgs = self.sgs_fixture(n=sg_count)
        count_stateful = int(sg_count / 2)

        LOG.info(f"Creating {sg_count} Security Groups, with {count_stateful} of them being stateful.")
        for i, sg in enumerate(self.test_sgs):
            stateful = i < count_stateful
            LOG.info(f"Creating {'STATEFUL' if stateful else 'STATELESS'} Security Group: {sg['name']}")
            result = self.neutron_client.create_security_group(
                {"security_group": {"name": sg['name'], "stateful": stateful}})
            sg['id'] = result['security_group']['id']
            sg['stateful'] = stateful
            self.assertIsNotNone(sg['id'])
            self.addCleanup(self.neutron_client.delete_security_group, sg['id'])

        # Verify the Security Groups are created in OpenStack
        LOG.info("Verifying Security Groups are created in OpenStack")
        for sg in self.test_sgs:
            sg_os = self.neutron_client.show_security_group(sg['id'])['security_group']
            self.assertIsNotNone(sg_os, f"Security Group {sg['id']} not found in OpenStack.")
            self.assertDictContainsSubset({
                'id': sg['id'],
                'name': sg['name'],
            }, sg_os)

    def assert_security_groups_deleted(self):
        """
        Assert that the security groups are deleted.
        """
        for sg in self.test_sgs:
            self.assertRaises(NotFound, self.neutron_client.show_security_group, sg['id'])

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=1, sleep_duration=2)
    def get_nsx_sg_by_os_id(self, os_sg_id):
        resp = self.nsx_client.get(API.GROUP.format(os_sg_id))
        if resp.ok:
            return resp.json()
        return None

    def sgs_fixture(self, n=10):
        """
        Generate a list of security group fixtures.

        Args:
            n (int): The number of security group fixtures to generate. Default is 10.

        Returns:
            list: A list of dictionaries representing the security group fixtures. Each dictionary
                  contains the 'name' and 'id' of the security group.
        """
        return [
            {"name": f"e2e-sg{i+1}-" + str(uuid.uuid4()), "id": None, "stateful": None}
            for i in range(n)
        ]

    def sg_rules_fixture(self):
        """
        Returns a tuple containing different types of security group rules.

        The tuple contains the following rule types:
        1. Remote IP Prefix rule types
        2. Remote Group rule types
        3. ICMP rule types
        4. Port range rule types

        Each rule type is represented as a dictionary with specific attributes.

        Returns:
            tuple: A tuple containing different types of security group rules.
        """
        # 1. Remote IP Prefix rule types
        remote_prefix_rules = [
            {"description": "E2E Test Egress IPv4/TCP rule with random remote IP prefix", "direction": "egress",
             "ethertype": "IPv4", "protocol": "tcp", "remote_ip_prefix": str(ipaddress.IPv4Address(random.randint(0, 2**32-1)))},
            {"description": "E2E Test Ingress IPv6/TCP rule with random remote IP prefix", "direction": "ingress",
             "ethertype": "IPv6", "protocol": "tcp", "remote_ip_prefix": str(ipaddress.IPv6Address(random.randint(0, 2**128-1)))}
        ]

        # 2. Remote Group rule types
        remote_group_rules = [
            {"description": "E2E Test Egress IPv4/UDP rule with remote group", "direction": "egress",
                "ethertype": "IPv4", "protocol": "udp", "remote_group_id": self.def_os_sg['id']},
            {"description": "E2E Test Ingress IPv6/UDP rule with remote group", "direction": "ingress",
                "ethertype": "IPv6", "protocol": "tcp", "remote_group_id": self.def_os_sg['id']}
        ]

        # 3. ICMP rule types
        icmp_rules = [
            {"description": "E2E Test Ingress IPv4/ICMP rule",
                "direction": "ingress", "ethertype": "IPv4", "protocol": "icmp"},
            {"description": "E2E Test Egress IPv4/ICMP rule", "direction": "egress", "ethertype": "IPv4", "protocol": "icmp"},
            {"description": "E2E Test Ingress IPv6/ICMP rule",
                "direction": "ingress", "ethertype": "IPv6", "protocol": "icmp"},
            {"description": "E2E Test Egress IPv6/ICMP rule", "direction": "egress", "ethertype": "IPv6", "protocol": "icmp"}
        ]

        # 4. Port range rule types
        port_range_rules = [
            {"description": "E2E Test Egress IPv4/ANY rule", "direction": "egress",
                "ethertype": "IPv4", "protocol": None, "port_range_min": None, "port_range_max": None},
            {"description": "E2E Test Ingress IPv4/UDP port range (1024-2048) rule", "direction": "ingress",
             "ethertype": "IPv4", "protocol": "udp", "port_range_min": 1024, "port_range_max": 2048},
            {"description": "E2E Test Ingress IPv4/TCP HTTP rule", "direction": "ingress",
                "ethertype": "IPv4", "protocol": "tcp", "port_range_min": 80, "port_range_max": 80},
            {"description": "E2E Test Egress IPv4/TCP HTTPS rule", "direction": "egress",
                "ethertype": "IPv4", "protocol": "tcp", "port_range_min": 443, "port_range_max": 443},
            {"description": "E2E Test Ingress IPv6/TCP HTTPS rule", "direction": "ingress",
                "ethertype": "IPv6", "protocol": "tcp", "port_range_min": 443, "port_range_max": 443},
            {"description": "E2E Test Egress IPv6/TCP port range (1024-65525) rule", "direction": "egress",
             "ethertype": "IPv6", "protocol": "tcp", "port_range_min": 1024, "port_range_max": 65535}
        ]

        return (remote_prefix_rules, remote_group_rules, icmp_rules, port_range_rules)
