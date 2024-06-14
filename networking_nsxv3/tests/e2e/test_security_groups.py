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
        random_remote = []
        if self.test_sgs:
            if len(self.test_sgs) > 0:
                random_remote.append({"description": "E2E Test Random Remote Ingress IPv4/TCP rule with remote group", "direction": "ingress",
                                      "ethertype": "IPv4", "protocol": "tcp", "remote_group_id": random.choice(self.test_sgs)['id']})
            if len(self.test_sgs) > 2:
                random_remote.append({"description": "E2E Test Random Remote Ingress IPv6/TCP rule with remote group", "direction": "ingress",
                                      "ethertype": "IPv6", "protocol": "tcp", "remote_group_id": random.choice(self.test_sgs)['id']})

        remote_group_rules = [
            {"description": "E2E Test Egress IPv4/UDP rule with remote group", "direction": "egress",
                "ethertype": "IPv4", "protocol": "udp", "remote_group_id": self.def_os_sg['id']},
            {"description": "E2E Test Ingress IPv6/TCP rule with remote group", "direction": "ingress",
                "ethertype": "IPv6", "protocol": "tcp", "remote_group_id": self.def_os_sg['id']}
        ]
        remote_group_rules.extend(random_remote)

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
        self._test_add_port_to_security_group(rule_types=['remote_ip_prefix'], sg_count=4)

    def test_add_port_to_security_group_tag_membership_remote_group(self):
        LOG.info("Testing Add Port to Security Group with Tag Membership and Remote Group Rules")
        self._test_add_port_to_security_group(rule_types=['remote_group'], sg_count=4)

    def test_add_port_to_security_group_tag_membership_icmp(self):
        LOG.info("Testing Add Port to Security Group with Tag Membership and ICMP Rules")
        self._test_add_port_to_security_group(rule_types=['icmp'], sg_count=4)

    def test_add_port_to_security_group_tag_membership_port_range(self):
        LOG.info("Testing Add Port to Security Group with Tag Membership and Port Range Rules")
        self._test_add_port_to_security_group(rule_types=['port_range'], sg_count=4)

    def test_add_port_to_security_group_static_membership_all(self):
        LOG.info("Testing Add Port to Security Group with Static Membership and All Rules")
        self._test_add_port_to_security_group(rule_types=['all'], sg_count=30, stateful_count=30)

    def test_update_port_security_group(self):
        LOG.info("Testing Update Port Security Group")
        self._test_add_port_to_security_group(rule_types=['all'], sg_count=3, stateful_count=1)

        # Update the port to remove the Security Groups
        LOG.info("Updating Ports to remove the Security Groups")
        for port in self.test_ports:
            self.neutron_client.update_port(port['id'], {'port': {'security_groups': []}})

        # Sleep for a few seconds to allow the ports to be removed from the Security Groups
        eventlet.sleep(10)

        # Assert Security Groups are deleted in NSX
        LOG.info("Verifying Security Groups are deleted in NSX")
        failed = []
        for sg in self.test_sgs:
            sg_members = self.get_sg_members_no_retry(sg['id'])
            retry = 10
            sg_fail = True
            while retry > 0:
                retry -= 1
                if len(sg_members) == 0:
                    sg_fail = False
                    break
                LOG.info(f"Security Group {sg['id']} still has {len(sg_members)} members in NSX. Retrying...")
                eventlet.sleep(30)
            if sg_fail:
                failed.append(sg['id'])
        self.assertEqual(len(failed), 0, f"Security Groups {failed} still have members in NSX.")

    def test_add_remove_rules_to_security_group(self):
        LOG.info("Testing Add and Remove Rules to Security Group")
        self._test_add_port_to_security_group(rule_types=['all'], sg_count=3, stateful_count=2)

        # Add more rules to the security groups
        LOG.info("Adding more rules to the Security Groups")
        self.add_rules_to_security_groups(rule_types=['icmp'])

        # Sleep for a few seconds to allow the rules to be added to the Security Groups
        eventlet.sleep(10)

        # Assert Security Group Rules are created in NSX
        LOG.info("Verifying Security Group Rules are created in NSX")
        self.assert_nsx_sg_rules()

        # Remove the rules from the security groups
        LOG.info("Removing Rules from the Security Groups")
        self.add_rules_to_security_groups(rule_types=[])

        # Sleep for a few seconds to allow the rules to be removed
        eventlet.sleep(10)

        # Assert the rules are deleted in NSX
        LOG.info("Verifying Security Group Rules are deleted in NSX")
        failed = []
        for sg in self.test_sgs:
            retry = 10
            LOG.info(f"Waiting for Security Group {sg['id']} to delete rules in NSX...")
            rule_fail = True
            while retry > 0:
                retry -= 1
                nsx_rules = self.get_nsx_rules_no_retry(sg['id'])
                if len(nsx_rules) == 0:
                    rule_fail = False
                    break
                LOG.info(f"Security Group {sg['id']} still has {len(nsx_rules)} rules in NSX. Retrying...")
                eventlet.sleep(30)
            if rule_fail:
                failed.append(sg['id'])

        self.assertEqual(len(failed), 0, f"Security Groups {failed} still have rules in NSX.")

    def _test_add_port_to_security_group(self, rule_types, sg_count, stateful_count=None):
        # Create some Security Groups and store their IDs
        LOG.info(f"Creating {sg_count} Security Groups")
        self.create_security_groups(sg_count=sg_count, statefull_count=stateful_count)

        # Add Rules to the security groups
        LOG.info("Adding Rules to the Security Groups")
        self.add_rules_to_security_groups(rule_types=rule_types)

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
        self.assert_ports_in_os_sgs()

        # Attach the ports to the server
        LOG.info(f"Attaching Ports to the Test Server '{self.test_server1_name}'")
        self.attach_test_ports_to_test_server()

        # Sleep for a few seconds to allow the ports to be attached to the server
        eventlet.sleep(10)

        # Assert Security Groups are created in NSX and the ports are associated with them
        LOG.info("Verifying Security Groups are created in NSX and the ports are associated with them")
        self.assert_ports_in_nsx_sgs()

        # Assert Security Group Rules are created in NSX
        LOG.info("Verifying Security Group Rules are created in NSX")
        self.assert_nsx_sg_rules()

    ##############################################################################################
    ##############################################################################################

    def get_sgs_slice(self, stateful=True):
        if stateful:
            return [sg for sg in self.test_sgs if sg['stateful']]
        return [sg for sg in self.test_sgs if not sg['stateful']]

    def add_rules_to_security_groups(self, rule_types=['all']):
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
            if 'all' in rule_types or 'remote_ip_prefix' in rule_types:
                rules.extend(remote_ip_prefix_rules)

            # 2. Remote Group rule types
            if 'all' in rule_types or 'remote_group' in rule_types:
                rules.extend(remote_group_rules)

            # 3. ICMP rule types
            if 'all' in rule_types or 'icmp' in rule_types:
                rules.extend(icmp_rules)

            # 4. Port range rule types
            if 'all' in rule_types or 'port_range' in rule_types:
                rules.extend(port_range_rules)

            # Create the rules
            for rule_fixture in rules:
                LOG.debug(f"Creating rule: {rule_fixture['description']}")
                rule_params["security_group_rule"] = {
                    "security_group_id": sg['id']
                }
                rule_params["security_group_rule"].update(rule_fixture)
                self.neutron_client.create_security_group_rule(rule_params)

        # Assert the rules are created in OpenStack by checking the number of rules in each Security Group
        for sg in self.test_sgs:
            sg_os = self.neutron_client.show_security_group(sg['id'])['security_group']
            self.assertIsNotNone(sg_os, f"Security Group {sg['id']} not found in OpenStack.")
            self.assertGreaterEqual(len(sg_os['security_group_rules']), len(rules))

    def create_security_groups(self, sg_count=10, statefull_count=None):
        """
        Create multiple security groups and store their IDs in the self.test_sgs list.
        The security groups are created with random names.
        If statefull_count==None then half of them are stateful otherwise 'statefull_count' are stateful.

        Args:
            sg_count (int): The number of security groups to create. Default is 10.
            statefull_count (int): The number of stateful security groups to create. Default is None.

        Returns:
            None

        Raises:
            AssertionError: If any of the security groups fail to be created.

        """
        self.test_sgs = self.sgs_fixture(n=sg_count)
        count_stateful = int(sg_count / 2) if statefull_count is None else statefull_count

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

    def assert_nsx_sg_rules(self):
        for sg in self.test_sgs:
            os_sg = self.neutron_client.show_security_group(sg['id'])['security_group']
            self.assertIsNotNone(os_sg, f"Security Group {sg['id']} not found in OpenStack.")

            osrules = os_sg['security_group_rules']
            self.assertIsNotNone(osrules, f"Security Group {sg['id']} has no rules in OpenStack.")

            nsx_sg = self.get_nsx_sg_by_os_id(os_sg['id'])
            self.assertIsNotNone(nsx_sg, f"Security Group {os_sg['id']} not found in NSX.")

            nsx_sg_rules = self.get_nsx_rules(os_sg_id=os_sg['id'], desired_count=len(osrules))

            self.assertIsNotNone(nsx_sg_rules, f"""Security Group {os_sg['id']} has no rules in NSX or the number of rules in NSX is incorrect.
                                 Expected: {len(osrules)} Rules, Found: {len(self.get_nsx_rules_no_retry(os_sg['id']))} Rules.""")
            self.assertEqual(len(nsx_sg_rules), len(osrules),
                             f"Security Group {os_sg['id']} has incorrect number of rules in NSX.")

            osrules_by_sg_id, nsx_rules_by_sg_id = self._group_os_nsx_rules(osrules, nsx_sg_rules)
            rules_direction_map = {
                'ingress': 'IN',
                'egress': 'OUT'
            }
            for sg_id, os_rules in osrules_by_sg_id.items():
                nsx_rules = nsx_rules_by_sg_id.get(sg_id, [])
                self.assertEqual(len(os_rules), len(nsx_rules),
                                 f"Security Group {sg_id} has incorrect number of rules in NSX.")
                # Assert the rules are the same ID in both OpenStack and NSX
                for os_rule in os_rules:
                    nsx_rule = next((r for r in nsx_rules if r['id'] == os_rule['id']), None)
                    self._assert_rule_profiles(os_rule, nsx_rule)
                    self._assert_rule_scope(os_rule, nsx_rule)
                    self.assertIsNotNone(nsx_rule, f"Rule {os_rule['id']} not found in NSX.")
                    self.assertEqual('ALLOW', nsx_rule['action'], f"Rule {os_rule['id']} has incorrect action in NSX.")
                    self.assertEqual(os_rule['ethertype'].upper(), nsx_rule['ip_protocol'].upper(),
                                     f"Rule {os_rule['id']} has incorrect ethertype in NSX.")
                    self.assertEqual(rules_direction_map.get(
                        os_rule['direction']), nsx_rule['direction'], f"Rule {os_rule['id']} has incorrect direction in NSX.")
                    self._assert_rule_port_range(os_rule, nsx_rule)
                    self._assert_rule_remote_ip_prefix(os_rule, nsx_rule)
                    self._assert_rule_remote_group_id(os_rule, nsx_rule)
                    self._assert_rule_protocol(os_rule, nsx_rule)

    def _assert_rule_profiles(self, os_rule, nsx_rule):
        self.assertEqual("ANY", nsx_rule['profiles'][0], f"Rule {os_rule['id']} has incorrect profile in NSX.")

    def _assert_rule_scope(self, os_rule, nsx_rule):
        self.assertEqual("ANY", nsx_rule['scope'][0], f"Rule {os_rule['id']} has incorrect scope in NSX.")

    def _assert_rule_port_range(self, os_rule, nsx_rule):
        if os_rule['port_range_min'] is not None and os_rule['port_range_max'] is not None:
            if os_rule['port_range_min'] == os_rule['port_range_max']:
                self.assertEqual(f"{os_rule['port_range_min']}", f"{nsx_rule['service_entries'][0]['destination_ports'][0]}",
                                 f"Rule {os_rule['id']} has incorrect port range in NSX.")
            else:
                self.assertEqual(f"{os_rule['port_range_min']}-{os_rule['port_range_max']}", nsx_rule['service_entries']
                                 [0]['destination_ports'][0], f"Rule {os_rule['id']} has incorrect port range in NSX.")

    def _assert_rule_remote_ip_prefix(self, os_rule, nsx_rule):
        if os_rule['remote_ip_prefix']:
            if os_rule["direction"] == "ingress":
                self.assertIn(os_rule['remote_ip_prefix'], nsx_rule['source_groups'],
                              f"Rule {os_rule['id']} has incorrect remote_ip_prefix in NSX.")
            elif os_rule["direction"] == "egress":
                self.assertIn(os_rule['remote_ip_prefix'], nsx_rule['destination_groups'],
                              f"Rule {os_rule['id']} has incorrect remote_ip_prefix in NSX.")

    def _assert_rule_remote_group_id(self, os_rule, nsx_rule):
        if os_rule['remote_group_id']:
            if os_rule["direction"] == "ingress":
                self.assertIn(f"/infra/domains/default/groups/{os_rule['remote_group_id']}",
                              nsx_rule['source_groups'], f"Rule {os_rule['id']} has incorrect remote_group_id in NSX.")
            elif os_rule["direction"] == "egress":
                self.assertIn(f"/infra/domains/default/groups/{os_rule['remote_group_id']}",
                              nsx_rule['destination_groups'], f"Rule {os_rule['id']} has incorrect remote_group_id in NSX.")

    def _assert_rule_protocol(self, os_rule, nsx_rule):
        if os_rule['protocol'] == 'icmp':
            if os_rule['ethertype'] == "IPv4":
                self.assertEqual("ICMPv4", nsx_rule.get('service_entries', [{}])[0].get(
                    'protocol'), f"Rule {os_rule['id']} has incorrect L4 protocol in NSX.")
            elif os_rule['ethertype'] == "IPv6":
                self.assertEqual("ICMPv6", nsx_rule.get('service_entries', [{}])[0].get(
                    'protocol'), f"Rule {os_rule['id']} has incorrect L4 protocol in NSX.")
        if os_rule['protocol'] == 'tcp' or os_rule['protocol'] == 'udp':
            self.assertEqual(os_rule['protocol'].upper(), nsx_rule['service_entries'][0]
                             ['l4_protocol'].upper(), f"Rule {os_rule['id']} has incorrect protocol in NSX.")

    def _group_os_nsx_rules(self, osrules, nsx_sg_rules):
        # Group all osrules by 'security_group_id' key
        osrules_by_sg_id: dict[str, list[dict]] = {}
        for rule in osrules:
            sg_id = rule['security_group_id']
            osrules_by_sg_id.setdefault(sg_id, []).append(rule)

            # Group all nsx_sg_rules by 'parent_path' key
        nsx_rules_by_sg_id: dict[str, list[dict]] = {}
        for nsx_rule in nsx_sg_rules:
            nsx_sg_id = nsx_rule['parent_path'].split('/')[-1]
            nsx_rules_by_sg_id.setdefault(nsx_sg_id, []).append(nsx_rule)

        return osrules_by_sg_id, nsx_rules_by_sg_id

    def assert_ports_in_nsx_sgs(self):
        attached_ports = self.test_server.interface_list()
        for p in self.test_ports:
            self.assertIn(p['id'], [p.id for p in attached_ports], f"Port {p['id']} not attached to the server.")
        self.assert_os_ports_nsx_sg_membership(attached_ports)

    def assert_ports_in_os_sgs(self):
        for i, port in enumerate(self.test_ports):
            sgs_slice = self.get_sgs_slice(stateful=i % 2 == 0)
            os_port = self.neutron_client.show_port(port['id'])['port']
            self.assertIsNotNone(os_port, f"Port {port['id']} not found in OpenStack.")
            self.assertEqual(len(os_port['security_groups']), len(sgs_slice),
                             f"Port {port['id']} is not in the correct number of Security Groups.")
            for sg in sgs_slice:
                self.assertIn(sg['id'], os_port['security_groups'],
                              f"Port {port['id']} is not in Security Group {sg['id']}.")
