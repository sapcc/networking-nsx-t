import eventlet
eventlet.monkey_patch()

from novaclient.v2.servers import Server
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
from networking_nsxv3.tests.e2e import base
import os
import uuid
from oslo_log import log as logging
import ipaddress
import random
import copy

from networking_nsxv3.common import config  # noqa

LOG = logging.getLogger(__name__)


class TestPorts(base.E2ETestCase):

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
            {"name": "e2e-port-" + str(uuid.uuid4()), "id": None},
            {"name": "e2e-port-" + str(uuid.uuid4()), "id": None},
            {"name": "e2e-port-" + str(uuid.uuid4()), "id": None}
        ]

        self.new_server: Server = None

    def tearDown(self):
        super().tearDown()

        # Clean up & Assert cleanup
        LOG.info("Tearing down test case.")
        self.doCleanups()
        self._assert_ports_cleanup()
        self._assert_server_cleanup()

    def test_create_ports(self):
        LOG.info("Testing port creation and deletion.")

        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.test_ports]} on network '{self.test_network['name']}'.")
        self.create_test_ports()

        # Assert created ports are in the list of all ports
        LOG.info(f"Asserting created ports are in the list of all ports (in OpenStack).")
        ports_after_create = self.neutron_client.list_ports()
        for port in self.test_ports:
            self.assertIn(port['id'], [p['id'] for p in ports_after_create['ports']])

        # Assert the ports are NOT created on the NSX side as they are not attached to a server
        LOG.info(f"Asserting created ports are NOT created in NSX as they are not attached to a server.")
        for port in self.test_ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNone(nsx_port)

    def test_create_standalone_ports_and_attach(self):
        LOG.info("Testing port creation, attachment and detachment.")

        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.test_ports]} on network '{self.test_network['name']}'.")
        self.create_test_ports()

        # Attach the ports to the test server
        LOG.info(f"Attaching ports to server '{self.test_server.name}'.")
        self._attach_ports()

        # Assert the ports are attached to the correct server
        LOG.info(
            f"Asserting the ports {[p['name'] for p in self.test_ports]} are attached to server '{self.test_server.name}' in Openstack.")
        for port in self.test_ports:
            self.assertEqual(self.test_server.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Assert the ports are created on the NSX side
        LOG.info(f"Asserting the ports {[p['name'] for p in self.test_ports]} are created in NSX.")
        for port in self.test_ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)

        # Get Port Security Groups and assert the port participates in them at the NSX side
        LOG.info(
            f"Asserting the server '{self.test_server.name}' ports participate in the correct security groups in NSX.")
        self.assert_server_nsx_ports_sgs(self.test_server.interface_list())

    def test_detach_port(self):
        LOG.info("Testing port detachment.")

        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.test_ports]} on network '{self.test_network['name']}'.")
        self.create_test_ports()

        # First attach the ports
        LOG.info(f"Attaching ports to server '{self.test_server.name}'.")
        self._attach_ports()

        # Assert the ports are attached to the correct server
        LOG.info(
            f"Asserting the ports {[p['name'] for p in self.test_ports]} are attached to server '{self.test_server.name}' in Openstack.")
        for port in self.test_ports:
            self.assertEqual(self.test_server.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Detach the ports from the server
        for port in self.test_ports:
            # Assert that the port deattachment operations is successful
            LOG.info(f"Detaching port '{port['name']}' from server '{self.test_server.name}'.")
            result = self.nova_client.servers.interface_detach(server=self.test_server.id, port_id=port['id'])
            self.assertIsNotNone(result, "Port deattachment operation failed.")

        # We can not verify the port is removed from NSX as it will be removed after some time,
        # defined by the "nsxv3_remove_orphan_ports_after" setting of the agent.

    def test_create_server(self):
        LOG.info("Testing server creation and deletion.")

        img_name = os.environ.get("E2E_CREATE_SERVER_IMAGE_NAME", "cirros-0.3.2-i386-disk")
        flvr_name = os.environ.get("E2E_CREATE_SERVER_FLAVOR_NAME", "m1.nano")
        srv_name = os.environ.get("E2E_CREATE_SERVER_NAME_PREFIX", "os-e2e-test-") + str(uuid.uuid4())
        sg_name = "default"
        net = self.test_network

        LOG.info(
            f"Creating a server '{srv_name}' on network '{net['name']}' with image '{img_name}', flavor '{flvr_name}' and security group '{sg_name}'.")
        self.new_server = self.create_test_server(
            srv_name, img_name, flvr_name, net['id'], security_groups=[sg_name])
        self.addCleanup(self.nova_client.servers.delete, self.new_server.id)

        # Assert server has the "default" security group
        LOG.info(f"Asserting server '{self.new_server.name}' has the 'default' security group in OpenStack.")
        self._assert_os_server_default_sg(self.new_server)

        # Assert that on NSX side the server has the default security group
        LOG.info(f"Asserting server '{self.new_server.name}' has the 'default' security group in NSX.")
        self._assert_server_nsx_sg(self.new_server)

        # Assert the server's ports are created on the NSX side
        LOG.info(f"Asserting server '{self.new_server.name}' has its ports created in NSX.")
        self._assert_server_nsx_ports(self.new_server)

        # Assert the server's ports are members of the correct security groups in NSX
        LOG.info(f"Asserting server '{self.new_server.name}' ports are members of the correct security groups in NSX.")
        self.assert_server_nsx_ports_sgs(self.new_server.interface_list())

    def test_assign_unassign_ipv4_to_port(self):
        LOG.info("Testing IPv4 assignment and unassignment to ports.")

        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.test_ports]} on network '{self.test_network['name']}'.")
        self.create_test_ports()

        # Attach the ports to the test server
        LOG.info(f"Attaching ports to server '{self.test_server.name}'.")
        self._attach_ports()

        # Assert the ports are attached to the correct server
        LOG.info(
            f"Asserting the ports {[p['name'] for p in self.test_ports]} are attached to server '{self.test_server.name}' in Openstack.")
        for port in self.test_ports:
            self.assertEqual(self.test_server.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Assert the ports are created on the NSX side
        LOG.info(f"Asserting the ports {[p['name'] for p in self.test_ports]} are created in NSX.")
        for port in self.test_ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)

        # Get Port Security Groups and assert the port participates in them at the NSX side
        LOG.info(
            f"Asserting the server '{self.test_server.name}' ports participate in the correct security groups in NSX.")
        self.assert_server_nsx_ports_sgs(self.test_server.interface_list())

        # Get the CIDR from the specified netowrk subnets on the OpenStack side
        cidr = self.neutron_client.show_subnet(self.test_network['subnets'][0])['subnet']['cidr']
        all_ips = [str(ip) for ip in ipaddress.IPv4Network(cidr)]
        ips = copy.deepcopy(all_ips[2:-2])
        self._assign_ips_to_ports(ips)

        # Assert the IPs assigned to the ports
        self._assert_ips_assigned(cidr, all_ips)

        # Unassign an IP from the ports
        self._unassign_ips_from_ports()

        # Assert the IPs is unassigned from the ports
        self._assert_ips_unassigned()

    def test_assign_unassign_ipv6_to_port(self):
        LOG.info("Testing IPv6 assignment and unassignment to ports.")

        # Create an entire new network for this test
        net_name = "e2e-test-ipv6-" + str(uuid.uuid4())
        LOG.info(f"Creating a new network '{net_name}' for the test.")
        self._create_network(net_name)

        # Create an IPv6 subnet for the network
        LOG.info(f"Creating an IPv6 subnet for the network '{net_name}'.")
        subnet = self.neutron_client.create_subnet({
            "subnet": {
                "network_id": self.test_network['id'],
                "ip_version": 6,
                "cidr": "2002:db8::/122"
            }
        })
        self.addCleanup(self.neutron_client.delete_subnet, subnet['subnet']['id'])

        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.test_ports]} on network '{self.test_network['name']}'.")
        self.create_test_ports()

        # Attach the ports to the test server
        LOG.info(f"Attaching ports to server '{self.test_server.name}'.")
        self._attach_ports()

        # Assert the ports are attached to the correct server
        LOG.info(
            f"Asserting the ports {[p['name'] for p in self.test_ports]} are attached to server '{self.test_server.name}' in Openstack.")
        for port in self.test_ports:
            self.assertEqual(self.test_server.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Assert the ports are created on the NSX side
        LOG.info(f"Asserting the ports {[p['name'] for p in self.test_ports]} are created in NSX.")
        for port in self.test_ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)

        # Assign an unique random IPv6 from the network subnet to each port
        cidr = subnet['subnet']['cidr']
        all_ips = [str(ip) for ip in ipaddress.IPv6Network(cidr)]
        ips = copy.deepcopy(all_ips[2:-2])
        self._assign_ips_to_ports(ips)

        # Assert the IPs assigned to the ports
        self._assert_ips_assigned(cidr, all_ips)

        # Unassign an IP from the ports
        self._unassign_ips_from_ports()

        # Assert the IPs is unassigned from the ports
        self._assert_ips_unassigned()

    ##############################################################################################
    ##############################################################################################

    def _assert_ports_cleanup(self):
        ports_after_cleanup = self.neutron_client.list_ports()

        # Assert deleted ports are not in the list of all ports
        if self.test_ports:
            for port in self.test_ports:
                self.assertNotIn(port['id'], [p['id'] for p in ports_after_cleanup.get('ports', [])])

    def _assert_server_cleanup(self):
        if self.new_server:
            # Await server deletion
            c = 10
            while True:
                c -= 1
                try:
                    self.nova_client.servers.get(self.new_server.id)
                    if c == 0:
                        self.fail(f"The server '{self.new_server.name}' is not deleted for {c * 10} seconds.")
                    eventlet.sleep(10)
                except Exception as e:
                    break
            # Assert server is deleted
            self.assertRaises(Exception, self.nova_client.servers.get, self.new_server.id,
                              f"The server '{self.new_server.name}' is not deleted.")

    def _assert_server_nsx_ports(self, server: Server):
        for port in server.interface_list():
            nsx_port = self.get_nsx_port_by_os_id(port.id)
            self.assertIsNotNone(nsx_port, f"OS '{port.id}' Port not found in NSX.")
            self.assertIn(port.mac_addr, [p['mac_address'] for p in nsx_port['address_bindings']],
                          "OS Port MAC address not found in the realized NSX Port.")
            self.assertIn(port.fixed_ips[0]['ip_address'], [
                          p['ip_address'] for p in nsx_port['address_bindings']], "OS Port IP address not found in the realized NSX Port.")

    def _assert_server_nsx_sg(self, server: Server):
        sg_id = next((sg.id for sg in server.list_security_group() if sg.name == "default"), None)
        nsx_sg = self.get_nsx_sg_by_os_id(sg_id)
        self.assertIsNotNone(nsx_sg, "Security Group 'default' not found in NSX.")

    def _assert_os_server_default_sg(self, server: Server):
        self.assertIn("default", [sg.name for sg in server.list_security_group()])

    def _assert_ips_assigned(self, cidr, all_ips):
        # Assert the IP is assigned to the ports in OpenStack
        for port in self.test_ports:
            port_info = self.neutron_client.show_port(port['id'])['port']
            for ip in port_info['fixed_ips']:
                self.assertIn(
                    ip['ip_address'], all_ips, f"Assigned IP '{ip['ip_address']}' is not in the CIDR '{cidr}' for port '{port['name']}'.")

        # Assert the IP is assigned to the ports in NSX
        for port in self.test_ports:
            eventlet.sleep(10)  # Wait for the NSX to update the port
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)
            port_info = self.neutron_client.show_port(port['id'])['port']
            for ip in port_info['fixed_ips']:
                self.assertIn(ip['ip_address'], [p['ip_address'] for p in nsx_port['address_bindings']],
                              f"Assigned IP '{ip['ip_address']}' is not in the NSX Port for port '{port['name']}'.")

    def _assert_ips_unassigned(self):
        # Assert the IPs are unassigned from the ports in OpenStack
        for port in self.test_ports:
            port_info = self.neutron_client.show_port(port['id'])['port']
            self.assertEqual(len(port_info['fixed_ips']), 1, f"Port '{port['name']}' has more than one IP assigned.")

        # Assert the IPs are unassigned from the ports in NSX
        for port in self.test_ports:
            eventlet.sleep(10)
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)
            port_info = self.neutron_client.show_port(port['id'])['port']
            self.assertEquals(len(nsx_port['address_bindings']), 1,
                              f"NSX Port for port '{port['name']}' has more than one IP assigned.")
            self.assertEquals(port_info['fixed_ips'][0]['ip_address'], nsx_port['address_bindings'][0]['ip_address'],
                              f"NSX Port for port '{port['name']}' has different IP assigned.")

    def _attach_ports(self):
        """ Attach the ports to the test server (self.test_server). Also add cleanup for detachment.
        """
        for port in self.test_ports:
            self.nova_client.servers.interface_attach(
                server=self.test_server.id,
                port_id=port['id'],
                net_id=None,
                fixed_ip=None
            )
            self.addCleanup(self.nova_client.servers.interface_detach, server=self.test_server.id, port_id=port['id'])

    def _assign_ips_to_ports(self, ips):
        """ Assign the IPs to the ports in self.test_ports, from the list of IPs provided.
        """
        for port in self.test_ports:
            # Get random IP from the CIDR
            ip = random.choice(ips)
            ips.pop(ips.index(ip))
            LOG.info(f"Assigning IP '{ip}' to port '{port['name']}'.")
            p = self.neutron_client.show_port(port['id'])['port']
            # Append the IP to the port fixed IPs
            p['fixed_ips'].append({"ip_address": ip})
            self.neutron_client.update_port(port['id'], {"port": {"fixed_ips": p['fixed_ips']}})

    def _unassign_ips_from_ports(self):
        """ Unassign the IPs from the ports in self.test_ports.
        """
        for port in self.test_ports:
            port_info = self.neutron_client.show_port(port['id'])['port']
            ip = port_info['fixed_ips'].pop()
            LOG.info(f"Unassigning IP '{ip['ip_address']}' from port '{port['name']}'.")
            self.neutron_client.update_port(port['id'], {"port": {"fixed_ips": port_info['fixed_ips']}})

    def _create_network(self, net_name):
        self.neutron_client.create_network({"network": {"name": net_name}})
        self.set_test_network(net_name)
        self.addCleanup(self.neutron_client.delete_network, self.test_network['id'])
