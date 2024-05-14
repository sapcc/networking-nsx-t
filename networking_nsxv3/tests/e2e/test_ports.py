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
        servers = self.nova_client.servers.list()
        self.test_server1: Server = next((s for s in servers if s.name == self.test_server1_name), None)

        # Get the network with the name defined in the class
        networks = self.neutron_client.list_networks()
        self.existing_test_network = next(
            (n for n in networks['networks'] if n['name'] == self.test_network1_name), None)

        # Assert the server and network are found
        self.assertIsNotNone(self.test_server1)
        self.assertIsNotNone(self.existing_test_network)

        # Generate a random names for ports
        self.ports = [
            {"name": "test-port-" + str(uuid.uuid4()), "id": None},
            {"name": "test-port-" + str(uuid.uuid4()), "id": None},
            {"name": "test-port-" + str(uuid.uuid4()), "id": None}
        ]

        self.new_server: Server = None

    def tearDown(self):
        super().tearDown()
        # Clean up & Assert cleanup
        LOG.info("Tearing down test case.")

        # Delete created ports
        self._cleanup_created_ports()

        # Delete created server
        self._cleanup_created_server()

    def test_create_ports(self):
        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.ports]} on network '{self.existing_test_network['name']}'.")
        self._create_ports()

        # Assert created ports are in the list of all ports
        LOG.info(f"Asserting created ports are in the list of all ports (in OpenStack).")
        ports_after_create = self.neutron_client.list_ports()
        for port in self.ports:
            self.assertIn(port['id'], [p['id'] for p in ports_after_create['ports']])

        # Assert the ports are NOT created on the NSX side as they are not attached to a server
        LOG.info(f"Asserting created ports are NOT created in NSX as they are not attached to a server.")
        for port in self.ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNone(nsx_port)

    def test_create_standalone_ports_and_attach(self):
        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.ports]} on network '{self.existing_test_network['name']}'.")
        self._create_ports()

        # Attach the ports to the test server
        LOG.info(f"Attaching ports to server '{self.test_server1.name}'.")
        self._attach_ports()

        # Assert the ports are attached to the correct server
        LOG.info(
            f"Asserting the ports {[p['name'] for p in self.ports]} are attached to server '{self.test_server1.name}' in Openstack.")
        for port in self.ports:
            self.assertEqual(self.test_server1.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Assert the ports are created on the NSX side
        LOG.info(f"Asserting the ports {[p['name'] for p in self.ports]} are created in NSX.")
        for port in self.ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)

        # Get Port Security Groups and assert the port participates in them at the NSX side
        LOG.info(
            f"Asserting the server '{self.test_server1.name}' ports participate in the correct security groups in NSX.")
        self._assert_server_nsx_ports_sgs(self.test_server1.interface_list())

    def test_detach_port(self):
        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.ports]} on network '{self.existing_test_network['name']}'.")
        self._create_ports()

        # First attach the ports
        LOG.info(f"Attaching ports to server '{self.test_server1.name}'.")
        self._attach_ports()

        # Assert the ports are attached to the correct server
        LOG.info(
            f"Asserting the ports {[p['name'] for p in self.ports]} are attached to server '{self.test_server1.name}' in Openstack.")
        for port in self.ports:
            self.assertEqual(self.test_server1.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Detach the ports from the server
        for port in self.ports:
            # Assert that the port deattachment operations is successful
            LOG.info(f"Detaching port '{port['name']}' from server '{self.test_server1.name}'.")
            result = self.nova_client.servers.interface_detach(server=self.test_server1.id, port_id=port['id'])
            self.assertIsNotNone(result, "Port deattachment operation failed.")

        # We can not verify the port is removed from NSX as it will be removed after some time,
        # defined by the "nsxv3_remove_orphan_ports_after" setting of the agent.

    def test_create_server(self):
        img_name = os.environ.get("E2E_CREATE_SERVER_IMAGE_NAME", "cirros-0.3.2-i386-disk")
        flvr_name = os.environ.get("E2E_CREATE_SERVER_FLAVOR_NAME", "m1.nano")
        srv_name = os.environ.get("E2E_CREATE_SERVER_NAME_PREFIX", "os-e2e-test-") + str(uuid.uuid4())
        sg_name = "default"
        net = self.existing_test_network

        LOG.info(
            f"Creating a server '{srv_name}' on network '{net['name']}' with image '{img_name}', flavor '{flvr_name}' and security group '{sg_name}'.")
        self.new_server = self.create_test_server(
            srv_name, img_name, flvr_name, net['id'], security_groups=[sg_name])

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
        self._assert_server_nsx_ports_sgs(self.new_server.interface_list())

    def test_assign_unassign_ipv4_to_port(self):
        # Create a ports on the network
        LOG.info(
            f"Creating ports {[p['name'] for p in self.ports]} on network '{self.existing_test_network['name']}'.")
        self._create_ports()

        # Attach the ports to the test server
        LOG.info(f"Attaching ports to server '{self.test_server1.name}'.")
        self._attach_ports()

        # Assert the ports are attached to the correct server
        LOG.info(
            f"Asserting the ports {[p['name'] for p in self.ports]} are attached to server '{self.test_server1.name}' in Openstack.")
        for port in self.ports:
            self.assertEqual(self.test_server1.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Assert the ports are created on the NSX side
        LOG.info(f"Asserting the ports {[p['name'] for p in self.ports]} are created in NSX.")
        for port in self.ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)

        # Get Port Security Groups and assert the port participates in them at the NSX side
        LOG.info(
            f"Asserting the server '{self.test_server1.name}' ports participate in the correct security groups in NSX.")
        self._assert_server_nsx_ports_sgs(self.test_server1.interface_list())

        # Get the CIDR from the specified netowkr subnets on the OpenStack side
        cidr = self.neutron_client.show_subnet(self.existing_test_network['subnets'][0])['subnet']['cidr']
        all_ips = [str(ip) for ip in ipaddress.IPv4Network(cidr)]
        ips = copy.deepcopy(all_ips[2:-2])
        for port in self.ports:
            # Get random IP from the CIDR
            ip = random.choice(ips)
            ips.pop(ips.index(ip))
            LOG.info(f"Assigning IP '{ip}' to port '{port['name']}'.")
            p = self.neutron_client.show_port(port['id'])['port']
            # Append the IP to the port fixed IPs
            p['fixed_ips'].append({"ip_address": ip})
            self.neutron_client.update_port(port['id'], {"port": {"fixed_ips": p['fixed_ips']}})

        # Assert the IP is assigned to the port
        for port in self.ports:
            port_info = self.neutron_client.show_port(port['id'])['port']
            for ip in port_info['fixed_ips']:
                self.assertIn(
                    ip['ip_address'], all_ips, f"Assigned IP '{ip['ip_address']}' is not in the CIDR '{cidr}' for port '{port['name']}'.")

        # Assert the IP is assigned to the port in NSX
        for port in self.ports:
            eventlet.sleep(10)  # Wait for the NSX to update the port
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)
            port_info = self.neutron_client.show_port(port['id'])['port']
            for ip in port_info['fixed_ips']:
                self.assertIn(ip['ip_address'], [p['ip_address'] for p in nsx_port['address_bindings']],
                              f"Assigned IP '{ip['ip_address']}' is not in the NSX Port for port '{port['name']}'.")

        # Unassign an IP from the ports
        for port in self.ports:
            port_info = self.neutron_client.show_port(port['id'])['port']
            ip = port_info['fixed_ips'].pop()
            LOG.info(f"Unassigning IP '{ip['ip_address']}' from port '{port['name']}'.")
            self.neutron_client.update_port(port['id'], {"port": {"fixed_ips": port_info['fixed_ips']}})

        # Assert the IP is unassigned from the port
        for port in self.ports:
            port_info = self.neutron_client.show_port(port['id'])['port']
            self.assertEqual(len(port_info['fixed_ips']), 1, f"Port '{port['name']}' has more than one IP assigned.")

        # Assert the IP is unassigned from the port in NSX
        for port in self.ports:
            eventlet.sleep(10)
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNotNone(nsx_port)
            port_info = self.neutron_client.show_port(port['id'])['port']
            self.assertEquals(len(nsx_port['address_bindings']), 1,
                              f"NSX Port for port '{port['name']}' has more than one IP assigned.")
            self.assertEquals(port_info['fixed_ips'][0]['ip_address'], nsx_port['address_bindings'][0]['ip_address'],
                              f"NSX Port for port '{port['name']}' has different IP assigned.")

    def test_assign_unassign_ipv6_to_port(self):
        # TODO: Implement this test
        pass

    ##############################################################################################
    ##############################################################################################

    def _cleanup_created_ports(self):
        for port in self.ports:
            if port['id']:
                self.neutron_client.delete_port(port['id'])

        ports_after_cleanup = self.neutron_client.list_ports()

        # Assert deleted ports are not in the list of all ports
        for port in self.ports:
            self.assertNotIn(port['id'], [p['id'] for p in ports_after_cleanup.get('ports', [])])

    def _cleanup_created_server(self):
        if self.new_server:
            self.nova_client.servers.delete(self.new_server.id)
            # Await server deletion
            while True:
                try:
                    self.nova_client.servers.get(self.new_server.id)
                    eventlet.sleep(10)
                except Exception as e:
                    break
            # Assert server is deleted
            self.assertRaises(Exception, self.nova_client.servers.get, self.new_server.id)

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

    def _assert_server_nsx_ports_sgs(self, ports: list):
        for port in ports:
            port_sgs = self.neutron_client.show_port(port.id)['port']['security_groups']
            # For each SG get the Group from NSX and its members
            for sg_id in port_sgs:
                nsx_ports_for_sg = self.get_nsx_sg_effective_members(sg_id)
                self.assertIsNotNone(nsx_ports_for_sg, f"Security Group {sg_id} not found in NSX.")
                # Assert the port is a member of the SG
                nsx_port = next((p for p in nsx_ports_for_sg if p['display_name'] == port.id), None)
                self.assertIsNotNone(nsx_port, f"Port {port.id} not found in Security Group {sg_id} in NSX.")

    def _create_ports(self):
        for port in self.ports:
            result = self.neutron_client.create_port({
                "port": {
                    "network_id": self.existing_test_network['id'],
                    "name": port['name']
                }
            })
            port['id'] = result['port']['id']

    def _attach_ports(self):
        for port in self.ports:
            self.nova_client.servers.interface_attach(
                server=self.test_server1.id,
                port_id=port['id'],
                net_id=None,
                fixed_ip=None
            )
