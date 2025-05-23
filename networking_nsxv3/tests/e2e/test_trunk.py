import eventlet
eventlet.monkey_patch()

from networking_nsxv3.common import config  # noqa
from novaclient.v2.servers import NetworkInterface
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
from networking_nsxv3.tests.e2e import base
import uuid
import os
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class TestTrunk(base.E2ETestCase):

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

        self.trunk_name = f"e2e_test_trunk_{uuid.uuid4()}"
        self.test_ports = [
            {"name": "e2e-trunk-parent-" + str(uuid.uuid4()), "id": None},
            {"name": "e2e-trunk-subp1-" + str(uuid.uuid4()), "id": None},
            {"name": "e2e-trunk-subp2-" + str(uuid.uuid4()), "id": None}
        ]

    def tearDown(self):
        super().tearDown()

        # Clean up & Assert cleanup
        LOG.info("Tearing down test case.")
        self.doCleanups()

    def test_trunk_create_delete(self):
        LOG.info("Testing creating and deleting a trunk.")

        # First Create test ports
        LOG.info(f"Creating test ports {[p['name'] for p in self.test_ports]}")
        self.create_test_ports()

        # Create the Trunk
        trunk = self._create_assert_trunk()

        # Delete the Trunk
        LOG.info(f"Deleting Trunk '{self.trunk_name}'")
        self.neutron_client.delete_trunk(trunk['trunk']['id'])

        # Assert Trunk is deleted
        LOG.info(f"Asserting Trunk '{self.trunk_name}' is deleted.")
        self.assertRaises(Exception, self.neutron_client.show_trunk, trunk['trunk']['id'])

    def test_attach_detach_trunk(self):
        LOG.info("Testing attaching and detaching a trunk to a server.")

        # First Create test ports
        LOG.info(f"Creating test ports {[p['name'] for p in self.test_ports]}")
        self.create_test_ports()

        # Create the Trunk
        trunk = self._create_assert_trunk()
        self.addCleanup(self.neutron_client.delete_trunk, trunk['trunk']['id'])

        # Attach the parent port to the test server
        LOG.info(f"Attaching trunk parent port '{self.trunk_parent_port['id']}' to the server '{self.test_server.id}'")
        self._attach_port_to_the_server(self.trunk_parent_port['id'])

        # Assert the trunk parent port is attached to the server
        LOG.info(
            f"Asserting trunk parent port '{self.trunk_parent_port['id']}' is attached to the server '{self.test_server.id}'")
        parent_port = self.neutron_client.show_port(self.trunk_parent_port['id'])['port']
        self.assertEqual(self.test_server.id, parent_port['device_id'],
                         "Trunk parent port is not attached to the server.")
        server_ports: list[NetworkInterface] = self.nova_client.servers.interface_list(self.test_server.id)
        self.assertTrue(any(p.port_id == parent_port['id'] for p in server_ports),
                        "Trunk parent port is not attached to the server.")

        # Assert port is created in NSX and has the correct attachment details
        LOG.info(f"Asserting trunk parent port '{parent_port['id']}' is created in NSX.")
        nsx_port = self.get_nsx_port_by_os_id(parent_port['id'])
        self.assertIsNotNone(nsx_port)
        self.assertEqual(parent_port['id'], nsx_port['display_name'], "NSX Port display name is not as expected.")
        self.assertEqual(parent_port['id'], nsx_port['attachment']['id'], "NSX Port attachment id is not as expected.")
        self.assertEqual("PARENT", nsx_port['attachment']['type'], "NSX Port attachment type is not as expected.")
        self.assertEqual(parent_port['binding:vif_details']["segmentation_id"], nsx_port['attachment']['traffic_tag'],
                         "NSX Port attachment traffic tag is not as expected.")

        # Assert all subports are also created in NSX and have the correct attachment details
        LOG.info(
            f"Asserting trunk subports {[ p['port_id'] for p in parent_port['trunk_details']['sub_ports']]} are created in NSX.")
        for p in parent_port['trunk_details']['sub_ports']:
            nsx_port = self.get_nsx_port_by_os_id(p['port_id'])
            self.assertIsNotNone(nsx_port)
            self.assertEqual(p['port_id'], nsx_port['display_name'], "NSX Port display name is not as expected.")
            self.assertEqual(p['port_id'], nsx_port['attachment']['id'], "NSX Port attachment id is not as expected.")
            self.assertEqual("CHILD", nsx_port['attachment']['type'], "NSX Port attachment type is not as expected.")
            self.assertEqual(p['segmentation_id'], nsx_port['attachment']['traffic_tag'],
                             "NSX Port attachment traffic tag is not as expected.")

        # Assert the server ports participate in the correct security groups in NSX
        LOG.info(
            f"Asserting the server '{self.test_server.name}' ports participate in the correct security groups in NSX.")
        self.assert_os_ports_nsx_sg_membership(server_ports)

        # Unattach the parent port from the test server
        LOG.info(
            f"Unattaching trunk parent port '{parent_port['id']}' from the server '{self.test_server.id}'")
        self.nova_client.servers.interface_detach(self.test_server.id, parent_port['id'])
        eventlet.sleep(5)

        # Assert the trunk parent port is unattached from the server and is unbound
        LOG.info(
            f"Asserting trunk parent port '{parent_port['id']}' is unattached from the server '{self.test_server.id}' and is unbound.")
        parent_port = self.neutron_client.show_port(parent_port['id'])['port']
        self.assertFalse(bool(parent_port['device_id']), "Trunk parent port is still attached to the server.")
        self.assertEqual('unbound', parent_port['binding:vif_type'], "Trunk parent port is still bound to host.")
        self.assertEqual({}, parent_port['binding:vif_details'], "Trunk parent port is still bound to host.")

    def test_add_remove_trunk_subports(self):
        LOG.info("Testing adding and removing subports to a trunk.")

        # First Create test ports
        LOG.info(f"Creating test ports {[p['name'] for p in self.test_ports]}")
        self.create_test_ports()

        # Create the Trunk
        trunk = self._create_assert_trunk()
        self.addCleanup(self.neutron_client.delete_trunk, trunk['trunk']['id'])

        # Attach the parent port to the test server
        self._attach_port_to_the_server(self.trunk_parent_port['id'])

        # Add a new subport
        new_port = self.create_new_port()
        self.neutron_client.trunk_add_subports(trunk['trunk']['id'], {
            'sub_ports': [{'port_id': new_port['id'], 'segmentation_type': 'vlan', 'segmentation_id': 300}]
        })

        # Assert the new subport is added to the trunk
        trunk1 = self.neutron_client.show_trunk(trunk['trunk']['id'])
        self.assertIsNotNone(trunk1)
        t = trunk1['trunk']
        self.assertEqual(3, len(t['sub_ports']), "Trunk subports count is not as expected.")
        self.assertEqual(new_port['id'], t['sub_ports'][2]['port_id'], "Trunk subport is not as expected.")

        # Assert the new subport is attached to the server
        new_port = self.neutron_client.show_port(new_port['id'])['port']
        self.assertEqual(self.test_server.id, new_port['device_id'], "Trunk subport is not attached to the server.")

        # Assert the new subport is created in NSX and has the correct attachment details
        nsx_port = self.get_nsx_port_by_os_id(new_port['id'])
        self.assertIsNotNone(nsx_port)
        self.assertEqual(new_port['id'], nsx_port['display_name'], "NSX Port display name is not as expected.")

        # Remove the new subport
        self.neutron_client.trunk_remove_subports(trunk['trunk']['id'], {
            'sub_ports': [{'port_id': new_port['id']}]
        })

        # Assert the new subport is removed from the trunk
        trunk2 = self.neutron_client.show_trunk(trunk['trunk']['id'])
        self.assertIsNotNone(trunk2)
        t = trunk2['trunk']
        self.assertEqual(2, len(t['sub_ports']), "Trunk subports count is not as expected.")
        self.assertNotEqual(new_port['id'], t['sub_ports'][0]['port_id'], "Trunk subport is not removed.")
        self.assertNotEqual(new_port['id'], t['sub_ports'][1]['port_id'], "Trunk subport is not removed.")

        # Assert the new subport is unattached from the server and is unbound
        new_port = self.neutron_client.show_port(new_port['id'])['port']
        self.assertFalse(bool(new_port['device_id']), "Trunk subport is still attached to the server.")
        self.assertEqual('unbound', new_port['binding:vif_type'], "Trunk subport is still bound to host.")
        self.assertEqual({}, new_port['binding:vif_details'], "Trunk subport is still bound to host.")

    def test_create_server_with_trunk(self):
        LOG.info("Testing creating a server with a trunk.")

        # First Create test ports
        LOG.info(f"Creating test ports {[p['name'] for p in self.test_ports]}")
        self.create_test_ports()

        # Create the Trunk
        trunk = self._create_assert_trunk()
        self.addCleanup(self.neutron_client.delete_trunk, trunk['trunk']['id'])

        # Create a new server with the trunk
        server_name = os.environ.get("E2E_CREATE_SERVER_NAME_PREFIX", "os-e2e-test-") + str(uuid.uuid4())
        img_name = os.environ.get("E2E_CREATE_SERVER_IMAGE_NAME", "cirros-0.3.2-i386-disk")
        flvr_name = os.environ.get("E2E_CREATE_SERVER_FLAVOR_NAME", "m1.nano")
        sg_name = "default"

        LOG.info(f"Creating server '{server_name}' with\n"
                 f" - trunk: '{self.trunk_name}'\n"
                 f" - image: '{img_name}'\n"
                 f" - flavor: '{flvr_name}'\n"
                 f" - security group: '{sg_name}'")

        server = self.create_test_server(name=server_name,
                                         image_name=img_name,
                                         flavor_name=flvr_name,
                                         security_groups=[sg_name],
                                         nic_ports=[{
                                             "port-id": self.trunk_parent_port['id'],
                                             "net-id": self.trunk_parent_port['network_id']
                                         }])
        self.addCleanup(self.nova_client.servers.delete, server.id)

        # Assert the server is created
        server1 = self.nova_client.servers.get(server.id)
        self.assertIsNotNone(server1)

        # Assert the server has the correct trunk attached
        LOG.info(f"Asserting server '{server_name}' has trunk '{self.trunk_name}' attached.")
        server_ports = self.nova_client.servers.interface_list(server.id)
        self.assertTrue(any(p.port_id == self.trunk_parent_port['id'] for p in server_ports),
                        "Trunk parent port is not attached to the server.")
        self.assertTrue(any(p.port_id == self.trunk_child_ports[0]['id'] for p in server_ports),
                        "Trunk subport1 is not attached to the server.")
        self.assertTrue(any(p.port_id == self.trunk_child_ports[1]['id'] for p in server_ports),
                        "Trunk subport2 is not attached to the server.")

        # Assert the server ports are created in NSX and have the correct attachment details
        LOG.info(f"Asserting server '{server_name}' ports are created in NSX.")
        for p in server_ports:
            nsx_port = self.get_nsx_port_by_os_id(p.port_id)
            self.assertIsNotNone(nsx_port)
            self.assertEqual(p.port_id, nsx_port['display_name'], "NSX Port display name is not as expected.")
            self.assertEqual(p.port_id, nsx_port['attachment']['id'], "NSX Port attachment id is not as expected.")
            self.assertEqual("PARENT" if p.port_id == self.trunk_parent_port['id'] else "CHILD",
                             nsx_port['attachment']['type'], "NSX Port attachment type is not as expected.")

        # Assert the server ports participate in the correct security groups in NSX
        LOG.info(f"Asserting the server '{server_name}' ports participate in the correct security groups in NSX.")
        self.assert_os_ports_nsx_sg_membership(server_ports)

    ###################################################################################
    ###################################################################################

    def _attach_port_to_the_server(self, port_id: str):
        """ Attach the port (port_id) to the test server (self.test_server).
        """
        self.nova_client.servers.interface_attach(
            server=self.test_server.id,
            port_id=port_id,
            net_id=None,
            fixed_ip=None
        )

    def _create_assert_trunk(self) -> dict:
        """ Create a trunk and assert its properties. The ports are not attached to any VM.
            :return: The created trunk
        """
        # Get the created ports from OpenStack
        self.trunk_parent_port = self.neutron_client.show_port(self.test_ports[0]['id'])['port']
        self.trunk_child_ports = [self.neutron_client.show_port(port['id'])['port'] for port in self.test_ports[1:]]

        # Create Trunk
        LOG.info(f"Creating Trunk '{self.trunk_name}' with parent port '{self.trunk_parent_port['id']}' "
                 f"and subports '{[p['id'] for p in self.trunk_child_ports]}'")
        trunk = self.neutron_client.create_trunk({
            'trunk': {
                'name': self.trunk_name,
                'port_id': self.trunk_parent_port['id'],
                'sub_ports': [
                    {'port_id': self.trunk_child_ports[0]['id'], 'segmentation_type': 'vlan', 'segmentation_id': 100},
                    {'port_id': self.trunk_child_ports[1]['id'], 'segmentation_type': 'vlan', 'segmentation_id': 200}
                ]
            }
        })
        self.assertIsNotNone(trunk)

        # Assert Trunk is created
        trunk1 = self.neutron_client.show_trunk(trunk['trunk']['id'])
        self.assertIsNotNone(trunk1)

        expected_child1 = self.trunk_child_ports[0]
        expected_child2 = self.trunk_child_ports[1]
        t = trunk1['trunk']
        trunk_child1 = t['sub_ports'][0]
        trunk_child2 = t['sub_ports'][1]

        self.assertEqual("DOWN", t['status'], "Trunk status is not DOWN.")
        self.assertTrue(t['admin_state_up'], "Trunk admin state is not UP.")
        self.assertEqual(self.trunk_name, t['name'], "Trunk name is not as expected.")
        self.assertEqual(self.trunk_parent_port['id'], t['port_id'], "Trunk parent port is not as expected.")
        self.assertEqual(2, len(t['sub_ports']), "Trunk subports count is not as expected.")
        self.assertEqual(expected_child1['id'], trunk_child1['port_id'], "Trunk subport1 is not as expected.")
        self.assertEqual(100, trunk_child1['segmentation_id'], "Trunk subport1 segmentation id is not as expected.")
        self.assertEqual(expected_child2['id'], trunk_child2['port_id'], "Trunk subport2 is not as expected.")
        self.assertEqual(200, trunk_child2['segmentation_id'], "Trunk subport2 segmentation id is not as expected.")

        # Assert trunk ports are not created in NSX as they are not attached to any VM
        LOG.info(f"Asserting trunk ports are not created in NSX as they are not attached to any VM")
        for port in self.test_ports:
            nsx_port = self.get_nsx_port_by_os_id(port['id'])
            self.assertIsNone(nsx_port)
        return trunk
