import eventlet
eventlet.monkey_patch()

from novaclient.v2.servers import Server
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
from networking_nsxv3.tests.e2e import base
import uuid
import os
from oslo_log import log as logging


from networking_nsxv3.common import config  # noqa

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
            {"name": "test-trunk-" + str(uuid.uuid4()), "id": None}
        ]

    def tearDown(self):
        super().tearDown()

        # Clean up & Assert cleanup
        LOG.info("Tearing down test case.")
        self.doCleanups()

    def test_trunk_create_delete(self):
        # First Create test poty
        self.create_test_ports()

        # Get the created port from OS
        self.test_server1_port = self.neutron_client.show_port(self.test_ports[0]['id'])['port']

        # Create Trunk
        LOG.info(f"Creating Trunk '{self.trunk_name}' with parent port '{self.test_server1_port['id']}'")
        trunk = self.neutron_client.create_trunk(
            {'trunk': {'name': self.trunk_name, 'port_id': self.test_server1_port['id']}})
        self.assertIsNotNone(trunk)

        # Assert Trunk is created
        trunk1 = self.neutron_client.show_trunk(trunk['trunk']['id'])
        self.assertIsNotNone(trunk1)

        self.assertEqual("DOWN", trunk1['trunk']['status'], "Trunk status is not DOWN.")
        self.assertTrue(trunk1['trunk']['admin_state_up'], "Trunk admin state is not UP.")

        # Delete the Trunk
        LOG.info(f"Deleting Trunk '{self.trunk_name}'")
        self.neutron_client.delete_trunk(trunk['trunk']['id'])
        
        # Assert Trunk is deleted
        self.assertRaises(Exception, self.neutron_client.show_trunk, trunk['trunk']['id'])