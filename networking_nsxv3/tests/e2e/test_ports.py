import eventlet
eventlet.monkey_patch()
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
from networking_nsxv3.tests.e2e import base
import os
import uuid
from oslo_log import log as logging


from networking_nsxv3.common import config  # noqa


LOG = logging.getLogger(__name__)


class TestPorts(base.E2ETestCase):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self.test_network1_name = os.environ.get("E2E_NETWORK_NAME", None)
        self.test_server1_name = os.environ.get("E2E_SERVER_NAME", None)

    def setUp(self):
        super().setUp()

        if not self.test_network1_name:
            self.fail("E2E_NETWORK_NAME is not set. Please set it to the name of the network to use for testing.")
        if not self.test_server1_name:
            self.fail("E2E_SERVER_NAME is not set. Please set it to the name of the server to use for testing.")

        # Get the server with the name defined in the class
        servers = self.nova_client.servers.list()
        self.test_server1 = next((s for s in servers if s.name == self.test_server1_name), None)

        # Get the network with the name defined in the class
        networks = self.neutron_client.list_networks()
        self.test_network1 = next((n for n in networks['networks'] if n['name'] == self.test_network1_name), None)

        # Assert the server and network are found
        self.assertIsNotNone(self.test_server1)
        self.assertIsNotNone(self.test_network1)

        # Generate a random names for ports
        self.ports = [
            {"name": "test-port-" + str(uuid.uuid4()), "id": None},
            {"name": "test-port-" + str(uuid.uuid4()), "id": None},
            {"name": "test-port-" + str(uuid.uuid4()), "id": None}
        ]

    def tearDown(self):
        super().tearDown()
        # Clean up & Assert cleanup
        LOG.info("Tearing down test case...")

        # Delete created ports
        for port in self.ports:
            if port['id']:
                self.neutron_client.delete_port(port['id'])
        ports_after_cleanup = self.neutron_client.list_ports()
        # Assert deleted ports are not in the list og all ports
        for port in self.ports:
            self.assertNotIn(port['id'], [p['id'] for p in ports_after_cleanup['ports']])

    def test_create_standalone_ports_and_attach(self):
        LOG.info("Testing creation of standalone port...")

        # Create a ports on the network
        for port in self.ports:
            result = self.neutron_client.create_port({
                "port": {
                    "network_id": self.test_network1['id'],
                    "name": port['name']
                }
            })
            port['id'] = result['port']['id']

        # Assert created ports are in the list of all ports
        ports_after_create = self.neutron_client.list_ports()
        for port in self.ports:
            self.assertIn(port['id'], [p['id'] for p in ports_after_create['ports']])

        # Attach the ports to the test server
        for port in self.ports:
            self.nova_client.servers.interface_attach(
                server=self.test_server1.id,
                port_id=port['id'],
                net_id=None,
                fixed_ip=None
            )
        # Assert the ports are attached to the correct server
        for port in self.ports:
            self.assertEqual(self.test_server1.id, self.neutron_client.show_port(port['id'])['port']['device_id'])

        # Assert the ports are created on the NSX side
        for port in self.ports:
            nsx_port = self.get_nsx_port_by_id(port['id'])
            self.assertIsNotNone(nsx_port)

    ##############################################################################################
    ##############################################################################################

    @base.E2ETestCase.retry(max_retries=5, sleep_duration=5)
    def get_nsx_port_by_id(self, os_port_id):
        resp = self.nsx_client.get(API.SEARCH_QUERY, {"query": API.SEARCH_Q_SEG_PORT.format(os_port_id)})
        if resp.ok:
            if resp.json()['result_count'] == 0:
                return None
            return resp.json()['results'][0]
        return None
