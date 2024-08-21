import eventlet
eventlet.monkey_patch()

from networking_nsxv3.common import config  # noqa
from oslo_log import log as logging
import uuid
import os
from networking_nsxv3.tests.e2e import base
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API

LOG = logging.getLogger(__name__)


class TestQoS(base.E2ETestCase):

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self.test_server1_name = os.environ.get("E2E_SERVER_NAME", None)

    def setUp(self):
        super().setUp()
        # self.skipTest("Skipping test temporarily.")

        if not self.test_server1_name:
            self.fail("E2E_SERVER_NAME is not set. Please set it to the name of the server to use for testing.")

        # Get the server with the name defined in the class
        self.set_test_server(self.test_server1_name)

        self.qos_policy_name = f"e2e_test_qos_policy_{uuid.uuid4()}"
        self.bandwidth_limit_rule = {'max_kbps': 2048, 'max_burst_kbps': 2048, 'direction': 'egress'}

    def tearDown(self):
        super().tearDown()

    def test_create_qos(self):
        LOG.info(f"Testing QoS Policy creation and deletion")

        # Create QoS Policy
        LOG.info(f"Creating QoS Policy '{self.qos_policy_name}'")
        qos_policy = self.neutron_client.create_qos_policy({'policy': {'name': self.qos_policy_name}})
        self.assertIsNotNone(qos_policy)

        # Add QoS Rule to QoS Policy
        LOG.info(f"Adding Bandwidth Limit Rule to QoS Policy '{self.qos_policy_name}'")
        qos_rule = self.neutron_client.create_bandwidth_limit_rule(
            qos_policy['policy']['id'], {'bandwidth_limit_rule': self.bandwidth_limit_rule})
        self.assertIsNotNone(qos_rule)

        # Get Server Ports
        server_ports = self.neutron_client.list_ports(device_id=self.test_server.id)['ports']
        self.assertTrue(len(server_ports) > 0, f"Server {self.test_server.id} has no ports.")

        # Attach QoS Policy to Server Port
        server_port = server_ports[0]
        LOG.info(f"Attaching QoS Policy '{self.qos_policy_name}' to Server Port '{server_port['id']}'")
        self.neutron_client.update_port(server_port['id'], {'port': {'qos_policy_id': qos_policy['policy']['id']}})

        # Assert QoS Profile is created in NSX
        nsx_qos_prfl = self.get_nsx_qos_by_os_id(qos_policy['policy']['id'])
        self.assertIsNotNone(nsx_qos_prfl, f"QoS Profile '{self.qos_policy_name}' was not created in NSX")
        self.assertDictContainsSubset({
            'id': qos_policy['policy']['id'],
            'display_name': qos_policy['policy']['id'],
        }, nsx_qos_prfl)
        self.assertDictContainsSubset({
            'resource_type': 'EgressRateLimiter',
            'enabled': True,
            'average_bandwidth': int(self.bandwidth_limit_rule['max_kbps']/1024),
            # 'burst_size': int(self.bandwidth_limit_rule['max_burst_kbps']/1024), # TODO: Pending https://github.com/sapcc/networking-nsx-t/pull/135
        }, nsx_qos_prfl['shaper_configurations'][0])

        # Assert QoS Policy is attached to Server Port in NSX
        nsx_port = self.get_nsx_port_by_os_id(server_port['id'])
        self.assertIsNotNone(nsx_port, f"Server Port '{server_port['id']}' was not found in NSX")
        # TODO: Assert QoS Policy is attached to Server Port in NSX after PR https://github.com/sapcc/networking-nsx-t/pull/135 is merged

        # Detach QoS Policy from Server Port
        LOG.info(f"Detaching QoS Policy '{self.qos_policy_name}' from Server Port '{server_port['id']}'")
        self.neutron_client.update_port(server_port['id'], {'port': {'qos_policy_id': None}})
        eventlet.sleep(10)

        # Delete Qos Policy Rule
        LOG.info(f"Deleting Bandwidth Limit Rule from QoS Policy '{self.qos_policy_name}'")
        self.neutron_client.delete_bandwidth_limit_rule(
            qos_rule['bandwidth_limit_rule']['id'], qos_policy['policy']['id'])
        eventlet.sleep(10)

        # Delete QoS Policy
        LOG.info(f"Deleting QoS Policy '{self.qos_policy_name}'")
        try:
            self.neutron_client.delete_qos_policy(qos_policy['policy']['id'])
        except Exception as e:
            pass  # TODO: Pending https://github.com/sapcc/networking-nsx-t/pull/135
        eventlet.sleep(10)

        # Assert QoS Profile is deleted from NSX
        self.assertTrue(self.get_nsx_qos_by_os_id_after_clean(
            qos_policy['policy']['id']), f"QoS Profile '{self.qos_policy_name}' was not deleted from NSX")

    ##############################################################################################
    ##############################################################################################

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def get_nsx_qos_by_os_id(self, os_qos_id):
        resp = self.nsx_client.get(API.QOS_PROFILE.format(os_qos_id))
        if resp.ok:
            return resp.json()
        return None

    @base.RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def get_nsx_qos_by_os_id_after_clean(self, os_qos_id):
        resp = self.nsx_client.get(API.QOS_PROFILE.format(os_qos_id))
        if resp.ok:
            return None
        return True
