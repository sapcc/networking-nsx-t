from unittest import mock

from neutron.tests.unit import testlib_api
from neutron_lib import context

from networking_nsxv3.api import rpc as nsxv3_rpc
from networking_nsxv3.db import db


class TestAgentsDbBase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAgentsDbBase, self).setUp()
        self.ctx = context.get_admin_context()
        self.rpc = nsxv3_rpc.NSXv3ServerRpcCallback()

    def test_allowed_address_pairs(self):
        """Test that the allowed address pairs do not contain duplicates."""
        fake_port = {
            'id': 'fake_port',
            'mac_address': 'fake_mac',
        }
        ipaddress = [('fake_ip',)]
        allowed_address_pairs = [('fake_ip', 'fake_mac'), ('fake_ip_v2', 'fake_mac_v2')]

        expected_results = [{'ip_address': 'fake_ip', 'mac_address': 'fake_mac'},
                            {'ip_address': 'fake_ip_v2', 'mac_address': 'fake_mac_v2'}]

        with mock.patch.object(db, 'get_port', return_value=fake_port), \
                mock.patch.object(db, 'get_port_addresses', return_value=ipaddress), \
                mock.patch.object(db, 'get_port_allowed_pairs', return_value=allowed_address_pairs):

            port = self.rpc.get_port(self.ctx, '', fake_port['id'])
            self.assertEqual(2, len(port['address_bindings']))
            self.assertEqual(expected_results, port['address_bindings'])
