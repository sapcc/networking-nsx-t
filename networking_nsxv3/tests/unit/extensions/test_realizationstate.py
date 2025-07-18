import eventlet
eventlet.monkey_patch()

import json
import webtest
import networking_nsxv3.common.config

from neutron.api import extensions
from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.unit.api.test_extensions import setup_extensions_middleware
from networking_nsxv3.api.rpc import NSXv3AgentRpcClient
from networking_nsxv3.extensions import __path__ as nsxt_ext_path
from networking_nsxv3.extensions import nsxtpolicy
from neutron_lib.api.definitions import portbindings
from unittest import mock


from neutron.tests.unit.plugins.ml2 import test_plugin

class TestCustomExtension(test_plugin.Ml2PluginV2TestCase):
    def setUp(self):
        super().setUp()
        self.ext_mgr = extensions.ExtensionManager(nsxt_ext_path[0])
        self.app = webtest.TestApp(setup_extensions_middleware(self.ext_mgr))

    def test_extension_registration(self):
        # Registration happens automatically when the driver is imported
        ext_paths = extensions.get_extensions_path()
        self.assertIn(nsxt_ext_path[0], ext_paths)

    def test_extension_loaded(self):
        assert nsxtpolicy.Nsxtpolicy.get_alias() in self.ext_mgr.extensions

    def test_extension_status(self):
        resp = self.app.get("/nsxt-policy/port")
        self.assertEqual({'extension_reached': True}, resp.json)

    def test_port_realization_status(self):
        port_id = "fake-port-id"
        binding_host = 'fake-host'

        with mock.patch.object(NSXv3AgentRpcClient, 'is_port_realized', return_value=True):
            resp = self.app.get(f"/nsxt-policy/port/realization_status?port_id={port_id}&binding_host={binding_host}")
            self.assertEqual({'realized': True}, resp.json)

    def test_port_realization_status_no_binding_host(self):
        host = 'fake-host'
        host_arg = {portbindings.HOST_ID: host}
        with self.port(device_owner='compute:xyz', is_admin=True,
                       arg_list=(portbindings.HOST_ID,),
                       **host_arg) as port:
            port_id = port["port"]['id']

            from networking_nsxv3.api.rpc import NSXv3AgentRpcClient
            with mock.patch.object(NSXv3AgentRpcClient, 'is_port_realized',
                                   return_value=True) as mock_get_realization_status:
                self.app.get(f"/nsxt-policy/port/realization_status?port_id={port_id}")
                mock_get_realization_status.assert_called_once_with("fake-host", port_id)
