import copy
import datetime
from unittest import mock

from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as exc
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import portbindings_db
from neutron.db import segments_db
from neutron.db.models import portbinding as pmodels
from neutron.objects import agent as agent_obj
from neutron.objects import base
from neutron.tests.unit import testlib_api
from neutron.plugins.ml2 import models

from networking_nsxv3.db import db


class FakePlugin(base_plugin.NeutronDbPluginV2, portbindings_db.PortBindingMixin):
    """A fake plugin class containing all DB methods."""


class TestAgentsDbBase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAgentsDbBase, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = FakePlugin()

    def test_get_enabled_agent_on_host_found(self):
        tenant_id = 1
        host = None
        net_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        net = self.plugin.create_network(self.context, {"network": {
            "tenant_id": tenant_id,
            "id": net_id,
            "shared": False,
            "name": "test_net_1",
            "admin_state_up": True,
            "description": ""
        }})
        port = self.plugin.create_port(self.context, {"port": {
            "tenant_id": tenant_id,
            "name": "test_port_1",
            "id": port_id,
            "network_id": net_id,
            "fixed_ips": constants.ATTR_NOT_SPECIFIED,
            "admin_state_up": True,
            "device_id": "123",
            "device_owner": "admin",
            "description": ""
        }})

        expected1 = db.get_port(self.context, host, port_id)
        expected2 = db.get_ports_with_revisions(self.context, host, 100, 0)
        # TODO: add portbinding/qos/parent and complete the test
