from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import models_v2
from neutron.db.models.allowed_address_pair import AllowedAddressPair
from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.unit import testlib_api
from neutron_lib import constants
from neutron_lib import context
from oslo_utils import uuidutils
from sqlalchemy.orm.session import Session

from networking_nsxv3.api import rpc as nsxv3_rpc
from networking_nsxv3.common import constants as nsxv3_constants


class FakePlugin(base_plugin.NeutronDbPluginV2):
    """A fake plugin class containing all DB methods."""


class TestAgentsDbBase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAgentsDbBase, self).setUp()
        self.ctx = context.get_admin_context()
        self.session: Session = self.ctx.session
        self.plugin = FakePlugin()
        self.rpc = nsxv3_rpc.NSXv3ServerRpcCallback()

        self.tenant_id = 1
        self.host = "test"
        self.ip_pool_id = uuidutils.generate_uuid()
        self.net_id = uuidutils.generate_uuid()
        self.port_id_1 = uuidutils.generate_uuid()

        self._populate_neutron_db()

    def _populate_neutron_db(self):
        self.plugin.create_network(self.ctx, {"network": {
            "tenant_id": self.tenant_id,
            "id": self.net_id,
            "shared": False,
            "name": "test_net_1",
            "admin_state_up": True,
            "description": ""
        }})
        self.plugin.create_subnetpool(self.ctx, {"subnetpool": {
            "tenant_id": self.tenant_id,
            "id": self.ip_pool_id,
            "name": "default_test_pool",
            "prefixes": ["192.168.0.0", "192.168.1.0", "192.168.2.0"],
            # "min_prefix": 16,
            "min_prefixlen": 16,
            # "max_prefix": "",
            "max_prefixlen": 32,
            # "default_prefix": "",
            "default_prefixlen": 32,
            # "default_quota": "",
            # "address_scope_id": "",
            "is_default": True,
            "shared": True,
            "description": ""
        }})
        self.port = self.plugin.create_port(self.ctx, {"port": {
            "tenant_id": self.tenant_id,
            "name": "test_port_1",
            "id": self.port_id_1,
            "network_id": self.net_id,
            "fixed_ips": constants.ATTR_NOT_SPECIFIED,
            "admin_state_up": True,
            "device_id": "123",
            "device_owner": "admin",
            "description": ""
        }})

        self.subnet = self.plugin.create_subnet(self.ctx, {"subnet": {
            "tenant_id": self.tenant_id,
            "name": "subnet_192_168",
            "cidr": "192.168.0.0/32",
            "ip_version": 4,
            "network_id": self.net_id,
            "subnetpool_id": self.ip_pool_id,
            "allocation_pools": [],
            "enable_dhcp": True,
            "dns_nameservers": [],
            "host_routes": []
        }})

        neutron_db = [
            ml2_models.PortBinding(
                port_id=self.port_id_1,
                host=self.host,
                vif_type="ovs"
            ),
            ml2_models.PortBindingLevel(
                port_id=self.port_id_1,
                host=self.host,
                driver=nsxv3_constants.NSXV3,
                level=1
            ),
            models_v2.IPAllocation(
                port_id=self.port_id_1,
                ip_address="192.168.0.100",
                subnet_id=self.subnet.get("id"),
                network_id=self.net_id
            )
        ]

        with self.session.begin(subtransactions=True):
            for entry in neutron_db:
                self.session.add(entry)

    def test_duplicated_address_groups(self):
        """Test that the address groups are not duplicated."""
        with self.session.begin(subtransactions=True):
            self.session.add(AllowedAddressPair(
                port_id=self.port_id_1,
                mac_address=self.port['mac_address'],
                ip_address="192.168.0.100",
            ))
        port = self.rpc.get_port(self.ctx, self.host, self.port_id_1)

        self.assertEqual(1, len(port['address_bindings']))
        self.assertEqual(self.port['mac_address'], port['address_bindings'][0]['mac_address'])
        self.assertEqual("192.168.0.100", port['address_bindings'][0]['ip_address'])
