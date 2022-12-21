from neutron_lib import constants
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import models_v2

from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.unit import testlib_api
from sqlalchemy.orm.session import Session
from networking_nsxv3.common import constants as nsxv3_constants
from neutron.db.qos.models import (QosPolicy, QosPortPolicyBinding)
from neutron.services.trunk import models as trunk_model
from neutron.db.models import securitygroup as sg_model

from networking_nsxv3.db import db


class FakePlugin(base_plugin.NeutronDbPluginV2):
    """A fake plugin class containing all DB methods."""


class TestAgentsDbBase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAgentsDbBase, self).setUp()
        self.ctx = context.get_admin_context()
        self.session: Session = self.ctx.session
        self.plugin = FakePlugin()

        self.tenant_id = 1
        self.host = "test"
        self.ip_pool_id = uuidutils.generate_uuid()
        self.net_id = uuidutils.generate_uuid()
        self.port_id_1 = uuidutils.generate_uuid()
        self.subport_id_1 = uuidutils.generate_uuid()
        self.port_id_2 = uuidutils.generate_uuid()
        self.qos_id_1 = uuidutils.generate_uuid()
        self.trunk_id_1 = uuidutils.generate_uuid()
        self.sg_id_1 = uuidutils.generate_uuid()

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
        self.plugin.create_port(self.ctx, {"port": {
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
        self.plugin.create_port(self.ctx, {"port": {
            "tenant_id": self.tenant_id,
            "name": "test_port_2",
            "id": self.port_id_2,
            "network_id": self.net_id,
            "fixed_ips": constants.ATTR_NOT_SPECIFIED,
            "admin_state_up": True,
            "device_id": "1234",
            "device_owner": "admin",
            "description": ""
        }})
        self.plugin.create_port(self.ctx, {"port": {
            "tenant_id": self.tenant_id,
            "name": "test_subport_1",
            "id": self.subport_id_1,
            "network_id": self.net_id,
            "fixed_ips": constants.ATTR_NOT_SPECIFIED,
            "admin_state_up": True,
            "device_id": "123",
            "device_owner": "admin",
            "description": ""
        }})

        subnet = self.plugin.create_subnet(self.ctx, {"subnet": {
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
                subnet_id=subnet.get("id"),
                network_id=self.net_id
            ),
            QosPolicy(
                id=self.qos_id_1,
                project_id=self.tenant_id,
                name="Test_QOS_1"
            ),
            trunk_model.Trunk(
                id=self.trunk_id_1,
                project_id=self.tenant_id,
                name="test_trunk_1",
                port_id=self.port_id_1
            ),
            trunk_model.SubPort(
                trunk_id=self.trunk_id_1,
                port_id=self.subport_id_1,
                segmentation_type="vlan",
                segmentation_id=1200
            ),
            sg_model.SecurityGroup(
                id=self.sg_id_1,
                project_id=self.tenant_id,
                name="test_sg_1",
            )
        ]

        with self.session.begin(subtransactions=True):
            for entry in neutron_db:
                self.session.add(entry)

    def test_get_ports(self):
        port_1 = db.get_port(self.ctx, self.host, self.port_id_1)
        port_2 = db.get_port(self.ctx, self.host, self.port_id_2)
        ports_with_rev = db.get_ports_with_revisions(self.ctx, self.host, 100, 0)
        port_addresses = db.get_port_addresses(self.ctx, self.port_id_1)

        self.assertDictSupersetOf(
            {
                "id": self.port_id_1,
                "parent_id": "",
                "traffic_tag": None,
                "admin_state_up": True,
                "status": "ACTIVE",
                "qos_policy_id": "",
                "security_groups": [],
                "address_bindings": [],
                "revision_number": 0,
                "binding:host_id": "test",
                "vif_details": "",
                "binding:vnic_type": "normal",
                "binding:vif_type": "ovs"
            }, port_1)
        self.assertEqual(1, len(ports_with_rev))
        self.assertEqual(self.port_id_1, ports_with_rev.pop()[0])
        self.assertEqual(1, len(port_addresses))
        self.assertEqual("192.168.0.100", port_addresses[0][0])
        self.assertEqual(None, port_2)

    def test_get_port_with_children(self):
        port_1 = db.get_port_with_children(self.ctx, self.host, self.port_id_1)
        port_2 = db.get_port_with_children(self.ctx, self.host, self.port_id_2)
        ports_with_rev = db.get_ports_with_revisions(self.ctx, self.host, 100, 0)

        self.assertDictSupersetOf(
            {
                "id": self.port_id_1,
                "child_ports": [(self.subport_id_1, 1200)],
                "parent_id": "",
                "traffic_tag": None,
                "admin_state_up": True,
                "status": "ACTIVE",
                "qos_policy_id": "",
                "security_groups": [],
                "address_bindings": [],
                "revision_number": 0,
                "binding:host_id": "test",
                "vif_details": "",
                "binding:vnic_type": "normal",
                "binding:vif_type": "ovs"
            }, port_1)
        self.assertEqual(1, len(ports_with_rev))
        self.assertEqual(self.port_id_1, ports_with_rev.pop()[0])
        self.assertEqual(None, port_2)

    def test_port_qos(self):
        with self.session.begin(subtransactions=True):
            self.session.add(QosPortPolicyBinding(
                policy_id=self.qos_id_1,
                port_id=self.port_id_1
            ))
        port_1 = db.get_port(self.ctx, self.host, self.port_id_1)
        qos_with_rev = db.get_qos_policies_with_revisions(self.ctx, self.host, 100, 0)
        qos = db.get_qos(self.ctx, self.qos_id_1)
        qos_port = db.get_qos_ports_by_host(self.ctx, self.host, self.qos_id_1)

        self.assertEqual(self.qos_id_1, port_1.get("qos_policy_id"))
        self.assertEqual(1, len(qos_with_rev))
        self.assertEqual(self.qos_id_1, qos_with_rev[0][0])
        self.assertEqual("Test_QOS_1", qos[0])
        self.assertEqual(self.port_id_1, qos_port[0])

    def test_trunk_port(self):
        with self.session.begin(subtransactions=True):
            self.session.add(trunk_model.SubPort(
                port_id=self.port_id_2,
                trunk_id=self.trunk_id_1,
                segmentation_type="vlan",
                segmentation_id=11
            ))
            self.session.add(ml2_models.PortBinding(
                port_id=self.port_id_2,
                host=self.host,
                vif_type="ovs"
            ))
            self.session.add(ml2_models.PortBindingLevel(
                port_id=self.port_id_2,
                host=self.host,
                driver=nsxv3_constants.NSXV3,
                level=1
            ))

        port_2 = db.get_port(self.ctx, self.host, self.port_id_2)

        self.assertDictSupersetOf(
            {
                "id": self.port_id_2,
                "parent_id": self.port_id_1,
                "traffic_tag": 11,
                "admin_state_up": True,
                "status": "ACTIVE",
                "qos_policy_id": "",
                "security_groups": [],
                "address_bindings": [],
                "revision_number": 0,
                "binding:host_id": "test",
                "vif_details": "",
                "binding:vnic_type": "normal",
                "binding:vif_type": "ovs"
            }, port_2)

    def test_port_sgs(self):
        with self.session.begin(subtransactions=True):
            self.session.add(sg_model.SecurityGroupPortBinding(
                security_group_id=self.sg_id_1,
                port_id=self.port_id_1
            ))

        has_sg_on_host = db.has_security_group_used_by_host(self.ctx, self.host, self.sg_id_1)
        sg_with_rev = db.get_security_groups_with_revisions(self.ctx, self.host, 100, 0)
        sg = db.get_security_group_revision(self.ctx, self.sg_id_1)
        port_sgs = db.get_port_security_groups(self.ctx, self.port_id_1)
        port_ids = db.get_port_id_by_sec_group_id(self.ctx, self.host, self.sg_id_1)
        sgs_for_host = db.get_security_groups_for_host(self.ctx, self.host, 100, 0)
        sg_ips = db.get_security_group_members_ips(self.ctx, self.sg_id_1)
        sg_port_ids = db.get_security_group_port_ids(self.ctx, self.host, self.sg_id_1)

        self.assertEqual(True, has_sg_on_host)
        self.assertEqual(1, len(sg_with_rev))
        self.assertEqual(self.sg_id_1, sg_with_rev[0][0])
        self.assertEqual(3, len(sg))
        self.assertEqual(self.sg_id_1, sg[0])
        self.assertEqual(0, sg[1])
        self.assertEqual(True, sg[2])
        self.assertEqual(1, len(port_sgs))
        self.assertEqual(self.sg_id_1, port_sgs[0][0])
        self.assertEqual(1, len(port_ids))
        self.assertEqual(self.port_id_1, port_ids[0])
        self.assertEqual(9, len(sgs_for_host))
        for sgs_for_h in sgs_for_host:
            self.assertEqual(self.sg_id_1, sgs_for_h[0])
        self.assertEqual(1, len(sg_ips))
        self.assertEqual("192.168.0.100", sg_ips[0][0])
        self.assertEqual(1, len(sg_port_ids))
        self.assertEqual(self.port_id_1, sg_port_ids[0])
