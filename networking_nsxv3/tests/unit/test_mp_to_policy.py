import re
import time

import responses
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import\
    mp_to_policy_migration, provider_nsx_policy, provider_nsx_mgmt
from networking_nsxv3.tests.unit.provider import Inventory
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging
from mock import patch

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


# INFO - Can introduce responses to directly run the tests against live NSX-T
# responses.add_passthru(re.compile('https://nsxm-l-01a.corp.local/\\w+'))


def get_url(path):
    return "https://nsx-l-01a.corp.local{}".format(path)


class TestProviderMpToPolicy(base.BaseTestCase):
    def get_result_by_name(self, payload, display_name):
        r = [o for o in payload.get("results", []) if o.get("display_name") == display_name]
        if len(r) > 1:
            raise Exception("Ambiguous {}".format(display_name))
        return r.pop(0) if len(r) == 1 else None

    def get_by_name(self, container, name):
        result = [obj for id, obj in container.items() if obj.get("display_name") == name]
        return result.pop(0) if result else None

    def get_tag(self, resource, scope):
        for item in resource.get("tags", {}):
            if item.get("scope") == scope:
                return item.get("tag")

    def setUp(self):
        super(TestProviderMpToPolicy, self).setUp()

        cfg.CONF.set_override("force_mp_to_policy", True, "AGENT")
        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])

        self.inventory = Inventory("https://nsxm-l-01a.corp.local:443", version="3.2.2.0")
        self._register_api_responses()

    def _register_api_responses(self):
        r = responses
        for m in [r.GET, r.POST, r.PUT, r.DELETE, r.PATCH]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    def port_fixture(self):
        provider_port = {
            "logical_switch_id": "419e0f47-7ff5-40c8-8256-0bd9173a4e1f",
            "attachment": {
                "attachment_type": "VIF",
                "id": "80372EA3-5F58-4B06-8456-3067D60B3023"
            },
            "admin_state": "UP",
            "address_bindings": [],
            "switching_profile_ids": [
                {
                    "key": "SwitchSecuritySwitchingProfile",
                    "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888"
                },
                {
                    "key": "SpoofGuardSwitchingProfile",
                    "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1"
                },
                {
                    "key": "IpDiscoverySwitchingProfile",
                    "value": "0c403bc9-7773-4680-a5cc-847ed0f9f52e"
                },
                {
                    "key": "MacManagementSwitchingProfile",
                    "value": "1e7101c8-cfef-415a-9c8c-ce3d8dd078fb"
                },
                {
                    "key": "PortMirroringSwitchingProfile",
                    "value": "93b4b7e8-f116-415d-a50c-3364611b5d09"
                },
                {
                    "key": "QosSwitchingProfile",
                    "value": "f313290b-eba8-4262-bd93-fab5026e9495"
                }
            ],
            "ignore_address_bindings": [],
            "resource_type": "LogicalPort",
            "display_name": "someid",
            "description": "",
            "tags": []
        }

        os_sg = {
            "id": "53C33142-3607-4CB2-B6E4-FA5F5C9E3C19",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [{
                "id": "1",
                "ethertype": "IPv4",
                "direction": "ingress",
                "remote_group_id": "",
                "remote_ip_prefix": "192.168.10.0/24",
                "security_group_id": "",
                "port_range_min": "5",
                "port_range_max": "1",
                "protocol": "icmp"
            }]
        }

        os_sg_second = {
            "id": "FB8B899A-2DAF-4DFA-9E6A-D2869C16BCD0",
            "revision_number": 2,
            "tags": ["capability_tcp_strict"],
            "rules": [{
                "id": "1",
                "ethertype": "IPv4",
                "direction": "ingress",
                "remote_group_id": "",
                "remote_ip_prefix": "192.168.11.0/24",
                "security_group_id": "",
                "port_range_min": "5",
                "port_range_max": "1",
                "protocol": "icmp"
            }]
        }

        os_qos = {
            "id": "628722EC-B0AA-4AF8-8045-3071BEE00EB2",
            "revision_number": "3",
            "name": "test",
            "rules": [{"dscp_mark": "5"}]
        }

        os_port_parent = {
            "id": "80372EA3-5F58-4B06-8456-3067D60B3023",
            "revision_number": "2",
            "parent_id": "",
            "mac_address": "fa:16:3e:e4:11:f1",
            "admin_state_up": "UP",
            "qos_policy_id": os_qos.get("id"),
            "security_groups": [os_sg.get("id"), os_sg_second.get("id")],
            "address_bindings": ["172.24.4.3", "172.24.4.4"],
            "vif_details": {
                "nsx-logical-switch-id": "712CAD71-B3F5-4AA0-8C3F-8D453DCBF2F2",
                "segmentation_id": "3200"
            },
            "_last_modified_time": time.time()
        }

        os_port_child = {
            "id": "CAB0602E-6E2D-4483-A7A8-E0FCDBF5E49D",
            "revision_number": "4",
            "parent_id": os_port_parent.get("id"),
            "mac_address": "fa:16:3e:e4:11:f1",
            "admin_state_up": "UP",
            "qos_policy_id": os_qos.get("id"),
            "security_groups": [os_sg.get("id")],
            "address_bindings": ["172.24.4.3", "172.24.4.4"],
            "vif_details": {
                "nsx-logical-switch-id": "712CAD71-B3F5-4AA0-8C3F-8D453DCBF2F2",
                "segmentation_id": "3400"
            }
        }

        return provider_port, os_sg, os_sg_second, os_qos, os_port_parent, os_port_child

    @responses.activate
    def test_migration_service_not_enabled(self):
        responses.reset()
        responses.add(url=re.compile(r".*"), status=500)
        try:
            mp_to_policy_migration.Provider()
        except RuntimeError as e:
            self.assertEqual(True, "MP-TO-POLICY API not enabled" in str(e))
            return
        assert False

    @responses.activate
    def test_migrate_sw_profiles_not_supported_type(self):
        migr_provider = mp_to_policy_migration.Provider()

        m_data = migr_provider.migrate_sw_profiles(
            not_migrated=[("not-supported-id", "PortMirroringSwitchingProfile")])
        self.assertEqual(None, m_data)

    @responses.activate
    def test_migrate_sw_profiles_supported_type(self):
        _, _, _, os_qos, _, _ = self.port_fixture()
        migr_provider = mp_to_policy_migration.Provider()
        mngr_provider = provider_nsx_mgmt.Provider()
        plcy_provider = provider_nsx_policy.Provider()

        mngr_provider.qos_realize(os_qos)
        inv = self.inventory.inv[Inventory.PROFILES]
        mngr_qos: dict = self.get_by_name(inv, os_qos.get("id"))

        migr_provider.migrate_sw_profiles(
            not_migrated=[(mngr_qos.get("id"), "QosSwitchingProfile")])
        prfls = plcy_provider.get_non_default_switching_profiles()

        policy_qos_profile = prfls[0]
        self.assertEqual(os_qos.get("id"), policy_qos_profile.get("display_name"))
        self.assertEqual("QoSProfile", policy_qos_profile.get("resource_type"))
        self.assertEqual(mngr_qos.get("id"), policy_qos_profile.get("id"))
        self.assertEqual("nsx_policy", mngr_qos.get("_create_user"))
        self.assertEqual(mngr_qos.get("tags"), policy_qos_profile.get("tags"))

    @responses.activate
    def test_port_migration(self):
        _, _, _, _, os_port_parent, _ = self.port_fixture()
        migr_provider = mp_to_policy_migration.Provider()
        mngr_provider = provider_nsx_mgmt.Provider()
        plcy_provider = provider_nsx_policy.Provider()

        mngr_provider.port_realize(os_port_parent)
        inv = self.inventory.inv[Inventory.PORTS]
        mngr_port: dict = self.get_by_name(inv, os_port_parent.get("id"))

        migr_provider.migrate_ports([mngr_port.get("id")])
        plcy_port = plcy_provider.get_port(os_port_parent.get("id"))[1]

        self.assertEqual(os_port_parent.get("id"), plcy_port.get("display_name"))
        self.assertEqual("SegmentPort", plcy_port.get("resource_type"))
        self.assertEqual(mngr_port.get("id"), plcy_port.get("id"))
        self.assertEqual("nsx_policy", mngr_port.get("_create_user"))
        self.assertEqual(mngr_port.get("tags"), plcy_port.get("tags"))

    @responses.activate
    def test_switch_migration(self):
        migr_provider = mp_to_policy_migration.Provider()
        mngr_provider = provider_nsx_mgmt.Provider()
        plcy_provider = provider_nsx_policy.Provider()

        mngr_meta = mngr_provider.network_realize(10)
        migr_provider.migrate_switch(mngr_meta.id)
        plcy_provider.metadata_refresh(plcy_provider.SEGMENT)
        plcy_meta = plcy_provider.network_realize(10)

        mngr_inv = self.inventory.inv[Inventory.SWITCHES]
        plcy_inv = self.inventory.inv[Inventory.SEGMENTS]
        mngr_net: dict = mngr_inv.get(mngr_meta.id)
        plcy_net: dict = plcy_inv.get(plcy_meta.id)

        self.assertEqual(mngr_meta.id, plcy_meta.id)
        self.assertEqual(mngr_net.get("id"), plcy_net.get("id"))
        self.assertEqual(mngr_net.get("display_name"), plcy_net.get("display_name"))
        self.assertEqual(True, str(mngr_net.get("vlan")) in plcy_net.get("vlan_ids"))
        self.assertEqual("Segment", plcy_net.get("resource_type"))
        self.assertEqual("LogicalSwitch", mngr_net.get("resource_type"))
        self.assertEqual("nsx_policy", mngr_net.get("_create_user"))

    @responses.activate
    def test_bulk_migration(self):
        _, _, _, os_qos, os_port_parent, _ = self.port_fixture()

        migr_provider = mp_to_policy_migration.Provider()
        mngr_provider = provider_nsx_mgmt.Provider()
        plcy_provider = provider_nsx_policy.Provider()

        mngr_provider.qos_realize(os_qos)
        mngr_net_meta = mngr_provider.network_realize(3200)
        os_port_parent["vif_details"]["nsx-logical-switch-id"] = mngr_net_meta.id
        mngr_port_meta = mngr_provider.port_realize(os_port_parent)

        mngr_port_inv = self.inventory.inv[Inventory.PROFILES]
        mngr_qos: dict = self.get_by_name(mngr_port_inv, os_qos.get("id"))

        pb = mp_to_policy_migration.PayloadBuilder()
        payload = pb\
            .sw_profiles([(mngr_qos.get("id"), "QosSwitchingProfile")])\
            .switch(mngr_net_meta.id)\
            .ports([mngr_port_meta.id])\
            .build()
        migr_provider.migrate_bulk(payload)

        plcy_provider.metadata_refresh(plcy_provider.SEGMENT)
        plcy_net_meta = plcy_provider.network_realize(3200)
        mngr_net_inv = self.inventory.inv[Inventory.SWITCHES]
        plcy_net_inv = self.inventory.inv[Inventory.SEGMENTS]
        mngr_port_inv = self.inventory.inv[Inventory.PORTS]
        mngr_net: dict = mngr_net_inv.get(mngr_net_meta.id)
        plcy_net: dict = plcy_net_inv.get(plcy_net_meta.id)
        prfls = plcy_provider.get_non_default_switching_profiles()
        mngr_port: dict = self.get_by_name(mngr_port_inv, os_port_parent.get("id"))
        plcy_port = plcy_provider.get_port(os_port_parent.get("id"))[1]

        policy_qos_profile = prfls[0]
        self.assertEqual(os_qos.get("id"), policy_qos_profile.get("display_name"))
        self.assertEqual("QoSProfile", policy_qos_profile.get("resource_type"))
        self.assertEqual(mngr_qos.get("id"), policy_qos_profile.get("id"))
        self.assertEqual("nsx_policy", mngr_qos.get("_create_user"))
        self.assertEqual(mngr_qos.get("tags"), policy_qos_profile.get("tags"))

        self.assertEqual(os_port_parent.get("id"), plcy_port.get("display_name"))
        self.assertEqual("SegmentPort", plcy_port.get("resource_type"))
        self.assertEqual(mngr_port.get("id"), plcy_port.get("id"))
        self.assertEqual("nsx_policy", mngr_port.get("_create_user"))
        self.assertEqual(mngr_port.get("tags"), plcy_port.get("tags"))

        self.assertEqual(mngr_net_meta.id, plcy_net_meta.id)
        self.assertEqual(mngr_net.get("id"), plcy_net.get("id"))
        self.assertEqual(mngr_net.get("display_name"), plcy_net.get("display_name"))
        self.assertEqual(True, str(mngr_net.get("vlan")) in plcy_net.get("vlan_ids"))
        self.assertEqual("Segment", plcy_net.get("resource_type"))
        self.assertEqual("LogicalSwitch", mngr_net.get("resource_type"))
        self.assertEqual("nsx_policy", mngr_net.get("_create_user"))

    @responses.activate
    def test_port_already_migrated(self):
        _, _, _, _, os_port_parent, _ = self.port_fixture()
        migr_provider = mp_to_policy_migration.Provider()
        mngr_provider = provider_nsx_mgmt.Provider()
        plcy_provider = provider_nsx_policy.Provider()

        mngr_provider.port_realize(os_port_parent)
        inv = self.inventory.inv[Inventory.PORTS]
        mngr_port: dict = self.get_by_name(inv, os_port_parent.get("id"))

        migr_provider.migrate_ports([mngr_port.get("id")])
        plcy_port = plcy_provider.get_port(os_port_parent.get("id"))[1]

        self.assertEqual(os_port_parent.get("id"), plcy_port.get("display_name"))

        try:
            migr_provider.migrate_ports([mngr_port.get("id")])
        except RuntimeError as e:
            self.assertEqual(True, "Policy Resource already exists" in str(e))
            return
        assert False

    @responses.activate
    def test_migration_rollback(self):
        responses.reset()
        responses.add(method=responses.GET, match_querystring=True,
                      url=re.compile(r"(.*)/status-summary\?component_type=MP_TO_POLICY_MIGRATION"),
                      status=200, json={"overall_migration_status": "FAIL"})
        self._register_api_responses()

        _, _, _, _, os_port_parent, _ = self.port_fixture()
        migr_provider = mp_to_policy_migration.Provider()
        mngr_provider = provider_nsx_mgmt.Provider()

        mngr_meta = mngr_provider.port_realize(os_port_parent)
        inv = self.inventory.inv[Inventory.PORTS]
        mngr_port: dict = self.get_by_name(inv, os_port_parent.get("id"))

        try:
            with patch.object(mp_to_policy_migration.Provider, '_try_rollback') as _try_rollback_mock:
                migr_provider.migrate_ports([mngr_port.get("id")])
        except RuntimeError as e:
            self.assertEqual(True, "FAILED" in str(e))
            _try_rollback_mock.assert_called_once_with(migr_data={
                'migration_data': [{
                    'type': 'LOGICAL_PORT',
                    'resource_ids': [
                        {
                            'manager_id': mngr_meta.id,
                            'policy_id': mngr_meta.id
                        }
                    ]}]})
            return
        assert False
