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

        self.inventory = Inventory("https://nsxm-l-01a.corp.local:443", version="3.1.3.6")
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
        inv = self.inventory.inventory[Inventory.PROFILES]
        qos: dict = self.get_by_name(inv, os_qos.get("id"))

        migr_provider.migrate_sw_profiles(
            not_migrated=[(qos.get("id"), "QosSwitchingProfile")])
        prfls = plcy_provider.get_non_default_switching_profiles()

        policy_qos_profile = prfls[0]
        self.assertEqual(os_qos.get("id"), policy_qos_profile.get("display_name"))
        self.assertEqual(os_qos.get("resource_type"), policy_qos_profile.get("QoSProfile"))
        self.assertEqual(qos.get("id"), policy_qos_profile.get("id"))

    @responses.activate
    def test_port_migration(self):
        # TODO
        # mp_to_policy_migration.Provider().migrate_ports(["1"])
        pass
