import unittest
import testtools
import logging
import uuid
import sys

from com.vmware.nsx_client import LogicalSwitches, SwitchingProfiles

from com.vmware.nsx.model_client import NSGroupTagExpression
from com.vmware.nsx.model_client import LogicalSwitch
from com.vmware.nsx.model_client import FirewallSection
from com.vmware.nsx.model_client import Tag
from com.vmware.nsx.model_client import IPSet
from com.vmware.nsx.model_client import NSGroup
from com.vmware.nsx.model_client import QosSwitchingProfile
from com.vmware.nsx.model_client import BatchRequestItem

from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_client

LOG = logging.getLogger(__name__)


class NetworkTest(testtools.TestCase):

    TRANSPORT_ZONE_ID = "ffff"

    def setUp(self):
        super(NetworkTest, self).setUp()
        self.nsxv3 = nsxv3_client.NSXv3ClientImpl()
        self.uuid = str(uuid.uuid4())

    def test_create_logical_switch(self):
        sw_name = self.uuid
        NetworkTest.TRANSPORT_ZONE_ID
        segmentation_id = "3200"
        ls_spec = LogicalSwitch(
            display_name=sw_name,
            description="",
            resource_type="",
            tags=[],
            admin_state=LogicalSwitch.ADMIN_STATE_UP,
            transport_zone_id=NetworkTest.TRANSPORT_ZONE_ID,
            uplink_teaming_policy_name=None,
            # LogicalSwitch.REPLICATION_MODE_SOURCE
            replication_mode=LogicalSwitch.REPLICATION_MODE_MTEP,
            vni=None,
            vlan=None,
            switching_profile_ids=[],
            address_bindings=[],
            vlan_trunk_spec={
                "vlan_ranges": [
                    {
                        "start": int(segmentation_id),
                        "end": int(segmentation_id)
                    }
                ]
            }
        )
        ls = self.nsxv3.create(sdk_service=LogicalSwitches, sdk_model=ls_spec)
        self.assertEqual(ls_spec.display_name, ls.display_name)

    def test_get_logical_switch(self):
        sw_name = self.uuid
        NetworkTest.TRANSPORT_ZONE_ID
        ls_spec = LogicalSwitch(display_name=sw_name)

        ls = self.nsxv3.get(sdk_service=LogicalSwitches, sdk_model=ls_spec)
        self.assertIsNotNone(ls.id)

    def test_create_qos_profile(self):
        qos_policy_name = self.uuid
        revision_number = "6"
        qos_spec = QosSwitchingProfile(
            class_of_service=None,
            dscp=None,
            shaper_configuration=None,
            description="",
            display_name=qos_policy_name,
            tags=[
                Tag(
                    scope=nsxv3_constants.NSXV3_REVISION_SCOPE,
                    tag=str(revision_number))
            ]
        )
        qos = self.nsxv3.create(
            sdk_service=LogicalSwitches, sdk_model=qos_spec)
        self.assertEqual(qos_spec.display_name, qos.display_name)

    def test_get_qos_profile(self):
        qos_policy_name = self.uuid
        qos_spec = LogicalSwitch(display_name=qos_policy_name)

        qos = self.nsxv3.get(
            sdk_service=SwitchingProfiles, sdk_model=qos_spec)
        self.assertIsNotNone(qos.id)

    def test_create_security_group(self):
        security_group_id = self.uuid

        fw_body = FirewallSection(
            display_name=security_group_id,
            is_default=False,
            resource_type='FirewallSection',
            section_type='LAYER3',
            stateful=True
        )

        ips_body = IPSet(
            display_name=security_group_id,
            ip_addresses=[],
            resource_type='IPSet'
        )

        nsg_body = NSGroup(
            display_name=security_group_id,
            resource_type='NSGroup',
            tags=[Tag(
                scope=nsxv3_constants.NSXV3_SECURITY_GROUP_SCOPE,
                tag=security_group_id)],
            membership_criteria=[NSGroupTagExpression(
                scope=nsxv3_constants.NSXV3_SECURITY_GROUP_SCOPE,
                scope_op=NSGroupTagExpression.SCOPE_OP_EQUALS,
                tag=security_group_id,
                tag_op=NSGroupTagExpression.TAG_OP_EQUALS,
                target_type=NSGroupTagExpression.TARGET_TYPE_LOGICALPORT)
            ]
        )

        req = [
            BatchRequestItem(
                uri="/v1/firewall/sections",
                method=BatchRequestItem.METHOD_POST,
                body=fw_body),
            BatchRequestItem(
                uri="/v1/ip-sets",
                method=BatchRequestItem.METHOD_POST,
                body=ips_body),
            BatchRequestItem(
                uri="/v1/ns-groups",
                method=BatchRequestItem.METHOD_POST,
                body=nsg_body)
        ]

        status = self.nsxv3.batch(
            request_items=req,
            continue_on_error=False,
            atomic=True)

        self.assertIs(self.nsxv3.is_batch_successful(status), True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        NetworkTest.TRANSPORT_ZONE_ID = sys.argv.pop()
    unittest.main()
