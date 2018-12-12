from oslo_utils import timeutils
from oslo_log import log as logging
from oslo_config import cfg
import time
import re
import copy
import json
import math


from vmware.vapi.bindings.struct import PrettyPrinter
from vmware.vapi.stdlib.client.factories import StubConfigurationFactory

from com.vmware.nsx_client import LogicalSwitches
from com.vmware.nsx_client import TransportZones
from com.vmware.nsx_client import LogicalPorts
from com.vmware.nsx_client import NsGroups
from com.vmware.nsx_client import SwitchingProfiles
from com.vmware.nsx_client import IpSets

from com.vmware.nsx_client import Batch
from com.vmware.nsx.model_client import TransportZone
from com.vmware.nsx.model_client import LogicalSwitch
from com.vmware.nsx.model_client import BatchRequest
from com.vmware.nsx.model_client import BatchRequestItem
from com.vmware.nsx.model_client import BatchResponse
from com.vmware.nsx.model_client import Tag
from com.vmware.nsx.model_client import LogicalPort
from com.vmware.nsx.model_client import PacketAddressClassifier
from com.vmware.nsx.model_client import SwitchingProfileTypeIdEntry
from com.vmware.nsx.model_client import QosSwitchingProfile
from com.vmware.nsx.model_client import IpDiscoverySwitchingProfile
from com.vmware.nsx.model_client import SpoofGuardSwitchingProfile

from com.vmware.vapi.std.errors_client import Unauthorized
from com.vmware.vapi.std.errors_client import NotFound
from com.vmware.vapi.std.errors_client import ConcurrentChange


from neutron_lib.services.qos import constants as qos_consts
from neutron_lib import constants as neutron_consts
from com.vmware.nsx.model_client import Dscp

from com.vmware.nsx.firewall_client import Sections
from com.vmware.nsx.model_client import ICMPTypeNSService
from com.vmware.nsx.model_client import FirewallRule
from com.vmware.nsx.model_client import FirewallService
from com.vmware.nsx.model_client import FirewallSection
from com.vmware.nsx.model_client import FirewallSectionRuleList
from com.vmware.nsx.model_client import ResourceReference
from com.vmware.nsx.model_client import L4PortSetNSService
from com.vmware.nsx.model_client import Tag
from com.vmware.nsx.model_client import VapiStruct
from com.vmware.nsx.model_client import IPSet
from com.vmware.nsx.model_client import NSGroup
from com.vmware.nsx.model_client import NSGroupTagExpression

from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.common import locking as nsxv3_locking
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_client


LOG = logging.getLogger(__name__)

QOS_SPEC_SHAPER_CONFIGURATION = {
    "IngressRateShaper": {
        "resource_type": "IngressRateShaper",
        "enabled": False,
        "average_bandwidth_mbps": 0,
        "peak_bandwidth_mbps": 0,
        "burst_size_bytes": 0
    },
    "IngressBroadcastRateShaper": {
        "resource_type": "IngressBroadcastRateShaper",
        "enabled": False,
        "burst_size_bytes": 0,
        "peak_bandwidth_kbps": 0,
        "average_bandwidth_kbps": 0
    },
    "EgressRateShaper": {
        "resource_type": "EgressRateShaper",
        "enabled": False,
        "average_bandwidth_mbps": 0,
        "peak_bandwidth_mbps": 0,
        "burst_size_bytes": 0
    }
}

QOS_SPEC_DSCP = {
    "mode": "TRUSTED",
    "priority": 0
}


class NSXv3Facada(nsxv3_client.NSXv3ClientImpl):

    IPK = SwitchingProfileTypeIdEntry.KEY_IPDISCOVERYSWITCHINGPROFILE
    SGK = SwitchingProfileTypeIdEntry.KEY_SPOOFGUARDSWITCHINGPROFILE
    QSK = SwitchingProfileTypeIdEntry.KEY_QOSSWITCHINGPROFILE
    SGW = SpoofGuardSwitchingProfile.WHITE_LIST_PROVIDERS_LPORT_BINDINGS

    def __init__(self):
        super(NSXv3Facada, self).__init__()
        self.tz_name = cfg.CONF.NSXV3.nsxv3_transport_zone_name

    def setup(self):
        self._login()
        self.tz_id = self.get(sdk_service=TransportZones, 
            sdk_model=TransportZone(display_name=self.tz_name)).id

        ipd_sp_spec = IpDiscoverySwitchingProfile(
            arp_bindings_limit=1,
            arp_snooping_enabled=False,
            dhcp_snooping_enabled=True,
            vm_tools_enabled=False,
            description="",
            display_name="{}-{}".format(self.tz_name, "default-IpDiscovery"),
            tags=[]
        )

        sg_sp_spec = SpoofGuardSwitchingProfile(
            white_list_providers=[self.SGW],
            description="",
            display_name="{}-{}".format(self.tz_name, "default-SpoofGuard"),
            tags=[])

        ipd_sp = self.get(sdk_service=SwitchingProfiles, sdk_model=ipd_sp_spec)
        sg_sp = self.get(sdk_service=SwitchingProfiles, sdk_model=sg_sp_spec)

        if not ipd_sp_spec:
            ipd_sp = self.create(
                sdk_service=SwitchingProfiles, sdk_model=ipd_sp_spec)
        if not sg_sp:
            sg_sp = self.create(
                sdk_service=SwitchingProfiles, sdk_model=sg_sp_spec)

        self.default_switching_profile_ids = [
            SwitchingProfileTypeIdEntry(key=self.IPK,value=ipd_sp.id),
            SwitchingProfileTypeIdEntry(key=self.SGK,value=sg_sp.id)
        ]


    def get_switch_id_for_segmentation_id(self, segmentation_id):
        sw_name = "{}-{}".format(self.tz_name, segmentation_id)

        ls_spec = LogicalSwitch(
            display_name=sw_name,
            description="",
            resource_type="",
            tags=[],
            admin_state=LogicalSwitch.ADMIN_STATE_UP,
            transport_zone_id=self.tz_id,
            uplink_teaming_policy_name=None,
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

        try:
            ls = self.create(sdk_service=LogicalSwitches, sdk_model=ls_spec)
        except Exception as e:
            if "Object exists" in str(e):
                ls = self.get(sdk_service=LogicalSwitches, sdk_model=ls_spec)
            else:
                raise e
            return ls.id

    def get_port(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        attr_key = "attachment.id"
        attr_val = str(sdk_model.attachment["id"])
        msg = "Getting '{}'  {}='{}' ... ".format(sdk_type, attr_key, attr_val)
        LOG.info(msg)

        kwargs = {
            "sdk_service": sdk_service, 
            "sdk_model": sdk_model, 
            "attr_key": "attachment_id", 
            "attr_val": attr_val
        }

        return self.retry_until_result(self.get_by_attr, kwargs=kwargs, 
            retry_max=3, retry_sleep=5)

    def port_update(self, attachment_id, revision, security_groups_ids,
            address_bindings, qos_name=None):
        # TODO - Port trunking branch will be hooked here
        lp = self.get_port(sdk_service=LogicalPorts, 
            sdk_model=LogicalPort(attachment={ "id": attachment_id}))
        
        if not lp:
            raise Exception("Not found. Unable to update port '{}'"
                .format(attachment_id))
        
        sg_scope = nsxv3_constants.NSXV3_SECURITY_GROUP_SCOPE
        rev_scope = nsxv3_constants.NSXV3_REVISION_SCOPE

        lp.tags = [Tag(scope=sg_scope, tag=id) for id in security_groups_ids]
        lp.tags.append(Tag(scope=rev_scope, tag=str(revision)))
        lp.switching_profile_ids = []
        lp.switching_profile_ids.extend(self.default_switching_profile_ids)

        if qos_name:
            qos = self.get(
                sdk_service=SwitchingProfiles, 
                sdk_model=QosSwitchingProfile(display_name=qos_name))
            if qos:
                lp.switching_profile_ids.append(
                    SwitchingProfileTypeIdEntry(key=self.QSK,value=qos.id))
        
        lp.address_bindings = []
        for ip, mac in address_bindings:
            pc = PacketAddressClassifier(ip_address=ip,mac_address=mac)
            lp.address_bindings.append(pc)

        return self.update(sdk_service=LogicalPorts, sdk_model=lp)

    def port_delete(self, attachment_id):
        lp = self.get_port(sdk_service=LogicalPorts, 
            sdk_model=LogicalPort(attachment={ "id": attachment_id}))

        if lp:
            self.delete(sdk_service=LogicalPorts, sdk_model=lp)
        else:
            LOG.warning("Port '{}' already deleted.".format(attachment_id))

    def create_switch_profile_qos(self, qos_policy_name, revision_number=None):
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
        self.create(sdk_service=SwitchingProfiles, sdk_model=qos_spec)

    def delete_switch_profile_qos(self, qos_policy_name):
        qos_spec = QosSwitchingProfile(display_name=qos_policy_name)
        qos = self.get(sdk_service=SwitchingProfiles, sdk_model=qos_spec)

        if qos:
            self.delete(sdk_service=SwitchingProfiles, sdk_model=qos)
        else:
            LOG.warning("QoS Profile '{}' already deleted."
                .format(qos_policy_name))

    def validate_switch_profile_qos(self, rules):
        for rule in rules:
            if "max_kbps" not in rule and "dscp_mark" not in rule:
                LOG.warning(
                    "The NSXv3 plugin cannot handler rule {}".format(rule))

    def update_switch_profile_qos(self, context, policy_name, 
        revision_number, rules):

        qos = {}
        shaper_configuration_spec = copy.deepcopy(
            QOS_SPEC_SHAPER_CONFIGURATION)
        dscp = copy.deepcopy(QOS_SPEC_DSCP)

        for rule in rules:
            # is a bandwidth_limit rule
            if "max_kbps" in rule:
                limits = {
                    "average_bandwidth_mbps": int(
                        round(
                            float(
                                rule["max_kbps"]) /
                            1024)),
                    "peak_bandwidth_mbps": int(
                        round(
                            float(
                                rule["max_kbps"]) /
                            1024) *
                        2),
                    "burst_size_bytes": int(
                        rule["max_burst_kbps"]) *
                    128,
                }
                if rule.get("direction") == "ingress":
                    shaper = shaper_configuration_spec["IngressRateShaper"]
                    shaper["enabled"] = True
                    shaper["average_bandwidth_mbps"] = limits[
                        "average_bandwidth_mbps"]
                    shaper["burst_size_bytes"] = limits[
                        "burst_size_bytes"]
                    shaper["peak_bandwidth_mbps"] = limits[
                        "peak_bandwidth_mbps"]
                else:
                    shaper = shaper_configuration_spec["EgressRateShaper"]
                    shaper["enabled"] = True
                    shaper["average_bandwidth_mbps"] = limits[
                        "average_bandwidth_mbps"]
                    shaper["burst_size_bytes"] = limits[
                        "burst_size_bytes"]
                    shaper["peak_bandwidth_mbps"] = limits[
                        "peak_bandwidth_mbps"]
            elif "dscp_mark" in rule:
                dscp = {
                    "mode": "UNTRUSTED",
                    "priority": int(rule["dscp_mark"])
                }
            else:
                LOG.warning(
                    "The NSXv3 plugin cannot handler rule {}".format(rule))


        qos_spec = {
            "shaper_configuration": [
                shaper_configuration_spec["IngressRateShaper"],
                shaper_configuration_spec["EgressRateShaper"],
                shaper_configuration_spec["IngressBroadcastRateShaper"]
            ],
            "dscp": dscp,
            "tags": [{
                "scope": nsxv3_constants.NSXV3_REVISION_SCOPE,
                "tag": str(revision_number)
            }]
        }

        get_kwargs = {
            "sdk_service" : SwitchingProfiles,
            "sdk_model": QosSwitchingProfile(display_name=policy_name)
        }
        qos = self.retry_until_result(operation=self.get, 
            kwargs=get_kwargs, retry_max=3,retry_sleep=5)
        
        if not qos:
            raise Exception("Not found. Unable to update policy '{}'".format(
                policy_name
            ))

        qos_spec["id"] = qos.id
        qos_spec["display_name"] = qos.display_name
        qos_spec["resource_type"] = qos.resource_type
        qos_spec["_revision"] = qos.revision

        url = "{}/{}/{}".format(
            self.base_url, "api/v1/switching-profiles", qos_spec["id"])
        return self._put(url=url, data=json.dumps(qos_spec))

    def get_name_revision_dict(self, sdk_model, attr_key=None, attr_val=None):
        sdk_type = str(sdk_model.__class__.__name__)
        name_rev = {}
        name_id = {}
        limit = cfg.CONF.NSXV3.nsxv3_max_records_per_query
        limit = limit if limit < 1000 else 1000
        cursor = ""
        rev_scope = nsxv3_constants.NSXV3_REVISION_SCOPE

        key = attr_key
        ands = [attr_val] if attr_val else []

        cycle=0
        while True:
            objs = self._query(resource_type=sdk_type, key=key, ands=ands, 
                size=limit, start=cursor)

            for obj in objs:
                if 'LogicalPort' in sdk_type:
                    name = obj.get("attachment").get("id")
                else:
                    name = obj.get("display_name")
                revision = ""
                if 'tags' in obj:
                    for tag in obj.get("tags"):
                        if tag.get("scope") == rev_scope:
                            revision = tag.get("tag")
                            break

                name_rev[name] = revision
                name_id[name] = obj.get("id")
            cycle=1
            if len(objs) < limit:
                break
            cursor = cycle * limit
        return (name_rev, name_id)

