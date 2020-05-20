import ipaddress
from oslo_log import log as logging
from oslo_config import cfg
import copy
import json
import datetime

from com.vmware.nsx_client import LogicalSwitches
from com.vmware.nsx_client import TransportZones
from com.vmware.nsx_client import LogicalPorts
from com.vmware.nsx_client import NsGroups
from com.vmware.nsx_client import SwitchingProfiles
from com.vmware.nsx_client import IpSets

from com.vmware.nsx.model_client import TransportZone
from com.vmware.nsx.model_client import LogicalSwitch
from com.vmware.nsx.model_client import Tag
from com.vmware.nsx.model_client import LogicalPort
from com.vmware.nsx.model_client import PacketAddressClassifier
from com.vmware.nsx.model_client import SwitchingProfileTypeIdEntry
from com.vmware.nsx.model_client import QosSwitchingProfile
from com.vmware.nsx.model_client import IpDiscoverySwitchingProfile
from com.vmware.nsx.model_client import SpoofGuardSwitchingProfile

from com.vmware.nsx.firewall_client import Sections
from com.vmware.nsx.model_client import ICMPTypeNSService
from com.vmware.nsx.model_client import FirewallRule
from com.vmware.nsx.model_client import FirewallService
from com.vmware.nsx.model_client import FirewallSection
from com.vmware.nsx.model_client import ResourceReference
from com.vmware.nsx.model_client import L4PortSetNSService
from com.vmware.nsx.model_client import IPProtocolNSService

from com.vmware.nsx.model_client import IPSet
from com.vmware.nsx.model_client import NSGroup
from com.vmware.nsx.model_client import NSGroupTagExpression

from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_client
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_utils

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.nsxv3_constants import *

LOG = logging.getLogger(__name__)


class Timestamp(object):

    def __init__(
            self, name, nsx_client, sdk_service, sdk_model, timeout):

        self._client = nsx_client
        self._service = sdk_service
        self._model = sdk_model
        self._timeout = timeout
        self._name = name

    def _get_date(self, timestamp=None):
        format = "%Y-%m-%d %H:%M:%S"
        dt = datetime.datetime
        if timestamp is None:
            return dt.now().strftime(format)
        else:
            return dt.strptime(timestamp, format)

    def has_set(self):
        return self._name in self._client.get_tags(self._service, self._model)

    def has_expired(self):
        tags = self._client.get_tags(self._service, self._model)

        timestamp_str = tags.get(self._name)
        if not timestamp_str:
            return True

        timestamp = self._get_date(timestamp_str) + \
            datetime.timedelta(hours=self._timeout)

        return timestamp < datetime.datetime.now()

    def update(self):
        tags = self._client.get_tags(self._service, self._model)
        tags[self._name] = self._get_date()
        self._client.set_tags(self._service, self._model, tags)


class NSXv3Facada(nsxv3_client.NSXv3ClientImpl):

    IPK = SwitchingProfileTypeIdEntry.KEY_IPDISCOVERYSWITCHINGPROFILE
    SGK = SwitchingProfileTypeIdEntry.KEY_SPOOFGUARDSWITCHINGPROFILE
    QSK = SwitchingProfileTypeIdEntry.KEY_QOSSWITCHINGPROFILE
    SGW = SpoofGuardSwitchingProfile.WHITE_LIST_PROVIDERS_LPORT_BINDINGS

    def __init__(self, api_scheduler):
        super(NSXv3Facada, self).__init__(api_scheduler=api_scheduler)
        self.tz_name = cfg.CONF.NSXV3.nsxv3_transport_zone_name

    def setup(self):
        self.login()
        self.tz_id = self.get(sdk_service=TransportZones,
                              sdk_model=TransportZone(display_name=self.tz_name
                                                      )).id
        self.agent_id = cfg.CONF.AGENT.agent_id

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

        ipd_sp = self.create(sdk_service=SwitchingProfiles,
                             sdk_model=ipd_sp_spec)

        sg_sp = self.create(sdk_service=SwitchingProfiles,
                            sdk_model=sg_sp_spec)

        id_entities = [
            SwitchingProfileTypeIdEntry(key=self.IPK, value=ipd_sp.id)
        ]

        if cfg.CONF.NSXV3.nsxv3_enable_spoof_guard:
            id_entities.append(SwitchingProfileTypeIdEntry(key=self.SGK,
                                                           value=sg_sp.id))

        self.default_switching_profile_ids = id_entities

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
            vlan=int(segmentation_id),
            switching_profile_ids=[],
            address_bindings=[]
        )

        return self.create(sdk_service=LogicalSwitches, sdk_model=ls_spec).id

    def get_port(self, sdk_service, sdk_model):
        sdk_service(self.stub_config)
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

        return self.retry_until_result(self.get_by_attr, kwargs=kwargs)

    def port_update(self, attachment_id, revision, security_groups_ids,
                    address_bindings, qos_name=None):
        # TODO - Port trunking branch will be hooked here
        attachment = {"id": attachment_id}
        lp = self.get_port(sdk_service=LogicalPorts,
                           sdk_model=LogicalPort(attachment=attachment))

        if not lp:
            msg = "Not found. Unable to update port '{}'".format(attachment_id)
            LOG.error(msg)
            raise Exception(msg)

        sg_scope = nsxv3_constants.NSXV3_SECURITY_GROUP_SCOPE
        rev_scope = nsxv3_constants.NSXV3_REVISION_SCOPE
        agent_scope = nsxv3_constants.NSXV3_AGENT_SCOPE

        lp.tags = [Tag(scope=sg_scope, tag=id) for id in security_groups_ids]
        lp.tags.append(Tag(scope=rev_scope, tag=str(revision)))
        lp.tags.append(Tag(scope=agent_scope, tag=str(self.agent_id)))
        lp.switching_profile_ids = []
        lp.switching_profile_ids.extend(self.default_switching_profile_ids)

        if qos_name:
            qos = self.get(
                sdk_service=SwitchingProfiles,
                sdk_model=QosSwitchingProfile(display_name=qos_name))
            if qos:
                lp.switching_profile_ids.append(
                    SwitchingProfileTypeIdEntry(key=self.QSK, value=qos.id))

        lp.address_bindings = []
        for ip, mac in address_bindings:
            if '/' in ip:
                continue
            pc = PacketAddressClassifier(ip_address=ip, mac_address=mac)
            lp.address_bindings.append(pc)

        return self.update(sdk_service=LogicalPorts, sdk_model=lp)

    def port_delete(self, attachment_id):
        attachment = {"id": attachment_id}
        lp = self.get_port(sdk_service=LogicalPorts,
                           sdk_model=LogicalPort(attachment=attachment))

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

        sdk_service = SwitchingProfiles
        sdk_model = QosSwitchingProfile(display_name=policy_name)
        qos = self.get(sdk_service=sdk_service, sdk_model=sdk_model)

        if not qos:
            raise Exception("Not found. Unable to update policy '{}'".format(
                policy_name
            ))

        qos_spec["id"] = qos.id
        qos_spec["display_name"] = qos.display_name
        qos_spec["resource_type"] = qos.resource_type
        qos_spec["_revision"] = qos.revision

        path = "{}/{}/{}".format(
            self.base_url, "api/v1/switching-profiles", qos_spec["id"])
        return self._put(path=path, data=json.dumps(qos_spec))

    def get_or_create_security_group(self, security_group_id):
        ips_spec = IPSet(
            display_name=security_group_id,
            ip_addresses=[],
            resource_type='IPSet'
        )
        nsg_spec = NSGroup(
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
        sec_spec = FirewallSection(
            display_name=security_group_id,
            is_default=False,
            resource_type='FirewallSection',
            section_type='LAYER3',
            stateful=True
        )

        ipset = self.create(sdk_service=IpSets, sdk_model=ips_spec)
        nsg = self.create(sdk_service=NsGroups, sdk_model=nsg_spec)
        sec = self.create(sdk_service=Sections, sdk_model=sec_spec)
        return (ipset, nsg, sec)

    def delete_security_group(self, security_group_id):
        sec_spec = FirewallSection(display_name=security_group_id)
        ips_spec = IPSet(display_name=security_group_id)
        nsg_spec = NSGroup(display_name=security_group_id)

        self.delete(sdk_service=Sections, sdk_model=sec_spec)
        self.delete(sdk_service=IpSets, sdk_model=ips_spec)
        self.delete(sdk_service=NsGroups, sdk_model=nsg_spec)
        return True

    def update_security_group_members(self, security_group_id, member_cidrs):
        ips_spec = IPSet(display_name=security_group_id)
        ips = self.get(sdk_service=IpSets, sdk_model=ips_spec)
        ips.ip_addresses = member_cidrs
        self.update(sdk_service=IpSets, sdk_model=ips)

    def update_security_group_capabilities(self,
                                           security_group_id, capabilities):
        fs_spec = FirewallSection(display_name=security_group_id)
        fs = self.get(sdk_service=Sections, sdk_model=fs_spec)

        fs.tcp_strict = nsxv3_constants.NSXV3_CAPABILITY_TCP_STRICT in\
            capabilities

        self.update(sdk_service=Sections, sdk_model=fs)

    def update_security_group_rules(self, security_group_id,
                                    revision_number, add_rules, del_rules):

        sec_spec = FirewallSection(display_name=security_group_id)
        sec = self.get(sdk_service=Sections, sdk_model=sec_spec)

        path = "/api/v1/firewall/sections/{}/rules".format(sec.id)

        error = False
        revision = int(sec.revision)
        for sdk_obj in add_rules:
            data = nsxv3_utils.get_firewall_rule(sdk_obj)
            data["_revision"] = revision
            LOG.debug("Creating Firewall Rule %s", json.dumps(data))
            ret = self._post(path=path, data=data)
            if ret.status_code == 200:
                # Optimization
                # No need to parse response and load generated revision number
                # as we are holders of the security group Lock
                revision += 1
            else:
                error = True
                LOG.error("Error post rule {}: {}"
                          .format(sdk_obj.display_name, ret.content))

        for rule_id in del_rules:
            LOG.debug("Removing Firewall Rule %s", rule_id)
            self._delete(path="{}/{}".format(path, rule_id))

        # Update Security Group (IP Set) revision_number when everythings is
        # updated. In case of falure above the revision will not be updated
        # and synchronization will try to fix the security group state
        rev_scope = nsxv3_constants.NSXV3_REVISION_SCOPE
        ips_spec = IPSet(display_name=security_group_id)
        ips = self.get(sdk_service=IpSets, sdk_model=ips_spec)
        # Update revision number only if there no errors
        if not error:
            ips.tags = [Tag(scope=rev_scope, tag=str(revision_number))]
        self.update(sdk_service=IpSets, sdk_model=ips)

    def get_security_group_rule_spec(self, rule):
        id = rule["id"]
        min = rule["port_range_min"]
        max = rule["port_range_max"]
        protocol = rule["protocol"]
        ethertype = rule['ethertype']
        direction = rule['direction']
        remote_group_id = rule["remote_group_id"]
        # Required by default security group rule to allow group members only
        # local_group_id = rule["local_group_id"]
        remote_ip_prefix = rule["remote_ip_prefix"]
        security_group_id = rule["security_group_id"]
        apply_to = rule["apply_to"]

        DIRECTIONS = {'ingress': 'IN', 'egress': 'OUT'}
        PROTOCOLS = {'IPv4': 'IPV4', 'IPv6': 'IPV6'}
        PROTOCOL_TYPES = {'IPv4': 'IPv4Address', 'IPv6': 'IPv6Address'}
        SESSION_PROTOCOLS = {
            'tcp': L4PortSetNSService.L4PROTOCOL_TCP,
            'udp': L4PortSetNSService.L4PROTOCOL_UDP
        }
        ICMP_PROTOCOLS = {
            'IPv4': ICMPTypeNSService.PROTOCOL_ICMPV4,
            'IPv6': ICMPTypeNSService.PROTOCOL_ICMPV6
        }

        target = None
        # For future use. Any type maps to None as value
        # ANY_TARGET = None
        port = ANY_PORT = '1-65535'
        service = ANY_SERVICE = None
        ANY_PROTOCOL = None
        ANY_TARGET = None

        # Set default security group rule to allow ANY
        current = ANY_TARGET

        # Set default security group rule to allow group members only
        # When set it allowes inbout/outbound traffic only to group memebrs.
        # current = ResourceReference(target_type='IPSet',
        #                             target_display_name=security_group_id,
        #                             target_id=local_group_id)

        applied_to = ResourceReference(
            target_type='NSGroup',
            target_id=apply_to,
            is_valid=True,
            target_display_name=security_group_id)

        if remote_ip_prefix:
            remote_ip_prefix = str(
                ipaddress.ip_network(
                    unicode(remote_ip_prefix),
                    strict=False))

        if remote_group_id:
            target = ResourceReference(
                target_type='IPSet',
                target_id=remote_group_id,
                is_valid=True,
                target_display_name=security_group_id)
        elif remote_ip_prefix in [None, '0.0.0.0/0', '::/0']:
            target = ANY_TARGET
        elif remote_ip_prefix.startswith('0.0.0.0/'):
            # TODO: Due bug in NSX-T API ignore 0.0.0.0 Network definitions
            # that are not ANY_TARGET
            return None
        else:
            target = ResourceReference(target_type=PROTOCOL_TYPES[ethertype],
                                       target_display_name=remote_ip_prefix,
                                       target_id=remote_ip_prefix,
                                       is_valid=True)

        if min and max:
            port = "{}-{}".format(min, max) if min != max else str(min)
        if protocol == 'icmp':
            # Disable ICMP rule generation
            # for invalid ICMP type/code combinations
            if min not in VALID_ICMP_RANGES[ethertype]\
                    or max not in VALID_ICMP_RANGES[ethertype][min]:
                return None
            service = ICMPTypeNSService(
                icmp_type=str(min) if min else None,
                icmp_code=str(max) if max else None,
                protocol=ICMP_PROTOCOLS[ethertype])
        elif protocol in ["tcp", "udp"]:
            service = L4PortSetNSService(
                l4_protocol=SESSION_PROTOCOLS[protocol],
                destination_ports=[port],
                source_ports=[ANY_PORT])
        elif str(protocol).isdigit():
            service = IPProtocolNSService(protocol_number=int(protocol))
        elif protocol and protocol in IP_PROTOCOL_NUMBERS:
            ip_protocol = IP_PROTOCOL_NUMBERS.get(protocol)
            service = IPProtocolNSService(protocol_number=int(ip_protocol))
        elif protocol is ANY_PROTOCOL:
            service = ANY_SERVICE
        else:
            LOG.warning("Unsupported protocol '{}' for rule '{}'."
                        .format(protocol, id))
            return None

        current = [current] if current else None
        target = [target] if target else None

        return FirewallRule(
            action=FirewallRule.ACTION_ALLOW,
            display_name=id,
            direction=DIRECTIONS[direction],
            ip_protocol=PROTOCOLS[ethertype],
            sources=target if direction in 'ingress' else current,
            destinations=current if direction in 'ingress' else target,
            services=[FirewallService(service=service)] if service else None,
            applied_tos=[applied_to])

    def get_revisions(self, sdk_model, attr_key=None, attr_val=None):
        sdk_type = str(sdk_model.__class__.__name__)
        name_rev = {}
        name_id = {}
        metadata = {}
        limit = cfg.CONF.NSXV3.nsxv3_max_records_per_query
        limit = limit if limit < 1000 else 1000
        cursor = ""
        rev_scope = nsxv3_constants.NSXV3_REVISION_SCOPE

        key = attr_key
        ands = [attr_val] if attr_val else []

        def is_managed_by(obj):
            for tag in obj.get("tags"):
                if tag.get("scope") == nsxv3_constants.NSXV3_AGENT_SCOPE\
                    and tag.get("tag") == self.agent_id:
                    return True
            return False

        cycle = 0
        while True:
            objs = self._query(resource_type=sdk_type, key=key, ands=ands,
                               size=limit, start=cursor)

            for obj in objs:
                if 'LogicalPort' in sdk_type:
                    name = obj.get("attachment").get("id")
                    if 'tags' in obj:
                        # Skip port if not managed by the agent
                        if not is_managed_by(obj):
                            continue
                else:
                    name = obj.get("display_name")
                revision = ""
                if 'tags' in obj:
                    for tag in obj.get("tags"):
                        if tag.get("scope") == rev_scope:
                            revision = tag.get("tag")
                            break
                if 'FirewallRule' in sdk_type:
                    metadata[name] = {
                        'FirewallRule.disabled': obj.get("disabled"),
                    }

                name_rev[name] = revision
                name_id[name] = obj.get("id")
            cycle += 1
            if len(objs) < limit:
                break
            cursor = cycle * limit
        return name_rev, name_id, metadata

    def set_tags(self, sdk_service, sdk_model, tags):
        obj = self.get(sdk_service=sdk_service, sdk_model=sdk_model)
        obj.tags = []
        for scope, tag in tags.items():
            obj.tags.append(Tag(scope=scope, tag=str(tag)))
        self.update(sdk_service=sdk_service, sdk_model=obj)

    def get_tags(self, sdk_service, sdk_model):
        obj = self.get(sdk_service=sdk_service, sdk_model=sdk_model)
        tags = dict()
        if obj.tags:
            for tag in obj.tags:
                tags[tag.scope] = tag.tag
        return tags
