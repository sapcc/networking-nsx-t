from oslo_log import log as logging
from oslo_config import cfg
import copy
import json

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


# IP_PROTOCOL_NUMBERS source
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
IP_PROTOCOL_NUMBERS = {
    "hopopt": 0,
    "icmp": 1,
    "igmp": 2,
    "ggp": 3,
    "ip-in-ip": 4,
    "st": 5,
    "tcp": 6,
    "cbt": 7,
    "egp": 8,
    "igp": 9,
    "bbn-rcc-mon": 10,
    "nvp-ii": 11,
    "pup": 12,
    "argus": 13,
    "emcon": 14,
    "xnet": 15,
    "chaos": 16,
    "udp": 17,
    "mux": 18,
    "dcn-meas": 19,
    "hmp": 20,
    "prm": 21,
    "xns-idp": 22,
    "trunk-1": 23,
    "trunk-2": 24,
    "leaf-1": 25,
    "leaf-2": 26,
    "rdp": 27,
    "irtp": 28,
    "iso-tp4": 29,
    "netblt": 30,
    "mfe-nsp": 31,
    "merit-inp": 32,
    "dccp": 33,
    "3pc": 34,
    "idpr": 35,
    "xtp": 36,
    "ddp": 37,
    "idpr-cmtp": 38,
    "tp++": 39,
    "il": 40,
    "ipv6": 41,
    "sdrp": 42,
    "ipv6-route": 43,
    "ipv6-frag": 44,
    "idrp": 45,
    "rsvp": 46,
    "gres": 47,
    "dsr": 48,
    "bna": 49,
    "esp": 50,
    "ah": 51,
    "i-nlsp": 52,
    "swipe": 53,
    "narp": 54,
    "mobile": 55,
    "tlsp": 56,
    "skip": 57,
    "ipv6-icmp": 58,
    "ipv6-nonxt": 59,
    "ipv6-opts": 60,
    "cftp": 62,
    "sat-expak": 64,
    "kryptolan": 65,
    "rvd": 66,
    "ippc": 67,
    "sat-mon": 69,
    "visa": 70,
    "ipcu": 71,
    "cpnx": 72,
    "cphb": 73,
    "wsn": 74,
    "pvp": 75,
    "br-sat-mon": 76,
    "sun-nd": 77,
    "wb-mon": 78,
    "wb-expak": 79,
    "iso-ip": 80,
    "vmtp": 81,
    "secure-vmtp": 82,
    "vines": 83,
    "ttp": 84,
    "iptm": 84,
    "nsfnet-igp": 85,
    "dgp": 86,
    "tcf": 87,
    "eigrp": 88,
    "ospf": 89,
    "sprite-rpc": 90,
    "larp": 91,
    "mtp": 92,
    "ax.25": 93,
    "os": 94,
    "micp": 95,
    "scc-sp": 96,
    "etherip": 97,
    "encap": 98,
    "gmtp": 100,
    "ifmp": 101,
    "pnni": 102,
    "pim": 103,
    "aris": 104,
    "scps": 105,
    "qnx": 106,
    "a/n": 107,
    "ipcomp": 108,
    "snp": 109,
    "compaq-peer": 110,
    "ipx-in-ip": 111,
    "vrrp": 112,
    "pgm": 113,
    "l2tp": 115,
    "ddx": 116,
    "iatp": 117,
    "stp": 118,
    "srp": 119,
    "uti": 120,
    "smp": 121,
    "sm": 122,
    "ptp": 123,
    "fire": 125,
    "crtp": 126,
    "crudp": 127,
    "sscopmce": 128,
    "iplt": 129,
    "sps": 130,
    "pipe": 131,
    "sctp": 132,
    "fc": 133,
    "rsvp-e2e-ignore": 134,
    "mobility header": 135,
    "udplite": 136,
    "mpls-in-ip": 137,
    "manet": 138,
    "hip": 139,
    "shim6": 140,
    "wesp": 141,
    "rohc": 142
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
        self.login()
        self.tz_id = self.get(sdk_service=TransportZones,
                              sdk_model=TransportZone(display_name=self.tz_name
                                                      )).id

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

        url = "{}/{}/{}".format(
            self.base_url, "api/v1/switching-profiles", qos_spec["id"])
        return self._put(url=url, data=json.dumps(qos_spec))

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

    def update_security_group_rules(self, security_group_id,
                                    revision_number, add_rules, del_rules):

        sec_spec = FirewallSection(display_name=security_group_id)
        sec = self.get(sdk_service=Sections, sdk_model=sec_spec)

        path = "/api/v1/firewall/sections/{}/rules".format(sec.id)

        revision = int(sec.revision)
        for sdk_obj in add_rules:
            data = nsxv3_utils.get_firewall_rule(sdk_obj)
            data["_revision"] = revision
            ret = self._post(path=path, data=data)
            if ret.status_code == 200:
                # Optimization
                # No need to parse response and load generated revision number as
                # we are holders of the security group Lock
                revision += 1
            else:
                LOG.error("Error post rule {}: {}"
                            .format(sdk_obj.display_name, ret.content))

        for rule_id in del_rules:
            self._delete(path="{}/{}".format(path, rule_id))

        # Update Security Group (IP Set) revision_number when everythings is
        # updated. In case of falure above the revision will not be updated
        # and synchronization will try to fix the security group state
        rev_scope = nsxv3_constants.NSXV3_REVISION_SCOPE
        ips_spec = IPSet(display_name=security_group_id)
        ips = self.get(sdk_service=IpSets, sdk_model=ips_spec)
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

        if remote_group_id:
            target = ResourceReference(
                target_type='IPSet',
                target_id=remote_group_id,
                is_valid=True,
                target_display_name=security_group_id)
        elif remote_ip_prefix is None:
            target = ANY_TARGET
        elif remote_ip_prefix != '0.0.0.0/0':
            target = ResourceReference(target_type=PROTOCOL_TYPES[ethertype],
                                       target_display_name=remote_ip_prefix,
                                       target_id=remote_ip_prefix,
                                       is_valid=True)

        if min and max:
            port = "{}-{}".format(min, max) if min != max else str(min)
        if protocol == 'icmp':
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
        elif protocol and hasattr(IP_PROTOCOL_NUMBERS, protocol):
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

        cycle = 0
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
            cycle = 1
            if len(objs) < limit:
                break
            cursor = cycle * limit
        return (name_rev, name_id)
