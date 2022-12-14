import copy
import time
from typing import Dict, List, Tuple
import uuid

import netaddr
from oslo_config import cfg
from oslo_log import log as logging

from networking_nsxv3.common.constants import *
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider as base
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import Client
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class API(object):
    ZONES = "/api/v1/transport-zones"
    PROFILES = "/api/v1/switching-profiles"

    RULE = "/api/v1/firewall/sections/{}/rules/{}"
    RULES = "/api/v1/firewall/sections/{}/rules"
    RULES_CREATE = "/api/v1/firewall/sections/{}/rules?action=create_multiple"

    PORTS = "/api/v1/logical-ports"
    PORT = "/api/v1/logical-ports/{}"

    SWITCHES = "/api/v1/logical-switches"
    SWITCH = "/api/v1/logical-switches/{}"

    IPSETS = "/api/v1/ip-sets"
    IPSET = "/api/v1/ip-sets/{}"

    NSGROUPS = "/api/v1/ns-groups"
    NSGROUP = "/api/v1/ns-group/{}"

    SECTIONS = "/api/v1/firewall/sections"
    SECTION = "/api/v1/firewall/sections/{}"

    PARAMS_GET_DEFAULT_PROFILES = {"switching_profile_type": "IpDiscoverySwitchingProfile,SpoofGuardSwitchingProfile"}
    PARAMS_ALL_PROFILES = {"include_system_owned": True}

    PARAMS_GET_QOS_PROFILES = {"switching_profile_type": "QosSwitchingProfile"}


class ResourceMeta(base.ResourceMeta):
    pass


class Resource(base.Resource):
    def __init__(self, resource: dict):
        self.resource = resource

    @property
    def is_managed(self):
        if self.type == "LogicalSwitch" or self.type == "QosSwitchingProfile":
            return True
        if "policyPath" in self.tags:
            return False
        if not self.resource.get("locked"):
            user = self.resource.get("_create_user")
            if user == "admin" or user == cfg.CONF.NSXV3.nsxv3_login_user:
                return True

            if self.type == "LogicalPort":
                att_id = self.resource.get("attachment", {}).get("id")
                if user != "nsx_policy" and att_id:
                    return True
        return False

    @property
    def type(self):
        return self.resource.get("resource_type")

    @property
    def id(self):
        return self.resource.get("id")

    @property
    def unique_id(self):
        return self.resource.get("id")

    @property
    def has_valid_os_uuid(self) -> bool:
        try:
            uuid.UUID(self.os_id)
            return True
        except (ValueError, TypeError):
            return False

    @property
    def os_id(self):
        os_id = self.resource.get("display_name")
        if self.type == "LogicalSwitch":
            os_id = os_id.split("-")[-1]
        if self.type == "LogicalPort":
            os_id = self.resource.get("attachment", {}).get("id")
        return os_id

    @property
    def tags(self):
        tags = {}
        for item in self.resource.get("tags", []):
            scope = item.get("scope")
            tag = item.get("tag")

            if scope in tags:
                if type(tags[scope]) != list:
                    tags[scope] = [tags[scope]]
                tags[scope].append(tag)
            else:
                tags[scope] = tag

        return tags

    @property
    def meta(self):
        tags = self.tags
        # Set age to most recent and rev to 0 NSGroups to always skip the update
        return ResourceMeta(
            id=self.id,
            rev=tags.get(NSXV3_REVISION_SCOPE),  # empty set for NSGroup
            age=int(time.time()) if self.type == "NSGroup" else tags.get(NSXV3_AGE_SCOPE),
            revision=self.resource.get("_revision"),
            last_modified_time=self.resource.get("_last_modified_time"),
        )


class Payload(object):
    @staticmethod
    def get_compacted_cidrs(os_cidrs) -> dict:
        """Reduce number of CIDRs based on the netmask overlapping
        """
        compacted_cidrs = []
        for cidr in netaddr.IPSet(os_cidrs).iter_cidrs():
            if cidr.version == 4 and cidr.prefixlen == 32:
                compacted_cidrs.append(str(cidr.ip))
            elif cidr.version == 6 and cidr.prefixlen == 128:
                compacted_cidrs.append(str(cidr.ip))
            else:
                compacted_cidrs.append(str(cidr))
        return compacted_cidrs

    @staticmethod
    def tags(os_obj, more=dict()) -> list:
        tags = {
            NSXV3_AGE_SCOPE: int(time.time())
        }
        if os_obj:
            tags[NSXV3_REVISION_SCOPE] = os_obj.get("revision_number")
        tags.update(more)

        provider_tags = []
        for scope, tag in tags.items():
            if type(tag) == list:
                for value in tag:
                    provider_tags.append({"scope": scope, "tag": value})
            else:
                provider_tags.append({"scope": scope, "tag": tag})

        return provider_tags

    @staticmethod
    def ip_discovery() -> dict:
        os_id = cfg.CONF.NSXV3.nsxv3_ip_discovery_switching_profile
        return {
            "resource_type": "IpDiscoverySwitchingProfile",
            "arp_bindings_limit": 1,
            "arp_snooping_enabled": True,
            "dhcp_snooping_enabled": True,
            "vm_tools_enabled": False,
            "display_name": os_id,
        }

    @staticmethod
    def spoofguard() -> dict:
        os_id = cfg.CONF.NSXV3.nsxv3_spoof_guard_switching_profile
        return {"resource_type": "SpoofGuardSwitchingProfile", "white_list_providers": [], "display_name": os_id}

    @staticmethod
    def network(os_net, provider_net) -> dict:
        return {
            "resource_type": "LogicalSwitch",
            "vlan": os_net.get("segmentation_id"),
            "transport_zone_id": provider_net.get("transport_zone_id"),
            "address_bindings": [],
            "admin_state": "UP",
            "description": "",
            "display_name": os_net.get("id"),
            "hybrid": False,
            "switching_profile_ids": [],
        }

    def qos(self, os_qos, provider_qos) -> dict:
        payload = {
            "resource_type": "QosSwitchingProfile",
            "display_name": os_qos.get("id"),
            "tags": self.tags(os_qos),
            "shaper_configuration": [],
            "dscp": {"mode": "TRUSTED", "priority": 0},
        }

        _type = {"ingress": "IngressRateShaper", "egress": "EgressRateShaper"}

        for rule in os_qos.get("rules"):
            if "dscp_mark" in rule:
                payload["dscp"] = {"mode": "UNTRUSTED", "priority": int(rule["dscp_mark"])}
                continue
            payload["shaper_configuration"].append(
                {
                    "resource_type": _type.get(rule.get("direction")),
                    "enabled": True,
                    "average_bandwidth_mbps": int(round(float(rule["max_kbps"]) / 1024)),
                    "peak_bandwidth_mbps": int(round(float(rule["max_kbps"]) / 1024) * 2),
                    "burst_size_bytes": int(rule["max_burst_kbps"]) * 128,
                }
            )
        return payload

    def port(self, os_port, provider_port) -> dict:
        p = os_port
        pp = provider_port

        p_ppid = pp.get("parent_id")
        p_qid = pp.get("qos_policy_id")

        port = {
            "resource_type": "LogicalPort",
            "display_name": os_port.get("id"),
            "logical_switch_id": p.get("vif_details").get("nsx-logical-switch-id"),
            "admin_state": "UP",
            "switching_profile_ids": pp.get("switching_profile_ids"),
            "address_bindings": p.get("address_bindings"),
            "attachment": {
                "attachment_type": "VIF",
                "id": os_port.get("id"),
                "context": {
                    "resource_type": "VifAttachmentContext",
                    "vif_type": "PARENT",
                    "traffic_tag": p.get("vif_details").get("segmentation_id"),
                },
            },
            "tags": self.tags(os_port, more={NSXV3_SECURITY_GROUP_SCOPE: p.get("security_groups")}),
        }

        if p_ppid:
            port["attachment"]["id"] = p.get("id")
            port["attachment"]["context"]["vif_type"] = "CHILD"
            port["attachment"]["context"]["parent_vif_id"] = os_port.get("parent_id")
            if os_port.get("traffic_tag"):
                port["attachment"]["context"]["traffic_tag"] = os_port["traffic_tag"]

        if p_qid:
            port["switching_profile_ids"].append(
                {"key": "QosSwitchingProfile", "value": provider_port.get("qos_policy_id")}
            )

        return port

    def sg_members_container(self, os_sg, provider_sg) -> dict:
        cidrs = self.get_compacted_cidrs(os_sg.get("cidrs"))

        return {
            "resource_type": "IPSet",
            "display_name": os_sg.get("id"),
            "ip_addresses": cidrs,
            "tags": self.tags(
                os_sg, more={NSXV3_SECURITY_GROUP_SCOPE: os_sg.get("id"), NSXV3_REVISION_SCOPE: "latest"}
            ),
        }

    def sg_rules_ext_container(self, os_sg, provider_sg) -> dict:
        return {
            "resource_type": "NSGroup",
            "display_name": os_sg.get("id"),
            "membership_criteria": [
                {
                    "resource_type": "NSGroupTagExpression",
                    "scope": NSXV3_SECURITY_GROUP_SCOPE,
                    "scope_op": "EQUALS",
                    "tag": os_sg.get("id"),
                    "tag_op": "EQUALS",
                    "target_type": "LogicalPort",
                }
            ],
            "tags": self.tags(
                os_sg, more={NSXV3_SECURITY_GROUP_SCOPE: os_sg.get("id"), NSXV3_REVISION_SCOPE: "latest"}
            ),
        }

    def sg_rules_container(self, os_sg, provider_sg) -> dict:
        section = {
            "resource_type": "FirewallSection",
            "display_name": os_sg.get("id"),
            "section_type": "LAYER3",
            "is_default": False,
            "stateful": os_sg.get("stateful", True),
            "tcp_strict": NSXV3_CAPABILITY_TCP_STRICT in os_sg.get("tags", dict()),
            "applied_tos": [
                {
                    "target_display_name": os_sg.get("id"),
                    "target_id": provider_sg.get("applied_tos"),
                    "target_type": "NSGroup",
                }
            ],
        }

        if provider_sg.get("tags_update"):
            tags = {NSXV3_SECURITY_GROUP_SCOPE: os_sg.get("id")}
            section["tags"] = self.tags(os_sg, more=tags)

        return section

    def sg_rule(self, os_rule, provider_rule) -> dict:
        id = os_rule["id"]
        ethertype = os_rule["ethertype"]
        direction = os_rule["direction"]

        current = []
        target = self._sg_rule_target(os_rule, provider_rule)

        service, err = self._sg_rule_service(os_rule, provider_rule)
        if err:
            LOG.error("Not supported service %s", os_rule)
            LOG.error("Error info: %s", err)
            return None
        services = [{"service": service}] if service else None

        return {
            "direction": {"ingress": "IN", "egress": "OUT"}.get(direction),
            "ip_protocol": {"IPv4": "IPV4", "IPv6": "IPV6"}.get(ethertype),
            "sources": target if direction in "ingress" else current,
            "destinations": current if direction in "ingress" else target,
            "disabled": False,
            "display_name": id,
            "services": services,
            "action": "ALLOW",
            "logged": False,  # TODO selective logging
            "rule_tag": id.replace("-", ""),
            "_revision": provider_rule["_revision"],
        }

    def sg_rule_remote(self, cidr) -> dict:
        # NSX bug. Related IPSet to handle  0.0.0.0/x and ::0/x
        return {"resource_type": "IPSet", "display_name": cidr, "ip_addresses": [cidr], "tags": self.tags(None)}

    @staticmethod
    def _sg_rule_target(os_rule, provider_rule) -> list:

        if os_rule.get("remote_group_id"):
            id = provider_rule.get("remote_group_id")
            name = os_rule["remote_group_id"]
            type = "IPSet"
        elif provider_rule.get("remote_ip_prefix_id"):
            # Non-OpenStack property "remote_ip_prefix_id"
            # Used due to limitations of NSX-T Management API
            id = provider_rule.get("remote_ip_prefix_id")
            name = os_rule["remote_ip_prefix"]
            type = "IPSet"
        elif os_rule.get("remote_ip_prefix"):
            id = name = str(netaddr.IPNetwork(os_rule["remote_ip_prefix"]))
            type = {"IPv4": "IPv4Address", "IPv6": "IPv6Address"}.get(os_rule["ethertype"])
        else:
            # Any
            return []

        return [{"target_type": type, "target_id": id, "is_valid": True, "target_display_name": name}]

    @staticmethod
    def _sg_rule_service(os_rule, provider_rule, subtype="NSService") -> Tuple[dict, str]:
        _min = os_rule.get("port_range_min")
        _max = os_rule.get("port_range_max")
        protocol = os_rule.get("protocol")
        ethertype = os_rule.get("ethertype")

        if protocol == "icmp":
            _min = int(_min) if str(_min).isdigit() else _min
            _max = int(_max) if str(_max).isdigit() else _max

            if _min and VALID_ICMP_RANGES[ethertype].get(_min) is None:
                return None, "Not supported ICMP Range {}-{}".format(_min, _max)
            if _max and _max not in VALID_ICMP_RANGES[ethertype].get(_min, []):
                return None, "Not supported ICMP Range {}-{}".format(_min, _max)

            icmp_type = str(_min) if _min is not None else ""
            icmp_code = str(
                _max) if _max is not None and _min is not None and VALID_ICMP_RANGES[ethertype][_min] else ""
            return (
                {
                    "resource_type": "ICMPType{}".format(subtype),
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                    "protocol": {"IPv4": "ICMPv4", "IPv6": "ICMPv6"}.get(ethertype),
                },
                None,
            )

        if protocol in ["tcp", "udp"]:
            if not _min and not _max:
                _min = "1"
                _max = "65535"
            return (
                {
                    "resource_type": "L4PortSet{}".format(subtype),
                    "l4_protocol": {"tcp": "TCP", "udp": "UDP"}.get(protocol),
                    "destination_ports": ["{}-{}".format(_min, _max) if _min != _max and _max else str(_min)],
                    "source_ports": ["1-65535"],
                },
                None,
            )

        if str(protocol).isdigit():
            return ({"resource_type": "IPProtocol{}".format(subtype), "protocol_number": int(protocol)}, None)

        if protocol and protocol in IP_PROTOCOL_NUMBERS:
            return (
                {
                    "resource_type": "IPProtocol{}".format(subtype),
                    "protocol_number": int(IP_PROTOCOL_NUMBERS.get(protocol)),
                },
                None,
            )

        if not protocol:  # ANY
            return None, None

        return None, "Unsupported protocol {}.".format(protocol)


class Provider(base.Provider):

    PORT = "Port"
    QOS = "QoS"
    NETWORK = "Network"
    SG_RULES_EXT = "Security Group (Rules Enforcement)"

    def __init__(self, payload: Payload = Payload()):
        super(Provider, self).__init__(client=Client(), zone_id=None)
        LOG.info("Activating Management API Provider.")
        self.provider = "Management"

        self.payload: Payload = payload
        self.switch_profiles = []

        self._setup_default_switching_profiles()

    def _setup_default_switching_profiles(self):
        sg = self.payload.spoofguard()
        ip = self.payload.ip_discovery()
        sg_id = None
        ip_id = None

        profiles = self.client.get_all(path=API.PROFILES, params=API.PARAMS_GET_DEFAULT_PROFILES)

        LOG.info("Looking for the default Switching Profiles.")
        for p in profiles:
            if not ip_id and ip.get("display_name") == p.get("display_name"):
                ip_id = p.get("id")
            if not sg_id and sg.get("display_name") == p.get("display_name"):
                sg_id = p.get("id")
            if ip_id and sg_id:
                break

        if not ip_id:
            LOG.info("Ip Discovery Switching Profile not found. Creating it.")
            o = self.client.post(path=API.PROFILES, data=ip).json()
            ip_id = o.get("id")
        if not sg_id:
            LOG.info("Spoof Guard Switching Profile not found. Creating it.")
            o = self.client.post(path=API.PROFILES, data=sg).json()
            sg_id = o.get("id")

        self.switch_profiles = [
            {"key": "SpoofGuardSwitchingProfile", "value": sg_id},
            {"key": "IpDiscoverySwitchingProfile", "value": ip_id},
        ]

    def _metadata_loader(self):
        mp = base.MetaProvider
        return {
            Provider.PORT: mp(API.PORTS),
            Provider.QOS: mp(API.PROFILES),
            Provider.SG_MEMBERS: mp(API.IPSETS),
            Provider.SG_RULES: mp(API.SECTIONS),
            Provider.SG_RULES_EXT: mp(API.NSGROUPS),
            Provider.SG_RULES_REMOTE_PREFIX: mp(API.IPSETS),
            Provider.NETWORK: mp(API.SWITCHES),
        }

    def get_all_switching_profiles(self):
        return self.client.get_all(path=API.PROFILES, params=API.PARAMS_ALL_PROFILES)

    def metadata_refresh(self, resource_type, params=dict()):

        if resource_type != Provider.SG_RULE:
            provider = self._metadata[resource_type]
            with provider.meta:
                LOG.info("[%s] Fetching NSX-T metadata for Type:%s.", self.provider, resource_type)
                if provider.endpoint == API.PROFILES:
                    params = API.PARAMS_GET_QOS_PROFILES
                resources = self.client.get_all(path=provider.endpoint, params=params)
                with LockManager.get_lock(resource_type):
                    provider.meta.reset()
                    for o in resources:
                        res = Resource(o)
                        if not res.is_managed:
                            continue
                        if resource_type == Provider.SG_MEMBERS:
                            if NSXV3_REVISION_SCOPE not in res.tags:
                                continue
                        if resource_type == Provider.SG_RULES_REMOTE_PREFIX:
                            if NSXV3_REVISION_SCOPE in res.tags:
                                continue
                        if resource_type == Provider.SG_RULES:
                            if not res.has_valid_os_uuid:
                                continue
                        if resource_type == Provider.PORT:
                            # Ensure this port is attached to a agent managed
                            # logical switch, else skip it
                            is_valid_vlan = False
                            for name, ls in self._metadata[Provider.NETWORK].meta.meta.items():
                                if ls.id == res.resource.get("logical_switch_id") and name.isnumeric():
                                    is_valid_vlan = True
                                    break
                            if not is_valid_vlan:
                                continue

                        provider.meta.add(res)

    def metadata_delete(self, resource_type, os_id):
        if resource_type != Provider.SG_RULE:
            with LockManager.get_lock(resource_type):
                self._metadata[resource_type].meta.rm(os_id)

    def metadata_update(self, resource_type, provider_object):
        if resource_type != Provider.SG_RULE:
            with LockManager.get_lock(resource_type):
                res = Resource(provider_object)
                self._metadata[resource_type].meta.update(res)
                return res.meta

    def metadata(self, resource_type, os_id) -> ResourceMeta:
        if resource_type == Provider.SG_RULE:
            with LockManager.get_lock(Provider.SG_RULES):
                meta = self._metadata[Provider.SG_RULES].meta.get(os_id)
                if meta:
                    rules = self.client.get_all(API.RULES.format(meta.id))
                    meta = {Resource(o).os_id: o for o in rules}
                return meta

        with LockManager.get_lock(resource_type):
            return self._metadata[resource_type].meta.get(os_id)

    def meta_provider(self, resource_type) -> base.MetaProvider:
        return self._metadata.get(resource_type)

    def _realize(self, resource_type, delete, convertor, os_o, provider_o):
        os_id = os_o.get("id")

        begin_report = "[{}] Resource:{} with ID:{} is going to be %s.".format(self.provider, resource_type, os_id)
        end_report = "[{}] Resource:{} with ID:{} has been %s.".format(self.provider, resource_type, os_id)

        path = self.meta_provider(resource_type).endpoint
        metadata = self.metadata(resource_type, os_id)

        if metadata:
            path = "{}/{}".format(path, metadata.id)
            if delete:
                LOG.info(begin_report, "deleted")

                if resource_type == Provider.SG_RULES:
                    params = {"cascade": True}
                elif resource_type == Provider.PORT:
                    params = {"detach": True}
                elif resource_type == Provider.QOS:
                    params = {"unbind": True}
                else:
                    params = dict()

                if resource_type == Provider.PORT:
                    res = self.client.get(path=path)
                    if res.status_code == 404:
                        LOG.info(end_report, "rescheduled due 404: not found")
                        return metadata

                    o = res.json()
                    if o.get("attachment", {}).get("context", {}).get("vif_type") != "CHILD":
                        stamp = int(o.get("_last_modified_time")) / 1000

                        if not self.orphan_ports_tmout_passed(stamp):
                            LOG.info(end_report, "rescheduled for deletion")
                            return metadata

                self.client.delete(path=path, params=params)

                LOG.info(end_report, "deleted")

                return self.metadata_delete(resource_type, os_id)
            else:
                LOG.info(begin_report, "updated")
                if resource_type == Provider.SG_RULES_EXT:
                    LOG.debug(
                        "Skipping update of NSGroup:%s",
                    )
                data = convertor(os_o, provider_o)
                if metadata.revision != None:
                    data["_revision"] = metadata.revision
                o = self.client.put(path=path, data=data)
                LOG.info(end_report, "updated")
                return self.metadata_update(resource_type, o.json())
        else:
            if not delete:
                LOG.info(begin_report, "created")
                o = self.client.post(path=path, data=convertor(os_o, provider_o))
                LOG.info(end_report, "created")
                return self.metadata_update(resource_type, o.json())
            LOG.info(end_report, "already deleted")

    def outdated(self, resource_type: str, os_meta: dict):
        self.metadata_refresh(resource_type)

        if resource_type == Provider.SG_RULES:
            if type(self) == Provider:
                self.metadata_refresh(Provider.SG_RULES_EXT)
            self.metadata_refresh(Provider.SG_RULES_REMOTE_PREFIX)

        meta = self._metadata.get(resource_type).meta

        k1 = set(os_meta.keys())
        k2 = set(meta.keys())

        # Treat both new and orphaned as outdated, but filter out orphaned ports not yet to be deleted
        outdated = k1.difference(k2)
        orphaned = k2.difference(k1)

        # Don't count orphans for members, we don't know yet if they are really orphaned
        if resource_type == Provider.SG_MEMBERS:
            orphaned = set()

        # Remove Ports not yet exceeding delete timeout
        if resource_type == Provider.PORT:
            orphaned = [
                orphan for orphan in orphaned
                if self.orphan_ports_tmout_passed(meta.get(orphan).last_modified_time / 1000)
            ]

        outdated.update(orphaned)

        # Add revision outdated
        for id in k1.intersection(k2):
            if not meta.get(id).age or str(os_meta[id]) != str(meta.get(id).rev):
                meta.get(id)
                outdated.add(id)

        if type(self) == Provider and resource_type == Provider.SG_RULES:
            # NSGroups not matching Sections concidered as outdated SG
            groups = self._metadata.get(Provider.SG_RULES_EXT).meta
            outdated.update(set(groups.keys()).difference(k1))

        LOG.info(
            "[%s] The number of outdated resources for Type:%s Is:%s.", self.provider, resource_type, len(outdated)
        )
        LOG.debug("Outdated resources of Type:%s Are:%s", resource_type, outdated)

        current = k2.difference(outdated)
        if resource_type == Provider.PORT:
            # Ignore ports that are going to be deleted anyway (and therefor not existing in neutron)
            current = set([_id for _id in current if _id in os_meta])
        return outdated, current

    def age(self, resource_type: str, os_ids: List[str]):
        return [(resource_type, id, self.metadata(resource_type, id).age) for id in os_ids]

    def get_port(self, os_id):
        port = self.client.get_unique(path=API.PORTS, params={"attachment_id": os_id})
        if port:
            return self.metadata_update(Provider.PORT, port), port
        return None

    def port_realize(self, os_port: dict, delete=False):
        provider_port = dict()

        if delete:
            self._realize(Provider.PORT, delete, None, os_port, provider_port)
            return

        if os_port.get("parent_id"):
            # Child port always created internally
            parent_port = self.get_port(os_port.get("parent_id"))
            if parent_port and parent_port[0]:
                provider_port["parent_id"] = parent_port[0].id
            else:
                LOG.warning("Not found. Parent Port:%s for Child Port:%s", os_port.get("parent_id"), os_port.get("id"))
                return
        else:
            # Parent port is NOT always created externally
            port = self.get_port(os_port.get("id"))
            if port and port[0]:
                provider_port["id"] = port[0].id
            else:
                LOG.warning("Not found. Port: %s", os_port.get("id"))

        if os_port.get("qos_policy_id"):
            meta_qos = self.metadata(Provider.QOS, os_port.get("qos_policy_id"))
            if meta_qos:
                provider_port["qos_policy_id"] = meta_qos.id
            else:
                LOG.warning("Not found. QoS:%s for Port:%s", os_port.get("qos_policy_id"), os_port.get("id"))

        provider_port["switching_profile_ids"] = copy.deepcopy(self.switch_profiles)

        return self._realize(Provider.PORT, False, self.payload.port, os_port, provider_port)

    def qos_realize(self, qos, delete=False):
        return self._realize(Provider.QOS, delete, self.payload.qos, qos, dict())

    def sg_members_realize(self, sg, delete=False):
        if delete and self.metadata(Provider.SG_RULES, sg.get("id")):
            LOG.warning(
                "Resource:%s with ID:%s deletion is rescheduled due to dependency.", Provider.SG_MEMBERS, sg.get("id")
            )
            return
        return self._realize(Provider.SG_MEMBERS, delete, self.payload.sg_members_container, sg, dict())

    def sg_rules_realize(self, os_sg, delete=False, logged=False):
        provider_sg = dict()

        nsg_args = [Provider.SG_RULES_EXT, delete, self.payload.sg_rules_ext_container, os_sg, dict()]
        sec_args = [Provider.SG_RULES, delete, self.payload.sg_rules_container, os_sg, provider_sg]

        if delete:
            meta_sec = self._realize(*sec_args)
            meta_nsg = self._realize(*nsg_args)
            return

        meta_nsg = self._realize(*nsg_args)
        provider_sg.update({"applied_tos": meta_nsg.id})
        # Create/update/delete section keeping existing tags(revision)
        meta_sec = self._realize(*sec_args)

        # CRUD rules
        self._sg_rules_realize(os_sg, meta_sec, logged=logged)

        # Update section tags(revision) when all rules applied successfully
        provider_sg["tags_update"] = True
        self._realize(*sec_args)

    def _sg_rules_realize(self, os_sg, meta_sg: ResourceMeta, logged=False):

        sg_rules = {o.get("id"): o for o in os_sg.get("rules")}

        if len(sg_rules) > 1000:
            LOG.error("Unable to update Security Group:%s with more than 1K rules.", os_sg.get("id"))
            return

        sec_id = meta_sg.id

        sec_rules = self.metadata(Provider.SG_RULE, os_sg.get("id"))

        sec_rules_ids = set(sec_rules.keys())
        sg_rules_ids = set(sg_rules.keys())

        os_rules_add = sg_rules_ids.difference(sec_rules_ids)
        os_rules_remove = sec_rules_ids.difference(sg_rules_ids)
        os_rules_existing = sg_rules_ids.intersection(sec_rules_ids)

        for id in os_rules_remove:
            path = API.RULE.format(sec_id, sec_rules.get(id).get("id"))
            self.client.delete(path=path)

        sec_rev = self.client.get(path=API.SECTION.format(sec_id)).json().get("_revision")

        data = {"rules": []}
        while os_rules_add:
            id = os_rules_add.pop()
            rule = sg_rules.get(id)

            sec_rule = self._get_sg_provider_rule(rule, sec_rev)
            sec_rule = self.payload.sg_rule(rule, sec_rule)
            if sec_rule:
                data["rules"].append(sec_rule)

        if data["rules"]:
            path = API.RULES_CREATE.format(sec_id)
            resp = self.client.post(path=path, data=data)
            sec_rev = resp.json().get("rules")[0].get("_revision")

        for id in os_rules_existing:
            data = sec_rules.get(id)
            if data.get("disabled") or not meta_sg.age:
                rule = sg_rules.get(id)
                path = API.RULE.format(sec_id, data.get("id"))
                data = self.payload.sg_rule(rule, self._get_sg_provider_rule(rule, sec_rev))
                resp = self.client.put(path=path, data=data)
                sec_rev = resp.json().get("_revision")

        resp = self.client.get(path=API.SECTION.format(sec_id))
        self.metadata_update(Provider.SG_RULES, resp.json())

    def _create_sg_provider_rule_remote_prefix(self, cidr):
        return self.client.post(path=API.IPSETS, data=self.payload.sg_rule_remote(cidr)).json()

    def _delete_sg_provider_rule_remote_prefix(self, id):
        self.client.delete(path=API.IPSET.format(id))

    def network_realize(self, segmentation_id):
        meta = self.metadata(self.NETWORK, segmentation_id)
        if not meta:
            os_net = {"id": "{}-{}".format(self.zone_name, segmentation_id), "segmentation_id": segmentation_id}
            provider_net = {"transport_zone_id": self.zone_id}

            data = self.payload.network(os_net, provider_net)
            o = self.client.post(path=API.SWITCHES, data=data).json()
            meta = self.metadata_update(self.NETWORK, o)
        return meta

    def sanitize(self, slice):
        if slice <= 0:
            return ([], None)

        def remove_orphan_remote_prefixes(provider_id):
            self._delete_sg_provider_rule_remote_prefix(provider_id)

        self.metadata_refresh(Provider.SG_RULES_REMOTE_PREFIX)

        meta = self._metadata.get(Provider.SG_RULES_REMOTE_PREFIX).meta

        sanitize = []
        for os_id in meta.keys():
            # After all sections meet certain NSXV3_AGE_SCOPE all their rules
            # are going to reference static IPSets, thus remove the rest
            if "0.0.0.0/" not in os_id and "::/" not in os_id:
                resource = meta.get(os_id)
                if resource.get_all_ambiguous():
                    for res in resource.get_all_ambiguous():
                        sanitize.append((res.id, remove_orphan_remote_prefixes))
                sanitize.append((resource.id, remove_orphan_remote_prefixes))

                if len(sanitize) >= slice:
                    sanitize = sanitize[0:slice]
                    break

        return sanitize
