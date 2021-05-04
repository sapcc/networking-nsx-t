import copy
import ipaddress
import json
import time

import eventlet
import netaddr
from networking_nsxv3.common.constants import *
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider as abs
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import Client
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


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


class Payload(object):

    def tags(self, os_obj, more=dict()):
        tags = {
            NSXV3_REVISION_SCOPE: os_obj.get("revision_number"),
            NSXV3_AGENT_SCOPE: cfg.CONF.AGENT.agent_id,
            NSXV3_GENERATION_SCOPE: int(time.time())
        }
        tags.update(more)
        return [{"scope": s, "tag": t} for s, t in tags.items()]

    def ip_discovery(self):
        os_id = "{}-{}".format(cfg.CONF.AGENT.agent_id, "IpDiscovery")
        return {
            "resource_type": "IpDiscoverySwitchingProfile",
            "arp_bindings_limit": 1,
            "arp_snooping_enabled": True,
            "dhcp_snooping_enabled": True,
            "vm_tools_enabled": False,
            "display_name": os_id,
        }

    def spoofguard(self):
        os_id = "{}-{}".format(cfg.CONF.AGENT.agent_id, "SpoofGuard")
        return {
            "resource_type": "SpoofGuardSwitchingProfile",
            "white_list_providers": ["LPORT_BINDINGS"],
            "display_name": os_id
        }
    
    def qos(self, os_qos, provider_qos):
        payload = {
            "resource_type": "QosSwitchingProfile",
            "display_name": os_qos.get("id"),
            "tags": self.tags(os_qos),
            "shaper_configuration": [],
            "dscp": { "mode": "TRUSTED", "priority": 0 }
        }

        type = {"ingress": "IngressRateShaper", "egress": "EgressRateShaper"}

        for rule in os_qos.get("rules"):
            if "dscp_mark" in rule:
                payload["dscp"] = {
                    "mode": "UNTRUSTED",
                    "priority": int(rule["dscp_mark"])
                }
                continue
            payload["shaper_configuration"].append({
                "resource_type": type.get(rule.get("direction")),
                "enabled": True,
                "average_bandwidth_mbps": \
                    int(round(float(rule["max_kbps"]) / 1024)),
                "peak_bandwidth_mbps": \
                    int(round(float(rule["max_kbps"]) / 1024) * 2),
                "burst_size_bytes": int(rule["max_burst_kbps"]) * 128
            })
        return payload        
    
    def port(self, os_port, provider_port):
        p = os_port
        pp = provider_port

        p_pid = pp.get("id")
        p_ppid = pp.get("parent_id")
        p_qid = pp.get("qos_policy_id")

        if not p_pid and not p_ppid:
            LOG.error("Port '%s' not found.", p.get("id"))
            return

        port = {
            "display_name": os_port.get("id"),
            "logical_switch_id": \
                p.get("vif_details").get("nsx-logical-switch-id"),
            "admin_state": "UP",
            "switching_profile_ids": pp.get("switching_profile_ids"),
            "address_bindings": p.get("address_bindings"),
            "context": {
                "resource_type": "VifAttachmentContext",
                "vif_type": "PARENT"
            },
            "tags": self.tags(os_port, more={NSXV3_SECURITY_GROUP_SCOPE:os_id \
                for os_id in p.get("security_groups")})
        }

        if p_ppid:
            port["attachment"] = {
                "attachment_type": "VIF",
                "id": p.get("id")
            }
            port["context"]["vif_type"] = "CHILD"
            port["context"]["parent_vif_id"] = p_ppid
            port["context"]["traffic_tag"] = \
                p.get("vif_details").get("segmentation_id")
        
        if p_qid:
            port["switching_profile_ids"].append({
                "key": "QosSwitchingProfile",
                "value": provider_port.get("qos_policy_id")
            })

        return port

    def sg_members_container(self, os_sg, provider_sg):
        cidrs = [str(ip).replace("/32", "") for ip in netaddr.IPSet(
            os_sg.get("cidrs")).iter_cidrs()]

        return {
            "resource_type": "IPSet",
            "display_name": os_sg.get("id"),
            "ip_addresses": cidrs,
            "tags": self.tags(os_sg, more={
                NSXV3_SECURITY_GROUP_SCOPE: os_sg.get("id")
            })
        }
    
    def sg_rules_ext_container(self, os_sg, provider_sg):
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
                    "target_type": "LogicalPort"
                }
            ],
            "tags": self.tags(os_sg, more={
                NSXV3_SECURITY_GROUP_SCOPE: os_sg.get("id")
            })
        }
    
    def sg_rules_container(self, os_sg, provider_sg):
        return {
            "resource_type": "FirewallSection",
            "display_name": os_sg.get("id"),
            "section_type": "LAYER3",
            "is_default": False,
            "stateful": True,
            "tcp_strict": NSXV3_CAPABILITY_TCP_STRICT in os_sg.get("tags"),
            "applied_tos": [
                {
                    "target_display_name": os_sg.get("id"),
                    "target_id": provider_sg.get("applied_tos"),
                    "target_type": "NSGroup"
                }
            ],
            "tags": self.tags(os_sg, more={
                NSXV3_SECURITY_GROUP_SCOPE: os_sg.get("id")
            })
        }

    def sg_rule(self, os_rule, provider_rule):
        id = os_rule["id"]
        ethertype = os_rule['ethertype']
        direction = os_rule['direction']

        current = []
        target = self._sg_rule_target(os_rule, provider_rule)
        if not target:
            LOG.error("Not supported target OpenStack '%s' Provider '%s'", 
                os_rule, provider_rule)
            return None
        target = [target] if target else []

        service, err = self._sg_rule_service(os_rule, provider_rule)
        if err:
            LOG.error("Not supported service %s", os_rule)
            return None

        return {
            "direction": {'ingress': 'IN', 'egress': 'OUT'}.get(direction),
            "ip_protocol": {'IPv4': 'IPV4', 'IPv6': 'IPV6'}.get(ethertype),
            "sources": target if direction in 'ingress' else current,
            "destinations": current if direction in 'ingress' else target,
            "disabled": False,
            "display_name": id,
            "services": [{
                "service": service
            }],
            "action": "ALLOW",
            "logged": False, # TODO selective logging
            "rule_tag": id.replace("-",""),
            "_revision": 0
        }

    def sg_rule_remote_ip(self, os_rule, provider_rule):
        # TODO NSX bug. Related IPSet to handle  0.0.0.0/x (x != 0)
        return {
            "resource_type": "IPSet",
            "display_name": os_rule.get("id"),
            "ip_addresses": [os_rule.get("remote_ip_prefix")],
            "tags": self.tags(os_rule, more={
                NSXV3_SECURITY_GROUP_REMOTE_SCOPE: os_rule.get("security_group_id")
            })
        }


    def _sg_rule_target(self, os_rule, provider_rule):
        id = os_rule["id"]
        remote_group_id = os_rule["remote_group_id"]
        remote_ip_prefix = os_rule["remote_ip_prefix"]

        if remote_group_id:
            return {
                "target_type": "IPSet",
                "target_id": provider_rule.get("remote_group_id"),
                "is_valid": True,
                "target_display_name": remote_group_id
            }

        if remote_ip_prefix:
            remote_ip_prefix = \
                str(ipaddress.ip_network(unicode(remote_ip_prefix),
                                         strict=False))

            if remote_ip_prefix in [None, '0.0.0.0/0', '::/0']:
                return # ANY
            
            if remote_ip_prefix.startswith('0.0.0.0/'):
                return {
                    "target_type": "IPSet",
                    "target_id": provider_rule.get("remote_ip_prefix"),
                    "target_display_name": id
                }
            return {
                "target_type": {
                    'IPv4': 'IPv4Address', 
                    'IPv6': 'IPv6Address'}.get(os_rule['ethertype']),
                "target_id": remote_ip_prefix,
                "target_display_name": remote_ip_prefix
            }


    def _sg_rule_service(self, os_rule, provider_rule, subtype="NSService"):
        min = os_rule["port_range_min"]
        max = os_rule["port_range_max"]
        protocol = os_rule["protocol"]
        ethertype = os_rule['ethertype']

        port = ANY_PORT = '1-65535'
        service = ANY_SERVICE = None
        ANY_PROTOCOL = None

        if protocol == 'icmp':
            min = int(min) if str(min).isdigit() else min
            max = int(max) if str(max).isdigit() else max

            if min not in VALID_ICMP_RANGES[ethertype] or \
                max not in VALID_ICMP_RANGES[ethertype][min]:
                return \
                    (None, "Not supported ICMP Range {}-{}".format(min, max))

            return ({
                "resource_type": "ICMPType{}".format(subtype),
                "icmp_type": str(min) if min else None,
                "icmp_code": str(max) if max else None,
                "protocol": { 
                    'IPv4': "ICMPv4", 
                    'IPv6': "ICMPv6"
                }.get(ethertype)
            }, None)

        if protocol in ["tcp", "udp"]:
            return ({
                "resource_type": "L4PortSet{}".format(subtype),
                "l4_protocol": {'tcp': "TCP", 'udp': "UDP"}.get(protocol),
                "destination_ports": ["{}-{}".format(min, max) \
                    if min != max and max else str(min)],
                "source_ports": [ANY_PORT]
            }, None)
        
        if str(protocol).isdigit():
            return ({
                "resource_type": "IPProtocol{}".format(subtype),
                "protocol_number": int(protocol)
            }, None)

        if protocol and protocol in IP_PROTOCOL_NUMBERS:
            return ({
                "resource_type": "IPProtocol{}".format(subtype),
                "protocol_number": int(IP_PROTOCOL_NUMBERS.get(protocol))
            }, None)
        
        if not protocol: # ANY
            return (None, None)
        
        return (None,"Unsupported protocol {}.".format(protocol))


class Provider(abs.Provider):

    SG_RULES_EXT = "Security Group (Rules Enforcement)"

    def __init__(self):
        self._cache = self._cache_loader()
        self._chache_refresh_window = cfg.CONF.NSXV3.nsxv3_cache_refresh_window
        
        self.client = Client()
        self.payload = self._payload()

        self.zone_id = None
        self.switch_profiles = []

        zone_name = cfg.CONF.NSXV3.nsxv3_transport_zone_name
        LOG.info("Looking for TransportZone with name %s.", zone_name)
        for zone in self.client.get_all(path=API.ZONES):
            if zone.get("display_name") == zone_name:
                self.zone_id = zone.get("id")
        
        if not self.zone_id:
            raise Exception("Not found Transport Zone {}".format(zone_name))

        sg = self.payload.spoofguard()
        ip = self.payload.ip_discovery()
        sg_id = None
        ip_id = None

        profiles = self.client.get_all(path=API.PROFILES, params={
            "switching_profile_type": \
                "IpDiscoverySwitchingProfile,SpoofGuardSwitchingProfile"
        })

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
            {
                "key": "SpoofGuardSwitchingProfile",
                "value": sg_id
            },
            {
                "key": "IpDiscoverySwitchingProfile",
                "value": ip_id
            }
        ]

    def _payload(self):
        return Payload()

    def _cache_loader(self):
        # Resource := {os_id: {"id": id, "rev": revision}, ...}
        return {
            Provider.PORT: {
                "provider": API.PORTS,
                "resources": dict()
            },
            Provider.QOS: {
                "provider": API.PROFILES,
                "resources": dict()
            },
            Provider.SG_MEMBERS: {
                "provider": API.IPSETS,
                "resources": dict()
            },
            Provider.SG_RULES: {
                "provider": API.SECTIONS,
                "resources": dict()
            },
            Provider.SG_RULES_EXT: {
                "provider": API.NSGROUPS,
                "resources": dict()
            },
            Provider.NETWORK: {
                "provider": API.SWITCHES,
                "resources": dict()
            }
        }

    def _realize(self, resource_type, delete, convertor, os_o, provider_o):
        os_id = os_o.get("id")
        
        report = "Resource:{} with ID:{} is going to be %s.".format(resource_type, os_id)

        path = self._cache.get(resource_type).get("provider")

        meta = self.metadata(resource_type, os_id)
        if meta:
            path = "{}/{}".format(path, meta.get(os_id).get("id"))
            if delete:
                LOG.info(report, "deleted")
                params = {"cascade": True} if resource_type == Provider.SG_RULES else dict()
                self.client.delete(path=path, params=params)
                return self.metadata_delete(resource_type, os_id)
            else:
                LOG.info(report, "updated")
                data = convertor(os_o, provider_o)
                revision = meta.get(os_id).get("_revision")
                if revision != None:
                    data["_revision"] = revision
                if resource_type == Provider.SG_MEMBERS:
                    if self._sg_members_require_update(self.client.get(path).json(), data):
                        o = self.client.put(path=path, data=data)
                        return self.metadata_update(resource_type, o.json())
                    else:
                        return meta
                else:
                    o = self.client.put(path=path, data=data)
                    return self.metadata_update(resource_type, o.json())
        else:
            if not delete:
                LOG.info(report, "updated")
                o = self.client.post(path=path, data=convertor(os_o, provider_o))
                return self.metadata_update(resource_type, o.json())
            LOG.info("Resource:%s with ID:%s already deleted.", resource_type, os_id)

    def _metadata_refresh(self, provider):
        meta = dict()
        params = {"switching_profile_type": "QosSwitchingProfile"}\
            if provider == API.PROFILES else dict()
        
        # NSX does not allow to filter by custom property
        # Search API has hard limit of 50k objects (with cursor)
        result = self.client.get_all(path=provider, params=params)

        for o in result:
            if o.get("_create_user") != "admin":
                continue

            tags = {t.get("scope"):t.get("tag") for t in o.get("tags", [])}

            # TODO - enable for multiple Agents for a single NSX-T Manager
            # if NSXV3_AGENT_SCOPE not in tags or \
            #     tags[NSXV3_AGENT_SCOPE] != cfg.CONF.AGENT.agent_id:
            #     continue

            if provider == API.IPSETS:
                cidrs = o.get("ip_addresses")
                if len(cidrs) == 1 and "0.0.0.0" in cidrs[0]:
                    # This is RULE specific IPSet
                    continue
            
            # Set generation to most recent for NSGroups, always skip update
            gen = int(time.time()) if provider == API.NSGROUPS \
                else tags.get(NSXV3_GENERATION_SCOPE)

            # TODO - check for collisions (Ambiguously) and perform actions
            meta[o.get("display_name")] = {
                "id": o.get("id"), 
                "rev": tags.get(NSXV3_REVISION_SCOPE), # empty set for NSGroup
                "gen": gen,
                "_revision": o.get("_revision")
            }
        return meta

    def metadata_refresh(self, resource_type):
        if resource_type == Provider.SG_RULE:
            return # Not cached
        
        resources = self._cache.get(resource_type)
        backup = dict()
        resources["backup"] = backup
        eventlet.sleep(self._chache_refresh_window)

        with LockManager.get_lock(resource_type):
            LOG.info("Fetching NSX-T inventory metadata for resource type %s.",
                     resource_type)

            meta = self._metadata_refresh(resources.get("provider"))
            meta.update(backup)
            del resources["backup"] 
            resources["resources"] = meta

    def metadata_delete(self, resource_type, os_id):
        if resource_type == Provider.SG_RULE:
            pass

        with LockManager.get_lock(resource_type):
            resources = self._cache.get(resource_type).get("resources")
            backup = self._cache.get(resource_type).get("backup")
            
            if backup and os_id in backup:
                del backup[os_id]
            if os_id in resources:
                meta = resources[os_id]
                del resources[os_id]
                return meta

    def metadata_update(self, resource_type, provider_object):
        if resource_type == Provider.SG_RULE:
            pass

        with LockManager.get_lock(resource_type):
            return self._metadata_update(resource_type, provider_object)
    
    def _metadata_update(self, resource_type, provider_object):
        os_id = provider_object.get("display_name")

        tags = {
            t.get("scope"):t.get("tag") for t in provider_object.get("tags", [])
        }

        meta = {
            "id": provider_object.get("id"),
            "rev": tags.get(NSXV3_REVISION_SCOPE),
            "gen": tags.get(NSXV3_GENERATION_SCOPE),
            "_revision": provider_object.get("_revision")
        }

        
        self._cache.get(resource_type).get("resources")[os_id] = meta
        backup = self._cache.get(resource_type).get("backup")
        if backup:
            backup[os_id] = meta
        return {os_id: meta}

    def metadata(self, resource_type, os_id):
        if resource_type == Provider.SG_RULE:
            with LockManager.get_lock(Provider.SG_RULES):
                meta = self._cache.get(\
                    Provider.SG_RULES).get("resources").get(os_id)
                if meta: 
                    rules = self.client.get_all(\
                        API.RULES.format(meta.get("id")))
                    return {rule.get("display_name"):rule for rule in rules}
                return dict()

        with LockManager.get_lock(resource_type):
            meta = self._cache.get(resource_type).get("resources").get(os_id)
            if not meta and resource_type == Provider.PORT:
                # Parent ports are created externally and need to be looked up
                port = self._get_port(os_id)
                if port:
                    # Updating the name to use _metadata_update 
                    port["display_name"] = os_id
                    return self._metadata_update(resource_type, port)
            return { os_id: meta } if meta else None

    def _get_port(self, os_id):
        # TODO - the only way to be optimized is via unofficial search API
        provider_ports = self.client.get_all(API.PORTS)
        for port in provider_ports:
            if os_id in str(port.get("attachment", {}).get("id", "")):
                return port

    def outdated(self, resource_type, os_meta):
        self.metadata_refresh(resource_type)
        if resource_type == Provider.SG_RULES:
            self.metadata_refresh(Provider.SG_RULES_EXT)
        meta = self._cache.get(resource_type).get("resources")

        k1 = set(os_meta.keys())
        k2 = set(meta.keys())

        # Treat both new and orphaned as outdated
        outdated = k1.difference(k2)
        outdated.update(k2.difference(k1))

        # Add revision outdated 
        for id in k1.intersection(k2):
            if str(os_meta[id]) != str(meta[id].get("rev")):
                outdated.add(id)

        if resource_type == Provider.SG_RULES:
            # NSGroups not matching Sections concidered as outdated SG
            groups = self._cache.get(Provider.SG_RULES_EXT).get("resources")
            outdated.update(set(groups.keys()).difference(k1))

        LOG.info("The number of outdated resources for Type:%s Is:%s.", 
                 resource_type, len(outdated))
        LOG.debug("Outdated resources of Type:%s Are:%s", 
                  resource_type, outdated)

        current = k2.difference(outdated)
        return outdated, current

    def age(self, resource_type, os_ids):
        type = resource_type
        meta = self._cache.get(resource_type).get("resources")
        return [(type,id,meta.get(id, {}).get("age", "0")) for id in os_ids]

    def port_realize(self, os_port, meta=None, delete=False):
        if delete:
            self._realize(Provider.PORT, delete, None, os_port, None)
            return

        os_pid = os_port.get("id")
        os_ppid = os_port.get("parent_id")
        os_qid = os_port.get("qos_policy_id")
        
        provider_port = dict()

        if os_ppid:
            meta_pport = self.metadata(Provider.PORT, os_ppid)
            if not meta_pport:
                LOG.error("Parent port '%s' not found for Child '%s'",
                    os_ppid, os_pid)
                return
            provider_port["parent_id"] = meta_pport.get(os_ppid).get("id")

        meta_port = self.metadata(Provider.PORT, os_pid)
        
        if not meta_port and not os_ppid:
            LOG.error("Port port '%s' not found", os_pid)
            return
        
        if meta_port:
            provider_port["id"] = meta_port.get(os_pid).get("id")

        if os_qid:
            meta_qos = self.metadata(Provider.QOS, os_qid)
            if not meta_qos:
                LOG.error("QoS '%s' not found for Port '%s'", os_qid, os_pid)
            else:
                provider_port["qos_policy_id"] = meta_qos.get(os_qid).get("id")

        provider_port["switching_profile_ids"] = copy.deepcopy(self.switch_profiles)

        return self._realize(Provider.PORT, delete, 
                             self.payload.port, os_port, provider_port )

    def qos_realize(self, qos, meta=None, delete=False):
        return self._realize(Provider.QOS, delete, self.payload.qos, qos, dict())
    
    def sg_members_realize(self, sg, meta=None, delete=False):
        # Members sill be updated only if ip_addressess differs
        return self._realize(Provider.SG_MEMBERS, delete,
                             self.payload.sg_members_container, sg, dict())


    def sg_rules_realize(self, os_sg, provider_rules_meta=None, delete=False):
        provider_sg = dict()

        nsg_args = [Provider.SG_RULES_EXT, delete, \
            self.payload.sg_rules_ext_container, os_sg, dict()]
        sec_args = [Provider.SG_RULES, delete, \
            self.payload.sg_rules_container, os_sg, provider_sg]

        meta_sg_rules_ipsets = self._get_sg_remote_ipsets(provider_rules_meta)

        # Apply Security Group Desired State
        if delete:
            meta_sec = self._realize(*sec_args)
            meta_nsg = self._realize(*nsg_args)
            
            for _,provider_ipset_id in meta_sg_rules_ipsets.items():
                self.client.delete(path=API.IPSET.format(provider_ipset_id))
        else:
            meta_nsg = self._realize(*nsg_args)
            provider_sg.update({
                "applied_tos": meta_nsg.get(os_sg.get("id")).get("id")
            })
            meta_sec = self._realize(*sec_args)

            self._sg_rules_realize(\
                os_sg, meta_sec, provider_rules_meta, meta_sg_rules_ipsets)


    def _sg_rules_realize(self, os_sg, meta_sg, meta_sg_rules, meta_sg_rules_remote):

        sg_id = meta_sg.items()[0][0]
        sg_rules = {o.get("id"):o for o in os_sg.get("rules")}

        sec_id = meta_sg.get(sg_id).get("id")
        sec_rev = meta_sg.get(sg_id).get("_revision")

        sec_rules = meta_sg_rules
        sec_rules_ipsets = meta_sg_rules_remote

        sec_rules_ids = set(sec_rules.keys())
        sg_rules_ids = set(sg_rules.keys())

        os_rules_add = sg_rules_ids.difference(sec_rules_ids)
        os_rules_remove = sec_rules_ids.difference(sec_rules_ids)
        os_rules_enable = sec_rules_ids.intersection(sec_rules_ids)
        
        pool_size = cfg.CONF.NSXV3.nsxv3_max_records_per_query
        # NSX-T 3.0.2 API limit is 1k rules per request
        pool_size = 1000 if pool_size >= 1000 else pool_size

        data = {"rules": []}
        while os_rules_add:
            id = os_rules_add.pop()
            rule = sg_rules.get(id)

            sec_rule = self._get_sg_provider_rule(rule, sec_rules_ipsets.get(id))
            sec_rule = self.payload.sg_rule(rule, sec_rule)

            if not sec_rule:
                LOG.error("Not supported rule %s", rule)
                if len(data["rules"]) % pool_size == 0:
                    continue
            else:
                data["rules"].append(sec_rule)
            if len(data["rules"]) % pool_size == 0 or not os_rules_add:
                path = API.RULES_CREATE.format(sec_id)
                try:
                    resp = self.client.post(path=path, data=data)
                    sec_rev = resp.json().get("rules")[0].get("_revision")
                except Exception as err:
                    LOG.error("Security Group rules creation has failed. Error: %s", err)
                data["rules"] = []
        
        for id in os_rules_enable:
            data = sec_rules.get(id)
            if data.get("disabled"):
                path=API.RULE.format(sec_id, sec_rule.get("id"))
                data["disabled"] = False
                resp = self.client.put(path=path,data=data)
                sec_rev = resp.json().get("rules")[0].get("_revision")
        
        for id in os_rules_remove:
            path=API.RULE.format(sec_id, sec_rules.get(id).get("id"))
            self.client.delete(path=path)

        # NSX-T Needs some time to detect that dependent rules are removed
        for id in os_rules_remove:
            path=API.IPSET.format(sec_rules_ipsets.get(id))
            self.client.delete(path=path)

        resp = self.client.get(path=API.SECTION.format(sec_id))
        self.metadata_update(Provider.SG_RULES, resp.json())
            

    def _get_sg_remote_ipsets(self, provider_rules_meta):
        meta_ipsets = dict()
        for _, rule in provider_rules_meta.items():
            os_sg_rule_id = rule.get("display_name")
            for ref in rule.get("sources",[]) + rule.get("destinations",[]):
                if isinstance(ref, dict) and \
                    ref.get("target_display_name") == os_sg_rule_id:
                        meta_ipsets[os_sg_rule_id] = ref.get("target_id")
        return meta_ipsets


    def _get_sg_provider_rule(self, os_rule, provider_rule_remote_id):
        cidr = os_rule.get("remote_ip_prefix")
        group_id = os_rule.get("remote_group_id")

        if cidr:
            if cidr.startswith("0.0.0.0/") and not cidr.startswith("0.0.0.0/0"):
                if provider_rule_remote_id:
                    # TODO - remove the following lines after the
                    # initial environment clean up
                    path = path=API.IPSET.format(provider_rule_remote_id)
                    o = self.client.get(path=path).json()
                    tags = {t.get("scope"):t.get("tag") for t in o.get("tags", [])}
                    if NSXV3_SECURITY_GROUP_REMOTE_SCOPE not in tags:
                        data = self.payload.sg_rule_remote_ip(os_rule, dict())
                        data = {"tags": data.get("tags")}
                        o = self.client.put(path=path, data=data)
                    return {"remote_ip_prefix": provider_rule_remote_id}
                try:
                    data = self.payload.sg_rule_remote_ip(os_rule, dict())
                    o = self.client.post(path=API.IPSETS, data=data)
                    return {"remote_ip_prefix": o.json().get("id")}
                except Exception as err:
                    LOG.error(err)
        if group_id:
            meta = self.metadata(Provider.SG_MEMBERS, group_id)
            if meta:
                return {"remote_group_id": meta.get(group_id).get("id")}
            else:
                LOG.error("Cannot resolve remote security group %s", group_id)
        return None


    def _sg_members_require_update(self, current_payload, new_payload):
        a = current_payload.get("ip_addresses")
        b = new_payload.get("ip_addresses")
        a.sort()
        b.sort()
        return a != b
