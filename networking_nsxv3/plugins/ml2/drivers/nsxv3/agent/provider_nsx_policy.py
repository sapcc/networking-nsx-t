import os

import netaddr
from networking_nsxv3.common.constants import *
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *
from oslo_config import cfg


class API(provider_nsx_mgmt.API):
    POLICIES = "/policy/api/v1/infra/domains/default/security-policies"
    POLICY = "/policy/api/v1/infra/domains/default/security-policies/{}"

    GROUPS = "/policy/api/v1/infra/domains/default/groups"
    GROUP = "/policy/api/v1/infra/domains/default/groups/{}"

    RULES = "/policy/api/v1/infra/domains/default/security-policies/{}/rules"
    RULE = "/policy/api/v1/infra/domains/default/security-policies/{}/rules/{}"


class Payload(provider_nsx_mgmt.Payload):

    def sg_members_container(self, os_sg, provider_sg):
        os_id = os_sg.get("id")
        os_cidrs = os_sg.get("cidrs")

        cidrs = netaddr.IPSet([str(ip[0]) for ip in os_cidrs]).iter_cidrs()
        cidrs = [str(ip).replace("/32", "") for ip in cidrs]

        return {
            "display_name": os_id,
            "expression": [
                {
                    "value": "security_group|{}".format(os_id),
                    "member_type": "LogicalPort",
                    "key": "Tag",
                    "operator": "EQUALS",
                    "resource_type": "Condition"
                },
                {
                    "resource_type": "ConjunctionOperator",
                    "conjunction_operator": "OR"
                },
                {
                    "resource_type": "IPAddressExpression",
                    "ip_addresses": cidrs
                }
            ],
            "tags": self._tags(os_sg)
        }

    def sg_rules_container(self, os_sg, provider_sg):
        os_id = os_sg.get("id")

        scope = "/infra/domains/default/groups/{}"

        return {
            "category": "Application",
            "display_name": os_id,
            "stateful": True,
            "tcp_strict": NSXV3_CAPABILITY_TCP_STRICT in os_sg.get("tags"),
            "scope": [scope.format(provider_sg.get("scope"))],
            "tags": self._tags(os_sg)
        }

    def sg_rule(self, os_rule, provier_rule):
        os_id = os_rule["id"]
        ethertype = os_rule['ethertype']
        direction = os_rule['direction']

        def group_ref(group_id):
            return group_id if group_id == "ANY" else \
                "/infra/domains/default/groups/" + group_id

        def service_ref(service_id):
            return "/infra/services/" + service_id

        current = ["ANY"]
        target = group_ref(provier_rule.get("target"))
        target = [target] if target else ["ANY"]

        return {
            "direction": {'ingress': 'IN', 'egress': 'OUT'}.get(direction),
            "ip_protocol": {'IPv4': 'IPV4', 'IPv6': 'IPV6'}.get(ethertype),
            "sources": target if direction in 'ingress' else current,
            "destinations": current if direction in 'ingress' else target,
            "disabled": True,
            "display_name": os_id,
            "services": [{
                "service": service_ref(provier_rule.get("service"))
            }],
            "action": "ALLOW",
            "logged": False,  # TODO selective logging
            "rule_tag": ""  # TODO - used by selective logging
        }

    def sg_rule_remote_ip(self, os_rule, provider_rule):
        os_id = os_rule.get("id")
        os_cidrs = os_rule.get("remote_ip_prefix")

        cidrs = netaddr.IPSet([str(ip[0]) for ip in os_cidrs]).iter_cidrs()
        cidrs = [str(ip).replace("/32", "") for ip in cidrs]

        return {
            "display_name": os_id,
            "expression": [
                {
                    "resource_type": "IPAddressExpression",
                    "ip_addresses": cidrs
                }
            ],
            "tags": {NSXV3_SECURITY_GROUP_REMOTE_SCOPE: os_rule.get(
                "security_group_id")}
        }

    def sg_rule_service(self, os_rule, provider_rule):
        min = os_rule["port_range_min"]
        max = os_rule["port_range_max"]
        protocol = os_rule["protocol"]
        ethertype = os_rule['ethertype']

        service_name = "{}-{}-{}-{}".format(ethertype, protocol, min, max)
        service_entry = {"display_name": service_name}
        service = {
            "display_name": service_name,
            "service_entries": [service_entry],
        }

        if protocol == 'icmp':
            if min not in VALID_ICMP_RANGES[ethertype] or \
                    max not in VALID_ICMP_RANGES[ethertype][min]:
                return \
                    (None, "Not supported ICMP Range {}-{}".format(min, max))

            service_entry.update({
                "resource_type": "ICMPTypeServiceEntry",
                "icmp_type": str(min) if min else None,
                "icmp_code": str(max) if max else None,
                "protocol": {"IPv4": "ICMPv4", "IPv6": "ICMPv6"}.get(ethertype)
            })
        elif protocol in ["tcp", "udp"]:
            service_entry.update({
                "resource_type": "L4PortSetServiceEntry",
                "l4_protocol": {'tcp': "TCP", 'udp': "UDP"}.get(protocol),
                "destination_ports": ["{}-{}".format(min, max) \
                                          if min != max else str(min)],
                "source_ports": ["1-65535"]
            })
        elif str(protocol).isdigit():
            service_entry.update({
                "resource_type": "IPProtocolServiceEntry",
                "protocol_number": int(protocol)
            })
        elif protocol and protocol in IP_PROTOCOL_NUMBERS:
            service_entry.update({
                "resource_type": "IPProtocolServiceEntry",
                "protocol_number": int(IP_PROTOCOL_NUMBERS.get(protocol))
            })
        elif not protocol:  # ANY
            return (None, None)
        else:
            return (None, "Unsupported protocol {}.".format(protocol))

        return (service, None)


class Provider(provider_nsx_mgmt.Provider):

    def __init__(self):
        super(Provider, self).__init__()

    def _cache_loader(self):
        cache = super(Provider, self)._cache_loader()
        cache[Provider.SG_MEMBERS] = {
            "provider": API.GROUPS,
            "resources": dict()
        }
        cache[Provider.SG_RULES] = {
            "provider": API.GROUPS,
            "resources": dict()
        }
        cache[Provider.SG_MEMBERS] = {
            "provider": API.POLICIES,
            "resources": dict()
        }
        cache[Provider.SG_RULES] = {
            "provider": API.RULES,
            "resources": dict()
        }
        return cache

    def sg_rules_realize(self, os_sg, meta_rules=None, delete=False):
        os_id = os_sg.get("id")

        provider_sg = {"scope": self.metadata(Provider.SG_MEMBERS, os_id)}

        policy_args = [Provider.SG_RULES, delete, \
                       self.payload.sg_rules_container, os_sg, provider_sg]

        meta_sg = self._realize(*policy_args)
        if meta_sg:
            provider_sg_id = meta_sg.get(os_id).get("id")

        if delete:
            if provider_sg_id and meta_rules:
                self._sg_rules_remove(provider_sg_id, meta_rules)
            return

        batch = []
        batch_size = cfg.CONF.NSXV3.nsxv3_max_records_per_query
        # NSX-T API limit is 1k rules per request
        batch_size = 1000 if batch_size >= 1000 else batch_size

        for rule in os_sg.get("add_rules"):
            if rule.get("remote_group_id"):
                provider_rule = self._sg_rule_remote_group(rule)
            if rule.get("remote_ip_prefix"):
                provider_rule = self._sg_rule_remote_ip(rule)

            batch.append(self.payload.sg_rule(rule, provider_rule))
            if len(batch) % batch_size == 0:
                path = API.RULES_CREATE.format(provider_sg_id)
                self.client.patch(path=path, data={"rules": batch})
                batch = []

        # Update existing rules if disabled - NSX behavior
        for os_id in set(meta_rules.keys()).difference(os_sg.get(
                "delete_rules")):
            rule = meta_rules.get(os_id)
            if rule.get("disabled"):
                data = dict()
                data.update(rule)
                data["disabled"] = False
                path = API.RULE.format(provider_sg_id, rule.get("id"))
                self.client.put(path=path, data=data)

        deleted_rules = os_sg.get("delete_rules")
        deleted_rules_meta = [rule for id, rule in meta_rules.items() if
                              id in deleted_rules]
        self._sg_rules_remove(provider_sg_id, deleted_rules_meta,
                              remove_rule=True)

    def _sg_rules_remove(self, provider_sg_id, provider_rules,
                         remove_rule=False):
        for os_id, rule in provider_rules.items():
            for group_ref in rule.get("sources") + rule.get("destinations"):
                group_id = os.path.basename(group_ref)
                if group_id == os_id:
                    self.client.delete(path=API.GROUP.format(group_id))
            if remove_rule:
                path = API.RULE.format(provider_sg_id, rule.get("id"))
                self.client.delete(path=path)

    def _sg_rule_remote_group(self, rule):
        return {
            "remote_group_id": self.metadata( \
                Provider.SG_MEMBERS, rule.get("remote_group_id"))
        }

    def _sg_rule_remote_ip(self, rule):
        # TODO NSX bug. Related IPSet to handle  0.0.0.0/x (x != 0)
        p = rule.get("remote_ip_prefix")
        p.startswith("0.0.0.0/") and not p.startswith("0.0.0.0/0")
        o = self.client.post(path=API.IPSETS,
                      data=self.payload.sg_rule_ip_prefix(rule))
        return {"remote_ip_prefix": o.get("id")}

    def _sg_members_require_update(self, current_payload, new_payload):
        return set(current_payload.get("ip_addresses")) != set(
            new_payload.get("ip_addresses"))
