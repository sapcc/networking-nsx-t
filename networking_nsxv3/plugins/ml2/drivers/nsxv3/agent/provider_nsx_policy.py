import json
import os

import eventlet
import netaddr
from networking_nsxv3.common.constants import *
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class API(provider_nsx_mgmt.API):
    POLICIES = "/policy/api/v1/infra/domains/default/security-policies"
    POLICY = "/policy/api/v1/infra/domains/default/security-policies/{}"

    GROUPS = "/policy/api/v1/infra/domains/default/groups"
    GROUP = "/policy/api/v1/infra/domains/default/groups/{}"

    STATUS = "/policy/api/v1/infra/realized-state/status"


class Payload(provider_nsx_mgmt.Payload):

    def sg_members_container(self, os_sg, provider_sg):
        sg = {
            "display_name": os_sg.get("id"),
            "expression": [
                {
                    "value": "security_group|{}".format(os_sg.get("id")),
                    "member_type": "LogicalPort",
                    "key": "Tag",
                    "operator": "EQUALS",
                    "resource_type": "Condition"
                }
            ],
            "tags": self.tags(os_sg)
        }

        cidrs = self.get_compacted_cidrs(os_sg.get("cidrs"))
        if cidrs:
            sg["expression"].append({
                "resource_type": "ConjunctionOperator",
                "conjunction_operator": "OR"
            })
            sg["expression"].append({
                "resource_type": "IPAddressExpression",
                "ip_addresses": cidrs
            })
        return sg

    def sg_rules_container(self, os_sg, provider_sg):
        return {
            "category": "Application",
            "display_name": os_sg.get("id"),
            "stateful": True,
            "tcp_strict": NSXV3_CAPABILITY_TCP_STRICT in os_sg.get("tags"),
            "scope": [
                "/infra/domains/default/groups/{}".format(
                    provider_sg.get("scope"))
            ],
            "tags": self.tags(os_sg),
            "rules": provider_sg.get("rules")
        }

    def sg_rule(self, os_rule, provider_rule):
        os_id = os_rule["id"]
        ethertype = os_rule['ethertype']
        direction = os_rule['direction']

        def group_ref(group_id):
            return group_id if group_id == "ANY" else \
                "/infra/domains/default/groups/" + group_id

        current = ["ANY"]
        if os_rule.get("remote_group_id"):
            target = [group_ref(provider_rule.get("remote_group_id"))]
        elif os_rule.get("remote_ip_prefix"):
            target = provider_rule.get("remote_ip_prefix")
        else:
            target = ["ANY"]

        service, err = self._sg_rule_service(os_rule, provider_rule, subtype="ServiceEntry")
        if not service and err:
            LOG.error("Not supported Rule ID:%s. Error:%s", os_id, err)
            return

        return {
            "id": os_id,
            "direction": {'ingress': 'IN', 'egress': 'OUT'}.get(direction),
            "ip_protocol": {'IPv4': 'IPV4', 'IPv6': 'IPV6'}.get(ethertype),
            "source_groups": target if direction in 'ingress' else current,
            "destination_groups": current if direction in 'ingress' else target,
            "disabled": False,
            "display_name": os_id,
            "service_entries": [service],
            "action": "ALLOW",
            "logged": False,  # TODO selective logging
            "tag": os_id.replace("-",""),
            "scope": ["ANY"], # Will be overwritten by Policy Scope
            "services": ["ANY"] # Required by NSX-T Policy validation
        }


class Provider(provider_nsx_mgmt.Provider):

    def __init__(self):
        super(Provider, self).__init__()

    def _payload(self):
        return Payload()

    def _cache_loader(self):
        cache = super(Provider, self)._cache_loader()
        cache[Provider.SG_MEMBERS] = {
            "provider": API.GROUPS,
            "resources": dict()
        }
        cache[Provider.SG_RULES] = {
            "provider": API.POLICIES,
            "resources": dict()
        }
        return cache

    
    def _wait_to_realize(self, resource_type, os_id):
        params = {
            "intent_path": "/infra/domains/default/security-policies/{}".format(os_id)
        }

        until = cfg.CONF.NSXV3.nsxv3_connection_retry_count
        pause = cfg.CONF.NSXV3.nsxv3_connection_retry_sleep

        for attempt in range(1, until + 1):
            o = self.client.get(path=API.STATUS, params=params).json()
            status = o.get("consolidated_status", {}).get("consolidated_status")
            if status == "SUCCESS":
                LOG.info("%s ID:%s in Status:%s", resource_type, os_id, status)
                return True
            else:
                LOG.info("%s ID:%s in Status:%s for %ss", resource_type, os_id, status, attempt*pause)
                eventlet.sleep(pause)
        # When multiple policies did not get realized in the defined timeframe,
        # this is a symptom for another issue. 
        # This should be detected by the Prometheus after a while
        LOG.warning("%s ID:%s did not get realized for %ss", resource_type, os_id, until*pause)


    def _realize(self, resource_type, delete, convertor, os_o, provider_o):
        path = self._cache.get(resource_type).get("provider")
        if "policy" not in path:
            return super(Provider, self)._realize(resource_type, delete, convertor, os_o, provider_o)

        os_id = provider_id = os_o.get("id")
        path = "{}/{}".format(path, provider_id) 
        
        report = "Resource:{} with ID:{} is going to be %s.".format(resource_type, os_id)        

        meta = self.metadata(resource_type, os_id)
        if meta:
            if delete:
                self.client.delete(path=path)
                return self.metadata_delete(resource_type, os_id)
            else:
                data = convertor(os_o, provider_o)
                self.client.patch(path=path, data=data)
                data["id"] = provider_id
                # NSX-T applies desired state, no need to fetch after put
                meta = self.metadata_update(resource_type, data)
                self._wait_to_realize(resource_type, os_id)
                return meta
        else:
            if not delete:
                data = convertor(os_o, provider_o)
                self.client.put(path=path, data=data)
                data["id"] = provider_id
                # NSX-T applies desired state, no need to fetch after put
                meta = self.metadata_update(resource_type, data)
                self._wait_to_realize(resource_type, os_id)
                return meta
            LOG.info("Resource:%s with ID:%s already deleted.", resource_type, os_id)


    def sg_rules_realize(self, os_sg, meta_rules=None, delete=False):
        os_id = provider_id = os_sg.get("id")

        if delete:
            self._realize(Provider.SG_RULES, delete, None, os_sg, dict())

        provider_rules = []
        for rule in os_sg.get("rules"):
            provider_rule = dict()
            if rule.get("remote_group_id"):
                group_id = rule.get("remote_group_id")
                group = self.metadata(Provider.SG_MEMBERS, group_id)
                provider_rule["remote_group_id"] = group.get(group_id).get("id")
            if rule.get("remote_ip_prefix"):
                provider_rule["remote_ip_prefix"] = self.payload.get_compacted_cidrs([rule.get("remote_ip_prefix")])

            # Manually tested with 2K rules NSX-T 3.1.0.0.0.17107167
            provider_rule = self.payload.sg_rule(rule, provider_rule)

            if provider_rule:
                provider_rules.append(provider_rule)

        provider_sg = {
            "scope": os_id,
            "rules": provider_rules
        }

        self._realize(Provider.SG_RULES, delete, self.payload.sg_rules_container, os_sg, provider_sg)
    
    def sanitize(self):
        pass
