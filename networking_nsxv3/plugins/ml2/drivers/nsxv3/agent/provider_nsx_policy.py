import functools
import re

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from networking_nsxv3.common.constants import *
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *
from networking_nsxv3.prometheus import exporter
import ipaddress

LOG = logging.getLogger(__name__)


def refresh_and_retry(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        self = args[0]
        resource_type = args[1]
        delete = args[2]
        os_obj = args[4]
        os_id = os_obj.get("id")
        try:
            return func(*args, **kwargs)
        except Exception:
            LOG.warning(
                "Resource: %s with ID: %s failed to be updated, retrying after metadata refresh", resource_type, os_id
            )
            self.metadata_refresh(resource_type)
            if resource_type == Provider.SG_RULES:
                provider_sg = self._create_provider_sg(os_obj, os_id)  # Regenerate the payload (provider_sg)
                return func(self, resource_type, delete, self.payload.sg_rules_container, os_obj, provider_sg)
            return func(*args, **kwargs)

    return wrapper


class API(provider_nsx_mgmt.API):
    POLICY_BASE = "/policy/api/v1"

    POLICIES = "/policy/api/v1/infra/domains/default/security-policies"
    POLICY = "/policy/api/v1/infra/domains/default/security-policies/{}"
    RULES = "/policy/api/v1/infra/domains/default/security-policies/{}/rules"

    GROUPS = "/policy/api/v1/infra/domains/default/groups"
    GROUP = "/policy/api/v1/infra/domains/default/groups/{}"

    SERVICES = "/policy/api/v1/infra/services"
    SERVICE = "/policy/api/v1/infra/services/{}"

    STATUS = "/policy/api/v1/infra/realized-state/status"


class PolicyResourceMeta(provider_nsx_mgmt.ResourceMeta):
    def __init__(self, id, rev, age, _revision, _last_modified_time, rules):
        super().__init__(id, rev, age, _revision, _last_modified_time)
        self.rules = rules


class PolicyResource(provider_nsx_mgmt.Resource):
    def __init__(self, resource):
        super().__init__(resource)

    @property
    def meta(self):
        rulez = self.resource.get("rules", [])
        _rules = {provider_nsx_mgmt.Resource(r).os_id: r for r in rulez}
        tags = self.tags
        # Set age to most recent and rev to 0 NSGroups to always skip the update
        return PolicyResourceMeta(
            id=self.id,
            rev=tags.get(NSXV3_REVISION_SCOPE),  # empty set for NSGroup
            age=int(time.time()) if self.type == "NSGroup" else tags.get(NSXV3_AGE_SCOPE),
            _revision=self.resource.get("_revision"),
            _last_modified_time=self.resource.get("_last_modified_time"),
            rules=_rules,
        )


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
                    "resource_type": "Condition",
                }
            ],
            "tags": self.tags(os_sg),
        }

        cidrs = self.get_compacted_cidrs(os_sg.get("cidrs"))
        if cidrs:
            sg["expression"].append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
            sg["expression"].append({"resource_type": "IPAddressExpression", "ip_addresses": cidrs})
        return sg

    def sg_rule_remote(self, cidr):
        # NSX bug. Related IPSet to handle  0.0.0.0/x and ::0/x
        return {
            "display_name": cidr,
            "expression": [{
                "resource_type": "IPAddressExpression",
                "ip_addresses": [cidr]
            }],
            "tags": self.tags(None)
        }

    def sg_rules_container(self, os_sg, provider_sg):
        return {
            "category": "Application",
            "display_name": os_sg.get("id"),
            "stateful": os_sg.get("stateful", True),
            "tcp_strict": NSXV3_CAPABILITY_TCP_STRICT in os_sg.get("tags", dict()),
            "scope": ["/infra/domains/default/groups/{}".format(provider_sg.get("scope"))],
            "tags": self.tags(os_sg),
            "rules": provider_sg.get("rules"),
        }

    def sg_rule(self, os_rule, provider_rule):
        os_id = os_rule["id"]
        ethertype = os_rule["ethertype"]
        direction = os_rule["direction"]

        def group_ref(group_id):
            return group_id if group_id == "ANY" else "/infra/domains/default/groups/" + group_id

        current = ["ANY"]
        if os_rule.get("remote_group_id"):
            target = [group_ref(provider_rule.get("remote_group_id"))]
        elif provider_rule.get("remote_ip_prefix_id"):
            target = [group_ref(provider_rule.get("remote_ip_prefix_id"))]
        elif os_rule.get("remote_ip_prefix"):
            target = [os_rule.get("remote_ip_prefix")]
            # Workaround for NSX-T glitch when IPv4-mapped IPv6 with prefix used in rules target
            self._filter_out_ipv4_mapped_ipv6_nets(target)
            if not len(target):
                return
        else:
            target = ["ANY"]

        service, err = self._sg_rule_service(os_rule, provider_rule, subtype="ServiceEntry")
        if err:
            LOG.error("Not supported service for Rule:%s. Error:%s", os_id, err)
            return

        service_entries = [service] if service else []

        res = {
            "id": os_id,
            "direction": {"ingress": "IN", "egress": "OUT"}.get(direction),
            "ip_protocol": {"IPv4": "IPV4", "IPv6": "IPV6"}.get(ethertype),
            "source_groups": target if direction in "ingress" else current,
            "destination_groups": current if direction in "ingress" else target,
            "disabled": False,
            "display_name": os_id,
            "service_entries": service_entries,
            "action": "ALLOW",
            "logged": False,  # TODO selective logging
            "tag": os_id.replace("-", ""),
            "scope": ["ANY"],  # Will be overwritten by Policy Scope
            "services": ["ANY"],  # Required by NSX-T Policy validation
        }
        if "_revision" in provider_rule:
            res["_revision"] = provider_rule["_revision"]
        return res

    def _filter_out_ipv4_mapped_ipv6_nets(self, target):
        for cidr in target:
            t = cidr.split("/")
            ip_obj = ipaddress.ip_address(t[0])
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped and (len(t) > 1):
                target.remove(cidr)
                LOG.warning(f"Not supported CIDR target rule: IPv4-mapped IPv6 with prefix ({cidr}).")


class Provider(provider_nsx_mgmt.Provider):
    def __init__(self, payload=Payload):
        super(Provider, self).__init__(payload=payload)
        self.provider = "Policy"
        if cfg.CONF.NSXV3.nsxv3_default_policy_infrastructure_rules:
            self._setup_default_infrastructure_rules()
        if self.client.version >= (3, 0):
            self._ensure_default_l3_policy()

    def _ensure_default_l3_policy(self):
        res = self.client.get(API.POLICY.format(NSXV3_DEFAULT_L3_SECTION))
        res.raise_for_status()
        for rule in res.json()["rules"]:
            if rule["action"] not in ["DROP", "REJECT"]:
                raise Exception("Default l3 section rule is not drop/reject, bailing out")

    def _setup_default_infrastructure_rules(self):
        LOG.info("Looking for the default Infrastructure Rules.")
        for policy in DEFAULT_INFRASTRUCTURE_POLICIES:
            path = API.POLICY.format(policy["id"])
            res = self.client.get(path=path)
            if res.ok:
                continue
            elif res.status_code == 404:
                LOG.info("Infrastructure Policy %s not found, creating...", policy["display_name"])
                self.client.put(path=path, data=policy).raise_for_status()
            else:
                res.raise_for_status()

    # overrides
    def _metadata_loader(self):
        mp = provider_nsx_mgmt.MetaProvider

        return {
            Provider.PORT: mp(API.PORTS),
            Provider.QOS: mp(API.PROFILES),
            Provider.SG_MEMBERS: mp(API.GROUPS),
            Provider.SG_RULES: mp(API.POLICIES),
            Provider.SG_RULES_REMOTE_PREFIX: mp(API.GROUPS),
            Provider.NETWORK: mp(API.SWITCHES),
        }

    @exporter.IN_REALIZATION.track_inprogress()
    def _wait_to_realize(self, resource_type, os_id):
        if resource_type == Provider.SG_RULES:
            path = API.POLICY.format(os_id)
        elif resource_type == Provider.SG_MEMBERS:
            path = API.GROUP.format(os_id)
        else:
            return

        params = {"intent_path": path.replace(API.POLICY_BASE, "")}

        until = cfg.CONF.NSXV3.nsxv3_realization_timeout
        pause = cfg.CONF.NSXV3.nsxv3_connection_retry_sleep

        status = ""
        for attempt in range(1, until + 1):
            o = self.client.get(path=API.STATUS, params=params).json()
            status = o.get("consolidated_status", {}).get("consolidated_status")
            if status == "SUCCESS":
                LOG.info("%s ID:%s in Status:%s", resource_type, os_id, status)
                exporter.REALIZED.labels(resource_type, status).inc()
                return True
            else:
                LOG.info("%s ID:%s in Status:%s for %ss", resource_type, os_id, status, attempt * pause)
                eventlet.sleep(pause)
        # When multiple policies did not get realized in the defined timeframe,
        # this is a symptom for another issue.
        # This should be detected by the Prometheus after a while
        exporter.REALIZED.labels(resource_type, status).inc()
        raise Exception("{} ID:{} did not get realized for {}s", resource_type, os_id, until * pause)

    @refresh_and_retry
    # overrides
    def _realize(self, resource_type, delete, convertor, os_o, provider_o):
        path = self._metadata.get(resource_type).endpoint
        if "policy" not in path:
            # Handle QoS and Ports
            return super(Provider, self)._realize(resource_type, delete, convertor, os_o, provider_o)

        os_id = provider_id = os_o.get("id")

        report = "Resource:{} with ID:{} is going to be %s.".format(resource_type, os_id)

        meta = self.metadata(resource_type, os_id)
        if meta:
            path = "{}/{}".format(path, meta.id)
            if delete:
                LOG.info(report, "deleted")
                self.client.delete(path=path)
                return self.metadata_delete(resource_type, os_id)
            else:
                LOG.info(report, "updated")
                data = convertor(os_o, provider_o)
                if meta._revision is not None:
                    data["_revision"] = meta._revision

                res = self.client.put(path=path, data=data)
                res.raise_for_status()
                data = res.json()
                data["id"] = provider_id
                # NSX-T applies desired state, no need to fetch after put
                meta = self.metadata_update(resource_type, data)
                self._wait_to_realize(resource_type, os_id)
                return meta
        else:
            if not delete:
                path = "{}/{}".format(path, os_id)
                LOG.info(report, "created")
                data = convertor(os_o, provider_o)
                res = self.client.put(path=path, data=data)
                res.raise_for_status()
                data = res.json()
                data["id"] = provider_id
                # NSX-T applies desired state, no need to fetch after put
                meta = self.metadata_update(resource_type, data)
                self._wait_to_realize(resource_type, os_id)
                return meta
            LOG.info("Resource:%s with ID:%s already deleted.", resource_type, os_id)

    # overrides
    def sg_rules_realize(self, os_sg, delete=False):
        os_id = os_sg.get("id")

        if delete:
            self._realize(Provider.SG_RULES, delete, None, os_sg, dict())
            return

        provider_sg = self._create_provider_sg(os_sg, os_id)
        self._realize(Provider.SG_RULES, delete, self.payload.sg_rules_container, os_sg, provider_sg)

    def _create_provider_sg(self, os_sg, os_id):
        provider_rules = []
        meta = self.metadata(Provider.SG_RULES, os_id)
        for rule in os_sg.get("rules"):
            # Manually tested with 2K rules NSX-T 3.1.0.0.0.17107167
            revision = meta.rules.get(rule["id"], {}).get("_revision") if meta else None
            provider_rule = self._get_sg_provider_rule(rule, revision)
            provider_rule = self.payload.sg_rule(rule, provider_rule)

            if provider_rule:
                provider_rules.append(provider_rule)

        provider_sg = {"scope": os_id, "rules": provider_rules}
        return provider_sg

    # overrides
    def metadata(self, resource_type, os_id) -> provider_nsx_mgmt.ResourceMeta:
        if resource_type == Provider.SG_RULES:
            with LockManager.get_lock(Provider.SG_RULES):
                meta = self._metadata[Provider.SG_RULES].meta.get(os_id)
                if meta:
                    if not meta.rules:
                        meta.rules = self._fetch_rules_from_nsx(meta)
                return meta

        return super(Provider, self).metadata(resource_type, os_id)

    # overrides
    def metadata_update(self, resource_type, provider_object):
        if resource_type != Provider.SG_RULE:
            with LockManager.get_lock(resource_type):
                res = (
                    provider_nsx_mgmt.Resource(provider_object)
                    if resource_type != Provider.SG_RULES
                    else PolicyResource(provider_object)
                )
                self._metadata[resource_type].meta.update(res)
                return res.meta

    # overrides
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
                        res = (
                            provider_nsx_mgmt.Resource(o) if resource_type != Provider.SG_RULES else PolicyResource(o)
                        )
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
                            # res.meta.rules = self._fetch_rules_from_nsx(res.meta) # we don't want thousands of requests here

                        provider.meta.add(res)

    def _fetch_rules_from_nsx(self, meta):
        rulez = self.client.get_all(API.RULES.format(meta.id))
        return {provider_nsx_mgmt.Resource(r).os_id: r for r in rulez}

    def _create_sg_provider_rule_remote_prefix(self, cidr):
        id = re.sub(r"\.|:|\/", "-", cidr)
        path = API.GROUP.format(id)
        data = self.payload.sg_rule_remote(cidr)
        try:
            return self.client.put(path=path, data=data).json()
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if 'already exists' in e.args[1]:
                    ctxt.reraise = False
                    return self.client.patch(path=path, data=data).json()

    def _delete_sg_provider_rule_remote_prefix(self, id):
        self.client.delete(path=API.GROUP.format(id))

    # overrides
    def sanitize(self, slice):
        if slice <= 0:
            return ([], None)

        def remove_orphan_service(provider_id):
            self.client.delete(path=API.SERVICE.format(provider_id))

        sanitize = super(Provider, self).sanitize(slice)

        if len(sanitize) < slice:
            services = self.client.get_all(path=API.SERVICES, params={"default_service": False})
            # Mitigating bug with 3.0.1 which ignores default_service = False
            for service in [sv for sv in services if not sv.get("is_default")]:
                sanitize.append((service.get("id"), remove_orphan_service))

        return sanitize
