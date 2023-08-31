import eventlet
eventlet.monkey_patch()

from typing import Callable, Dict, List, Set
import uuid
from requests.exceptions import HTTPError
import re
import json
import functools
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from networking_nsxv3.common.constants import *
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import Client
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider_nsx_mgmt
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider as base
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *
from networking_nsxv3.prometheus import exporter
import ipaddress


LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


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
        except HTTPError:
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

    INFRA = POLICY_BASE + "/infra"

    QOS_PROFILE_PATH = "/infra/qos-profiles/{}"
    QOS_PROFILES = INFRA + "/qos-profiles"
    QOS_PROFILE = POLICY_BASE + QOS_PROFILE_PATH

    POLICIES = INFRA + "/domains/default/security-policies"
    POLICY_PATH = "/infra/domains/default/security-policies/{}"
    RULE_PATH = POLICY_PATH + "/rules/{}"
    POLICY = POLICY_BASE + POLICY_PATH
    RULES = POLICY_BASE + POLICY_PATH + "/rules"
    RULES_CREATE = RULES + "/{}"

    SEARCH_QUERY = POLICY_BASE + "/search/query"
    SEARCH_Q_TRANSPORT_ZONES = "resource_type:PolicyTransportZone AND display_name:{}"
    SEARCH_Q_SEG_PORT = "resource_type:SegmentPort AND marked_for_delete:false AND attachment.id:{}"
    SEARCH_Q_SEG_PORTS = {"query": "resource_type:SegmentPort AND marked_for_delete:false"}
    SEARCH_Q_QOS_PROFILES = {
        "query": "resource_type:QoSProfile AND NOT display_name:*default* AND marked_for_delete:false"}
    SEARCH_Q_ALL_SEG_PROFILES = {
        "query":
        "resource_type:QoSProfile" +
        " OR resource_type:SpoofGuardProfile" +
        " OR resource_type:SegmentSecurityProfile" +
        " OR resource_type:PortMirroringProfile" +
        " OR resource_type:MacDiscoveryProfile" +
        " OR resource_type:IPDiscoveryProfile"
    }

    SEARCH_DSL = POLICY_BASE + "/search"
    SEARCH_DSL_QUERY = lambda res_type, dsl: {
        "query": f"resource_type:{res_type}",
        "dsl": f"{dsl}",
        "data_source": "INTENT",
        "exclude_internal_types": "true"
    }

    SEGMENTS = INFRA + "/segments"
    SEGMENT_PATH = "/infra/segments/{}"
    SEGMENT = POLICY_BASE + SEGMENT_PATH
    SEGMENT_PORTS = INFRA + "/segments/{}/ports"
    SEGMENT_PORT_PATH = "/infra/segments/{}/ports/{}"
    SEGMENT_PORT = POLICY_BASE + SEGMENT_PORT_PATH

    GROUP_PATH = "/infra/domains/default/groups/{}"
    GROUPS = INFRA + "/domains/default/groups"
    GROUP = POLICY_BASE + GROUP_PATH

    SERVICES = INFRA + "/services"
    SERVICE = INFRA + "/services/{}"

    STATUS = INFRA + "/realized-state/status"
    TRANSPORT_ZONES_PATH = "/infra/sites/default/enforcement-points/default/transport-zones/{}"
    TRANSPORT_ZONE = POLICY_BASE + TRANSPORT_ZONES_PATH

    POLICY_MNG_PREFIX = "default:"

    INFRA = "/policy/api/v1/infra"


class PolicyResourceMeta(provider_nsx_mgmt.ResourceMeta):
    def __init__(self, id, unique_id, rev, age, revision, last_modified_time,
                 rules,
                 static_sg_members,
                 sg_cidrs,
                 path,
                 parent_path,
                 resource_type,
                 marked_for_delete,
                 real_id=None
                 ):
        super(PolicyResourceMeta, self).__init__(id, rev, age, revision, last_modified_time)
        self.rules: list = rules
        self.sg_members: List[str] = static_sg_members
        self.sg_cidrs: List[str] = sg_cidrs
        self.path: str = path
        self.unique_id: str = unique_id
        self.parent_path: str = parent_path
        self.resource_type: str = resource_type
        self.marked_for_delete: bool = marked_for_delete
        self.real_id: str = real_id


class Resource(provider_nsx_mgmt.Resource):
    def __init__(self, resource: dict):
        super(Resource, self).__init__(resource)

    @property
    def is_managed(self):
        if self.resource.get("_system_owned", False):
            return False
        if self.resource.get("_protection", "NOT_PROTECTED") != "NOT_PROTECTED":
            return False
        if self.type in ["SecurityPolicy", Provider.PORT]:
            # rule name is a uuid
            if not self.has_valid_os_uuid:
                return False
        if self.type == Provider.NETWORK:
            # os_id of a segment is expected to be a number
            if not self.os_id.isnumeric():
                return False
        return True

    @property
    def os_id(self):
        os_id = self.resource.get("display_name")
        if self.type == "Segment":
            os_id = os_id.split("-")[-1]
        if self.type == "SegmentPort":
            os_id = self.resource.get("attachment", {}).get("id")
        return os_id

    @property
    def meta(self):
        rulez = self.resource.get("rules", [])
        sg_rules = {Resource(r).os_id: r for r in rulez}

        sg_expr: List[dict] = self.resource.get("expression", [])
        sg_has_expression = (bool(sg_expr) and isinstance(sg_expr, list))

        path_expr = list(filter(lambda expr: expr.get("resource_type", "") == "PathExpression", sg_expr))\
            if sg_has_expression else []
        cidr_expr = list(filter(lambda expr: expr.get("resource_type", "") == "IPAddressExpression", sg_expr))\
            if sg_has_expression else []

        sg_members = list(path_expr)[0].get("paths", []) if len(path_expr) else []
        sg_cidrs = list(cidr_expr)[0].get("ip_addresses", []) if len(cidr_expr) else []

        tags = self.tags

        return PolicyResourceMeta(
            real_id=self.id,
            id=self.id.split(API.POLICY_MNG_PREFIX)[1] if str(self.id).find(API.POLICY_MNG_PREFIX) == 0 else self.id,
            unique_id=self.resource.get("unique_id"),
            rev=tags.get(NSXV3_REVISION_SCOPE, 0),
            age=tags.get(NSXV3_AGE_SCOPE, 0),
            revision=self.resource.get("_revision"),
            last_modified_time=self.resource.get("_last_modified_time"),
            path=self.path,
            parent_path=self.resource.get("parent_path"),
            resource_type=self.resource.get("resource_type"),
            marked_for_delete=self.resource.get("marked_for_delete"),
            # Only Firewall Security Policies have the next prop (Provider.SG_RULES)
            rules=sg_rules,
            # Only Groups have the next props (Provider.SG_MEMBERS)
            static_sg_members=sg_members,
            sg_cidrs=sg_cidrs
        )

    @property
    def path(self):
        return self.resource.get("path")


class Payload(provider_nsx_mgmt.Payload):

    def infra(self, target_obj: dict, child_objs: List[dict]) -> dict:
        return {
            "resource_type": "Infra",
            "children": [
                {
                    "resource_type": "ChildResourceReference",
                    "id": target_obj.get("id"),
                    "target_type": target_obj.get("resource_type"),
                    "children": [
                        {
                            o.get("resource_type"): {
                                "path": o.get("path"),
                                "parent_path": o.get("parent_path"),
                                "id": o.get("id"),
                                "resource_type": o.get("resource_type")
                            },
                            "resource_type": "Child{}".format(o.get("resource_type")),
                            "marked_for_delete": o.get("marked_for_delete")
                        } for o in child_objs
                    ]
                }
            ]
        }

    def segment(self, os_net, provider_net) -> dict:
        os_id = os_net.get("id")
        tr_zone_id = provider_net.get("transport_zone_id")
        return {
            "type": "DISCONNECTED",
            "vlan_ids": [
                os_net.get("segmentation_id")
            ],
            "transport_zone_path": API.TRANSPORT_ZONES_PATH.format(tr_zone_id),
            "advanced_config": {
                "hybrid": False
            },
            "admin_state": "UP",
            "resource_type": "Segment",
            "id": str(uuid.uuid5(uuid.NAMESPACE_OID, os_id)),
            "display_name": os_id,
            "path": API.SEGMENT_PATH.format(os_id),
            "_revision": provider_net.get("_revision")
        }

    def qos(self, os_qos, provider_qos) -> dict:
        qos_id = provider_qos.get("id")

        payload = {
            "resource_type": "QoSProfile",
            "display_name": os_qos.get("id"),
            "id": qos_id,
            "tags": self.tags(os_qos),
            "path": API.QOS_PROFILE_PATH.format(qos_id),
            "parent_path": "/infra",
            "_revision": provider_qos.get("_revision"),
            "shaper_configurations": [],
            "dscp": {"mode": "TRUSTED", "priority": 0},
        }

        _type = {"ingress": "IngressRateLimiter", "egress": "EgressRateLimiter"}

        for rule in os_qos.get("rules"):
            if "dscp_mark" in rule:
                payload["dscp"] = {"mode": "UNTRUSTED", "priority": int(rule["dscp_mark"])}
                continue
            payload["shaper_configurations"].append(
                {
                    "resource_type": _type.get(rule.get("direction")),
                    "enabled": True,
                    "average_bandwidth": int(round(float(rule["max_kbps"]) / 1024)),
                    "peak_bandwidth": int(round(float(rule["max_kbps"]) / 1024) * 2),
                    "burst_size": int(rule["max_burst_kbps"]) * 128,
                }
            )
        return payload

    def segment_port(self, os_port, provider_port) -> dict:
        p_ppid = provider_port.get("parent_id")
        port_id = provider_port.get("id") or os_port.get("id")
        p_qid = provider_port.get("qos_policy_id")
        sec_groups = os_port.get("security_groups")
        sgs = {NSXV3_SECURITY_GROUP_SCOPE: sec_groups} if sec_groups else dict()
        path = provider_port.get("path") or API.SEGMENT_PORT_PATH.format(provider_port["nsx_segment_real_id"], port_id)

        segment_port = {
            "id": port_id,
            "display_name": os_port.get("id"),
            "resource_type": "SegmentPort",
            "admin_state": "UP",
            "attachment": {
                "id": os_port.get("id"),
                "type": "PARENT",
                "traffic_tag": os_port.get("vif_details").get("segmentation_id")
            },
            "address_bindings": os_port.get("address_bindings"),
            "tags": self.tags(os_port, more=sgs),
            "parent_path": API.SEGMENT_PATH.format(provider_port["nsx_segment_real_id"]),
            "path": path,
            "_revision": provider_port.get("_revision")
        }

        if p_ppid:
            segment_port["attachment"]["id"] = os_port.get("id")
            segment_port["attachment"]["type"] = "CHILD"
            segment_port["attachment"]["context_id"] = os_port.get("parent_id")
            if os_port.get("traffic_tag"):
                segment_port["attachment"]["traffic_tag"] = os_port["traffic_tag"]

        if p_qid:
            # Handled in Manager Provider
            pass

        return segment_port

    # NSX-T Group Members
    def sg_members_container(self, os_sg: dict, provider_sg: dict) -> dict:
        sg_id = os_sg.get("id")
        sg = {
            "id": sg_id,
            "display_name": sg_id,
            "path": API.GROUP_PATH.format(sg_id),
            "expression": [
                {
                    "value": "security_group|{}".format(os_sg.get("id")),
                    "member_type": "SegmentPort",
                    "key": "Tag",
                    "operator": "EQUALS",
                    "resource_type": "Condition",
                }
            ],
            "tags": self.tags(os_sg),
            "_revision": provider_sg.get("_revision")
        }
        _cidrs = os_sg.get("cidrs")
        cidrs = self.get_compacted_cidrs(_cidrs) if (_cidrs and len(_cidrs) > 0) else None
        if cidrs:
            sg["expression"].append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
            sg["expression"].append({"resource_type": "IPAddressExpression", "ip_addresses": cidrs})

        paths = provider_sg.get("paths")
        if paths:
            sg["expression"].append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
            sg["expression"].append({"resource_type": "PathExpression", "paths": paths})
        return sg

    def sg_rule_remote(self, cidr) -> dict:
        # NSX bug. Related IPSet to handle  0.0.0.0/x and ::0/x
        return {
            "display_name": cidr,
            "expression": [{
                "resource_type": "IPAddressExpression",
                "ip_addresses": [cidr]
            }],
            "tags": self.tags(None)
        }

    # Distributed Firewall Security Policy
    def sg_rules_container(self, os_sg: dict, provider_sg: dict) -> dict:
        os_id = os_sg.get("id")
        return {
            "category": "Application",
            "display_name": os_id,
            "stateful": os_sg.get("stateful", True),
            "tcp_strict": NSXV3_CAPABILITY_TCP_STRICT in os_sg.get("tags", dict()),
            "scope": ["/infra/domains/default/groups/{}".format(provider_sg.get("scope"))],
            "tags": self.tags(os_sg),
            "rules": provider_sg.get("rules"),
            "path": API.POLICY_PATH.format(os_id),
            "_revision": provider_sg.get("_revision")
        }

    def sg_rule(self, os_rule: dict, provider_rule: dict, logged=False, **kwargs) -> dict or None:
        sp_id = kwargs["sp_id"]
        os_id = os_rule["id"]
        ethertype = os_rule["ethertype"]
        direction = os_rule["direction"]

        def group_ref(group_id):
            return "ANY" if (not group_id or group_id == "ANY") else API.GROUP_PATH.format(group_id)

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
                return None
        else:
            target = ["ANY"]

        service, err = self._sg_rule_service(os_rule, provider_rule, subtype="ServiceEntry")
        if err:
            LOG.warning("Not supported service for Rule:%s. Error:%s", os_id, err)
            return None

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
            "logged": logged,
            "tag": sp_id,
            "scope": ["ANY"],  # Will be overwritten by Policy Scope
            "services": ["ANY"],  # Required by NSX-T Policy validation
            "path": API.RULE_PATH.format(sp_id, os_id),
            "_revision": provider_rule.get("_revision")
        }
        return res

    def _filter_out_ipv4_mapped_ipv6_nets(self, target):
        for cidr in target:
            t = cidr.split("/")
            ip_obj = ipaddress.ip_address(t[0])
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped and (len(t) > 1):
                target.remove(cidr)
                LOG.warning(f"Not supported CIDR target rule: IPv4-mapped IPv6 with prefix ({cidr}).")


class Provider(base.Provider):

    QOS = "Segment QoS"
    NETWORK = "Segment"
    PORT = "SegmentPort"
    RESCHEDULE_WARN_MSG = "Resource: %s with ID: %s deletion is rescheduled due to dependency."

    def __init__(self, payload: Payload = Payload(), zone_id: str = ""):
        super(Provider, self).__init__(client=Client(), zone_id=zone_id)
        LOG.info("Activating Policy API Provider.")
        self.provider = "Policy"
        self.payload = payload

        if cfg.CONF.NSXV3.nsxv3_default_policy_infrastructure_rules:
            self._setup_default_infrastructure_rules()
        if self.client.version >= (3, 0):
            self._ensure_default_l3_policy()
        self._setup_default_app_drop_logged_section()

    def _get_tz(self) -> dict or None:
        for tz in self.client.get_all(path=API.SEARCH_QUERY, params={"query": API.SEARCH_Q_TRANSPORT_ZONES.format(self.zone_name)}):
            if tz.get("display_name") == self.zone_name:
                return tz
        return None

    def _load_zones(self):
        LOG.info("Looking for TransportZone with name %s.", self.zone_name)

        zone_id = None
        zone_tags = []

        tz = self._get_tz()
        if tz:
            zone_id = tz.get("id")
            zone_tags = tz.get("tags", [])

        return zone_id, zone_tags

    def _ensure_default_l3_policy(self):
        res = self.client.get(path=API.POLICY.format(NSXV3_DEFAULT_L3_SECTION))
        res.raise_for_status()
        for rule in res.json()["rules"]:
            if rule["action"] not in ["DROP", "REJECT"]:
                raise Exception("Default l3 section rule is not drop/reject, bailing out")
        return res.json()

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

    def _setup_default_app_drop_logged_section(self):
        LOG.info("Looking for the Default Layer3 Logged Drop Section.")
        policy = DEFAULT_APPLICATION_DROP_POLICY
        path = API.POLICY.format(policy["id"])
        res = self.client.get(path=path)
        if res.ok:
            return
        elif res.status_code == 404:
            LOG.info("Default Layer3 Logged Drop Section %s not found, creating...", policy["display_name"])
            self.client.put(path=path, data=policy).raise_for_status()
        else:
            res.raise_for_status()

    # overrides
    def _metadata_loader(self):
        mp = base.MetaProvider

        return {
            Provider.NETWORK: mp(API.SEGMENTS),
            Provider.PORT: mp(API.SEGMENT_PORTS),
            Provider.QOS: mp(API.QOS_PROFILES),
            Provider.SG_MEMBERS: mp(API.GROUPS),
            Provider.SG_RULES: mp(API.POLICIES),
            Provider.SG_RULES_REMOTE_PREFIX: mp(API.GROUPS)
        }

    def _create_provider_sg(self, os_sg: dict, os_id: str, logged=False):
        provider_rules = []
        meta = self.metadata(Provider.SG_RULES, os_id)
        for rule in os_sg.get("rules", []):
            # Manually tested with 2K rules NSX-T 3.1.0.0.0.17107167
            revision = meta.rules.get(rule["id"], {}).get("_revision") if meta else None
            provider_rule = self._get_sg_provider_rule(rule, revision)  # TODO: this could be optimized
            provider_rule = self.payload.sg_rule(rule, provider_rule, logged=logged, sp_id=os_sg.get("id"))

            if provider_rule:
                provider_rules.append(provider_rule)

        provider_sg = {"scope": os_id, "rules": provider_rules, "_revision": meta.revision if meta else None}
        return provider_sg

    def _fetch_rules_from_nsx(self, meta: PolicyResourceMeta):
        rulez = self.client.get_all(path=API.RULES.format(meta.real_id))
        return {Resource(r).os_id: r for r in rulez}

    # overrides
    def _create_sg_provider_rule_remote_prefix(self, cidr):
        # TODO: remove this method from here and use Payload class instead
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

    def _is_valid_vlan(self, res: Resource) -> bool:
        ls_id: str
        ls: Resource
        for ls_id, ls in self._metadata[Provider.NETWORK].meta.meta.items():
            if ls.id in res.resource.get("parent_path") and ls_id.isnumeric():
                return True
        return False

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
                LOG.info("%s ID: %s in Status: %s", resource_type, os_id, status)
                exporter.REALIZED.labels(resource_type, status).inc()
                return True
            else:
                LOG.info("%s ID: %s in Status: %s for %ss", resource_type, os_id, status, attempt * pause)
                eventlet.sleep(pause)
        # When multiple policies did not get realized in the defined timeframe,
        # this is a symptom for another issue.
        # This should be detected by the Prometheus after a while
        exporter.REALIZED.labels(resource_type, status).inc()
        raise Exception("{} ID: {} did not get realized for {}s", resource_type, os_id, until * pause)

    # overrides
    @refresh_and_retry
    def _realize(self, resource_type: str, delete: bool, convertor: Callable, os_o: dict, provider_o: dict):
        os_id = os_o.get("id")
        report = "Resource: {} with ID: {} is going to be %s.".format(resource_type, os_id)

        meta = self.metadata(resource_type, os_id)
        if meta:
            if delete:
                try:
                    LOG.info(report, "deleted")
                    self.client.delete(path="{}{}".format(API.POLICY_BASE, meta.path))
                    return self.metadata_delete(resource_type, os_id)
                except RuntimeError as e:
                    if re.match("cannot be deleted as either it has children or it is being referenced", str(e)):
                        LOG.warning(self.RESCHEDULE_WARN_MSG, resource_type, os_id)
                        return
                    else:
                        raise e
            else:
                LOG.info(report, "updated")
                provider_o["_revision"] = meta.revision
                data = convertor(os_o, provider_o)
                path = "{}{}".format(API.POLICY_BASE, data.get("path"))
                res = self.client.put(path=path, data=data)
                res.raise_for_status()
                data = res.json()
                # NSX-T applies desired state, no need to fetch after put
                meta = self.metadata_update(resource_type, data)
                self._wait_to_realize(resource_type, os_id)
                return meta
        else:
            if not delete:
                LOG.info(report, "created")
                provider_o["_revision"] = None
                data = convertor(os_o, provider_o)
                path = "{}{}".format(API.POLICY_BASE, data.get("path"))
                res = self.client.put(path=path, data=data)
                res.raise_for_status()
                data = res.json()
                # NSX-T applies desired state, no need to fetch after put
                meta = self.metadata_update(resource_type, data)
                self._wait_to_realize(resource_type, os_id)
                return meta
            LOG.info("Resource: %s with ID: %s already deleted.", resource_type, os_id)

    def _delete_segment_port(self, os_port: dict, port_meta: PolicyResourceMeta) -> None:
        os_id = os_port.get("id")
        nsx_segment_id = port_meta.parent_path.replace(API.SEGMENT_PATH.format(""), "")
        target_o = {"id": nsx_segment_id, "resource_type": Provider.NETWORK}
        resp = self.client.get(API.SEGMENT_PORT.format(nsx_segment_id, port_meta.real_id))
        if resp.ok:
            child_o = resp.json()
            child_o["marked_for_delete"] = True
            payload = self.payload.infra(target_obj=target_o, child_objs=[child_o])
            resp = self.client.patch(path=f"{API.INFRA}?enforce_revision_check=false", data=payload)
            if not resp.ok:
                err_json = resp.json()
                err_msg = str(err_json.get("error_message"))
                LOG.debug(f"{err_msg}")
                match = re.search(r'referenced by other objects path=\[([\w\/\-\,]+)\]', err_msg)
                LOG.warning(self.RESCHEDULE_WARN_MSG, Provider.PORT, os_id)
                if match:
                    self._clear_all_static_memberships_for_port(port_meta)

            return self.metadata_delete(Provider.PORT, os_id)

    def _sg_logged_drop_rules_realize(self, os_sg, delete=False, logged=False):
        logged_drop_policy_rules = self.client.get_all(path=API.RULES.format(DEFAULT_APPLICATION_DROP_POLICY["id"]))
        is_logged = [rule for rule in logged_drop_policy_rules if rule["id"] == os_sg["id"]]

        if logged:
            if len(is_logged) < 1:
                rule = dict(DEFAULT_APPLICATION_DROP_RULE)
                rule["id"] = os_sg["id"]
                rule["display_name"] = os_sg["id"]
                rule["tag"] = os_sg["id"]
                rule["path"] = API.RULE_PATH.format(DEFAULT_APPLICATION_DROP_POLICY["id"], os_sg["id"])
                rule["scope"] = [API.GROUP_PATH.format(os_sg["id"])]
                logged_drop_policy_rules.append(rule)
                return self.client.put(
                    path=API.RULES_CREATE.format(DEFAULT_APPLICATION_DROP_POLICY["id"], rule["id"]), data=rule)
        else:
            if len(is_logged) > 0:
                return self.client.delete(
                    path=API.RULES_CREATE.format(DEFAULT_APPLICATION_DROP_POLICY["id"], is_logged[0]["id"]))

        if delete and len(is_logged) > 0:
            return self.client.delete(
                path=API.RULES_CREATE.format(DEFAULT_APPLICATION_DROP_POLICY["id"], is_logged[0]["id"]))

    def _clear_all_static_memberships_for_port(self, port_meta: PolicyResourceMeta):
        # Get all SGs where the port might have been a static member
        grps = self.client.get_all(path=API.SEARCH_DSL, params=API.SEARCH_DSL_QUERY("Group", port_meta.real_id))
        if len(grps) > 0:
            # Remove the port path from the SGs PathExpressions
            for grp in grps:
                exp = grp["expression"][4]  # the PathExpression is always the 5th element
                if exp["resource_type"] == "PathExpression" and port_meta.path in exp["paths"]:
                    exp["paths"].remove(port_meta.path)
                    if len(exp["paths"]) == 0:
                        # If no more paths, remove the PathExpression and the ConjunctionOperator
                        grp["expression"] = grp["expression"][:-2]  # remove the last two elements
                    with LockManager.get_lock("member-{}".format(grp["display_name"])):
                        sg_meta = self.metadata(self.SG_MEMBERS, grp["display_name"])
                        sg_meta.sg_members.remove(port_meta.path)
                        del grp["status"]
                        self.client.patch(path=API.GROUP.format(grp["id"]), data=grp)

    # overrides
    def port_realize(self, os_port: dict, delete=False):
        port_id = os_port.get("id")
        port_meta = self.metadata(Provider.PORT, port_id)

        if delete:
            if not port_meta:
                LOG.info("Segment Port:%s already deleted.", port_id)
                return
            return self._delete_segment_port(os_port, port_meta)

        # Realize the port via the Policy API
        provider_port = dict()
        parent_port_id = os_port.get("parent_id")

        if parent_port_id:
            # Child port always created internally
            parent_meta, nsx_port = self.get_port(parent_port_id)
            if parent_meta:
                provider_port["parent_id"] = parent_meta.real_id
            else:
                LOG.warning("Not found. Parent Segment Port:%s for Child Port:%s.", parent_port_id, port_id)
                return

        if port_meta:
            provider_port["id"] = port_meta.real_id
            provider_port["path"] = port_meta.path
            provider_port["_revision"] = port_meta.revision
        else:
            LOG.warning("Not found. Segment Port: %s", port_id)

        os_qos_id = os_port.get("qos_policy_id")

        if os_qos_id:
            # QoS policy attached on creation by the Manager API
            pass

        segment_meta = self.metadata(Provider.NETWORK, os_port.get("vif_details").get("segmentation_id"))
        if not segment_meta:
            raise Exception(f"Not found NSX-T Segment for port with ID: {port_id}")

        provider_port["nsx_segment_id"] = segment_meta.unique_id
        provider_port["nsx_segment_real_id"] = segment_meta.real_id

        # If the port has more than the maximum number of security groups allowed as tags,
        # we need to realize the port with empty security groups first,
        # and then add the port to the security groups as a static member.
        port_sgs = os_port.get("security_groups")
        max_sg_tags = min(cfg.CONF.AGENT.max_sg_tags_per_segment_port, 27)
        if len(port_sgs) > max_sg_tags:
            LOG.debug("Port:%s has %s security groups which is more than the maximum allowed %s.",
                      port_id, len(port_sgs), max_sg_tags)
            os_port["security_groups"] = None

            # In case the port already exists, realize the static group membership before the port is updated
            if port_meta:
                self.realize_sg_static_members(port_sgs, port_meta)

            # Realize the port with empty security groups tags
            updated_port_meta = self._realize(Provider.PORT, False, self.payload.segment_port, os_port, provider_port)

            # If the port was not existing, realize the static group membership after the port was created
            return updated_port_meta if port_meta is not None else self.realize_sg_static_members(port_sgs, updated_port_meta)
        else:
            if port_meta:
                self._clear_all_static_memberships_for_port(port_meta)

        return self._realize(Provider.PORT, False, self.payload.segment_port, os_port, provider_port)

    def realize_sg_static_members(self, port_sgs: List[str], port_meta: PolicyResourceMeta):
        for sg_id in port_sgs:
            with LockManager.get_lock("member-{}".format(sg_id)):
                sg_meta = self.metadata(self.SG_MEMBERS, sg_id)
                if not sg_meta:
                    # Realize the Security Group if it does not exist with empty members
                    sg_meta = self.sg_members_realize(
                        {"id": sg_id, "cidrs": [], "revision_number": 0, "member_paths": []})
                if not port_meta.path:
                    raise RuntimeError(f"Not found path in Metadata for port: {port_meta.real_id}")
                if port_meta.path not in sg_meta.sg_members:
                    sg_meta.sg_members.append(port_meta.path)
                    self.sg_members_realize({"id": sg_id,
                                             "cidrs": sg_meta.sg_cidrs,
                                             "member_paths": sg_meta.sg_members,
                                             "revision_number": sg_meta.revision or 0})

    def get_port(self, os_id):
        port = self.client.get_unique(path=API.SEARCH_QUERY, params={"query": API.SEARCH_Q_SEG_PORT.format(os_id)})
        if port:
            return self.metadata_update(Provider.PORT, port), port
        return None, None

    def get_port_meta_by_ids(self, port_ids: Set[str]) -> Set[PolicyResourceMeta]:
        segment_ports = set()
        with LockManager.get_lock(self.PORT):
            keys = set(self._metadata[self.PORT].meta.keys())
            segment_ports.update([self._metadata[self.PORT].meta.meta.get(id)
                                 for id in keys.intersection(port_ids)])
        return segment_ports

    # overrides
    def network_realize(self, segmentation_id: int) -> PolicyResourceMeta:
        segment = self.metadata(Provider.NETWORK, segmentation_id)
        if not segment or segment.real_id is None:
            os_net = {"id": "{}-{}".format(self.zone_name, segmentation_id), "segmentation_id": segmentation_id}
            provider_net = {"transport_zone_id": self.zone_id}
            segment = self._realize(Provider.NETWORK, False, self.payload.segment, os_net, provider_net)
        return segment

    def get_non_default_switching_profiles(self) -> list:
        prfls = self.client.get_all(path=API.SEARCH_QUERY, params=API.SEARCH_Q_ALL_SEG_PROFILES)
        # filter the list
        return [p for p in prfls if p and p.get("id").find("default") == -1]

    # overrides
    def sg_rules_realize(self, os_sg, delete=False, logged=False):
        os_id = os_sg.get("id")
        logged = bool(logged)
        self._sg_logged_drop_rules_realize(os_sg, delete, logged)

        if delete:
            self._realize(Provider.SG_RULES, delete, None, os_sg, dict())
            return

        provider_sg = self._create_provider_sg(os_sg, os_id, logged=logged)
        return self._realize(Provider.SG_RULES, delete, self.payload.sg_rules_container, os_sg, provider_sg)

    def qos_realize(self, qos: dict, delete=False):
        qos_id = qos.get("id")
        meta = self.metadata(Provider.QOS, qos_id)
        if not meta:
            return None
        provider_o = {"id": meta.real_id, "_revision": meta.revision}
        return self._realize(Provider.QOS, delete, self.payload.qos, qos, provider_o)

    def sg_members_realize(self, os_sg: dict, delete=False):
        os_id = os_sg.get("id")
        if delete and self.metadata(Provider.SG_RULES, os_id):
            provider_group = {"paths": [], "_revision": None}
            self._realize(Provider.SG_MEMBERS, False, self.payload.sg_members_container, os_sg, provider_group)
            LOG.warning(self.RESCHEDULE_WARN_MSG, Provider.SG_MEMBERS, os_id)
            return

        provider_group = {"paths": os_sg.get("member_paths"), "_revision": None}
        return self._realize(Provider.SG_MEMBERS, delete, self.payload.sg_members_container, os_sg, provider_group)

    # overrides
    def metadata(self, resource_type: str, os_id: str) -> PolicyResourceMeta:
        if resource_type == Provider.SG_RULES:
            with LockManager.get_lock(Provider.SG_RULES):
                meta = self._metadata[Provider.SG_RULES].meta.get(os_id)
                if meta:
                    if not meta.rules:
                        meta.rules = self._fetch_rules_from_nsx(meta)
                return meta

        with LockManager.get_lock(resource_type):
            return self._metadata[resource_type].meta.get(os_id)

    # overrides
    def metadata_update(self, resource_type, provider_object) -> PolicyResourceMeta:
        if resource_type != Provider.SG_RULE:
            with LockManager.get_lock(resource_type):
                res = Resource(provider_object)
                self._metadata[resource_type].meta.update(res)
                return res.meta

    # overrides
    def metadata_refresh(self, resource_type, params=dict()):
        provider = self._metadata[resource_type]
        with provider.meta:
            LOG.info("[%s] Fetching Policy NSX-T metadata for Type:%s.", self.provider, resource_type)
            endpoint = provider.endpoint
            if resource_type == Provider.PORT:
                endpoint = API.SEARCH_QUERY
                params = API.SEARCH_Q_SEG_PORTS
            if resource_type == Provider.QOS:
                endpoint = API.SEARCH_QUERY
                params = API.SEARCH_Q_QOS_PROFILES
            resources = self.client.get_all(path=endpoint, params=params)
            with LockManager.get_lock(resource_type):
                provider.meta.reset()
                for o in resources:
                    res = Resource(o)
                    if not res.is_managed:
                        continue
                    if resource_type == Provider.SG_MEMBERS and NSXV3_REVISION_SCOPE not in res.tags:
                        continue
                    if resource_type == Provider.SG_RULES_REMOTE_PREFIX and NSXV3_REVISION_SCOPE in res.tags:
                        continue
                    if resource_type == Provider.PORT and not self._is_valid_vlan(res):
                        continue

                    provider.meta.add(res)

    def metadata_delete(self, resource_type: str, os_id: str) -> None:
        with LockManager.get_lock(resource_type):
            self._metadata[resource_type].meta.rm(os_id)

    def outdated(self, resource_type: str, os_meta: Dict[str, dict]):
        self.metadata_refresh(resource_type)

        if resource_type == Provider.SG_RULES:
            self.metadata_refresh(Provider.SG_RULES_REMOTE_PREFIX)

        meta = self._metadata.get(resource_type).meta

        os_meta_ids = set(os_meta.keys())
        nsx_meta_ids = set(meta.keys())

        # Treat both new and orphaned as outdated, but filter out orphaned ports not yet to be deleted
        outdated = os_meta_ids.difference(nsx_meta_ids)  # for creation
        orphaned = nsx_meta_ids.difference(os_meta_ids)  # for deletion

        # Don't count orphans for members, we don't know yet if they are really orphaned
        if resource_type == Provider.SG_MEMBERS:
            orphaned: Set[str] = set()

        # Remove Ports not yet exceeding delete timeout
        if resource_type == Provider.PORT:
            orphaned = set([
                orphan for orphan in orphaned
                if self.orphan_ports_tmout_passed(meta.get(orphan).last_modified_time / 1000)
            ])

        outdated.update(orphaned)

        # Add revision outdated
        for id in os_meta_ids.intersection(nsx_meta_ids):
            if not meta.get(id).age or str(os_meta[id]) != str(meta.get(id).rev):
                meta.get(id)
                outdated.add(id)  # for update

        LOG.info(
            "[%s] The number of outdated resources for Type:%s Is:%s.", self.provider, resource_type, len(outdated)
        )
        LOG.debug("Outdated resources of Type:%s Are:%s", resource_type, outdated)

        current = nsx_meta_ids.difference(outdated)
        if resource_type == Provider.PORT:
            # Ignore ports that are going to be deleted anyway (and therefor not existing in neutron)
            current = set([_id for _id in current if _id in os_meta_ids])
        return outdated, current

    def age(self, resource_type: str, os_ids: List[str]):
        return [(resource_type, id, self.metadata(resource_type, id).age) for id in os_ids]

    # overrides
    def sanitize(self, slice):
        if slice <= 0:
            return ([], None)

        def remove_orphan_remote_prefixes(provider_id):
            self._delete_sg_provider_rule_remote_prefix(provider_id)

        def remove_orphan_service(provider_id):
            self.client.delete(path=API.SERVICE.format(provider_id))

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

        if len(sanitize) < slice:
            services = self.client.get_all(path=API.SERVICES, params={"default_service": False})
            # Mitigating bug with 3.0.1 which ignores default_service = False
            for service in [sv for sv in services if not sv.get("is_default")]:
                sanitize.append((service.get("id"), remove_orphan_service))
        return sanitize

    def set_policy_logging(self, log_obj, enable_logging):
        LOG.debug(f"PROVIDER: set_policy_logging: {json.dumps(log_obj, indent=2)} as {enable_logging}")

        # Check for a valid request
        if log_obj['resource_type'] != 'security_group':
            LOG.error(f"set_policy_logging: incompatible resource type: {log_obj['resource_type']}")
            return

        # Get current rules configuration
        res = self.client.get(path=API.POLICY.format(log_obj['resource_id']))
        res.raise_for_status()

        # Prepare update data
        data = {
            'rules': res.json()['rules']
        }
        for rule in data['rules']:
            rule['logged'] = enable_logging
            # rule['_revision'] = rule['_revision'] + 1

        # Update the logging state
        res = self.client.patch(path=API.POLICY.format(log_obj['resource_id']), data=data)
        res.raise_for_status()
        self._sg_logged_drop_rules_realize({"id": log_obj['resource_id']}, False, enable_logging)

    def enable_policy_logging(self, log_obj):
        LOG.debug(f"PROVIDER: enable_policy_logging")
        return self.set_policy_logging(log_obj, True)

    def disable_policy_logging(self, log_obj):
        LOG.debug(f"PROVIDER: disable_policy_logging")
        return self.set_policy_logging(log_obj, False)

    def update_policy_logging(self, log_obj):
        LOG.debug(f"PROVIDER: update_policy_logging")
        return self.set_policy_logging(log_obj, log_obj['enabled'])

    def tag_transport_zone(self, scope, tag):
        tz = self._get_tz()
        tags = tz.get("tags", [])
        updated_tag_list = []

        if len(tags) < 1:
            updated_tag_list = [{"scope": scope, "tag": tag}]
        else:
            updated_tag_list = list([t for t in tags if t.get("scope") != scope])
            updated_tag_list.append({"scope": scope, "tag": tag})

        tz["tags"] = updated_tag_list
        self.client.put(path=API.TRANSPORT_ZONE.format(tz.get("id")), data=tz)
