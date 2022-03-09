import functools
import re
from typing import Tuple

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

    IP_DISCOVERY_PROFILES = POLICY_BASE + "/infra/ip-discovery-profiles"
    MAC_DISCOVERY_PROFILES = POLICY_BASE + "/infra/mac-discovery-profiles"
    PORT_MIRRORING_PROFILES = POLICY_BASE + "/infra/port-mirroring-profiles"
    SEGMENT_SEC_PROFILES = POLICY_BASE + "/infra/segment-security-profiles"
    SPOOFGUARD_PROFILES = POLICY_BASE + "/infra/spoofguard-profiles"
    QOS_PROFILES = POLICY_BASE + "/infra/qos-profiles"

    IP_DISCOVERY_PROFILE = IP_DISCOVERY_PROFILES + "/{}"
    MAC_DISCOVERY_PROFILE = MAC_DISCOVERY_PROFILES + "/{}"
    PORT_MIRRORING_PROFILE = PORT_MIRRORING_PROFILES + "/{}"
    SEGMENT_SEC_PROFILE = SEGMENT_SEC_PROFILES + "/{}"
    SPOOFGUARD_PROFILE = SPOOFGUARD_PROFILES + "/{}"
    QOS_PROFILE = QOS_PROFILES + "/{}"

    POLICIES = POLICY_BASE + "/infra/domains/default/security-policies"
    POLICY_PATH = "/infra/domains/default/security-policies/{}"
    RULE_PATH = POLICY_PATH + "/rules/{}"
    POLICY = POLICY_BASE + POLICY_PATH
    RULES = POLICY_BASE + POLICY_PATH + "/rules"

    SEARCH_QUERY = POLICY_BASE + "/search/query"
    SEARCH_Q_SEG_PORT = "resource_type:SegmentPort AND marked_for_delete:false AND attachment.id:{}"
    SEARCH_Q_SEG_PORTS = "resource_type:SegmentPort AND marked_for_delete:false"

    SEGMENTS = POLICY_BASE + "/infra/segments"
    SEGMENT_PATH = "/infra/segments/{}"
    SEGMENT = POLICY_BASE + SEGMENT_PATH
    SEGMENT_PORTS = POLICY_BASE + "/infra/segments/{}/ports"
    SEGMENT_PORT_PATH = "/infra/segments/{}/ports/{}"
    SEGMENT_PORT = POLICY_BASE + SEGMENT_PORT_PATH

    GROUP_PATH = "/infra/domains/default/groups/{}"
    GROUPS = POLICY_BASE + "/infra/domains/default/groups"
    GROUP = POLICY_BASE + GROUP_PATH

    SERVICES = POLICY_BASE + "/infra/services"
    SERVICE = POLICY_BASE + "/infra/services/{}"

    STATUS = POLICY_BASE + "/infra/realized-state/status"
    TRANSPORT_ZONES_PATH = "/infra/sites/default/enforcement-points/default/transport-zones/{}"


class PolicyResourceMeta(provider_nsx_mgmt.ResourceMeta):
    def __init__(self, id, rev, age, revision, last_modified_time, rules, path):
        super(PolicyResourceMeta, self).__init__(id, rev, age, revision, last_modified_time)
        self.rules = rules
        self.path = path


class Resource(provider_nsx_mgmt.Resource):
    def __init__(self, resource: dict):
        super(Resource, self).__init__(resource)

    @property
    def is_managed(self):
        if self.is_mgmt_resource:
            return super(Resource, self).is_managed()

        if not self.resource.get("locked"):
            user = self.resource.get("_create_user")
            if user == "admin":
                return True

            if self.type == "SegmentPort":
                att_id = self.resource.get("attachment", {}).get("id")
                if user != "nsx_policy" and att_id:
                    return True
        return False

    @property
    def os_id(self):
        if self.is_mgmt_resource:
            return super(Resource, self).os_id()

        os_id = self.resource.get("display_name")
        if self.type == "Segment":
            os_id = os_id.split("-")[-1]
        if self.type == "SegmentPort":
            os_id = self.resource.get("attachment", {}).get("id")
        return os_id

    @property
    def meta(self):
        rulez = self.resource.get("rules", [])
        _rules = {Resource(r).os_id: r for r in rulez}
        tags = self.tags

        return PolicyResourceMeta(
            id=self.id,
            rev=tags.get(NSXV3_REVISION_SCOPE),
            age=tags.get(NSXV3_AGE_SCOPE),
            revision=self.resource.get("_revision"),
            last_modified_time=self.resource.get("_last_modified_time"),
            path=self.path,
            # Only Firewall Security Policies have the next prop (Provider.SG_RULES)
            rules=_rules
        )

    @property
    def path(self):
        return self.resource.get("path")

    @property
    def is_mgmt_resource(self) -> bool:
        return self.type in ["LogicalPort", "LogicalSwitch"]


class Payload(provider_nsx_mgmt.Payload):

    def segment(self, os_net, provider_net):
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
            "id": os_id,
            "display_name": os_id,
            "path": API.SEGMENT_PATH.format(os_id),
            "_revision": provider_net.get("_revision")
        }

    def segment_port(self, os_port, provider_port):
        p_ppid = provider_port.get("parent_id")
        # p_qid = provider_port.get("qos_policy_id")  # TODO: handle QOS profile for port
        segment_id = os_port.get("vif_details").get("nsx-logical-switch-id")
        port_id = provider_port.get("id") or os_port.get("id")

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
            "tags": self.tags(os_port, more={NSXV3_SECURITY_GROUP_SCOPE: os_port.get("security_groups")}),
            "parent_path": API.SEGMENT_PATH.format(segment_id),
            "path": API.SEGMENT_PORT_PATH.format(segment_id, port_id),
            "_revision": provider_port.get("_revision")
        }

        if p_ppid:
            segment_port["attachment"]["id"] = os_port.get("id")
            segment_port["attachment"]["type"] = "CHILD"
            segment_port["attachment"]["context_id"] = os_port.get("parent_id")
            if os_port.get("traffic_tag"):
                segment_port["attachment"]["traffic_tag"] = os_port["traffic_tag"]

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
                    "member_type": "LogicalPort",
                    "key": "Tag",
                    "operator": "EQUALS",
                    "resource_type": "Condition",
                }
            ],
            "tags": self.tags(os_sg),
            "_revision": provider_sg.get("_revision")
        }

        cidrs = self.get_compacted_cidrs(os_sg.get("cidrs"))
        if cidrs:
            sg["expression"].append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
            sg["expression"].append({"resource_type": "IPAddressExpression", "ip_addresses": cidrs})
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

    def sg_rule(self, os_rule: dict, provider_rule: dict, **kwargs) -> dict:
        sp_id = kwargs["sp_id"]
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


class Provider(provider_nsx_mgmt.Provider):
    def __init__(self, payload: Payload = Payload()):
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
            Provider.SEGMENT: mp(API.SEGMENTS),
            Provider.SEGMENT_PORT: mp(API.SEGMENT_PORTS),
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

    # overrides
    @refresh_and_retry
    def _realize(self, resource_type, delete, convertor, os_o, provider_o):
        path = self._metadata.get(resource_type).endpoint
        if "policy" not in path:
            # Handle QoS and Ports
            return super(Provider, self)._realize(resource_type, delete, convertor, os_o, provider_o)

        os_id = os_o.get("id")

        report = "Resource:{} with ID:{} is going to be %s.".format(resource_type, os_id)

        meta = self.metadata(resource_type, os_id)
        if meta:
            if delete:
                LOG.info(report, "deleted")
                self.client.delete(path="{}{}".format(API.POLICY_BASE, meta.path))
                return self.metadata_delete(resource_type, os_id)
            else:
                LOG.info(report, "updated")
                provider_o["_revision"] = meta.revision
                data = convertor(os_o, provider_o)
                path = "{}{}".format(API.POLICY_BASE, data.get("path"))
                res = self.client.put(path=path, data=data)
                res.raise_for_status()
                data = res.json()
                data["id"] = os_id
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
                data["id"] = os_id
                # NSX-T applies desired state, no need to fetch after put
                meta = self.metadata_update(resource_type, data)
                self._wait_to_realize(resource_type, os_id)
                return meta
            LOG.info("Resource:%s with ID:%s already deleted.", resource_type, os_id)

    def get_port(self, os_id) -> PolicyResourceMeta:
        port = self.client.get_unique(path=API.SEARCH_QUERY, params={"query": API.SEARCH_Q_SEG_PORT.format(os_id)})
        if port:
            return self.metadata_update(Provider.SEGMENT_PORT, port)

    # overrides
    def port_realize(self, os_port, delete=False):
        # Try get port from both APIs for backward compatability
        segment_port_meta = self.get_port(os_port.get("id"))
        switch_port_meta = super(Provider, self).get_port(os_port.get("id"))
        network_meta = self.get_network(os_port.get("vif_details").get("segmentation_id"))

        # If Manager API Port exists or network is still in Manager API, continue to realize it via Manager API
        if (not segment_port_meta and switch_port_meta) or network_meta:  # TODO: remove when completely migrated
            return super(Provider, self).port_realize(os_port, delete)

        # ELSE realize the port via Policy API
        provider_port = dict()
        if delete:
            self._realize(Provider.SEGMENT_PORT, True, None, os_port, provider_port)
            return

        if os_port.get("parent_id"):
            # Child port always created internally
            parent_port = self.get_port(os_port.get("parent_id"))
            if parent_port:
                provider_port["parent_id"] = parent_port.id
            else:
                # TODO: handle the edge case when the port is in Manager API
                LOG.warning("Not found. Parent Port:%s for Child Port:%s", os_port.get("parent_id"), os_port.get("id"))
                return
        else:
            if segment_port_meta:
                provider_port["id"] = segment_port_meta.id
                provider_port["_revision"] = segment_port_meta.revision
            else:
                LOG.warning("Not found. Port: %s", os_port.get("id"))

        # TODO: handle QOS with policy API
        # if os_port.get("qos_policy_id"):
        #     meta_qos = self.metadata(Provider.QOS, os_port.get("qos_policy_id"))
        #     if meta_qos:
        #         provider_port["qos_policy_id"] = meta_qos.id
        #     else:
        #         LOG.error("Not found. QoS:%s for Port:%s", os_port.get("qos_policy_id"), os_port.get("id"))
        # provider_port["switching_profile_ids"] = copy.deepcopy(self.switch_profiles)  # TODO: check if compatible

        return self._realize(Provider.SEGMENT_PORT, False, self.payload.segment_port, os_port, provider_port)

    def get_network(self, segmentation_id) -> PolicyResourceMeta or provider_nsx_mgmt.ResourceMeta:
        return self.metadata(Provider.SEGMENT, segmentation_id) or self.metadata(Provider.NETWORK, segmentation_id)

    # overrides
    def network_realize(self, segmentation_id: int) -> PolicyResourceMeta or provider_nsx_mgmt.ResourceMeta:
        meta = self.get_network(segmentation_id)
        if meta:
            return meta

        # ELSE use Policy API to realize the network
        os_net = {"id": "{}-{}".format(self.zone_name, segmentation_id), "segmentation_id": segmentation_id}
        provider_net = {"transport_zone_id": self.zone_id, "_revision": None}

        data = self.payload.segment(os_net, provider_net)
        o = self.client.put(path=API.SEGMENT.format(os_net.get("id")), data=data).json()
        meta = self.metadata_update(Provider.SEGMENT, o)

        return meta

    def get_non_default_switching_profiles(self) -> list:
        prfls = [
            API.IP_DISCOVERY_PROFILES,
            API.MAC_DISCOVERY_PROFILES,
            API.PORT_MIRRORING_PROFILES,
            API.SEGMENT_SEC_PROFILES,
            API.SPOOFGUARD_PROFILES,
            API.QOS_PROFILES
        ]
        prfls = [self.client.get_all(path=p) for p in prfls]
        # filter/flattern the list
        return [p for sublist in prfls for p in sublist if p and p.get("id").find("default") == -1]

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
            provider_rule = self._get_sg_provider_rule(rule, revision)  # TODO: this could be optimized
            provider_rule = self.payload.sg_rule(rule, provider_rule, sp_id=os_sg.get("id"))

            if provider_rule:
                provider_rules.append(provider_rule)

        provider_sg = {"scope": os_id, "rules": provider_rules, "_revision": meta.revision if meta else None}
        return provider_sg

    # overrides
    def metadata(self, resource_type: str, os_id: str) -> PolicyResourceMeta or provider_nsx_mgmt.ResourceMeta:
        if self.is_mgmt_resource(resource_type):
            return super(Provider, self).metadata(resource_type, os_id)
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
    def metadata_update(self, resource_type, provider_object) -> PolicyResourceMeta or provider_nsx_mgmt.ResourceMeta:
        if self.is_mgmt_resource(resource_type):
            return super(Provider, self).metadata_update(resource_type, provider_object)
        if resource_type != Provider.SG_RULE:
            with LockManager.get_lock(resource_type):
                res = Resource(provider_object)
                self._metadata[resource_type].meta.update(res)
                return res.meta

    # overrides
    def metadata_refresh(self, resource_type, params=dict()):
        if self.is_mgmt_resource(resource_type):
            return super(Provider, self).metadata_refresh(resource_type, params)

        provider = self._metadata[resource_type]
        with provider.meta:
            LOG.info("[%s] Fetching Policy NSX-T metadata for Type:%s.", self.provider, resource_type)
            endpoint = provider.endpoint
            if resource_type == Provider.SEGMENT_PORT:
                endpoint = API.SEARCH_QUERY
                params = {"query": API.SEARCH_Q_SEG_PORTS}
            resources = self.client.get_all(path=endpoint, params=params)
            with LockManager.get_lock(resource_type):
                provider.meta.reset()
                for o in resources:
                    res = Resource(o)
                    if not res.is_managed:
                        continue
                    if resource_type == Provider.SG_RULES and not res.has_valid_os_uuid:
                        continue
                    if resource_type == Provider.SEGMENT_PORT and not self._is_valid_vlan(res):
                        continue

                    provider.meta.add(res)

    def _is_valid_vlan(self, res: Resource) -> bool:
        ls_id: str
        ls: Resource
        for ls_id, ls in self._metadata[Provider.SEGMENT].meta.meta.items():
            if ls.path == res.resource.get("parent_path") and ls_id.isnumeric():
                return True
        return False

    def outdated(self, resource_type: str, os_meta: dict) -> Tuple[list, list]:
        if self.is_mgmt_resource(resource_type):
            return super(Provider, self).outdated(resource_type, os_meta)

        self.metadata_refresh(resource_type)

        if resource_type == Provider.SG_RULES:
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
        if resource_type == Provider.SEGMENT_PORT:
            orphaned = [
                orphan for orphan in orphaned if self._del_tmout_passed(meta.get(orphan).last_modified_time / 1000)
            ]

        outdated.update(orphaned)

        # Add revision outdated
        for id in k1.intersection(k2):
            if not meta.get(id).age or str(os_meta[id]) != str(meta.get(id).rev):
                meta.get(id)
                outdated.add(id)

        LOG.info(
            "[%s] The number of outdated resources for Type:%s Is:%s.", self.provider, resource_type, len(outdated)
        )
        LOG.debug("Outdated resources of Type:%s Are:%s", resource_type, outdated)

        current = k2.difference(outdated)
        if resource_type == Provider.SEGMENT_PORT:
            # Ignore ports that are going to be deleted anyway (and therefor not existing in neutron)
            current = [_id for _id in current if _id in os_meta]
        return outdated, current

    def is_mgmt_resource(self, resource_type: str) -> bool:
        return resource_type in [Provider.PORT, Provider.NETWORK, Provider.QOS, Provider.SG_RULES_EXT]

    def _fetch_rules_from_nsx(self, meta):
        rulez = self.client.get_all(API.RULES.format(meta.id))
        return {provider_nsx_mgmt.Resource(r).os_id: r for r in rulez}

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
        LOG.error("sanitize: {}".format(sanitize))
        return sanitize
