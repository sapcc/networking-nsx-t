import eventlet
import ipaddress
import copy
import json
import datetime
import requests
from requests.exceptions import HTTPError
from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout

from oslo_log import log as logging
from oslo_config import cfg

from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.common.synchronization import Scheduler
from networking_nsxv3.common import constants as nsxv3_constants

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.nsxv3_constants import *

LOG = logging.getLogger(__name__)

INFRA = "/policy/api/v1/infra"


class RetryPolicy(object):

    def __call__(self, func):

        def decorator(self, *args, **kwargs):

            requestInfo = ""

            if 'path' in kwargs and 'session/create' in kwargs.get('path'):
                pass
            else:
                requestInfo = "Function {} Argumetns {}".format(func.__name__, 
                                                                str(kwargs))

            until = cfg.CONF.NSXV3.nsxv3_connection_retry_count
            pause = cfg.CONF.NSXV3.nsxv3_connection_retry_sleep

            method = "{}.{}".format(self.__class__.__name__, func.__name__)
            
            pattern = "Retrying connection ({}/{}) with timeout {}s for {}"
            msg = None
            last_err = None

            for attempt in range(1, until + 1):
                try:
                    response = func(self, *args, **kwargs)

                    if 200 <= response.status_code < 300 or \
                        response.status_code in [404]:
                        return response
                    
                    last_err = "Error Code={} Message={}"\
                        .format(response.status_code, response.content)


                    LOG.error("Request={} Response={}".format(requestInfo,
                                                              last_err))

                    if response.status_code in [401, 403]:
                        self._login()
                        continue

                    # skip retry on the ramaining NSX errors
                    break                    
                except (HTTPError, ConnectionError, ConnectTimeout) as err:
                    last_err = err
                    LOG.error("Request={} Response={}".format(requestInfo,
                                                              last_err))

                msg = pattern.format(attempt, until, pause, method)

                LOG.debug(msg)
                eventlet.sleep(pause)

            raise Exception(msg, last_err)
        
        return decorator



class Client:

    def __init__(self, api_scheduler):
        self._timeout = cfg.CONF.NSXV3.nsxv3_request_timeout

        self._base_path = 'https://{}:{}'.format(
            cfg.CONF.NSXV3.nsxv3_login_hostname,
            cfg.CONF.NSXV3.nsxv3_login_port
        )

        self._login_timestamp = 0
        self._login_path = "/api/session/create"
        self._login_data = {
            "j_username": cfg.CONF.NSXV3.nsxv3_login_user,
            "j_password": cfg.CONF.NSXV3.nsxv3_login_password
        }

        self._session = requests.session()
        
        if cfg.CONF.NSXV3.nsxv3_suppress_ssl_wornings:
            self._session.verify = False
            requests.packages.urllib3.disable_warnings()

        self.api_scheduler = api_scheduler

    def _login(self):
        LOG.info("Session token - acquiring")
        now = int(datetime.datetime.now().strftime("%s"))
        with LockManager.get_lock(self._base_path):
            if now > self._login_timestamp:
                resp = self.post(path=self._login_path, data=self._login_data)
                if resp.status_code != requests.codes.ok:
                    resp.raise_for_status()

                self._session.headers["Cookie"] = \
                    resp.headers.get("Set-Cookie")
                self._session.headers["X-XSRF-TOKEN"] = \
                    resp.headers.get("X-XSRF-TOKEN")
                self._session.headers["Accept"] = "application/json"
                self._session.headers["Content-Type"] = "application/json"

                self._login_timestamp = \
                    int(datetime.datetime.now().strftime("%s"))

        LOG.info("Session token - acquired")
    
    def _params(self, **kwargs):
        kwargs["timeout"] = self._timeout
        kwargs["url"] = "{}{}".format(self._base_path, kwargs["path"])
        del kwargs["path"]
        return kwargs

    @RetryPolicy()
    def post(self, path, data):
        with self.api_scheduler:
            return self._session.post(**self._params(path=path, data=data))

    @RetryPolicy()
    def patch(self, path, data):
        with self.api_scheduler:
            return self._session.patch(**self._params(path=path, data=data))

    @RetryPolicy()
    def put(self, path, data):
        with self.api_scheduler:
            return self._session.put(**self._params(path=path, data=data))

    @RetryPolicy()
    def get(self, path, params={}):
        with self.api_scheduler:
            return self._session.get(**self._params(path=path, params=params))

    @RetryPolicy()
    def delete(self, path, params):
        with self.api_scheduler:
            return self._session.delete(**self._params(path=path, 
                                                       params=params))

class AgentIdentifier:
    """
    AgentIdentifier provide control over the NSX-T Policy Objects IDs
    """

    @staticmethod
    def build(identifier):
        return identifier
        # Uncomment in order to have exclusive IDs per Agent
        # return "{}-{}".format(cfg.CONF.AGENT.agent_id, identifier)

    @staticmethod
    def extract(identifier):
        return identifier
        # Uncomment in order to have exclusive IDs per Agent
        # tokens = identifier.split(cfg.CONF.AGENT.agent_id + '-')
        # return tokens.pop() if len(tokens) == 2 else None


class InfraBuilder:

    def __init__(self, client, transport_zone_id=None):
        self._client = client
        self.context = { 
            "resource_type": "Infra",
            "connectivity_strategy" : \
                cfg.CONF.NSXV3.nsxv3_dfw_connectivity_strategy,
            "children": [
                {
                    "resource_type": "ChildResourceReference",
                    "id": "default",
                    "target_type": "Domain",
                    "children": []
                }
            ]
        }

        self.transport_zone_id = transport_zone_id
    
    def build(self):
        self._client.patch(path=INFRA, data=json.dumps(self.context))

    def _add_domain_children(self, children):
        self.context["children"][0]["children"] += children
    
    def _add_children(self, children):
        self.context["children"] += children
    
    def _get_tags(self, infra_object=None):
        tags = [{
            "scope": nsxv3_constants.NSXV3_AGENT_SCOPE,
            "tag": cfg.CONF.AGENT.agent_id
        }]
        
        if infra_object is not None and infra_object.revision:
            tags.append({
                "scope": nsxv3_constants.NSXV3_REVISION_SCOPE,
                "tag": infra_object.revision
            })
        
        return tags

    def with_group(self, group, delete=False):
        identifier = AgentIdentifier.build(group.identifier)
        expression = []

        if group.dynamic_members:
            expression.append({
                "value": "security_group|" + identifier,
                "member_type": "LogicalPort",
                "key": "Tag",
                "operator": "EQUALS",
                "resource_type": "Condition"
            })

        if group.cidrs:
            if group.dynamic_members:
                expression.append({
                    "resource_type": "ConjunctionOperator",
                    "conjunction_operator": "OR"
                })
            expression.append({
                "resource_type": "IPAddressExpression",
                "ip_addresses": group.cidrs
            })

        self._add_domain_children([{
            "resource_type": "ChildGroup",
            "marked_for_delete": delete,
            "Group": {
                "resource_type": "Group",
                "id": identifier,
                "display_name": identifier,
                "expression": expression,
                "tags": self._get_tags(group)
            }
        }])
        return self

    def with_service(self, service, delete=False):
        identifier = AgentIdentifier.build(service.identifier)
        smin = service.port_range_min
        smax = service.port_range_max
        protocol = service.protocol
        ethertype = service.ethertype

        def is_valid_icmp(protocol):
            return protocol == 'icmp'
            
        def is_valid_icmp_range(min, max):
            return \
                min in VALID_ICMP_RANGES[ethertype] and \
                max in VALID_ICMP_RANGES[ethertype][min]

        def is_valid_l4(protocol):
            return protocol in ["tcp", "udp"]

        def is_valid_ip(protocol):
            text = str(protocol)
            return text.isdigit() or text in IP_PROTOCOL_NUMBERS

        def is_valid_any(protocol):
            return protocol == None

        def get_protocol_number(protocol):
            text = str(protocol)
            return int(text) if text.isdigit() else IP_PROTOCOL_NUMBERS.get(text)

        def get_port(min, max):
            port = "1-65535"
            if min and max:
                port = "{}-{}".format(min, max) if min != max else str(min)
            return port

        service_entry = {
            "display_name": identifier
        }

        if not delete and is_valid_icmp(protocol):
            if not is_valid_icmp_range(smin, smax):
                return
            service_entry["resource_type"] = "ICMPTypeServiceEntry"
            service_entry["protocol"] = ICMP_PROTOCOLS[ethertype]
            service_entry["icmp_type"] = str(smin) if isinstance(smin, int) \
                else None
            service_entry["icmp_code"] = str(smax) if isinstance(smax, int) \
                else None
        elif not delete and is_valid_l4(protocol):
            service_entry["resource_type"] = "L4PortSetServiceEntry"
            service_entry["l4_protocol"] = protocol.upper()
            service_entry["source_ports"] = ["1-65535"]
            service_entry["destination_ports"] = [get_port(smin, smax)]
        elif not delete and is_valid_ip(protocol):
            service_entry["resource_type"] = "IPProtocolServiceEntry"
            service_entry["protocol_number"] = get_protocol_number(protocol)

        if not delete and is_valid_any(protocol):
            return self
        
        if delete or service_entry["resource_type"]:
            self._add_children([{
                "resource_type": "ChildService",
                "marked_for_delete": delete,
                "Service": {
                    "resource_type": "Service",
                    "id": identifier,
                    "display_name": identifier,
                    "service_entries": [] if delete else [ service_entry ],
                    "tags": self._get_tags(service)
                }
            }])
        else:
            LOG.warn("Skipped. Unable to map service: {}/{}/{}-{}".format(\
                service.ethertype, service.protocol,
                service.port_range_min, service.port_range_max))

        return self
    
    def with_rule(self, section, rule, delete=False):
        identifier = AgentIdentifier.build(rule.identifier)

        DIRECTIONS = {'ingress': 'IN', 'egress': 'OUT'}
        PROTOCOLS = {'IPv4': 'IPV4', 'IPv6': 'IPV6'}
        PROTOCOL_TYPES = {'IPv4': 'IPv4Address', 'IPv6': 'IPv6Address'}

        def group_ref(group_id):
            return group_id if group_id == "ANY" else \
                "/infra/domains/default/groups/" + group_id
        
        def service_ref(service_id):
            return "/infra/services/" + service_id

        source = "ANY" # To allow only in group traffic set to source_group_id
        destination = "ANY"
        service = "ANY"

        if rule.service.protocol is not None:
            self.with_service(rule.service, delete=delete)

            # Skip rule creation in case service cannot be matched
            created = False
            for child in self.context["children"]:
                if child["resource_type"] == "ChildService" and \
                    child["Service"]["id"] == identifier:
                    created = True
                    break

            if created:
                service = service_ref(identifier)
            else:
                return

        if rule.remote_ip_prefix is not None:
            remote_cidr = str(ipaddress.ip_network(str(rule.remote_ip_prefix)))
            
            if remote_cidr not in [None, '0.0.0.0/0', '::/0']:

                if remote_cidr.startswith("0.0.0.0/"):
                    # \: Due bug in NSX-T API ignore 0.0.0.0 
                    # Network definitions that are not ANY
                    return

                destination = identifier
                # Create CIDR group for the firewall rule
                cidr_group = Group()
                cidr_group.identifier = rule.identifier
                cidr_group.cidrs = [remote_cidr]
                cidr_group.dynamic_members = False
                self.with_group(cidr_group, delete=delete)

        if rule.remote_group_id:
            destination = AgentIdentifier.build(rule.remote_group_id)

        infra_rule = {
            "resource_type": "Rule",
            "id": identifier,
        }
        infra_rule_extension = {}

        if delete:
            s = Service()
            g = Group()
            s.identifier = g.identifier = identifier
            self.with_service(s, delete=delete).with_group(g, delete=delete)
        else:
            # Switch source and destination according to the direction
            source_group = destination \
                if rule.direction in 'ingress' else source
            destination_group = source \
                if rule.direction in 'ingress' else destination

            infra_rule_extension = {
                "display_name": identifier,
                "disabled": False,
                "logged": False,
                "profiles": [ "ANY" ],
                "ip_protocol": PROTOCOLS[rule.ethertype],
                "direction": DIRECTIONS[rule.direction],
                "action": "ALLOW",
                "scope": [ 
                    group_ref(AgentIdentifier.build(rule.security_group_id))
                ],
                "source_groups": [ group_ref(source_group) ],
                "destination_groups": [ group_ref(destination_group) ],
                "services": [ service ],
                "tags": self._get_tags(rule)
            }

        section["children"] += [{
            "resource_type": "ChildRule",
            "marked_for_delete": delete,
            "Rule": dict(infra_rule, **infra_rule_extension)
        }]
        return self
    
    def with_policy(self, policy, delete=False):
        identifier = AgentIdentifier.build(policy.identifier)

        section = {
            "resource_type": "ChildSecurityPolicy",
            "marked_for_delete": delete,
            "SecurityPolicy": {
                "resource_type": "SecurityPolicy",
                "display_name": identifier,
                "id": identifier,
                "category": "Application",
                "stateful": True,
                "children": [],
                "tags": self._get_tags(policy)
            }
        }

        if policy.tcp_strict is not None:
            section["SecurityPolicy"]["tcp_strict"] = policy.tcp_strict

        if not delete:
            for rule in policy.rules_to_add:
                self.with_rule(section["SecurityPolicy"], rule, delete=False)

        for rule in policy.rules_to_remove:
            self.with_rule(section["SecurityPolicy"], rule, delete=True)

        self._add_domain_children([section])
        return self
    
    def with_segment(self, segment, delete=False):
        identifier = AgentIdentifier.build(segment.identifier)
        path = \
            "/infra/sites/default/enforcement-points/default/transport-zones/"
        self._add_domain_children([{
            "resource_type": "ChildSegment ",
            "marked_for_delete": delete,
            "Segment ": {
                "resource_type": "Segment",
                "id": identifier,
                "display_name": identifier,
                "vlan_ids": [segment.vlan],
                "transport_zone_path": path + self.transport_zone_id,
                "advanced_config": {
                    "address_pool_paths": []
                },
                "tags": self._get_tags(segment)
            }
        }])
        return self

class InfraService:

    def __init__(self, client):
        self._client = client
        self._page_size = cfg.CONF.NSXV3.nsxv3_max_records_per_query
        self._transport_zone_name = cfg.CONF.NSXV3.nsxv3_transport_zone_name

    def _get_tags(self, resource):
        tags = {}
        for tag in resource.get("tags", []):
            tags[tag["scope"]] = tag["tag"]
        return tags

    def _lookup_transport_zone(self, name):
        path = "{}{}".format(INFRA, ResourceContainers.TransportZone)
        response = self._client.get(path=path)
        for resource in content.get("results", []):
            if resource["name"] == name:
                return resource["id"]
        raise Exception("Unable to find TransportZone={}".format(name))


    def _get_revisions(self, resource_container, cursor):
        path = "{}{}".format(INFRA, resource_container)
        params = { "page_size": self._page_size, "cursor": cursor }

        try:
            response = self._client.get(path=path, params=params)
        except Exception as e:
            LOG.error("Unable to get path={} ERROR={}".format(path,e))
            return ("", {})
        
        content = json.loads(response.content)
        cursor = content.get("cursor", None)
        revisions = {}
        for resource in content.get("results", []):
            identifier = AgentIdentifier.extract(resource["id"])
            if identifier:
                tags = self._get_tags(resource)

                agent_id = tags.get(nsxv3_constants.NSXV3_AGENT_SCOPE, None)
                revision = tags.get(nsxv3_constants.NSXV3_REVISION_SCOPE, None)

                if agent_id != cfg.CONF.AGENT.agent_id or revision == None:
                    # Process only Agent objects
                    # An agent object always has agent_id and revision_number
                    continue

                revisions[identifier] = revision
        return (cursor, revisions)


    # Return dict(resource_id, revision)
    def get_revisions(self, resource_container, resource_id=None):
        if resource_id:
            identifier = AgentIdentifier.build(resource_id)
            resource_container = resource_container.format(identifier)
        cursor = ""
        result = {}
        while True:
            cursor, revisions = self._get_revisions(resource_container, cursor)
            result.update(revisions)
            if not cursor:
                break
        return result

    def get_revision(self, resource_container, resource_id):
        identifier = AgentIdentifier.build(resource_id)

        path = "{}{}/{}".format(INFRA, resource_container, identifier)
        response = self._client.get(path=path)

        if 200 <= response.status_code < 300:
            resource = json.loads(response.content)
            tags = self._get_tags(resource)
            return tags.get(nsxv3_constants.NSXV3_REVISION_SCOPE, "0")
        else:
            return 0
    
    def update_policy(self, identifier,
                              revision_rule=None, revision_member=None,
                              tcp_strict=None, cidrs=[],
                              add_rules=[], del_rules=[],
                              delete=False):

        builder = self.get_builder()

        if revision_rule is not None:
            policy = Policy()
            policy.identifier = identifier
            policy.revision = revision_rule
            policy.tcp_strict = tcp_strict
            policy.rules_to_add = add_rules
            policy.rules_to_remove = del_rules
            builder.with_policy(policy)
        
        if revision_member is not None:
            group = Group()
            group.identifier = identifier
            group.revision = revision_member
            group.dynamic_members = True
            builder.with_group(group)

        builder.build()
    
    def get_builder(self):
        return InfraBuilder(self._client)

class ResourceContainers:
    TransportZone = "/sites/default/enforcement-points/default/transport-zones"
    SecurityPolicy = "/domains/default/security-policies"
    SecurityPolicyRule = "/domains/default/security-policies/{}/rules"
    SecurityPolicyRuleService = "/services"
    SecurityPolicyGroup = "/domains/default/groups"
    Segment = "/segments"
    SegmentPort = "segments/{}/ports"
    SegmentPolicyIpDiscovery = ""
    SegmentPolicySpoofGuard =""
    SegmentPolicyQoS =""


class Revisionable:
    identifier = None
    revision = None

class Service(Revisionable):
    port_range_min = None
    port_range_max = None
    protocol = None
    ethertype = None

class Rule(Revisionable):
    ethertype = None
    direction = None
    remote_group_id = None
    remote_ip_prefix = None
    security_group_id = None
    service = None

class Policy(Revisionable):
    rules_to_add = []
    rules_to_remove = []
    tcp_strict = None

class Group(Revisionable):
    dynamic_members = True
    cidrs = []

class Segment(Revisionable):
    vlan = None
