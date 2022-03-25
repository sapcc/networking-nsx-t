import oslo_messaging
from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.db import db
from neutron_lib import context as neutron_context
from neutron_lib import exceptions, rpc
from neutron_lib.agent import topics
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log
from osprofiler.profiler import trace_cls

LOG = log.getLogger(__name__)


@trace_cls("rpc")
class NSXv3AgentRpcClient(object):
    """Neutron RPC Client for NSXv3 L2 agent"""

    version = nsxv3_constants.RPC_VERSION

    def __init__(self, context):
        target = oslo_messaging.Target(
            topic=nsxv3_constants.NSXV3,
            version=self.version
        )

        self.context = context
        self.rpc = rpc.get_client(target)

    def _get_call_context(self, host=None):
        topic = topics.get_topic_name(
            topics.AGENT, nsxv3_constants.NSXV3, topics.UPDATE, host)

        # fanout=True - broadcast to all agents, False only to the host
        return self.rpc.prepare(
            version=self.version,
            topic=topic,
            fanout=(host is None))

    def get_network_bridge(self, current, network_segments, network_current, host):
        LOG.debug("Bind port on Host {} & Segment {}".format(host, network_segments))
        return self._get_call_context(host).call(
            self.context, 'get_network_bridge',
            current=current,
            network_segments=network_segments,
            network_current=network_current
        )

    def create_policy(self, context, policy):
        LOG.debug("All gents. Creating policy={}.".format(policy.name))
        return self._get_call_context().cast(
            self.context, 'create_policy', policy=policy)

    def update_policy(self, context, policy):
        LOG.debug("All gents. Updating policy={}.".format(policy.name))
        if (hasattr(policy, "rules")):
            return self._get_call_context().cast(
                self.context, 'update_policy',policy=policy)

    def delete_policy(self, context, policy):
        LOG.debug("All gents. Deleting policy={}.".format(policy.name))
        return self._get_call_context().cast(
            self.context, 'delete_policy', policy=policy)

    def update_policy_precommit(self, context, policy):
        LOG.debug("All gents. Validating policy={}.".format(policy))
        if (hasattr(policy, "rules")):
            return self._get_call_context().cast(
                self.context, 'validate_policy', policy=policy)

    def create_log(self, context, log_obj):
        LOG.debug("NSXv3AgentRpcClient: (create_log): " + str(log_obj))
        self._get_call_context()\
            .cast(self.context, 'create_log', log_obj=log_obj)

    def create_log_precommit(self, context, log_obj):
        LOG.debug("NSXv3AgentRpcClient: (create_log_precommit): " + str(log_obj))
        self._get_call_context()\
            .cast(self.context, 'create_log_precommit', log_obj=log_obj)

    def update_log(self, context, log_obj):
        LOG.debug("NSXv3AgentRpcClient: (update_log): " + str(log_obj))
        self._get_call_context()\
            .cast(self.context, 'update_log', log_obj=log_obj)

    def update_log_precommit(self, context, log_obj):
        LOG.debug("NSXv3AgentRpcClient: (update_log_precommit): " + str(log_obj))
        self._get_call_context()\
            .cast(self.context, 'update_log_precommit', log_obj=log_obj)

    def delete_log(self, context, log_obj):
        LOG.debug("NSXv3AgentRpcClient: (delete_log): " + str(log_obj))
        self._get_call_context()\
            .cast(self.context, 'delete_log', log_obj=log_obj)

    def delete_log_precommit(self, context, log_obj):
        LOG.debug("NSXv3AgentRpcClient: (delete_log_precommit): " + str(log_obj))
        self._get_call_context()\
            .cast(self.context, 'delete_log_precommit', log_obj=log_obj)

    def resource_update(self, context, log_objs):
        LOG.debug("NSXv3AgentRpcClient: (resource_update): " + str(log_objs))
        self._get_call_context()\
            .cast(self.context, 'resource_update', log_objs=log_objs)


class NSXv3ServerRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.
    This class implements the client side of an rpc interface.  The server
    side can be found below: NSXv3ServerRpcCallback.  For more information on
    changing rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """

    rpc_version = nsxv3_constants.NSXV3_SERVER_RPC_VERSION

    def __init__(self):
        target = oslo_messaging.Target(topic=nsxv3_constants.NSXV3_SERVER_RPC_TOPIC, 
                                       version=self.rpc_version)
        self.context = neutron_context.get_admin_context()
        self.client = rpc.get_client(target)
        self.host = cfg.CONF.host        

    @log_helpers.log_method_call
    def get_ports_with_revisions(self, limit, cursor):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_ports_with_revisions',
                          host=self.host, limit=limit, cursor=cursor)

    @log_helpers.log_method_call
    def get_qos_policies_with_revisions(self, limit, cursor):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_qos_policies_with_revisions',
                          host=self.host, limit=limit, cursor=cursor)

    @log_helpers.log_method_call
    def get_security_groups_with_revisions(self, limit, cursor):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_security_groups_with_revisions',
                          host=self.host, limit=limit, cursor=cursor)

    @log_helpers.log_method_call
    def get_security_group(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_security_group',
                          host=self.host, security_group_id=security_group_id)

    @log_helpers.log_method_call
    def get_qos(self, qos_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_qos', host=self.host, qos_id=qos_id)

    @log_helpers.log_method_call
    def get_port(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_port', host=self.host, port_id=port_id)

    @log_helpers.log_method_call
    def get_rules_for_security_group_id(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_rules_for_security_group_id',
                          security_group_id=security_group_id)

    @log_helpers.log_method_call
    def get_security_group_members_effective_ips(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 
                          'get_security_group_members_effective_ips',
                          security_group_id=security_group_id)

    @log_helpers.log_method_call
    def get_security_groups_for_host(self, limit, cursor):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_security_groups_for_host',
                          host=self.host, limit=limit, cursor=cursor)

    @log_helpers.log_method_call
    def get_remote_security_groups_for_host(self, limit, cursor):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_remote_security_groups_for_host',
                          host=self.host, limit=limit, cursor=cursor)

    @log_helpers.log_method_call
    def has_security_group_used_by_host(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'has_security_group_used_by_host',
                          host=self.host, security_group_id=security_group_id)

    @log_helpers.log_method_call
    def get_port_logging(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_port_logging', port_id=port_id)

    @log_helpers.log_method_call
    def has_security_group_logging(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'has_security_group_logging',
                          security_group_id=security_group_id)


class NSXv3ServerRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction.
    This class implements the server side of an rpc interface.  The client
    side can be found above: NSXv3ServerRpcApi.  For more information on
    changing rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """

    rpc_version = nsxv3_constants.NSXV3_SERVER_RPC_VERSION
    target = oslo_messaging.Target(version=rpc_version)

    @property
    def plugin(self):
        if not getattr(self, '_plugin', None):
            self._plugin = directory.get_plugin()
        return self._plugin

    @log_helpers.log_method_call
    def get_ports_with_revisions(self, context, host, limit, cursor):
        return db.get_ports_with_revisions(context, host, limit, cursor)

    @log_helpers.log_method_call
    def get_qos_policies_with_revisions(self, context, host, limit, cursor):
        return db.get_qos_policies_with_revisions(context, host, limit, cursor)
    
    @log_helpers.log_method_call
    def get_security_groups_with_revisions(self, context, host, limit, cursor):
        return db.get_security_groups_with_revisions(context, host, limit, cursor)

    @log_helpers.log_method_call
    def get_security_group(self, context, host, security_group_id):
        id_rev = db.get_security_group_revision(context, security_group_id)
        if id_rev:
            return {
                "id": id_rev[0],
                "revision_number": id_rev[1],
                "stateful": id_rev[2],
                "tags": db.get_security_group_tag(context, security_group_id),
                "ports": db.get_port_id_by_sec_group_id(context, host, 
                                                        security_group_id)
            }

    @log_helpers.log_method_call
    def get_rules_for_security_group_id(self, context, security_group_id):
        return db.get_rules_for_security_group_id(context, security_group_id)

    @log_helpers.log_method_call
    def get_security_group_members_effective_ips(self, context, security_group_id):
        a = db.get_security_group_members_ips(context, security_group_id)
        b = db.get_security_group_members_address_bindings_ips(context, security_group_id)
        return [ips[0] for ips in a + b]
            
    @log_helpers.log_method_call
    def get_security_groups_for_host(self, context, host, limit, cursor):
        return db.get_security_groups_for_host(context, host, limit, cursor)

    @log_helpers.log_method_call
    def get_remote_security_groups_for_host(self, context, host, limit, cursor):
        return db.get_remote_security_groups_for_host(context, host, limit, cursor)
    
    @log_helpers.log_method_call
    def has_security_group_used_by_host(self, context, host, security_group_id):
        return db.has_security_group_used_by_host(context, host, security_group_id)

    @log_helpers.log_method_call
    def get_port(self, context, host, port_id):
        port = db.get_port(context, host, port_id)

        if not port:
            return None
        # NSX-T does not support CIDR as port manual binding - skipping X/X

        for ip in db.get_port_addresses(context, port_id):
            if "/" in ip:
                continue
            port["address_bindings"].append({"ip_address": ip[0],  "mac_address": port["mac_address"]})

        for ip, mac in db.get_port_allowed_pairs(context, port_id):
            if "/" in ip:
                continue
            port["address_bindings"].append({"ip_address": ip, "mac_address": mac})

        for sg_id in db.get_port_security_groups(context, port_id):
            port["security_groups"].append(sg_id[0])
        
        return port

    @log_helpers.log_method_call
    @oslo_messaging.expected_exceptions(exceptions.ObjectNotFound)
    def get_qos(self, context, host, qos_id):
        if not db.get_qos_ports_by_host(context, host, qos_id):
            return

        q = db.get_qos(context, qos_id)
        qos = {"id": qos_id, "name": q[0], "revision_number": q[1], "rules": []}

        for _, dscp_mark in db.get_qos_dscp_rules(context, qos_id):
            qos["rules"].append({"dscp_mark": dscp_mark})

        for dir, bps, burst in db.get_qos_bwl_rules(context, qos_id):
            qos["rules"].append({"direction": dir,"max_kbps": bps, "max_burst_kbps": burst})
        return qos

    @log_helpers.log_method_call
    def get_port_logging(self, context, port_id):
        return db.get_port_logging(context, port_id)

    @log_helpers.log_method_call
    def has_security_group_logging(self, context, security_group_id):
        return db.has_security_group_logging(context, security_group_id)
