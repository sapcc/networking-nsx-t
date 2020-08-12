from datetime import datetime
import oslo_messaging
from oslo_log import log
from neutron.common import rpc
from neutron.common import topics

from osprofiler.profiler import trace_cls

from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.db import db

from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers


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
        # True - broadcast to all agents
        # False - send only to the host
        fanout = True if host is None else False

        topic = topics.get_topic_name(
            topics.AGENT, nsxv3_constants.NSXV3, topics.UPDATE, host
        )

        return self.rpc.prepare(
            version=self.version,
            topic=topic,
            fanout=fanout
        )

    def get_network_bridge(
            self,
            current,
            network_segments,
            network_current,
            host):
        LOG.debug(
            "Bind port on Host {} & Segment {}".format(
                host, network_segments))
        return self._get_call_context(host).call(
            self.context,
            'get_network_bridge',
            current=current,
            network_segments=network_segments,
            network_current=network_current
        )

    def create_policy(self, context, policy):
        LOG.debug("All gents. Creating policy={}.".format(policy.name))
        return self._get_call_context().cast(
            self.context,
            'create_policy',
            policy=policy
        )

    def update_policy(self, context, policy):
        LOG.debug("All gents. Updating policy={}.".format(policy.name))
        if (hasattr(policy, "rules")):
            return self._get_call_context().cast(
                self.context,
                'update_policy',
                policy=policy
            )

    def delete_policy(self, context, policy):
        LOG.debug("All gents. Deleting policy={}.".format(policy.name))
        return self._get_call_context().cast(
            self.context,
            'delete_policy',
            policy=policy
        )

    def update_policy_precommit(self, context, policy):
        LOG.debug("All gents. Validating policy={}.".format(policy))
        if (hasattr(policy, "rules")):
            return self._get_call_context().cast(
                self.context,
                'validate_policy',
                policy=policy
            )

    def create_log(self, context, log_obj):
        self._get_call_context()\
            .cast(self.context, 'create_log', log_obj=log_obj)

    def create_log_precommit(self, context, log_obj):
        self._get_call_context()\
            .cast(self.context, 'create_log_precommit', log_obj=log_obj)

    def update_log(self, context, log_obj):
        self._get_call_context()\
            .cast(self.context, 'update_log', log_obj=log_obj)

    def update_log_precommit(self, context, log_obj):
        self._get_call_context()\
            .cast(self.context, 'update_log_precommit', log_obj=log_obj)

    def delete_log(self, context, log_obj):
        self._get_call_context()\
            .cast(self.context, 'delete_log', log_obj=log_obj)

    def delete_log_precommit(self, context, log_obj):
        self._get_call_context()\
            .cast(self.context, 'delete_log_precommit', log_obj=log_obj)

    def resource_update(self, context, log_objs):
        self._get_call_context()\
            .cast(self.context, 'resource_update', log_objs=log_objs)


class NSXv3ServerRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.
    This class implements the client side of an rpc interface.  The server
    side can be found below: NSXv3ServerRpcCallback.  For more information on
    changing rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """

    rpc_version = nsxv3_constants.NSXV3_SERVER_RPC_VERSION

    _LIMIT = 100
    _CREATE_AFTER = datetime.utcfromtimestamp(0).isoformat()

    def __init__(self, context, topic, host):
        target = oslo_messaging.Target(topic=topic, version=self.rpc_version)
        self.client = rpc.get_client(target)
        self.context = context
        self.host = host
        self.topic = topic

    @log_helpers.log_method_call
    def get_port_revision_tuples(
            self, limit=_LIMIT, created_after=_CREATE_AFTER):
        cctxt = self.client.prepare()
        return cctxt.call(
            self.context,
            'get_port_revision_tuples',
            host=self.host,
            limit=limit,
            created_after=created_after)

    @log_helpers.log_method_call
    def get_qos_policy_revision_tuples(
            self, limit=_LIMIT, created_after=_CREATE_AFTER):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_qos_policy_revision_tuples',
                          limit=limit, created_after=created_after)

    @log_helpers.log_method_call
    def get_security_group_revision(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_security_group_revision',
                          security_group_id=security_group_id)

    @log_helpers.log_method_call
    def get_security_group_revision_tuples(
            self, limit=_LIMIT, created_after=_CREATE_AFTER):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_security_group_revision_tuples',
                          limit=limit, created_after=created_after)

    @log_helpers.log_method_call
    def has_security_group_tag(
            self, security_group_id, tag_name):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'has_security_group_tag',
                          security_group_id=security_group_id,
                          tag_name=tag_name)

    @log_helpers.log_method_call
    def get_qos(self, qos_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_qos', qos_id=qos_id)

    @log_helpers.log_method_call
    def get_qos_bwl_rules(self, qos_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_qos_bwl_rules', qos_id=qos_id)

    def get_qos_dscp_rules(self, qos_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_qos_dscp_rules', qos_id=qos_id)

    @log_helpers.log_method_call
    def get_port(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_port', port_id=port_id)

    @log_helpers.log_method_call
    def get_port_security_groups(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_port_security_groups',
                          port_id=port_id)

    @log_helpers.log_method_call
    def get_port_allowed_pairs(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_port_allowed_pairs',
                          port_id=port_id)

    @log_helpers.log_method_call
    def get_port_addresses(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_port_addresses', port_id=port_id)

    @log_helpers.log_method_call
    def get_rules_for_security_groups_id(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_rules_for_security_groups_id',
                          security_group_id=security_group_id)

    @log_helpers.log_method_call
    def get_security_group_members_ips(self, security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_security_group_members_ips',
                          security_group_id=security_group_id)

    @log_helpers.log_method_call
    def get_security_group_members_address_bindings_ips(self,
                                                        security_group_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context,
                          'get_security_group_members_address_bindings_ips',
                          security_group_id=security_group_id)

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
    def get_port_revision_tuples(self, context, host, limit, created_after):
        return db.get_port_revision_tuples(context, host, limit, created_after)

    @log_helpers.log_method_call
    def get_qos_policy_revision_tuples(self, context, limit, created_after):
        return db.get_qos_policy_revision_tuples(context, limit, created_after)

    @log_helpers.log_method_call
    def get_security_group_revision(self, context, security_group_id):
        return db.get_security_group_revision(context, security_group_id)

    @log_helpers.log_method_call
    def get_security_group_revision_tuples(
            self, context, limit, created_after):
        return db.get_security_group_revision_tuples(
            context, limit, created_after)

    def has_security_group_tag(
            self, context, security_group_id, tag_name):
        return db.has_security_group_tag(
            context, security_group_id, tag_name)

    @log_helpers.log_method_call
    def get_qos(self, context, qos_id):
        return db.get_qos(context, qos_id)

    @log_helpers.log_method_call
    def get_qos_bwl_rules(self, context, qos_id):
        return db.get_qos_bwl_rules(context, qos_id)

    @log_helpers.log_method_call
    def get_qos_dscp_rules(self, context, qos_id):
        return db.get_qos_dscp_rules(context, qos_id)

    @log_helpers.log_method_call
    def get_port(self, context, port_id):
        return db.get_port(context, port_id)

    @log_helpers.log_method_call
    def get_port_security_groups(self, context, port_id):
        return db.get_port_security_groups(context, port_id)

    @log_helpers.log_method_call
    def get_port_allowed_pairs(self, context, port_id):
        return db.get_port_allowed_pairs(context, port_id)

    @log_helpers.log_method_call
    def get_port_addresses(self, context, port_id):
        return db.get_port_addresses(context, port_id)

    @log_helpers.log_method_call
    def get_rules_for_security_groups_id(self, context, security_group_id):
        return db.get_rules_for_security_groups_id(context, security_group_id)

    @log_helpers.log_method_call
    def get_security_group_members_ips(self, context, security_group_id):
        return db.get_security_group_members_ips(context, security_group_id)

    @log_helpers.log_method_call
    def get_security_group_members_address_bindings_ips(self, context,
                                                        security_group_id):
        return db.get_security_group_members_address_bindings_ips(
            context, security_group_id)\

    @log_helpers.log_method_call
    def get_port_logging(self, context, port_id):
        return db.get_port_logging(context, port_id)

    @log_helpers.log_method_call
    def has_security_group_logging(self, context, security_group_id):
        return db.has_security_group_logging(context, security_group_id)
