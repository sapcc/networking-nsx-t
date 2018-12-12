import oslo_messaging
from oslo_log import log
from neutron.common import rpc
from neutron.common import topics

from osprofiler.profiler import trace_cls

from networking_nsxv3.common import constants as nsxv3_constants

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
