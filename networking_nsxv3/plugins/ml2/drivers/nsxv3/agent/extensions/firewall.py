
from neutron.agent import firewall
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NSXv3SecurityGroupsDriver(firewall.FirewallDriver):
    """
    NSXv3SecurityGroupsDriver is a dummy driver.
    It is required to enable security group refresh events.
    Implicitly used by nsxv3_agent.NSXv3Manager
    """

    def __init__(self, **kwargs):
        LOG.debug("Initializing NSXv3SecurityGroupsDriver dummy driver.")

    def prepare_port_filter(self, ports):
        pass

    def apply_port_filter(self, ports):
        pass

    def update_port_filter(self, ports):
        pass

    def remove_port_filter(self, port_ids):
        pass

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass

    @property
    def ports(self):
        return {}

    def update_security_group_members(self, sg_id, ips):
        pass

    def update_security_group_rules(self, sg_id, rules):
        pass

    def security_group_updated(self, action_type, security_group_ids, 
                               device_id=None):
        pass
