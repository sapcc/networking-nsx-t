from unittest import mock

from neutron.tests import base
from oslo_config import cfg

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import agent
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import realization
from networking_nsxv3.tests.unit import provider


class TestDisableSecurityGroupUpdates(base.BaseTestCase):
    """Test cases for security_group_sync_mode configuration option."""

    def setUp(self):
        super(TestDisableSecurityGroupUpdates, self).setUp()
        cfg.CONF.set_override('security_group_sync_mode', 'active', group='AGENT')
        cfg.CONF.set_override('security_group_wait_timeout', 30, group='AGENT')
        
        self.context = mock.Mock()
        self.mock_agent = mock.Mock()
        self.mock_sg_agent = mock.Mock()
        self.mock_realizer = mock.Mock(spec=realization.AgentRealizer)
        self.mock_callback = mock.Mock()

        self.rpc_callback = agent.NSXv3AgentManagerRpcCallBackBase(
            self.context,
            self.mock_agent,
            self.mock_sg_agent,
            self.mock_callback,
            self.mock_realizer
        )

    def tearDown(self):
        super(TestDisableSecurityGroupUpdates, self).tearDown()
        cfg.CONF.clear_override('security_group_sync_mode', group='AGENT')
        cfg.CONF.clear_override('security_group_wait_timeout', group='AGENT')

    def test_security_groups_member_updated_enabled(self):
        """Test that security group member updates are processed in active mode."""
        cfg.CONF.set_override('security_group_sync_mode', 'active', group='AGENT')
        
        security_groups = ['sg-1', 'sg-2']
        self.rpc_callback.security_groups_member_updated(
            self.context,
            security_groups=security_groups
        )
        
        self.mock_callback.assert_called_once_with(
            security_groups,
            self.mock_realizer.security_group_members
        )

    def test_security_groups_member_updated_disabled(self):
        """Test that security group member updates are skipped in passive mode."""
        cfg.CONF.set_override('security_group_sync_mode', 'passive', group='AGENT')
        
        security_groups = ['sg-1', 'sg-2']
        self.rpc_callback.security_groups_member_updated(
            self.context,
            security_groups=security_groups
        )
        
        self.mock_callback.assert_not_called()

    def test_security_groups_rule_updated_enabled(self):
        """Test that security group rule updates are processed in active mode."""
        cfg.CONF.set_override('security_group_sync_mode', 'active', group='AGENT')
        
        security_groups = ['sg-1', 'sg-2']
        self.rpc_callback.security_groups_rule_updated(
            self.context,
            security_groups=security_groups
        )
        
        self.mock_callback.assert_called_once_with(
            security_groups,
            self.mock_realizer.security_group_rules
        )

    def test_security_groups_rule_updated_disabled(self):
        """Test that security group rule updates are skipped in passive mode."""
        cfg.CONF.set_override('security_group_sync_mode', 'passive', group='AGENT')
        
        security_groups = ['sg-1', 'sg-2']
        self.rpc_callback.security_groups_rule_updated(
            self.context,
            security_groups=security_groups
        )
        
        self.mock_callback.assert_not_called()

