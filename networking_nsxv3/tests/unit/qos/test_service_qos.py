import neutron
from neutron.tests import base
import neutron_lib
from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.tests.unit.call_tracker import CallTracker
from networking_nsxv3.services.qos.drivers.nsxv3.qos import NSXv3QosDriver

LOG = logging.getLogger(__name__)


class QosRpcMock(object):
    """Mocking QOS RPC"""

    def __init__(self, call_tracker):
        self.call_tracker = call_tracker

    def create_policy(self, context, policy):
        self.call_tracker.add_step('qos_create_policy', context)
        self.call_tracker.add_step('qos_create_policy', policy)
        self.call_tracker.add_step('qos_create_policy', 'pass')

    def update_policy(self, context, policy):
        self.call_tracker.add_step('qos_update_policy', context)
        self.call_tracker.add_step('qos_update_policy', policy)
        self.call_tracker.add_step('qos_update_policy', 'pass')

    def delete_policy(self, context, policy):
        self.call_tracker.add_step('qos_delete_policy', context)
        self.call_tracker.add_step('qos_delete_policy', policy)
        self.call_tracker.add_step('qos_delete_policy', 'pass')

    def update_policy_precommit(self, context, policy):
        self.call_tracker.add_step('qos_update_policy_precommit', context)
        self.call_tracker.add_step('qos_update_policy_precommit', policy)
        self.call_tracker.add_step('qos_update_policy_precommit', 'pass')


class TestNSXv3QosDriver(base.BaseTestCase):

    def setUp(self):
        super(TestNSXv3QosDriver, self).setUp()
        logging.setup(cfg.CONF, "demo")

        self.call_tracker = CallTracker()
        self.call_tracker.init_track('qos_create_policy')
        self.call_tracker.init_track('qos_update_policy')
        self.call_tracker.init_track('qos_delete_policy')
        self.call_tracker.init_track('qos_update_policy_precommit')

        self.qos_driver = NSXv3QosDriver.create(QosRpcMock(self.call_tracker))

    def test_is_vif_type_compatible(self):
        self.assertEquals(
            self.qos_driver.is_vif_type_compatible('vif_type'), True)

    def test_is_vnic_compatible(self):
        self.assertEquals(
            self.qos_driver.is_vnic_compatible('vnic_type'), True)

    def test_qos_create_policy(self):
        context = 'qos_create_policy:context'
        policy = 'qos_create_policy:policy'
        self.qos_driver.create_policy(context=context, policy=policy)
        self.assertEquals(self.call_tracker.compare_steps(
            'qos_create_policy', [context, policy, 'pass']), True)

    def test_qos_update_policy(self):
        context = 'qos_update_policy:context'
        policy = 'qos_update_policy:policy'
        self.qos_driver.update_policy(context=context, policy=policy)
        self.assertEquals(self.call_tracker.compare_steps(
            'qos_update_policy', [context, policy, 'pass']), True)

    def test_qos_delete_policy(self):
        context = 'qos_delete_policy:context'
        policy = 'qos_delete_policy:policy'
        self.qos_driver.delete_policy(context=context, policy=policy)
        self.assertEquals(self.call_tracker.compare_steps(
            'qos_delete_policy', [context, policy, 'pass']), True)

    def test_update_policy_precommit(self):
        context = 'qos_update_policy_precommit:context'
        policy = 'qos_update_policy_precommit:policy'
        self.qos_driver.update_policy_precommit(context=context, policy=policy)
        self.assertEquals(self.call_tracker.compare_steps(
            'qos_update_policy_precommit', [context, policy, 'pass']), True)
