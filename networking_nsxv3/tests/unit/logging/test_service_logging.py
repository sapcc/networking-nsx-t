from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.tests.unit.call_tracker import CallTracker
from networking_nsxv3.services.logapi.drivers.nsxv3.driver import NSXv3LogDriver

LOG = logging.getLogger(__name__)


class LogapiRpcMock(object):
    """Mocking LOGAPI RPC"""

    def __init__(self, call_tracker):
        self.call_tracker = call_tracker

    def create_log(self, context, log_obj):
        self.call_tracker.add_step('logapi_create_log', context)
        self.call_tracker.add_step('logapi_create_log', log_obj)
        self.call_tracker.add_step('logapi_create_log', 'pass')

    def create_log_precommit(self, context, log_obj):
        self.call_tracker.add_step('logapi_create_log_precommit', context)
        self.call_tracker.add_step('logapi_create_log_precommit', log_obj)
        self.call_tracker.add_step('logapi_create_log_precommit', 'pass')

    def update_log(self, context, log_obj):
        self.call_tracker.add_step('logapi_update_log', context)
        self.call_tracker.add_step('logapi_update_log', log_obj)
        self.call_tracker.add_step('logapi_update_log', 'pass')

    def update_log_precommit(self, context, log_obj):
        self.call_tracker.add_step('logapi_update_log_precommit', context)
        self.call_tracker.add_step('logapi_update_log_precommit', log_obj)
        self.call_tracker.add_step('logapi_update_log_precommit', 'pass')

    def delete_log(self, context, log_obj):
        self.call_tracker.add_step('logapi_delete_log', context)
        self.call_tracker.add_step('logapi_delete_log', log_obj)
        self.call_tracker.add_step('logapi_delete_log', 'pass')

    def delete_log_precommit(self, context, log_obj):
        self.call_tracker.add_step('logapi_delete_log_precommit', context)
        self.call_tracker.add_step('logapi_delete_log_precommit', log_obj)
        self.call_tracker.add_step('logapi_delete_log_precommit', 'pass')

    def resource_update(self, context, log_obj):
        self.call_tracker.add_step('logapi_resource_update', context)
        self.call_tracker.add_step('logapi_resource_update', log_obj)
        self.call_tracker.add_step('logapi_resource_update', 'pass')

    def is_vnic_compatible(self, vnic_type):
        self.call_tracker.add_step('logapi_is_vnic_compatible', vnic_type)
        self.call_tracker.add_step('logapi_is_vnic_compatible', 'pass')


class TestNSXv3LogDriver(base.BaseTestCase):

    def setUp(self):
        super(TestNSXv3LogDriver, self).setUp()
        logging.setup(cfg.CONF, "demo")

        self.call_tracker = CallTracker()
        self.call_tracker.init_track('logapi_register_callback_handler')
        self.call_tracker.init_track('logapi_create_log')
        self.call_tracker.init_track('logapi_create_log_precommit')
        self.call_tracker.init_track('logapi_update_log')
        self.call_tracker.init_track('logapi_update_log_precommit')
        self.call_tracker.init_track('logapi_delete_log')
        self.call_tracker.init_track('logapi_delete_log_precommit')
        self.call_tracker.init_track('logapi_resource_update')
        self.call_tracker.init_track('logapi_is_vnic_compatible')

        self.logapi_driver = NSXv3LogDriver.create(LogapiRpcMock(self.call_tracker))

    def test_register_callback_handler(self):
        logging_callback_resource_type = 'logapi_register_callback_handler:logging_callback_resource_type'
        logging_callback = 'logapi_register_callback_handler:logging_callback'
        self.logapi_driver.register_callback_handler(logging_callback_resource_type, logging_callback)
        self.assertEquals(self.call_tracker.compare_steps('logapi_register_callback_handler', []), True)

    def test_create_log(self):
        context = 'logapi_create_log:context'
        log_obj = 'logapi_create_log:log_obj'
        self.logapi_driver.create_log(context, log_obj)
        self.assertEquals(self.call_tracker.compare_steps('logapi_create_log',
                                                          [context, log_obj, 'pass']), True)

    def test_create_log_precommit(self):
        context = 'logapi_create_log_precommit:context'
        log_obj = 'logapi_create_log_precommit:log_obj'
        self.logapi_driver.create_log_precommit(context, log_obj)
        self.assertEquals(self.call_tracker.compare_steps('logapi_create_log_precommit',
                                                          [context, log_obj, 'pass']), True)

    def test_update_log(self):
        context = 'logapi_update_log:context'
        log_obj = 'logapi_update_log:log_obj'
        self.logapi_driver.update_log(context, log_obj)
        self.assertEquals(self.call_tracker.compare_steps('logapi_update_log',
                                                          [context, log_obj, 'pass']), True)

    def test_update_log_precommit(self):
        context = 'logapi_update_log_precommit:context'
        log_obj = 'logapi_update_log_precommit:log_obj'
        self.logapi_driver.update_log_precommit(context, log_obj)
        self.assertEquals(self.call_tracker.compare_steps('logapi_update_log_precommit',
                                                          [context, log_obj, 'pass']), True)

    def test_delete_log(self):
        context = 'logapi_delete_log:context'
        log_obj = 'logapi_delete_log:log_obj'
        self.logapi_driver.delete_log(context, log_obj)
        self.assertEquals(self.call_tracker.compare_steps('logapi_delete_log',
                                                          [context, log_obj, 'pass']), True)

    def test_delete_log_precommit(self):
        context = 'logapi_delete_log_precommit:context'
        log_obj = 'logapi_delete_log_precommit:log_obj'
        self.logapi_driver.delete_log_precommit(context, log_obj)
        self.assertEquals(self.call_tracker.compare_steps('logapi_delete_log_precommit',
                                                          [context, log_obj, 'pass']), True)

    def test_resource_update(self):
        context = 'logapi_resource_update:context'
        log_obj = 'logapi_resource_update:log_obj'
        self.logapi_driver.resource_update(context, log_obj)
        self.assertEquals(self.call_tracker.compare_steps('logapi_resource_update',
                                                          [context, log_obj, 'pass']), True)

    def test_is_vnic_compatible(self):
        vnic_type = 'logapi_is_vnic_compatible:vnic_type'
        self.assertEquals(isinstance(self.logapi_driver.is_vnic_compatible(vnic_type), bool), True)
        self.assertEquals(self.call_tracker.compare_steps('logapi_is_vnic_compatible', []), True)
