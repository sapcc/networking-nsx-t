import responses
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.driver import VMwareNSXv3MechanismDriver
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class TestDriver(base.BaseTestCase):
    def setUp(self):
        super(TestDriver, self).setUp()

        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])

        self.driver = VMwareNSXv3MechanismDriver()

    def tearDown(self):
        super(TestDriver, self).tearDown()
        responses.reset()

    def test_init(self):
        self.assertIsNotNone(self.driver)

    def test_connectivity(self):
        self.assertEqual("l2", self.driver.connectivity)

    def test_get_workers(self):
        workers = self.driver.get_workers()
        self.assertEqual(1, len(workers))
        self.assertEqual(0, workers[0].worker_process_count)
