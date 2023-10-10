import responses
from networking_nsxv3.common import config
from networking_nsxv3.extensions.nsxtoperations import Nsxtoperations
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class TestNsxOperations(base.BaseTestCase):
    def setUp(self):
        super(TestNsxOperations, self).setUp()

        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])

        self.extension = Nsxtoperations()

    def tearDown(self):
        super(TestNsxOperations, self).tearDown()
        responses.reset()

    def test_init(self):
        self.assertIsNotNone(self.extension)

   # TODO: tests
