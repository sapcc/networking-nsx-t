import unittest

import testtools
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class SecurityGroupTest(testtools.TestCase):

    def setUp(self):
        super(SecurityGroupTest, self).setUp()

    def test_dummy(self):
        LOG.info("Dummy test passed")


if __name__ == '__main__':
    unittest.main()
