import unittest

import six
import testtools
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from ipaddress import ip_network
from oslo_log import log as logging
from oslo_utils import uuidutils

LOG = logging.getLogger(__name__)


class SecurityGroupTest(testtools.TestCase):

    def setUp(self):
        super(SecurityGroupTest, self).setUp()

    def test_dummy(self):
        LOG.info("Dummy test passed")
        pass

if __name__ == '__main__':
    unittest.main()
