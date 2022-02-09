import copy
import json
import re
import uuid

import responses
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import mp_to_policy_migration
from networking_nsxv3.tests.unit.provider import Inventory
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


# INFO - Can introduce responses to directly run the tests against live NSX-T
# responses.add_passthru(re.compile('https://nsxm-l-01a.corp.local/\\w+'))


def get_url(path):
    return "https://nsx-l-01a.corp.local{}".format(path)


class TestProviderMpToPolicy(base.BaseTestCase):

    def setUp(self):
        super(TestProviderMpToPolicy, self).setUp()

        cfg.CONF.set_override("force_mp_to_policy", True, "AGENT")
        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])

        self.inventory = Inventory("https://nsxm-l-01a.corp.local:443", version="3.1.3.6")
        r = responses

        for m in [r.GET, r.POST, r.PUT, r.DELETE, r.PATCH]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    @responses.activate
    def test_ensure_switching_profiles(self):
        # TODO
        mp_to_policy_migration.Provider()

    @responses.activate
    def test_port_migration(self):
        # TODO
        mp_to_policy_migration.Provider()._migrate_port("1")
