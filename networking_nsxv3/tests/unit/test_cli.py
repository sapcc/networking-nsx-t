import argparse
import re

import responses
from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import cli
from networking_nsxv3.tests.unit.provider import Inventory
from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging
from unittest import mock


LOG = logging.getLogger(__name__)


class TestCLI(base.BaseTestCase):
    def setUp(self):
        super(TestCLI, self).setUp()

        logging.setup(cfg.CONF, "demo")
        logging.set_defaults(default_log_levels=["networking_nsxv3=DEBUG", "root=DEBUG"])

        self.inventory = Inventory("https://nsxm-l-01a.corp.local:443")
        r = responses

        for m in [r.GET, r.POST, r.PUT, r.DELETE]:
            r.add_callback(m, re.compile(r".*"), callback=self.inventory.api)

    def test_cli_initialization(self):
        sys_exit = self.assertRaises(SystemExit, cli.CLI)
        self.assertEqual(1, sys_exit.code)

    @responses.activate
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=argparse.Namespace(command="clean", config_file="neutron.test.cfg"))
    def test_cli_command_clean(self, *mock_args):
        cli.CLI()
        # TODO: assert something

    @responses.activate
    @mock.patch('argparse.ArgumentParser.parse_args',
                return_value=argparse.Namespace(command="export", config_file="neutron.test.cfg"))
    @mock.patch('networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.cli.NeutronInventory.export', return_value={})
    def test_cli_command_export(self, *mock_args):
        cli.CLI()
        # TODO: assert something
