import argparse
import logging
import os
import sys


import eventlet
eventlet.monkey_patch()

from oslo_config import cfg
from networking_nsxv3.common import config
from networking_nsxv3.tests.testcli.utility import password
from networking_nsxv3.tests.testcli.trunking.e2e_use_trunk import e2eTrunkTest
from networking_nsxv3.tests.testcli.utility import configloader as conf

LOG = logging.getLogger(__name__)


class CLI():
    '''
    CLI to trigger some local blackbox tests for the NSXT driver against the openstack API.
    Main idea is to create servers, connect them to a network and check if the nsxt driver is creating the ports, security groups as expected.

    :argument
    trunk
    --test-config <path_to_test_config.yaml>
    --nsxt-config <path to nsx config> - optional parameter

    openstack connection - load from env vars (OS_AUTH_URL, OS_PASSWORD ...)
    cli tries to automatically load the password from keychain
    '''
    def __init__(self):
        self.run()

    def _load_config(self):
        parser = argparse.ArgumentParser(description="Load config required for running the test")
        parser.add_argument(
            "--nsxt-config",
            help="OpenStack Neutron configuration file(s) location(s)")
        parser.add_argument(
            "-t", "--test-config", required=True,
            help="OpenStack object type target of synchronization")
        parser.add_argument(
            "--test-method",
            required=False,
            default=None,
            help="Run specific test case")

        args = parser.parse_args(sys.argv[2:])

        cfg.CONF(["--config-file", args.nsxt_config])
        test_conf = conf.e2eConfig(path=args.test_config).raw_data
        return args.nsxt_config, test_conf, args.test_method


    def trunk(self):
        LOG.info("Start Trunk Test")
        password.set_as_openstack_env()
        nsxt_config, test_config, test_method = self._load_config()
        e2e_test = e2eTrunkTest()
        e2e_test.run_test(test_config=test_config, nsxt_config=nsxt_config, test_method=None)
        LOG.info("Finished Trunk Test")

    def run(self):
        parser = argparse.ArgumentParser(
            description="Neutron ML2 NSX-T Agent testcli test command line interface",
            usage='''neutron-nsxv3-agent-cli-sync COMMAND
                              trunk - Run tests related to trunking
                          ''')
        parser.add_argument('command',
                            help='Subcommand trunk')
        args = parser.parse_args(sys.argv[1:2])

        if hasattr(self, args.command):
            getattr(self, args.command)()
        else:
            LOG.error("Unrecognized command")
            parser.print_help()
            exit(1)

if __name__ == "__main__":
     LOG.info("Start BlackBoxTests")
     CLI()
     LOG.info("Finished BlackBoxTests")

