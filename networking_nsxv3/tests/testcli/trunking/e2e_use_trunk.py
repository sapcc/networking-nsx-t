import openstack
import copy
import logging

from networking_nsxv3.tests.testcli.exceptions import ServerNotActive, TrunkNotActive
from networking_nsxv3.tests.testcli.test import e2eTest, e2eTestValidator
from networking_nsxv3.tests.testcli.utility.compute import delete_servers, create_servers, wait_for_server, change_port
from networking_nsxv3.tests.testcli.utility.networking import create_trunk, delete_trunk, prepare_networks, attatch_subport_to_trunk, prepare_network

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

class e2eTrunkTestValidator(e2eTestValidator):
    def __init__(self):
        super().__init__()

    def validate(self, con, server_objects, trunk):
        self._validate_nsxt_ports(con, server_objects)
        self._validate_port(con, server_objects)
        self._validate_trunk(con, trunk)

class e2eTrunkTest(e2eTest):

    def __init__(self, validator=e2eTrunkTestValidator()):
        super().__init__()
        self.validator = validator


    def _prepare_test(self, **kwargs):
        LOG.info("Start test preperation - deleting servers, create network, create trunk")
        config = copy.deepcopy(kwargs)

        servers = [config.get("RED"),config.get("BLUE")]
        trunk = config.get("TRUNK")
        #override in order not to attach child port to trunk
        trunk["SEGMENTATION_ID"] = None
        trunk["CHILD_PORT"] = None

        # test preperation
        delete_servers(con=self.con, servers=servers)
        delete_trunk(self.con, trunk)
        prepare_networks(self.con, networks=servers)
        create_trunk(self.con, trunk_config=trunk)
        LOG.info("Finished preperation - deleting servers, create network, create trunk")


    def attatch_subport_before_server_boot(self, **kwargs):
        '''
        Run trunk test
        Preperation - Create network, create, trunk (with subport)
        Test - Boot Server, afterwards attatch subport to trunk
        Validate - Server up, Port up, Logical Port existing, Trunk up
        :param kwargs:
        :return:
        '''
        trunk = kwargs.get("TRUNK")
        objects = [self._prepare_server_conf("RED", kwargs)]
        self._prepare_test(**kwargs)
        attatch_subport_to_trunk(self.con,trunk)

        servers = create_servers(con=self.con,server_config=objects)
        wait_for_server(con=self.con, servers=servers)

        self.validator.validate(self.con, server_objects=objects, trunk=trunk)

    def attach_subport_after_server_boot(self, **kwargs):
        '''
        Run trunk test
        Preperation - Create network, create, trunk (without subport)
        Test - Boot Server, afterwards attatch subport to trunk
        Validate - Server up, Port up, Logical Port existing, Trunk up
        :param kwargs:
        :return:
        '''
        trunk = kwargs.get("TRUNK")
        objects = [self._prepare_server_conf("RED", kwargs)]
        self._prepare_test(**kwargs)

        servers = create_servers(con=self.con, server_config=objects)
        wait_for_server(con=self.con, servers=servers)

        attatch_subport_to_trunk(self.con, trunk)

        self.validator.validate(self.con, server_objects=objects, trunk=trunk)

    def _all(self, **kwargs):
        LOG.info("RUN all trunk e2e test")

        try:
            LOG.info("Run TEST attach_subport_after_server_boot")
            self.attach_subport_after_server_boot(**kwargs)

            LOG.info("Run test attatch_subport_before_server_boot")
            self.attatch_subport_before_server_boot(**kwargs)

        except Exception as e:
            LOG.error(f"TEST EXECUTION FAILED {e}")


    def run_test(self,test_config, nsxt_config, test_method=None):
        self.con = self._connect_to_openstack()

        if test_method:
            if hasattr(self, test_method):
                getattr(self, test_method)(**test_config)
        else:
            self._all(**test_config)





