import time

import eventlet

eventlet.monkey_patch()

from networking_nsxv3.tests.integration.utility import configloader as testconfigloader
from networking_nsxv3.tests.integration.utility.test import e2eTest, e2eTestValidator
from networking_nsxv3.tests.integration.utility.compute import delete_servers, create_servers, wait_for_server, \
    wait_for_server_deletion
from networking_nsxv3.tests.integration.utility.networking import create_trunk, delete_trunk, prepare_networks, \
    attatch_subport_to_trunk, dettatch_subport_from_trunk, find_ports_by_server_name

from oslo_log import log as logging
from test_nsxv3_api import TestNSXTApi

LOG = logging.getLogger(__name__)

'''
    Run pytest for testing openstack trunking feature
    
    In order to execute the test access to NSXT installation and access to openstack api is required.  
    Set the following Env variables to run the test
    NSXV3
        - NSXV3_LOGIN_HOSTNAME
        - NSXV3_LOGIN_PASSWORD
        - NSXV3_LOGIN_PORT
        - NSXV3_LOGIN_USER
        - NSXV3_TRANSPORT_ZONE_NAME
    
    Openstack Env Variables
     - OS_AUTH_URL
     - OS_IDENTITY_API_VERSION
     - OS_PASSWORD
     - OS_PROJECT_DOMAIN_NAME
     - OS_PROJECT_NAME
     - OS_USER_DOMAIN_NAME
     - OS_USERNAME
    
    What the test does: 
    - Setup: Create network, ports, server, trunk
    - Test: Boot server on port (different scenarios)
    - Validate: Check trunk status in openstack db and nsxt logical port status
    
    
'''


class TestOpenstackTrunking(TestNSXTApi, e2eTest):
    test_config = None
    test_config_file = "./conf/e2e_trunk.yaml"
    con = None

    @classmethod
    def setup_class(cls):
        LOG.info(f"Global setup - Read Enviroment Variables, load test config")
        # Load NSXT configuration
        cls.validator = e2eTestValidator()
        cls._load_test_config()

    @classmethod
    def _load_test_config(cls):
        LOG.info(f"Load test config")
        cls.test_config = testconfigloader.e2eConfig(path=cls.test_config_file)

    def setUp(self):
        super(TestOpenstackTrunking, self).setUp()
        self.load_env_variables()
        LOG.info("Start preperation - deleting servers, create network, create trunk")
        self.con = self._connect_to_openstack()

        cfg_server = self.test_config.servers()
        cfg_trunk = self.test_config.trunk()
        LOG.info("cleanup ")
        wait_for_server_deletion(con=self.con, server_config=cfg_server)
        delete_trunk(self.con, cfg_trunk)
        LOG.info("creation ")
        prepare_networks(self.con, networks=cfg_server)
        create_trunk(self.con, trunk_config=cfg_trunk)
        LOG.info("Finished preperation - deleting servers, create network, create trunk")

    @classmethod
    def teardown_class(cls):
        pass

    def tearDown(self):
        super(TestOpenstackTrunking, self).tearDown()
        LOG.info("Start cleanup - deleting servers, create network, create trunk")
        cfg_server = self.test_config.servers()
        cfg_trunk = self.test_config.trunk()

        wait_for_server_deletion(con=self.con, server_config=cfg_server)
        delete_trunk(self.con, cfg_trunk)
        LOG.info("Finished cleanupd - deleting servers, delete trunk")

    def test_attatch_subport_after_server_boot(self):
        '''
                    Run trunk test
                    Preperation - Create network, create, trunk (without subport)
                    Test - Boot Server, afterwards attatch subport to trunk
                    Validate - Server up, Port up, Logical Port existing, Trunk up
                    :param kwargs:
                    :return:
        '''
        cfg_trunk = self.test_config.trunk()
        cfg_server = self.test_config.get_conf_by_key("RED")

        servers = create_servers(con=self.con, server_config=cfg_server)
        wait_for_server(con=self.con, servers=servers)

        attatch_subport_to_trunk(self.con, cfg_trunk)

        time.sleep(10)
        LOG.info(f"validate test results")

        err_status, err_msg = self.validator.validate_success(self.con, server_objects=cfg_server, trunk=cfg_trunk)
        assert err_status, err_msg

    #
    def test_attatch_subport_before_server_boot(self):
        '''
            Run trunk test
            Preperation - Create network, create, trunk (with subport)
            Test - attatch subport to trunk, boot server
            Validate - Server up, Port up, Logical Port existing, Trunk up
            :param kwargs:
            :return:
            '''
        cfg_trunk = self.test_config.trunk()
        cfg_server = self.test_config.get_conf_by_key("RED")

        attatch_subport_to_trunk(self.con, cfg_trunk)

        servers = create_servers(con=self.con, server_config=cfg_server)
        wait_for_server(con=self.con, servers=servers)

        time.sleep(10)
        LOG.info(f"validate test results")
        err_status, err_msg = self.validator.validate_success(self.con, server_objects=cfg_server, trunk=cfg_trunk)
        assert err_status, err_msg

    # Not working - Two hours until ports get cleaned up
    # def test_port_unbinding(self):
    #     '''
    #         Run trunk test
    #         Preperation - Create network, create, trunk (with subport)
    #         Test - attatch subport to trunk, boot server, delete server
    #         Validate - check if ports got deleted
    #         :param kwargs:
    #         :return:
    #         '''
    #     cfg_trunk = self.test_config.trunk()
    #     cfg_server = self.test_config.get_conf_by_key("RED")
    #     attatch_subport_to_trunk(self.con, cfg_trunk)
    #     #
    #     servers = create_servers(con=self.con, server_config=cfg_server)
    #     wait_for_server(con=self.con, servers=servers)
    #
    #     err_msg = self.validator.validate_nsxt_ports_by_server_name(self.con, cfg_server)
    #     time.sleep(5)
    #     if not err_msg:
    #         LOG.error(f'Something went wrong during the bind process')
    #
    #     ports = find_ports_by_server_name(self.con, cfg_server)
    #
    #     wait_for_server_deletion(con=self.con, server_config=cfg_server)
    #     time.sleep(15)
    #     err_msg = self.validator.validate_nsxt_ports_by_port_id(ports, expr="!=")
    #
    #     if not err_msg:
    #         assert False, "Ports still bound although server was deleted"

    def test_dettatch_subport_after_server_boot(self):
        '''
            Run trunk test
            Preperation - Create network, create, trunk (with subport)
            Test - dettach child port from running server
            Validate - Trunk down
            :param kwargs:
            :return:
            '''
        cfg_trunk = self.test_config.trunk()
        cfg_server = self.test_config.get_conf_by_key("RED")
        attatch_subport_to_trunk(self.con, cfg_trunk)

        servers = create_servers(con=self.con, server_config=cfg_server)
        wait_for_server(con=self.con, servers=servers)

        dettatch_subport_from_trunk(self.con, cfg_trunk)

        assert not self.validator._validate_trunk(self.con, cfg_trunk, status="DOWN")

