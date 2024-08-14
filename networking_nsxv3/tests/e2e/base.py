import eventlet
eventlet.monkey_patch()

from typing import List
from keystoneauth1 import identity
from keystoneauth1 import session
from networking_nsxv3.tests.e2e import neutron
from novaclient.v2.servers import Server
from novaclient.v2.servers import NetworkInterface
from novaclient.v2.client import Client as NovaClient
from novaclient import client as nova
from neutron.tests import base
import os
from oslo_log import log as logging
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx
from oslo_config import cfg
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
import uuid

from networking_nsxv3.common import config  # noqa


LOG = logging.getLogger(__name__)


class RetryDecorator(object):
    @staticmethod
    def RetryIfResultIsNone(max_retries, sleep_duration):
        """ Retry decorator for functions that return None on failure. """
        def decorator(func):
            def wrapper(*args, **kwargs):
                retry_counter = max_retries
                while retry_counter > 0:
                    result = func(*args, **kwargs)
                    if result is not None:
                        return result

                    eventlet.sleep(sleep_duration)
                    LOG.debug(f"{retry_counter}: Retrying function '{func.__name__}'\nargs: {args}\nkwargs: {kwargs}")
                    retry_counter -= 1

                total_time = max_retries * sleep_duration
                LOG.debug(
                    f"No result from func '{func.__name__}' after {max_retries} retries in {total_time} seconds.")
                return None

            return wrapper
        return decorator


class E2ETestCase(base.BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        g = os.environ.get

        logging.setup(cfg.CONF, "demo")

        cfg.CONF.set_override('debug', True)
        cfg.CONF.set_override("lock_path", "/tmp/", "oslo_concurrency")
        cfg.CONF.set_override("nsxv3_login_hostname", g("NSXV3_LOGIN_HOSTNAME"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_port", g("NSXV3_LOGIN_PORT"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_user", g("NSXV3_LOGIN_USER"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_password", g("NSXV3_LOGIN_PASSWORD"), "NSXV3")
        cfg.CONF.set_override("nsxv3_transport_zone_name", g("NSXV3_TRANSPORT_ZONE_NAME"), "NSXV3")
        # cfg.CONF.set_override("nsxv3_default_l3_rule_check", bool(int(g("NSXV3_DEFAULT_L3_RULE_CHECK"))), "NSXV3")
        cfg.CONF.set_override("nsxv3_connection_retry_count", "3", "NSXV3")
        cfg.CONF.set_override("nsxv3_request_timeout", "320", "NSXV3")

        http_p = "https" if bool(int(g("OS_HTTPS"))) else "http"
        os_auth_url = f"{http_p}://{g('OS_HOSTNAME')}/identity"
        cls.auth = identity.Password(auth_url=os_auth_url,
                                     username=g("OS_USERNAME"),
                                     password=g("OS_PASSWORD"),
                                     project_name=g("OS_PROJECT_NAME"),
                                     project_domain_id=g("OS_PROJECT_DOMAIN_ID"),
                                     user_domain_id=g("OS_USER_DOMAIN_ID"))
        cls.sess = session.Session(auth=cls.auth, verify=False)

        cls.nova_client: NovaClient = nova.Client('2.1', session=cls.sess)
        cls.neutron_client = neutron.CustomNeutronClient(session=cls.sess)
        cls.nsx_client = client_nsx.Client()
        cls.nsx_client.version  # This will force the client to login
        cls.OS_PROJECT_ID = cls.auth.get_project_id(cls.sess)
        cls.availability_zone = g("E2E_BB")

    def setUp(self):
        super().setUp()
        self.test_network = None

    def create_test_server(self, name, image_name, flavor_name, network_id=None, security_groups=["default"], nic_ports=[]) -> Server:
        if not network_id and not nic_ports:
            raise ValueError("Either 'network_id' or 'nic_ports' must be provided.")

        # Get the image
        images = self.nova_client.glance.list()
        image = next((i for i in images if i.name == image_name), None)
        # Assert image is found
        self.assertIsNotNone(image)

        # Get the flavor
        flavor = self.nova_client.flavors.list()
        flavor = next((f for f in flavor if f.name == flavor_name), None)
        # Assert flavor is found
        self.assertIsNotNone(flavor)

        # Create the server
        srv: Server = self.nova_client.servers.create(
            name=name,
            image=None,
            flavor=flavor.id,
            min_count=1,
            max_count=1,
            security_groups=security_groups,
            availability_zone=self.availability_zone,
            nics=[{'net-id': network_id}] if len(nic_ports) < 1 else nic_ports,
            block_device_mapping_v2=[{
                "uuid": image.id,
                "boot_index": 0,
                "source_type": "image",
                "destination_type": "volume",
                "volume_size": 1,
                "delete_on_termination": True
            }]
        )

        # Verify server is created successfully and is in 'ACTIVE' state
        timeout = 300
        while True:
            srv: Server = self.nova_client.servers.get(srv.id)
            if srv.status == "ACTIVE":
                break
            if srv.status == "ERROR":
                raise RuntimeError(
                    f"Test Server creation failed! Code: {srv.fault['code']}, Message: {srv.fault['message']}")
            timeout -= 10
            if timeout <= 0:
                raise RuntimeError("Test Server creation timed out (5 mins)!")
            LOG.info(
                f"Waiting for server '{srv.name}' to be ACTIVE. Current status: {srv.status}, Progress: {srv.progress}%")
            eventlet.sleep(10)
        return srv

    @RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def get_nsx_port_by_os_id(self, os_port_id):
        resp = self.nsx_client.get(API.SEARCH_QUERY, {"query": API.SEARCH_Q_SEG_PORT.format(os_port_id)})
        if resp.ok:
            if resp.json()['result_count'] == 0:
                return None
            return resp.json()['results'][0]
        return None

    @RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def get_nsx_sg_by_os_id(self, os_sg_id):
        resp = self.nsx_client.get(API.GROUP.format(os_sg_id))
        if resp.ok:
            return resp.json()
        return None

    @RetryDecorator.RetryIfResultIsNone(max_retries=30, sleep_duration=30)
    def get_nsx_rules(self, os_sg_id, desired_count=None):
        res = self.nsx_client.get(API.RULES.format(os_sg_id))
        if res.ok:
            j = res.json()
            if j['result_count'] == 0:
                return None
            if desired_count is not None:
                if j['result_count'] != desired_count:
                    return None
            return j['results']
        return None

    def get_nsx_rules_no_retry(self, os_sg_id):
        res = self.nsx_client.get(API.RULES.format(os_sg_id))
        if res.ok:
            j = res.json()
            if j['result_count'] == 0:
                return []
            return j['results']
        return []

    @RetryDecorator.RetryIfResultIsNone(max_retries=30, sleep_duration=60)
    def get_nsx_sg_effective_members(self, os_sg_id, ensure_port_names: set = None) -> list:
        """
        Retrieves the effective members of an NSX security group.
        Retries the request up to 30 times with a 60-second delay between retries.
        If the `ensure_port_names` parameter is provided, the method will ensure that all port names are present in the response before returning.

        Args:
            os_sg_id (str): The ID of the OpenStack security group.
            ensure_port_names (set, optional): A set of port names to ensure are present in the response.

        Returns:
            list: A list of effective members of the NSX security group, or None if the request fails or no members are found.
        """
        res = self.nsx_client.get(API.GROUP.format(os_sg_id) + "/members/segment-ports", {"page_size": 1000})
        if res.ok:
            j = res.json()
            if j['result_count'] == 0:
                return None
            if ensure_port_names is not None:
                # Ensure all ports are in the response
                port_names = set([p['display_name'] for p in j['results']])
                if not set(ensure_port_names).issubset(port_names):
                    return None
            return j['results']
        return None

    def get_sg_members_no_retry(self, os_sg_id) -> list:
        res = self.nsx_client.get(API.GROUP.format(os_sg_id) + "/members/segment-ports", {"page_size": 1000})
        if res.ok:
            j = res.json()
            if j['result_count'] == 0:
                return []
            return j['results']
        return []

    def get_os_default_security_group(self):
        # Get the default security group
        lsg = self.neutron_client.list_security_groups(project_id=self.OS_PROJECT_ID)
        default_sg = [sg for sg in lsg['security_groups'] if sg['name'] == 'default'][0]

        # Assert that the default security group exists and has active member ports
        self.assertIsNotNone(default_sg, "Default security group must exist")
        sg_ports = self.neutron_client.list_ports(security_groups=[default_sg['id']])
        self.assertGreater(len(sg_ports), 0, "Default security group must have at least one port")
        self.assertGreater(len(sg_ports['ports']), 0, "Default security group must have at least one port")
        self.assertTrue(any([p['status'] == 'ACTIVE' and p['admin_state_up'] for p in sg_ports['ports']]),
                        "Default security group must have at least one active port")

        return default_sg

    def set_test_network(self, net_name: str):
        """ Set the test network (self.test_network) to the network with the name provided.
        """
        networks = self.neutron_client.list_networks()
        self.test_network = next(
            (n for n in networks['networks'] if n['name'] == net_name), None)
        self.assertIsNotNone(self.test_network, f"Network '{net_name}' not found!")

    def set_test_server(self, server_name: str):
        """ Set the test server (self.test_server) to the server with the name provided.
        """
        servers = self.nova_client.servers.list(search_opts={"availability_zone": self.availability_zone})
        self.test_server: Server = next((s for s in servers if s.name == server_name), None)
        self.assertIsNotNone(self.test_server, f"Server '{server_name}' not found.")

    def create_test_ports(self):
        """
        Creates test ports for the given test network.

        This method iterates over the list of test ports (self.test_ports) and creates a port for each one.
        The created ports are associated with the test network specified by `self.test_network['id']`.
        The name of each port is set based on the corresponding `self.port['name']` value.

        Returns:
            None

        Raises:
            Any exceptions raised by the `neutron_client.create_port` method.
        """
        for port in self.test_ports:
            result = self.neutron_client.create_port({
                "port": {
                    "network_id": self.test_network['id'],
                    "name": port['name']
                }
            })
            port['id'] = result['port']['id']
            if port['id']:
                self.addCleanup(self.neutron_client.delete_port, port['id'])

    def create_new_port(self) -> dict:
        """ Create a new port on the test network.
            :return: The created port {'name': str, 'id': str}
        """
        new_port = {"name": "e2e-trunk-subport3-" + str(uuid.uuid4()), "id": None}
        LOG.info(f"Creating new subport '{new_port['name']}'")
        result = self.neutron_client.create_port({
            "port": {
                "network_id": self.test_network['id'],
                "name": new_port['name']
            }
        })
        new_port['id'] = result['port']['id']
        self.addCleanup(self.neutron_client.delete_port, new_port['id'])
        return new_port

    def attach_test_ports_to_test_server(self):
        """
        Attach test ports to the test server.

        This method attaches the test ports (self.test_ports) to the test server (elf.test_server),
        using the `nova_client.servers.interface_attach` method.
        It also adds a cleanup step to detach the ports using `nova_client.servers.interface_detach` method.

        Args:
            None

        Returns:
            None
        """
        for port in self.test_ports:
            self.nova_client.servers.interface_attach(
                server=self.test_server.id,
                port_id=port['id'],
                net_id=None,
                fixed_ip=None
            )
            self.addCleanup(self.nova_client.servers.interface_detach, server=self.test_server.id, port_id=port['id'])

    def assert_os_ports_nsx_sg_membership(self, ports: List[NetworkInterface]):
        LOG.info(f"""Verifying NSX Security Group membership for {len(ports)} ports:
                ({', '.join([p.id for p in ports])})
                This may take a while as the test will try to wait for NSX to sync with OpenStack...""")
        desired_results = []
        actual_results = []

        for port in ports:
            port_sgs = self.neutron_client.show_port(port.id)['port']['security_groups']
            desired_results.append({"port_id": port.id, "sgs": port_sgs})
            actual_results.append({"port_id": port.id, "sgs": []})
            # For each SG get the Group from NSX and its members
            for sg_id in port_sgs:
                nsx_ports_for_sg = self.get_nsx_sg_effective_members(sg_id, ensure_port_names={port.id})
                self.assertIsNotNone(nsx_ports_for_sg, f"""Security Group {sg_id} not found in NSX or the port {port.id} is not a member.
                                     Desired results: {desired_results[-1]}
                                     NSX Ports in SG {sg_id}: {[p['display_name'] for p in self.get_sg_members_no_retry(sg_id)]}""")
                # Assert the port is a member of the SG
                nsx_port = next((p for p in nsx_ports_for_sg if p['display_name'] == port.id), None)
                if nsx_port:
                    actual_results[-1]['sgs'].append(sg_id)

        # order 'sgs' sublists for comparison
        for r in actual_results:
            r['sgs'].sort()
        for r in desired_results:
            r['sgs'].sort()

        self.assertListEqual(desired_results, actual_results, "Security Group membership does not match.")
