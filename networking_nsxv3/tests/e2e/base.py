import eventlet
eventlet.monkey_patch()

from keystoneauth1 import identity
from keystoneauth1 import session
from networking_nsxv3.tests.e2e import neutron
from novaclient.v2.servers import Server
from novaclient.v2.client import Client as NovaClient
from novaclient import client as nova
from neutron.tests import base
import os
from oslo_log import log as logging
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx
from oslo_config import cfg
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import API
from urllib.parse import quote

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
                LOG.debug(f"No result from func '{func.__name__}' after {max_retries} retries in {total_time} seconds.")
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

    def setUp(self):
        super().setUp()
        self.test_network = None

    def create_test_server(self, name, image_name, flavor_name, network_id, security_groups=["default"], no_network=False) -> Server:
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
            nics=[{'net-id': network_id}] if not no_network else None,
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

    @RetryDecorator.RetryIfResultIsNone(max_retries=5, sleep_duration=5)
    def get_nsx_sg_effective_members(self, sg_id) -> list:
        res = self.nsx_client.get(path=API.SEARCH_DSL, params={
            "query": "resource_type:SegmentPort",
            "dsl": sg_id,
            "page_size": 100,
            "data_source": "INTENT",
            "exclude_internal_types": True
        })
        if res.ok:
            j = res.json()
            if j['result_count'] == 0:
                return None
            return j['results']
        return None

    def set_test_network(self, net_name: str):
        """ Set the test network (self.test_network) to the network with the name provided.
        """
        networks = self.neutron_client.list_networks()
        self.test_network = next(
            (n for n in networks['networks'] if n['name'] == net_name), None)
        self.assertIsNotNone(self.test_network, f"Network '{net_name}' not found!")
