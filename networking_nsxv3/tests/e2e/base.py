import eventlet
eventlet.monkey_patch()

from networking_nsxv3.common import config  # noqa
from oslo_config import cfg
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx
from oslo_log import log as logging
import os
from neutron.tests import base
from novaclient import client as nova
from novaclient.v2.client import Client as NovaClient
from networking_nsxv3.tests.e2e import neutron
from keystoneauth1 import session
from keystoneauth1 import identity


LOG = logging.getLogger(__name__)

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

        http_p = "https" if g("OS_HTTPS") == 'true' else "http"
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

    @staticmethod
    def retry(max_retries, sleep_duration):
        """ Retry decorator for functions that return None on failure. """
        def decorator(func):
            def wrapper(*args, **kwargs):
                retry_counter = max_retries
                while retry_counter > 0:
                    result = func(*args, **kwargs)
                    if result is not None:
                        LOG.info(f"Success after {max_retries - retry_counter} retries ({func.__name__}).")
                        return result

                    eventlet.sleep(sleep_duration)
                    LOG.info(f"{retry_counter}: Retrying function '{func.__name__}'")
                    retry_counter -= 1

                raise TimeoutError(f"Failed to fetch the desired result of func '{func.__name__}' after {max_retries} retries.")

            return wrapper
        return decorator
