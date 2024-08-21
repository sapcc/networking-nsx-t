import eventlet
eventlet.monkey_patch()

from networking_nsxv3.common import config # noqa
import os
from oslo_config import cfg
from oslo_log import log as logging
from oslo_cache import core as cache
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import client_nsx
from neutron.tests import base
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import Provider

LOG = logging.getLogger(__name__)


class TestTransportZoneCaching(base.BaseTestCase):
    transport_zone_name = "tmp-transport-zone-1"
    segment_id = 815

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cfg.CONF.set_override('debug', True)
        cfg.CONF.set_override("lock_path", "/tmp/", "oslo_concurrency")
        cfg.CONF.set_override("nsxv3_login_hostname", os.environ.get("NSXV3_LOGIN_HOSTNAME"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_port", os.environ.get("NSXV3_LOGIN_PORT"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_user", os.environ.get("NSXV3_LOGIN_USER"), "NSXV3")
        cfg.CONF.set_override("nsxv3_login_password", os.environ.get("NSXV3_LOGIN_PASSWORD"), "NSXV3")
        cfg.CONF.set_override("nsxv3_transport_zone_name", os.environ.get("NSXV3_TRANSPORT_ZONE_NAME"), "NSXV3")
        cfg.CONF.set_override("nsxv3_connection_retry_count", "3", "NSXV3")
        cfg.CONF.set_override("nsxv3_request_timeout", "320", "NSXV3")

        # Configure oslo.cache
        cache.configure(cfg.CONF)
        cfg.CONF.set_override("enabled", True, "cache")
        cfg.CONF.set_override("backend", "dogpile.cache.memory", "cache")

        # Configure transport_zone cache timeout
        cfg.CONF.set_override("nsxv3_transport_zone_id_cache_time", 600, "NSXV3")

    def setUp(self):
        super(TestTransportZoneCaching, self).setUp()
        self.skipTest("Skipping test temporarily.")

        client = client_nsx.Client()

        print(self.transport_zone_name)
        tmp_zone = {
            "display_name": self.transport_zone_name,
            "transport_type": "OVERLAY",
            "description": "tmp zone for testing"
        }

        res = client.post(
            path="/api/v1/transport-zones",
            data=tmp_zone
        )
        if not res.status_code in [200, 201]:
            raise Exception("Failed to create transport zone - Aborting test due to error in setup")

        self.transport_zone_id = res.json()["id"]
        self.delete_network_segment(self.segment_id)

    def tearDown(self):
        super(TestTransportZoneCaching, self).tearDown()
        self.delete_network_segment(self.segment_id)
        self.delete_zone(self.transport_zone_id)

    def delete_zone(self, zone_id):
        client = client_nsx.Client()
        path = f"/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones/{zone_id}"
        res = client.delete(path)
        if not res.status_code in [200, 204]:
            raise Exception("Failed to delete transport zone")

    def delete_network_segment(self, segement_id):
        client = client_nsx.Client()
        path = f"/policy/api/v1/infra/segments/{segement_id}"
        res = client.delete(path)
        if not res.status_code in [200, 204]:
            raise Exception("Failed to delete network segment")

    def test_transport_zone_id_caching(self):
        self.provider = Provider()
        zone_id_before_deletion = self.provider.zone_id

        self.delete_zone(self.transport_zone_id)

        # Test if calling network realize will fetch the zone_id from the cache
        # Segment creation will fail as the zone is deleted
        try:
            self.provider.network_realize(self.segment_id)
        except RuntimeError as e:
            pass
        self.assertEqual(zone_id_before_deletion, self.provider.zone_id)
