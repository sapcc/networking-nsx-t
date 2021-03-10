from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.nsxv3_policy import *
import unittest
import testtools
import logging
import uuid
import sys
import responses
import copy

from oslo_config import cfg

class SchedulerMock(object):
    def __call__(self, func):
        pass
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


cfg.CONF.register_opts([
    cfg.IntOpt('nsxv3_policy_migration_limit', default=2),
    cfg.IntOpt('nsxv3_connection_retry_count', default=2),
    cfg.IntOpt('nsxv3_connection_retry_sleep', default=0.1),
    cfg.IntOpt('nsxv3_request_timeout', default=1),
    cfg.IntOpt('nsxv3_operation_retry_count', default=2),
    cfg.IntOpt('nsxv3_operation_retry_sleep', default=0.1),
    cfg.IntOpt('nsxv3_requests_per_second', default=90),
    cfg.IntOpt('nsxv3_concurrent_requests', default=40),
    cfg.StrOpt('nsxv3_login_user', default='admin'),
    cfg.StrOpt('nsxv3_login_password', default='VMware1!'),
    cfg.HostAddressOpt('nsxv3_login_hostname',
                       default='nsxm-l-01a.corp.local'),
    cfg.PortOpt('nsxv3_login_port', default=443),
    cfg.StrOpt('nsxv3_transport_zone_name', default='openstack-tz'),
    cfg.BoolOpt('nsxv3_enable_spoof_guard', default=False),
    cfg.BoolOpt('nsxv3_suppress_ssl_wornings', default=True),
    cfg.ListOpt('nsxv3_managed_hosts', default=[]),
    cfg.IntOpt('nsxv3_max_records_per_query', default=1),
    cfg.IntOpt('nsxv3_remove_orphan_ports_after', default=12),
    cfg.StrOpt('nsxv3_dfw_connectivity_strategy', default='NONE')
    
], "NSXV3")

cfg.CONF.register_opts([
    cfg.StrOpt('agent_id', default='nsxm-l-01a.corp.local')
], "AGENT")

LOG = logging.getLogger(__name__)

PAGE_ONE={
    "results": [
        {
            "id": AgentIdentifier.build("4316253D-E0F9-40B8-9FA1-7C3514BB898C"),
            "tags": [
                { "scope": "agent_id", "tag": "nsxm-l-01a.corp.local" },
                { "scope": "revision_number", "tag": "11" }
            ],
        }
    ],
    "result_count" : 2,
    "cursor": "00011"
}

PAGE_TWO={
    "results": [
        {
            "id": AgentIdentifier.build("CA352DDC-08A5-47C5-9136-EF1935B86FA1"),
            "tags": [
                { "scope": "agent_id", "tag": "nsxm-l-01a.corp.local" },
                { "scope": "revision_number", "tag": "12" }
            ],
        }
    ],
    "result_count" : 2,
}

HEADERS = {"X-XSRF-TOKEN": "_token_", "Cookie": "_cookie_"}

def get_url_with_params(path, infra=True, page_size=1, cursor=""):
    prefix = "/policy/api/v1/infra" if infra else ""
    return "https://nsxm-l-01a.corp.local:443{}{}?page_size={}&cursor={}"\
        .format(prefix, path, page_size, cursor)

def get_url(path):
    return "https://nsxm-l-01a.corp.local:443{}".format(path)


class InfraServiceTest(testtools.TestCase):

    def setUp(self):
        super(InfraServiceTest, self).setUp()

    def mock_request_get(self, path):
        responses.add(method=responses.GET, 
                      url=get_url_with_params(path),
                      headers=HEADERS, json=PAGE_ONE, status=200, 
                      match_querystring=True)
        responses.add(method=responses.GET,
                      url=get_url_with_params(path, cursor="00011"),
                      headers=HEADERS, json=PAGE_TWO, status=200,
                      match_querystring=True)

    def mock_request_get_skip(self, path):
        page_one = copy.deepcopy(PAGE_ONE)
        page_two = copy.deepcopy(PAGE_TWO)

        page_one["results"][0]["id"] = \
            AgentIdentifier.extract(page_one["results"][0]["id"])

        responses.add(method=responses.GET, 
                      url=get_url_with_params(path),
                      headers=HEADERS, json=page_one, status=200, 
                      match_querystring=True)
        responses.add(method=responses.GET,
                      url=get_url_with_params(path, cursor="00011"),
                      headers=HEADERS, json=page_two, status=200,
                      match_querystring=True)

    @responses.activate
    def test_login(self):
        method = responses.POST
        url = get_url("/api/session/create")
        headers = {"X-XSRF-TOKEN": "_token_", "Set-Cookie": "_cookie_"}
        responses.add(method=method, url=url, headers=headers, status=200)
        Client(SchedulerMock())._login()

    @responses.activate
    def test_get_revisions(self):        
        self.mock_request_get(path=ResourceContainers.TransportZone)
        self.mock_request_get(path=ResourceContainers.SecurityPolicy)
        self.mock_request_get(path=ResourceContainers.SecurityPolicyGroup)

        res_1_id = AgentIdentifier.extract(PAGE_ONE["results"][0]["id"])
        res_1_rv = PAGE_ONE["results"][0]["tags"][1]["tag"]

        res_2_id = AgentIdentifier.extract(PAGE_TWO["results"][0]["id"])
        res_2_rv = PAGE_TWO["results"][0]["tags"][1]["tag"]

        revisions = InfraService(Client(SchedulerMock()))\
            .get_revisions(ResourceContainers.TransportZone)

        revisions1 = InfraService(Client(SchedulerMock()))\
            .get_revisions(ResourceContainers.SecurityPolicy)
        
        revisions2 = InfraService(Client(SchedulerMock()))\
            .get_revisions(ResourceContainers.SecurityPolicyGroup)


        self.assertEquals(len(revisions1), 2, "Expected two objects")
        self.assertEquals(\
            revisions1[res_1_id], res_1_rv, "Revision does not match")
        self.assertEquals(\
            revisions1[res_2_id], res_2_rv, "Revision does not match")

        self.assertEquals(len(revisions2), 2, "Expected two objects")
        self.assertEquals(\
            revisions2[res_1_id], res_1_rv, "Revision does not match")
        self.assertEquals(\
            revisions2[res_2_id], res_2_rv, "Revision does not match")
    
    @responses.activate
    def test_get_revisions_skip(self):        
        self.mock_request_get_skip(path=ResourceContainers.SecurityPolicy)

        res_2_id = AgentIdentifier.extract(PAGE_TWO["results"][0]["id"])
        res_2_rv = PAGE_TWO["results"][0]["tags"][1]["tag"]

        revisions = InfraService(Client(SchedulerMock()))\
            .get_revisions(ResourceContainers.SecurityPolicy)

        self.assertEquals(len(revisions), 2, "Expected two objects")
        self.assertEquals(\
            revisions[res_2_id], res_2_rv, "Revision does not match")

