import copy

import eventlet

eventlet.monkey_patch()

import responses
import json
import re

from networking_nsxv3.common import config
from neutron.tests import base
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import DEFAULT_INFRASTRUCTURE_POLICIES
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import Provider


class TestInfrastrucutreRuleChanges(base.BaseTestCase):
    provider = None

    def setUp(self):
        super().setUp()
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            rsps.add(
                method=responses.GET,
                url=re.compile(".*PolicyTransportZone.*"),
                body='{"results": [{"display_name": "openstack-tz", "id": "openstack-tz", "tags": []}]}'
            )
            rsps.add(
                method=responses.GET,
                url=re.compile('.*\/node\/version.*'),
                body='{"product_version": "0.0.0"}'
            )
            rsps.add(
                method=responses.GET,
                url=re.compile(".*default-layer3-logged-drop-section.*"),
                status=200
            )
            rsps.add(
                method=responses.GET,
                url=re.compile(".*default-layer3-section.*"),
                status=200,
                body='{"rules": []}'
            )
            self.provider = Provider()

    def tearDown(self):
        super().tearDown()
        self.provider = None

    def test_change_existing_rule(self):
        """
        Tests whether changing an existing rule is detected
        Additionally check if the _revision number is updated. 
        Updating objects in NSX-T requires the _revision number to be set.
        """
        change_rule = {
            "id": "ICMP_Allow",
            "rules": [
                {
                    "action": "ALLOW",
                    "display_name": "ICMP",
                    "destination_groups": ["1.1.1.1", "8.8.8.8"]
                }
            ]
        }

        realized_rule = {
            "rules": [
                {
                    "action": "ALLOW",
                    "display_name": "ICMP",
                    "path": "/infra/domains/default/security-policies/ICMP_Allow/rules/ICMP",
                    "_revision": 1,
                    "destination_groups": [
                        "1.1.1.1"
                    ],
                }
            ],
            "logging_enabled": False,
            "path": "/infra/domains/default/security-policies/ICMP_Allow",
            "realization_id": "a579efb4-446e-47a1-a63a-ab88125a43f1",
            "_revision": 0
        }
        diff = Provider._check_infrastructure_rules_for_updates(None, change_rule, realized_rule)
        with_revision = Provider._add_revision_number(None, change_rule, realized_rule)
        self.assertEquals(list(diff), [
            ('add', [0, 'destination_groups'], [(1, '8.8.8.8')])])

        self.assertEquals(with_revision["rules"][0]["_revision"], 1)
        self.assertEquals(with_revision["_revision"], 0)

    def test_add_new_rule_to_policy(self):
        """
        Tests whether adding a new rule to an existing policy is detected.
        """
        change_rule = {
            "id": "ICMP_Allow",
            "rules": [
                {
                    "display_name": "ICMP",
                },
                {
                    "display_name": "rule2",
                }
            ]
        }

        realized_rule = {
            "rules": [
                {
                    "display_name": "ICMP",
                    "_revision": 1
                }
            ],
            "_revision": 0
        }
        diff = Provider._check_infrastructure_rules_for_updates(None, change_rule, realized_rule)
        self.assertEquals(list(diff),
                          [('add', '', [(1, {'display_name': 'rule2'})])])

    def _mock_fetch_infrastructure_policy(self, response):
        response.add(
            method=responses.GET,
            url=re.compile(".*ICMP_Allow.*"),
            body=json.dumps(DEFAULT_INFRASTRUCTURE_POLICIES[0]),
            status=200
        )
        response.add(
            method=responses.GET,
            url=re.compile(".*Metadata_Allow.*"),
            body=json.dumps(DEFAULT_INFRASTRUCTURE_POLICIES[1]),
            status=200
        )
        response.add(
            method=responses.GET,
            url=re.compile(".*DHCP_Allow.*"),
            body=json.dumps(DEFAULT_INFRASTRUCTURE_POLICIES[2]),
            status=200
        )

    def test_infrastructure_policy_present(self):
        """
        Tests whether the infrastructure policies (Metadata Allow, ICMP Allow and DHCP Allow) are fetched from NSX-T.
        No updates are made to the policies.
        """
        with responses.RequestsMock() as rsps:
            self._mock_fetch_infrastructure_policy(rsps)

            self.provider._setup_default_infrastructure_rules()

            #Request: GET ICMP_Allow, GET Metadata_Allow, GET DHCP_Allow
            self.assertEquals(len(rsps.calls), 3)
            self.assertEquals(rsps.assert_all_requests_are_fired, True)

    def test_infrastrucutre_policy_rule_update(self):
        """
        Tests whether a change in the infrastructure policy is detected.
        Enriching the metadata policy leads to an update call for this policy.
        """
        metadata_policy_changed = copy.deepcopy(DEFAULT_INFRASTRUCTURE_POLICIES[1])
        metadata_policy_changed["rules"][0]["destination_groups"] = ["8.8.8.8"]
        metadata_policy_changed["_revision"] = 100
        metadata_policy_changed["rules"][0]["_revision"] = 200

        with responses.RequestsMock() as rsps:
            self._mock_fetch_infrastructure_policy(rsps)
            rsps.remove(responses.GET, re.compile(".*Metadata_Allow.*"))
            rsps.add(
                method=responses.GET,
                url=re.compile(".*Metadata_Allow.*"),
                body=json.dumps(metadata_policy_changed),
                status=200
            )
            rsps.add(
                method=responses.PUT,
                url=re.compile(".*Metadata_Allow.*"),
                status=200,
                json=json.dumps(metadata_policy_changed)
            )
            self.provider._setup_default_infrastructure_rules()
            req_metadata_allow = None
            for r in rsps.calls:
                if r.request.method == 'PUT':
                    req_metadata_allow = r

            #Request: GET ICMP_Allow, GET Metadata_Allow, GET DHCP_Allow, PUT Metadata_Allow
            self.assertEquals(len(rsps.calls), 4)
            self.assertEquals(rsps.assert_all_requests_are_fired, True)

            #Check if the revision number is updated
            res = json.loads(req_metadata_allow.request.body)
            self.assertEquals(res["_revision"], 100)
            self.assertEquals(res["rules"][0]["_revision"], 200)
