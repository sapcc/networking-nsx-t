import unittest
import uuid

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import RetryPolicy

class TestRetryPolicyHelper(unittest.TestCase):

    def test_get_resource_type(self):
        os_id = uuid.uuid4()
        paths = [
            ('security_rule', f"/policy/api/v1/infra/domains/default/security-policies/{os_id}/rules"),
            ('security_rule', f"/policy/api/v1/infra/domains/default/security-policies/{os_id}/rules/{os_id}"),
            ('security_policy', f"/policy/api/v1/infra/domains/default/security-policies"),
            ('security_policy', f"/policy/api/v1/infra/domains/default/security-policies/{os_id}"),
            ('group', f"/policy/api/v1/infra/domains/default/groups/{os_id}"),
            ('port', f"/policy/api/v1/infra/segments/{os_id}/ports"),
            ('segments', f"/policy/api/v1/infra/segments/{os_id}")
        ]

        for resource_type, path in paths:
            classified = RetryPolicy._get_resource_type(path)
            self.assertEqual(resource_type, classified)
