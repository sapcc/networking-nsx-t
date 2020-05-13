import unittest
import testtools
import logging
import uuid
import sys

from oslo_config import cfg

cfg.CONF.register_opts([
    cfg.StrOpt('agent_id', default='nsxm-l-01a.corp.local'),
    cfg.IntOpt(
        'locking_coordinator_url',
        default=None,
        help='Url of the distributed locking coordinator. None for local.')
], "AGENT")


# from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.nsxv3_policy import *

LOG = logging.getLogger(__name__)

def find(context, resource_type, domain=True):
    container = \
        context["children"][0]["children"] if domain else context["children"]
    for child in container:
        if child["resource_type"] == resource_type:
            return child

SOURCE_SECURITY_GROUP_ID = "4316253D-E0F9-40B8-9FA1-7C3514BB898C"
REMOTE_SECURITY_GROUP_ID = "FC8AF1FC-E744-4344-97B1-7BF33FBB904F"

RULE_ID = "EBE75A60-C268-4AFC-BA19-100CFFAF797A"

REMOTE_PREFIX = "192.168.1.1/32"
REMOTE_PREFIX_GROUP_ID = RULE_ID

class InfraBuilderTest(testtools.TestCase):

    def setUp(self):
        super(InfraBuilderTest, self).setUp()
        self.uuid = str(uuid.uuid4())

    def mock(self):
        tags = {
            "agent_id": cfg.CONF.AGENT.agent_id,
            "revision_number": 12
        }

        s = Policy()
        g = Group()
        r = Rule()
        e = Service()

        s.identifier = SOURCE_SECURITY_GROUP_ID
        g.identifier = SOURCE_SECURITY_GROUP_ID
        r.identifier = RULE_ID
        e.identifier = r.identifier

        g.dynamic_members = True
        g.tags = tags
        g.cidrs = ["192.168.1.0/24", "192.168.2.0/24"]

        e.port_range_min = "15"
        e.port_range_max = "32"
        e.protocol = "tcp"
        e.ethertype = "IPv4"
        e.tags = tags

        r.ethertype = "IPv4"
        r.direction = "ingress"
        r.remote_ip_prefix = REMOTE_PREFIX
        r.security_group_id = SOURCE_SECURITY_GROUP_ID
        r.service = e
        r.tags = tags

        s.rules_to_add = [r]
        s.tags = tags
        return s, r, e, g

    def test_security_group_create(self):
        s, r, e, g = self.mock()

        infra = InfraBuilder(None)
        infra.with_group(g)
        infra.with_policy(s)
        
        group = find(infra.context, "ChildGroup")
        policy = find(infra.context, "ChildSecurityPolicy")
        service = find(infra.context, "ChildService", domain=False)

        self.assertIsNotNone(group, "NSX-T Group should exist")
        self.assertEquals(group["marked_for_delete"], False, "Group is not for deleteion")

        self.assertIsNotNone(policy, "NSX-T Policy should exist")
        self.assertEquals(policy["marked_for_delete"], False, "Policy is not for deleteion")

        self.assertIsNotNone(service, "NSX-T Service should exist")
        self.assertEquals(service["marked_for_delete"], False, "Service is not for deleteion")
        
    def test_security_group_delete(self):
        s, r, e, g = self.mock()

        s.rules_to_add = []
        s.rules_to_remove = [r]

        infra = InfraBuilder(None)
        infra.with_group(g, delete=True)
        infra.with_policy(s, delete=True)
        
        group = find(infra.context, "ChildGroup")
        policy = find(infra.context, "ChildSecurityPolicy")
        service = find(infra.context, "ChildService", domain=False)

        self.assertIsNotNone(group, "NSX-T Group should exist")
        self.assertEquals(group["marked_for_delete"], True, "Group is for deleteion")

        self.assertIsNotNone(policy, "NSX-T Policy should exist")
        self.assertEquals(policy["marked_for_delete"], True, "Policy is for deleteion")

        self.assertIsNotNone(service, "NSX-T Service should exist")
        self.assertEquals(service["marked_for_delete"], True, "Service is for deleteion")

    def test_remote_group(self):
        s, r, e, g = self.mock()

        gr = Group()
        gr.identifier = REMOTE_SECURITY_GROUP_ID

        r.remote_ip_prefix = None
        r.remote_group_id = gr.identifier

        infra = InfraBuilder(None)
        infra.with_group(g)
        infra.with_policy(s)
        
        group = find(infra.context, "ChildGroup")
        policy = find(infra.context, "ChildSecurityPolicy")

        # Get Agent IDs
        g.identifier = AgentIdentifier.build(g.identifier)
        gr.identifier = AgentIdentifier.build(gr.identifier)

        self.assertIsNotNone(group, "NSX-T Group should exist")
        self.assertEquals(group["Group"]["id"], g.identifier, "Incorrect group ID")
        
        self.assertIn(g.identifier, group["Group"]["expression"][0]["value"], "Incorrect condition")
        self.assertEquals(g.cidrs, group["Group"]["expression"][2]["ip_addresses"], "Incorrect members")

        self.assertIsNotNone(policy, "NSX-T Policy should exist")
        self.assertIn(gr.identifier, policy["SecurityPolicy"]["children"][0]["Rule"]["source_groups"][0], "Implicit NSX-T Group is missing")

    def test_remote_prefix(self):
        s, r, e, g = self.mock()

        r.remote_ip_prefix = REMOTE_PREFIX

        infra = InfraBuilder(None)
        infra.with_policy(s)
        
        group = find(infra.context, "ChildGroup")
        policy = find(infra.context, "ChildSecurityPolicy")

        remote_prefix_group_id = AgentIdentifier.build(REMOTE_PREFIX_GROUP_ID)

        self.assertIsNotNone(group, "NSX-T Group should exist")
        self.assertEquals(group["Group"]["id"], remote_prefix_group_id, "Incorrect group ID")

        self.assertIsNotNone(policy, "NSX-T Policy should exist")
        # When traffic is ingress the source is the destination and vise versa
        self.assertIn(remote_prefix_group_id, policy["SecurityPolicy"]["children"][0]["Rule"]["source_groups"][0], "Implicit NSX-T Group is missing")

    def test_remote_prefix_any(self):
        s, r, e, g = self.mock()

        r.remote_ip_prefix = "0.0.0.0/0"

        infra = InfraBuilder(None)
        infra.with_policy(s)
        
        group = find(infra.context, "ChildGroup")
        policy = find(infra.context, "ChildSecurityPolicy")
        
        self.assertIsNone(group, "NSX-T Group should not exist")

        self.assertIsNotNone(policy, "NSX-T Policy should exist")
        self.assertIn("ANY", policy["SecurityPolicy"]["children"][0]["Rule"]["destination_groups"], "Destination group should be ANY")
    
    def test_remote_prefix_any_skip(self):
        s, r, e, g = self.mock()

        # NSX-T Bug - does not handle such addresses
        r.remote_ip_prefix = "0.0.0.0/16"

        infra = InfraBuilder(None)
        infra.with_policy(s)
        
        group = find(infra.context, "ChildGroup")
        policy = find(infra.context, "ChildSecurityPolicy")
        
        self.assertIsNone(group, "NSX-T Group should not exist")

        self.assertIsNotNone(policy, "NSX-T Policy should exist")
        self.assertEquals(len(policy["SecurityPolicy"]["children"]), 0, "Rules list should be empty")

    def test_protocol_any(self):
            s, r, e, g = self.mock()

            e.protocol = None
    
            infra = InfraBuilder(None)
            infra.with_policy(s)
            
            service = find(infra.context, "ChildService", domain=False)
            policy = find(infra.context, "ChildSecurityPolicy")

            self.assertIsNone(service, "NSX-T Service should exist")
            self.assertIsNotNone(policy, "NSX-T Policy should exist")
            self.assertEquals(policy["SecurityPolicy"]["children"][0]["Rule"]["services"], ["ANY"], "Services should be ANY")
    
    def test_protocol_rdp(self):
        s, r, e, g = self.mock()

        e.protocol = "rdp"

        infra = InfraBuilder(None)
        infra.with_policy(s)
        
        service = find(infra.context, "ChildService", domain=False)

        self.assertIsNotNone(service, "NSX-T Service should exist")
        self.assertEquals(27, service["Service"]["service_entries"][0]["protocol_number"], "Incorrect protocol")

    def test_protocol_icmp(self):
        s, r, e, g = self.mock()

        e.protocol = "icmp"
        e.port_range_min = 8
        e.port_range_max = 0

        infra = InfraBuilder(None)
        infra.with_policy(s)
        
        service = find(infra.context, "ChildService", domain=False)

        self.assertIsNotNone(service, "NSX-T Service should exist")

        service_entry = service["Service"]["service_entries"][0]

        self.assertEquals("ICMPv4", service_entry["protocol"], "Incorrect protocol")
        self.assertEquals("8", service_entry["icmp_type"], "Incorrect ICMP type")
        self.assertEquals("0", service_entry["icmp_code"], "Incorrect ICMP code")

    def test_protocol_icmp_invalid(self):
        s, r, e, g = self.mock()

        e.protocol = "icmp"
        e.port_range_min = 32
        e.port_range_max = 6

        infra = InfraBuilder(None)
        infra.with_policy(s)
        
        service = find(infra.context, "ChildService", domain=False)
        policy = find(infra.context, "ChildSecurityPolicy")

        self.assertIsNone(service, "NSX-T Service should exist")
        self.assertIsNotNone(policy, "NSX-T Policy should exist")
        self.assertEquals(len(policy["SecurityPolicy"]["children"]), 0, "Rules list should be empty")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        InfraBuilderTest.TRANSPORT_ZONE_ID = sys.argv.pop()
    unittest.main()
