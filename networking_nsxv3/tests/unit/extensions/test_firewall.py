import inspect
from neutron.tests import base
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.extensions.firewall import NSXv3SecurityGroupsDriver


class TestDummyFirewallExtension(base.BaseTestCase):
    def setUp(self):
        super(TestDummyFirewallExtension, self).setUp()
        self.fw = NSXv3SecurityGroupsDriver()

    def test_creation(self):
        assert not self.fw.ports
        for key in NSXv3SecurityGroupsDriver.__dict__:
            if not key.startswith("__") and hasattr(NSXv3SecurityGroupsDriver.__dict__[key], "__call__"):
                args = [NSXv3SecurityGroupsDriver, "dummy1", "dummy2", "dummy3", "dummy4"]
                method = NSXv3SecurityGroupsDriver.__dict__[key]
                assert not method.__call__(*args[0 : len(inspect.getfullargspec(method)[0])])
