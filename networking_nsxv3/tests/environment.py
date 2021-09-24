import json

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import (
    agent, provider_nsx_mgmt)
from networking_nsxv3.tests.unit import openstack
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class Environment(object):

    def __init__(self, name="Default", inventory=None, synchronization=True, force_api=None):
        self.name = name
        self.force_api = force_api
        self.synchronization = synchronization
        self.openstack_inventory = openstack.NeutronMock()
        if inventory:
            self.openstack_inventory.reload_inventory(inventory)

    def __enter__(self):
        self.rpc = openstack.TestNSXv3ServerRpcApi(self.openstack_inventory)
        self.manager = agent.NSXv3Manager(rpc=self.rpc, synchronization=self.synchronization, monitoring=False, force_api=self.force_api)
        rpc = self.manager.get_rpc_callbacks(None, None, None)
        notifier = openstack.TestNSXv3AgentManagerRpcCallBackBase(rpc)
        self.openstack_inventory.register(notifier)
        LOG.info("Environment:%s initial state of OpenStack inventory: %s", self.name, self.dump_openstack_inventory())
        LOG.info("Environment:%s initial state of NSX-T inventory: %s", self.name, self.dump_provider_inventory())
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.manager.shutdown()
        LOG.info("Environment:%s final state of OpenStack inventory: %s", self.name, self.dump_openstack_inventory())
        LOG.info("Environment:%s final state of NSX-T inventory: %s", self.name, self.dump_provider_inventory())

    @property
    def version(self):
        return self.manager.realizer.provider.client.version
    
    def is_management_api_mode(self):
        return type(self.manager.realizer.provider) is provider_nsx_mgmt.Provider
    
    def dump_openstack_inventory(self, printable=True):
        o = self.openstack_inventory.inventory
        return json.dumps(o, indent=4) if printable else o

    def dump_provider_inventory(self, printable=True):
        def provider_dict(meta_provider):
            mt = meta_provider.meta.meta_transaction
            return {
                "endpoint": meta_provider.endpoint,
                "meta": meta_dict(meta_provider.meta.meta),
                "meta_transaction": meta_dict(mt) if mt else {}
            }
        def meta_dict(meta):
            return {
                k:{
                    "id": v.id, 
                    "rev": v.rev, 
                    "age": v.age, 
                    "_revision": v._revision
                } for k,v in meta.items()
            }

        metadata = self.manager.realizer.provider._metadata
        o = {r:provider_dict(m)  for r,m in metadata.items()}
        return json.dumps(o, indent=4) if printable else o
