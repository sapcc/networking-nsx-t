
from oslo_log import log as logging
from oslo_config import cfg

from pyVmomi import vim
from com.vmware.nsx.fabric_client import VirtualMachines
from com.vmware.nsx_client import LogicalSwitches
from com.vmware.nsx.model_client import LogicalSwitch

from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import nsxv3_agent

LOG = logging.getLogger(__name__)


#     NSXv3 Agent annotations performing the migration from DVS to N-VDS

# NSXv3 Scope/Tag flags organizing the migration flow from DVS to NVDS
TAG_SCOPE = nsxv3_constants.NSXV3_MIGRATION_SCOPE
TAG_DVS = nsxv3_constants.NSXV3_MIGRATION_TAG_DVS
TAG_NVDS = nsxv3_constants.NSXV3_MIGRATION_TAG_NVDS


class NSXv3NVDsMigrator(object):

    def __init__(self, target, func, *args, **kwargs):
        self.target = target
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def decorate(self):
        if hasattr(self, self.func.__name__):
            func = getattr(self, self.func.__name__)
            return func(*self.args, **self.kwargs)
        else:
            return self.func(self.target, *self.args, **self.kwargs)

    def _get_port_tags(self, port, scope):
        result = []
        msg_ambiguous = "Ambiguous. Found {} virtual machines with id={}"
        device_id = port.get("device_id")
        # Only ports with assocate devices could be target of migration
        if not device_id:
            return result
        vms = self.target.nsxv3.list(VirtualMachines,
                                     external_id=device_id).results
        # Only ports with assocate devices could be target of migration
        # Port device is not created yet
        if len(vms) == 0:
            return result
        if len(vms) > 1:
            raise Exception(msg_ambiguous.format(len(vms), device_id))
        nsxv3_tags = vms.pop().tags
        nsxv3_tags = nsxv3_tags if nsxv3_tags else []
        for tag in nsxv3_tags:
            if tag.scope == TAG_SCOPE:
                result.append(tag.tag)
        return result

    def _migrate_port(self, port, segmentation_id):
        vsphere = self.target.vsphere
        nsxv3 = self.target.nsxv3

        if not cfg.CONF.host == port['binding:host_id']:
            LOG.debug("Skipping Port='{}' as it is not managed by the agent",
                      str(port))
            return

        lock_id = nsxv3_agent.get_segmentation_id_lock(segmentation_id)
        with LockManager.get_lock(lock_id):
            nsxv3.get_switch_id_for_segmentation_id(segmentation_id)

        vif_details = port.get("binding:vif_details")
        nsx_ls_id = vif_details.get("nsx-logical-switch-id")

        vim_vm = vsphere.get_managed_object(vim.VirtualMachine,
                                            port.get("device_id"))
        vim_nic = vsphere.get_vm_nic_by_mac(vm_obj=vim_vm,
                                            macAddress=port.get("mac_address"))
        # Change NIC external ID to the OpenStack Port
        vim_nic.externalId = port.get("id")
        nsx_ls_spec = LogicalSwitch(id=nsx_ls_id)
        nsx_ls = nsxv3.get(sdk_service=LogicalSwitches, sdk_model=nsx_ls_spec)

        vim_net = vsphere.get_managed_object(vim.Network, nsx_ls.display_name)
        if not isinstance(vim_net, vim.OpaqueNetwork):
            raise Exception("Provided network '{}' is not of type NSX-T"
                            .format(vim_net))
        vsphere.attach_vm_to_network(vm_obj=vim_vm, nic_obj=vim_nic,
                                     network_obj=vim_net)

    # Agent RCP method signature
    def port_update(self, context, port=None, network_type=None,
                    physical_network=None, segmentation_id=None):
        self._migrate_port(port, segmentation_id)
        return self.func(self.target, *self.args, **self.kwargs)


class migrator(object):
    def __call__(self, func):
        def decorator(self, *args, **kwargs):
            return NSXv3NVDsMigrator(self, func, *args, **kwargs).decorate()
        return decorator
