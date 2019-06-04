import ssl
from pyVmomi import vmodl, vim
from pyVim.connect import SmartConnect

from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

# Decorator
class connection_retry_policy(object):

    def __call__(self, func):

        def decorator(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except vim.fault.NotAuthenticated:
                LOG.exception("NotAuthenticated. Probably the session has expired.")
                self._connect()
                return func(self, *args, **kwargs)

        return decorator


class VSphereClient(object):

    def __init__(self):
        self.connection = None

    def _connect(self):
        suppress_ssl_wornings = cfg.CONF.vsphere.vsphere_suppress_ssl_wornings
        hostname = cfg.CONF.vsphere.vsphere_login_hostname
        username = cfg.CONF.vsphere.vsphere_login_username
        password = cfg.CONF.vsphere.vsphere_login_password

        ssl_context = None
        if suppress_ssl_wornings:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_context.verify_mode = ssl.CERT_NONE
        self.connection = SmartConnect(host=hostname, user=username,
                                       pwd=password, sslContext=ssl_context)

    def _get_conn(self):
        if not self.connection:
            self._connect()
        return self.connection
    
    @connection_retry_policy()
    def get_managed_object(self, vimtype, name):
        content = self._get_conn().content
        ccv = content.viewManager.CreateContainerView
        for o in ccv(content.rootFolder, [vimtype], True).view:
            if name in o.name:
                return o

    @connection_retry_policy()
    def wait_for_task(self, task):
        pc = self._get_conn().content.propertyCollector
        pc_spec = vmodl.query.PropertyCollector

        obj_specs = [pc_spec.ObjectSpec(obj=task)]
        property_spec = pc_spec.PropertySpec(type=vim.Task,
                                             pathSet=[], all=True)

        filter_spec = pc_spec.FilterSpec(objectSet=obj_specs,
                                         propSet=[property_spec])

        pcfilter = pc.CreateFilter(filter_spec, True)
        try:
            obj_set = pc.WaitForUpdates().filterSet[0].objectSet[0]
            task = obj_set.obj
            for change in obj_set.changeSet:
                if change.name == 'info':
                    state = change.val.state
                elif change.name == 'info.state':
                    state = change.val
                else:
                    continue

                if state == vim.TaskInfo.State.error:
                    raise task.info.error
            return task
        finally:
            if pcfilter:
                pcfilter.Destroy()

    @connection_retry_policy()
    def attach_vm_to_network(self, vm_obj, nic_obj, network_obj):
        nic_spec = vim.vm.device.VirtualDeviceSpec()
        nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        nic_spec.device = nic_obj
        nic_spec.device.key = nic_obj.key
        nic_spec.device.externalId = nic_obj.externalId
        nic_spec.device.macAddress = nic_obj.macAddress
        nic_spec.device.backing = nic_obj.backing
        nic_spec.device.wakeOnLanEnabled = nic_obj.wakeOnLanEnabled
        nic_spec.device.connectable = nic_obj.connectable

        nic_spec.device.backing = vim.vm.device.VirtualEthernetCard\
            .OpaqueNetworkBackingInfo()
        network_id = network_obj.summary.opaqueNetworkId
        network_type = network_obj.summary.opaqueNetworkType
        nic_spec.device.backing.opaqueNetworkType = network_type
        nic_spec.device.backing.opaqueNetworkId = network_id

        spec = vim.vm.ConfigSpec(deviceChange=[nic_spec])
        task = vm_obj.ReconfigVM_Task(spec=spec)
        self.wait_for_task(task)
        LOG.info("Server with id={}, nic_mac={} was attached to network={}."
                 .format(vm_obj.name, nic_obj.macAddress, network_obj.name))

    @connection_retry_policy()
    def get_vm_nic_by_mac(self, vm_obj, macAddress):
        card = vim.vm.device.VirtualEthernetCard
        for device in vm_obj.config.hardware.device:
            if isinstance(device, card) and device.macAddress == macAddress:
                return device
