import abc
import json
import importlib

from neutron.api import extensions
from neutron.api.v2.resource import Resource
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron import policy
from neutron import wsgi
from webob import exc as web_exc
from webob import exc as exceptions
from oslo_log import log

import networking_nsxv3.extensions

LOG = log.getLogger(__name__)

class NsxtOpsApiDefinition():
    COLLECTION="nsxtops"
    PATH = "nsxt-ops"
    NAME = "nsxt-operations"
    ALIAS = "nsxt-ops"
    DESCRIPTION = "API Extension supporting operative"
    UPDATED_TIMESTAMP = "2022-10-18T00:00:00-00:00"
    RESOURCE_ATTRIBUTE_MAP = {
        COLLECTION: {
            "security_group_id", "port_id"
        }
    }
    SUB_RESOURCE_ATTRIBUTE_MAP = {}
    REQUIRED_EXTENSIONS = []
    OPTIONAL_EXTENSIONS = []

class Nsxtoperations(api_extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return NsxtOpsApiDefinition.NAME

    @classmethod
    def get_alias(cls):
        return NsxtOpsApiDefinition.ALIAS

    @classmethod
    def get_description(cls):
        return NsxtOpsApiDefinition.DESCRIPTION

    @classmethod
    def get_namespace(cls):
        return NsxtOpsApiDefinition.ALIAS

    @classmethod
    def get_updated(cls):
        return NsxtOpsApiDefinition.UPDATED_TIMESTAMP

    @classmethod
    def get_resources(cls):
        resources = []
        plugin = directory.get_plugin()
        driver_module = importlib.import_module('networking_nsxv3.plugins.ml2.drivers.nsxv3.driver')

        trigger_manual_sync = extensions.ResourceExtension(NsxtOpsApiDefinition.PATH, Resource(TriggerManualSync(plugin,driver_module.VMwareNSXv3MechanismDriver())))

        resources.append(trigger_manual_sync)

        return resources

    def get_extended_resources(self, version):
        if version == "2.0":
            return {}
        else:
            return {}

# make sure this plugin gets autodiscovered and disable api-support checks
# we need to do it this way because we do not have our own plugin that we associate with
extensions.register_custom_supported_check(Nsxtoperations.get_alias(), lambda: True, True)
extensions.append_api_extensions_path(networking_nsxv3.extensions.__path__)

class TriggerManualSync(wsgi.Controller):
    def __init__(self, plugin, driver):
        self.plugin = plugin
        self.driver = driver

    def _validate_payload(self, payload):
        if not payload:
            return False
        if not all([i in NsxtOpsApiDefinition.RESOURCE_ATTRIBUTE_MAP[NsxtOpsApiDefinition.COLLECTION] for i in payload.keys()]):
            raise web_exc.HTTPBadRequest("Please use {keys}".format(keys=str(NsxtOpsApiDefinition.RESOURCE_ATTRIBUTE_MAP[NsxtOpsApiDefinition.COLLECTION])))
        return True

    def _process_payload(self, payload, method):
        for type, ids in payload.items():
            if isinstance(ids, list):
                #iterate over list of ids
                [LOG.info("Trigger update process for %s" % id ) for id in ids]
                [method(id=id, type=type) for id in ids]
            elif isinstance(ids, str):
                LOG.info("Trigger update process for %s" % ids)
                method(id=ids, type=type)


    def index(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    def show(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    def create(self, request, **kwargs):
       payload = json.loads(request.body)
       if self._validate_payload(payload):
           self._process_payload(payload, self.driver.trigger_sync)
           return str(payload)
       else:
           raise web_exc.HTTPError("Payload validation failed")

    def update(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    def delete(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")