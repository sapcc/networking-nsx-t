import abc

from neutron.api import extensions
from neutron.api.v2.resource import Resource
from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron import policy
from neutron import wsgi
from webob import exc as web_exc
from webob import exc as exceptions

import networking_nsxv3.extensions

class NsxtOpsApiDefinition():
    PATH = "nsxt-ops"
    NAME = "nsxt-operations"
    ALIAS = "nsxt-ops"
    DESCRIPTION = "API Extension supporting operative"
    UPDATED_TIMESTAMP = "2022-10-18T00:00:00-00:00"
    RESOURCE_ATTRIBUTE_MAP = {}
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
        trigger_manual_sync = extensions.ResourceExtension(NsxtOpsApiDefinition.PATH, Resource(TriggerManualSync(plugin)))

        resources.append(trigger_manual_sync)

        return resources

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(list(NsxtOpsApiDefinition.RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}

# make sure this plugin gets autodiscovered and disable api-support checks
# we need to do it this way because we do not have our own plugin that we associate with
extensions.register_custom_supported_check(Nsxtoperations.get_alias(), lambda: True, True)
extensions.append_api_extensions_path(networking_nsxv3.extensions.__path__)

class TriggerManualSync(wsgi.Controller):
    def __init__(self, plugin):
        self.plugin = plugin

    def index(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    def show(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    def create(self, request, **kwargs):
       return "Hello World"

    def update(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    def delete(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")