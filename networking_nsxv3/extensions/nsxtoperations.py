import abc
import json
import importlib
import functools

from neutron import policy
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

ACCESS_RULE = "context_is_cloud_admin"


def check_cloud_admin(f):
    @functools.wraps(f)
    def wrapper(self, request, *args, **kwargs):
        if not policy.check(request.context, ACCESS_RULE, {'project_id': request.context.project_id}):
            raise web_exc.HTTPUnauthorized("{} required for access".format(ACCESS_RULE))
        return f(self, request, *args, **kwargs)
    return wrapper

class NsxtOpsApiDefinition():
    COLLECTION="nsxtops"
    PATH = "nsxt-ops"
    NAME = "nsxt-operations"
    ALIAS = "nsxt-ops"
    DESCRIPTION = "API Extension supporting operative"
    UPDATED_TIMESTAMP = "2022-11-16T00:00:00-00:00"
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
                for id in ids:
                    LOG.info("Trigger update process for %s" % id)
                    method(id=id, type=type)
            elif isinstance(ids, str):
                LOG.info("Trigger update process for %s" % ids)
                method(id=ids, type=type)

    @check_cloud_admin
    def index(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    @check_cloud_admin
    def show(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    """
    Trigger synchronization between neuton database and nsxt based on security_group_id or port_id. 
    Call inputs requires at least one security_group or port_id (either specified as string or as list). 
    Optionally both arguements can be specified in the same call.  
    Sample call: 
            curl --location --request POST 'http://127.0.0.1:9696/v2.0/nsxt-ops' \
                 --header 'Content-Type: application/json' \
                 --data-raw '{
                         "port_id": ["uuid-port1", "uuid-port2"] or "port_id": "uuid-port",
                         "security_group_id": ["uuid-sq1", "uuid-sg2"] or "port_id": "uuid-sg"
            }'
    """
    @check_cloud_admin
    def create(self, request, **kwargs):
       payload = json.loads(request.body)
       if self._validate_payload(payload):
           self._process_payload(payload, self.driver.trigger_sync)
           return str(payload)
       else:
           raise web_exc.HTTPError("Payload validation failed")

    @check_cloud_admin
    def update(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    @check_cloud_admin
    def delete(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")