import abc
import json
import importlib
import functools

#Load common config here, as registering the api extension fails without
from neutron.common import config
config.register_common_config_options()

from neutron.api import extensions
from neutron.api.v2.resource import Resource
from neutron_lib.api import extensions as api_extensions

from neutron_lib.api import faults
from neutron import policy

try:
    from neutron.api import wsgi
except ImportError:
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

class NSXTAPIDefinition:
    NAME = "NSXT Policy API"
    ALIAS = "nsxt-policy"
    DESCRIPTION = "Expose NSXT Policy API via Neutron API"
    UPDATED_TIMESTAMP = "2025-07-25T09:25:00+02:00"
    RESOURCE_ATTRIBUTE_MAP = {}
    SUB_RESOURCE_ATTRIBUTE_MAP = {}
    REQUIRED_EXTENSIONS = []
    OPTIONAL_EXTENSIONS = []


class Nsxtpolicy(api_extensions.APIExtensionDescriptor):
    """NSX policy API extensions"""
    # class name cannot be camelcase, needs to be just capitalized

    api_definition = NSXTAPIDefinition

    @classmethod
    def _add_controller(cls, endpoints, ctrl, path, parent=None, path_prefix=None):
        member_actions = getattr(ctrl, "MEMBER_ACTIONS", None)
        collection_actions = getattr(ctrl, "COLLECTION_ACTIONS", None)
        res = Resource(ctrl, faults.FAULT_MAP)
        ep = extensions.ResourceExtension(path, res,
                                          member_actions=member_actions,
                                          collection_actions=collection_actions,
                                          parent=parent,
                                          path_prefix=path_prefix)
        endpoints.append(ep)

    @classmethod
    def get_resources(cls):
        """List of extensions.ResourceExtension extension objects.

        Resources define new nouns, and are accessible through URLs.
        """
        endpoints = []

        driver_module = importlib.import_module('networking_nsxv3.plugins.ml2.drivers.nsxv3.driver')
        driver = driver_module.VMwareNSXv3MechanismDriver()
        cls._add_controller(endpoints, SegmentPortController(driver), "port", path_prefix='nsxt-policy')

        return endpoints


# make sure this plugin gets autodiscovered and disable api-support checks
# we need to do it this way because we do not have our own plugin that we associate with
extensions.register_custom_supported_check(Nsxtpolicy.get_alias(), lambda: True, True)
extensions.append_api_extensions_path(networking_nsxv3.extensions.__path__)

class SegmentPortController(wsgi.Controller):
    MEMBER_ACTIONS = {"realization_status": 'GET'}

    def __init__(self, driver):
        self.driver = driver
        super().__init__()

    @check_cloud_admin
    def index(self, request, **kwargs):
        return {"extension_reached": True}

    @check_cloud_admin
    def show(self, request, **kwargs):
        port_id = request.params.get("port_id")
        binding_host = request.params.get('binding_host')

        if port_id:
            realization_status = self._port_realization_status(port_id, binding_host)
        else:
            raise web_exc.HTTPBadRequest("No port_id given")
        return {"realized": realization_status}

    @check_cloud_admin
    def update(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Update operation is not supported")

    @check_cloud_admin
    def delete(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Delete operation is not supported")

    def _port_realization_status(self, port_id, binding_host):
        try:
            status = self.driver.is_port_realized(port_id, binding_host)
        except Exception as e:
            LOG.error("Error getting realization status for port %s: %s", port_id, str(e))
            return False
        return status
