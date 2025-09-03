import abc
import json
import importlib
import functools

from neutron.api import extensions
from neutron.api.v2.resource import Resource
from neutron_lib.api import extensions as api_extensions
from neutron import policy
from neutron import wsgi
from webob import exc as web_exc
from oslo_log import log

import networking_nsxv3.extensions

LOG = log.getLogger(__name__)

ACCESS_RULE = "context_is_cloud_admin"
PATH_PREFIX = "/nsxtops"


def check_cloud_admin(f):
    @functools.wraps(f)
    def wrapper(self, request, *args, **kwargs):
        if not policy.check(request.context, ACCESS_RULE, {'project_id': request.context.project_id}):
            raise web_exc.HTTPUnauthorized("{} required for access".format(ACCESS_RULE))
        return f(self, request, *args, **kwargs)
    return wrapper

class NsxtOpsApiDefinition():
    COLLECTION="nsxtops"
    NAME = "nsxt-operations"
    ALIAS = "nsxtops"
    DESCRIPTION = "API Extension supporting nsxt operations"
    UPDATED_TIMESTAMP = "2024-01-29T00:00:00-00:00"
    RESOURCE_ATTRIBUTE_MAP = {}
    SUB_RESOURCE_ATTRIBUTE_MAP = {}
    REQUIRED_EXTENSIONS = []
    OPTIONAL_EXTENSIONS = []

class Nsxtoperationsv2(api_extensions.ExtensionDescriptor):
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
    def _add_controller(cls, endpoints, ctrl, path):
        res = Resource(ctrl)
        member_actions = getattr(ctrl, "MEMBER_ACTIONS", None)
        collection_actions = getattr(ctrl, "COLLECTION_ACTIONS", None)
        ep = extensions.ResourceExtension(path,
                                          res,
                                          member_actions=member_actions,
                                          collection_actions=collection_actions,
                                          path_prefix=PATH_PREFIX)
        endpoints.append(ep)

    @classmethod
    def get_resources(cls):
        endpoints = []
        driver_module = importlib.import_module('networking_nsxv3.plugins.ml2.drivers.nsxv3.driver')
        driver = driver_module.VMwareNSXv3MechanismDriver()

        cls._add_controller(endpoints, SyncSG(driver), 'sync/sg')
        cls._add_controller(endpoints, SyncPort(driver), 'sync/port')

        return endpoints

    def get_extended_resources(self, version):
        if version == "2.0":
            return {}
        else:
            return {}

# make sure this plugin gets autodiscovered and disable api-support checks
# we need to do it this way because we do not have our own plugin that we associate with
extensions.register_custom_supported_check(Nsxtoperationsv2.get_alias(), lambda: True, True)
extensions.append_api_extensions_path(networking_nsxv3.extensions.__path__)


class SyncType(wsgi.Controller):
    MEMBER_ACTIONS = {}

    def __init__(self, driver):
        self.driver = driver

    @check_cloud_admin
    def index(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    @check_cloud_admin
    def show(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    @check_cloud_admin
    def create(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    @check_cloud_admin
    def update(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

    @check_cloud_admin
    def delete(self, request, **kwargs):
        raise web_exc.HTTPNotImplemented("Method not implemented")

class SyncPort(SyncType):
    @check_cloud_admin
    def update(self, request, **kwargs):
        port_id = kwargs.pop('id')
        self.driver.trigger_sync(id=port_id, type="port_id")
        return port_id

class SyncSG(SyncType):
    @check_cloud_admin
    def update(self, request, **kwargs):
        security_group_id = kwargs.pop('id')
        self.driver.trigger_sync(id=security_group_id, type="security_group_id")
        return security_group_id
