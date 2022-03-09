import copy
import hashlib
import json
import re
import time
from requests import Request
from urllib.parse import parse_qs, urlparse

from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class Inventory(object):
    ZONES = "api/v1/transport-zones"
    PROFILES = "api/v1/switching-profiles"
    PORTS = "api/v1/logical-ports"
    SWITCHES = "api/v1/logical-switches"
    SEGMENTS = "policy/api/v1/infra/segments"
    SEGMENT_PORTS = "policy/api/v1/search/query/SegmentPort"
    IPSETS = "api/v1/ip-sets"
    NSGROUPS = "api/v1/ns-groups"
    SECTIONS = "api/v1/firewall/sections"
    POLICIES = "policy/api/v1/infra/domains/default/security-policies"
    GROUPS = "policy/api/v1/infra/domains/default/groups"

    CHILD_RULES = "rules"
    CHILD_RULES_CREATE = "rules?action=create_multiple"

    def __init__(self, base_url, version="2.4.2.0.0.14269501"):
        self.url = urlparse(base_url)
        self.version = version
        self.inventory = {
            Inventory.ZONES: {
                "97C47802-2781-4CBF-825B-08689269B077": {
                    "id": "97C47802-2781-4CBF-825B-08689269B077",
                    "resource_type": "TransportZone",
                    "display_name": "openstack-tz",
                    "_create_user": "admin"
                }
            },
            Inventory.PROFILES: dict(),
            Inventory.PORTS: dict(),
            Inventory.SWITCHES: dict(),
            Inventory.SEGMENTS: dict(),
            Inventory.SEGMENT_PORTS: dict(),
            Inventory.IPSETS: dict(),
            Inventory.NSGROUPS: dict(),
            Inventory.SECTIONS: dict(),
            Inventory.POLICIES: {
                "default-layer3-section": {
                    "rules": [{"action": "DROP"}],
                    "_create_user": "system"
                }
            },
            Inventory.GROUPS: dict(),
        }

    def resp(self, code, data=dict()):
        """
        Mocked response returns tuple containing (code, headers, body)
        """
        return (code, dict(), json.dumps(data))  # (code, headers, body)

    def identifier(self, inventory, content):
        """
        Generate predictable IDs based on inventory keys and content
        """
        return hashlib.md5("{}{}".format(str(inventory.keys()), str(content)).encode("utf-8")).hexdigest()

    def type(self, request: Request, inventory, resource):
        if request.method == "GET":
            url = urlparse(request.url)
            params = parse_qs(url.query)

            objects = [o for id, o in inventory.items() if id != "_"]
            if "QosSwitchingProfile" in params.get("switching_profile_type", []):
                objects = [o for o in objects if o.get("resource_type") == "QosSwitchingProfile"]
            return self.resp(200, {"results": objects})
        if request.method == "POST":
            resource["id"] = self.identifier(inventory, resource)
            resource["_create_user"] = "admin"
            resource["_last_modified_time"] = int(time.time() * 1000)
            resource["_revision"] = 1
            inventory[resource["id"]] = resource
            return self.resp(200, resource)

    def id(self, request: Request, inventory: dict, id: str, resource: dict):
        o = inventory.get(id)
        if request.method == "GET":
            return self.resp(200, o) if o else self.resp(404)
        if request.method == "PUT":
            if "policy" in request.url:
                if o and o.get("_revision") != resource.get("_revision"):
                    return self.resp(422, {"message": "Object _revision mismatch! (current: {}, requested: {})"
                                           .format(o.get("_revision"), resource.get("_revision"))})
                resource["_revision"] = int(resource["_revision"]) + 1 if resource.get("_revision") else 1
                resource["id"] = id
                resource["_create_user"] = "admin"
                resource["_last_modified_time"] = int(time.time() * 1000)
                inventory[id] = resource
                return self.resp(200, resource)
            if o:
                if resource.get("id") and resource.get("id") != id:
                    self.resp(422)
                o.update(resource)
                return self.resp(200, o)
            else:
                return self.resp(404)
        if request.method == "PATCH":
            if o:
                inventory[id] = resource
                return self.resp(200, o)
            else:
                if "policy" in request.url:
                    inventory[id] = resource
                    resource["path"] = request.path_url
                    return self.resp(200, resource)
                else:
                    return self.resp(404)
        if request.method == "DELETE":
            if o:
                del inventory[id]
                inventory_dump = json.dumps(self.inventory, indent=2)
                if id in inventory_dump:
                    inventory[id] = o
                    return self.resp(417, "Object with ID:{} still in use Inventory:{}".format(id, inventory_dump))
            return self.resp(200) if o else self.resp(404)

    def _version(self, request: Request):
        if "api/v1/node/version" in request.url and request.method == "GET":
            return self.resp(200, {"product_version": self.version})

    def _policy_status(self, request: Request):
        if "policy/api/v1/infra/realized-state" in request.url and request.method == "GET":
            return self.resp(200, {
                "consolidated_status": {
                    "consolidated_status": "SUCCESS"
                }
            })

    def _search_query(self, request: Request):
        if "policy/api/v1/search/query" in request.url and request.method == "GET":
            q: str = request.params.get("query")
            if not q:
                return self.resp(404)
            re_type = re.search(r'resource_type:(\w+)', q)
            if not re_type:
                return self.resp(404)

            resource_type = re_type.group(1)
            inventory: dict = self.inventory.get("policy/api/v1/search/query/{}".format(resource_type))
            if not inventory:
                return self.resp(404)

            if resource_type == "SegmentPort":
                re_port = re.search(r'attachment.id:([\w-]+)', q)
                if not re_port:
                    i_len = len(inventory)
                    return self.resp(200, {
                        "results": [o for o in inventory.values()], "result_count": i_len, "cursor": f"{i_len}"})
                port_id = re_port.group(1)
                o = inventory.get(port_id)
                if o:
                    return self.resp(200, {"results": [o], "result_count": 1, "cursor": "1"})
            return self.resp(404)

    def api(self, request: Request):
        policy_status = self._policy_status(request)
        version = self._version(request)
        search = self._search_query(request)

        if search:
            return search
        if policy_status:
            return policy_status
        if version:
            return version

        url = urlparse(request.url)
        if url.scheme != self.url.scheme or url.netloc != self.url.netloc:
            return self.resp(404)

        paths = url.path.lstrip("/").split("/")
        if len(paths) == 0:
            return self.resp(404)

        version, api, obj_type, obj_id, child_type, child_id = self._get_api_elements(paths)

        path = "/".join([api, version, obj_type])  # policy/api/v1/{type}
        LOG.info(f"Using Test Inventory Path: {path}")
        if path not in self.inventory:
            return self.resp(404)

        inventory = self.inventory[path]
        resource = json.loads(request.body) if request.body else dict()

        if child_id or child_type:
            child = self._get_child_resource(inventory, obj_id, child_id, child_type, request, resource)
            if child:
                return child

        if obj_id:
            return self.id(request, inventory, obj_id, resource)
        if obj_type:
            return self.type(request, inventory, resource)

    def _get_child_resource(self, inventory, obj_id, child_id, child_type, request, resource):
        if not inventory.get(obj_id):
            return self.resp(404)
        if not inventory.get(obj_id).get("_"):
            inventory[obj_id]["_"] = {}
        if not inventory.get(obj_id).get("_").get(child_type):
            inventory[obj_id]["_"][child_type] = {}

        inventory = inventory.get(obj_id).get("_").get(child_type)
        if child_id:
            return self.id(request, inventory, child_id, resource)
        if child_type:
            if child_type in resource:
                result = []
                for item in resource.get(child_type):
                    _, _, o = self.type(request, inventory, item)
                    result.append(json.loads(o))
                return self.resp(200, {child_type: result})
            else:
                return self.type(request, inventory, resource)

    @staticmethod
    def _get_api_elements(paths):
        api = version = obj_type = obj_id = child = child_id = None
        if paths:
            api = paths.pop(0)
            if api == "policy" and paths:
                api = "{}/{}".format(api, paths.pop(0))  # policy/api
        if paths:
            version = paths.pop(0)  # v1
        if paths:
            obj_type = paths.pop(0)

            if obj_type == "firewall" and paths:
                obj_type = "{}/{}".format(obj_type, paths.pop(0))
            elif obj_type == "infra" and paths[0] == "domains":
                obj_type = "{}/{}/{}/{}".format(obj_type, paths.pop(0), paths.pop(0), paths.pop(0))
            elif obj_type == "infra" and paths[0] == "segments" and len(paths) > 2 and paths[2] == "ports":
                obj_type = "search/query/SegmentPort"
                paths = paths[3:]
            elif obj_type == "infra":
                obj_type = "{}/{}".format(obj_type, paths.pop(0))
        if paths:
            obj_id = paths.pop(0)
        if paths:
            child = paths.pop(0)
        if paths:
            child_id = paths.pop(0)
        return version, api, obj_type, obj_id, child, child_id

    def lookup(self, resource_type, name):
        for _, o in self.inventory[resource_type].items():
            if o.get("display_name") == name:
                return copy.deepcopy(o)
