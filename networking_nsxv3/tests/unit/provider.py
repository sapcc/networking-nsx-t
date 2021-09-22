import copy
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class Inventory(object):

    ZONES = "api/v1/transport-zones"
    PROFILES = "api/v1/switching-profiles"
    PORTS = "api/v1/logical-ports"
    SWITCHES = "api/v1/logical-switches"
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
                    "display_name": "openstack-tz"
                }
            },
            Inventory.PROFILES: dict(),
            Inventory.PORTS: dict(),
            Inventory.SWITCHES: dict(),
            Inventory.IPSETS: dict(),
            Inventory.NSGROUPS: dict(),
            Inventory.SECTIONS: dict(),
            Inventory.POLICIES: {
                "default-layer3-section": {
                    "rules": [{"action": "DROP"}]
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
        return  hashlib.md5("{}{}".format(
            str(inventory.keys()),str(content)
        ).encode("utf-8")).hexdigest()

    def type(self, request, inventory, resource):
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
            inventory[resource["id"]] = resource
            if resource.get("_revision"):
                resource["_revision"] = int(resource["_revision"])+1
            return self.resp(200, resource)

    def id(self, request, inventory, id, resource):
        o = inventory.get(id)
        if request.method == "GET":    
            return self.resp(200, o) if o else self.resp(404)
        if request.method == "PUT":
            if "policy" in request.url:
                if o:
                    return self.resp(422)
                else:
                    inventory[id] = resource
                    resource["id"] = id
                    resource["_create_user"] = "admin"
                    resource["_last_modified_time"] = int(time.time() * 1000)
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
    
    def _version(self, request):
        if "api/v1/node/version" in request.url and request.method == "GET":
            return self.resp(200, {"product_version": self.version})

    def _policy_status(self, request):
        if "policy/api/v1/infra/realized-state" in request.url and request.method == "GET":
            return self.resp(200, {
                "consolidated_status": {
                    "consolidated_status": "SUCCESS"
                }
            })
        
    def api(self, request):
        policy_status = self._policy_status(request)
        version = self._version(request)
        if policy_status:
            return policy_status
        if version:
            return version

        url = urlparse(request.url)
        body = json.dumps(json.loads(request.body), indent=4) if request.body else None

        if url.scheme != self.url.scheme or url.netloc != self.url.netloc:
            return self.resp(404)
        
        paths = url.path.split("/")

        if len(paths) == 0:
            return self.resp(404)

        api = version = type = id = child = child_id = resource = None

        if paths:
            paths.pop(0)
        if paths:
            api = paths.pop(0)
            if api == "policy" and paths:
                api = "{}/{}".format(api, paths.pop(0))
        if paths:
            version = paths.pop(0)
        if paths:
            type = paths.pop(0)

            if type == "firewall" and paths:
                type = "{}/{}".format(type, paths.pop(0))
            elif type == "infra" and len(paths) > 2:
                type = "{}/{}/{}/{}".format(type, paths.pop(0), paths.pop(0), paths.pop(0))
        if paths:
            id = paths.pop(0)
        if paths:
            child = paths.pop(0)
        if paths:
            child_id = paths.pop(0)

        path = "/".join([api, version, type])

        if path not in self.inventory:
            return self.resp(404)

        inventory = self.inventory[path]
        resource = json.loads(request.body) if request.body else dict()

        if child_id or child:
            if not inventory.get(id):
                return self.resp(404)
            if not inventory.get(id).get("_"):
                inventory[id]["_"] = {}
            if not inventory.get(id).get("_").get(child):
                inventory[id]["_"][child] = {}

            inventory = inventory.get(id).get("_").get(child)
            if child_id:
                return self.id(request, inventory, child_id, resource)
            if child:
                if child in resource:
                    result = []
                    for item in resource.get(child):
                        _, _, o = self.type(request, inventory, item)
                        result.append(json.loads(o))
                    return self.resp(200, { child: result })
                else:
                    return self.type(request, inventory, resource)
        
        if id:
            return self.id(request, inventory, id, resource)
        if type:
            return self.type(request, inventory, resource)

    def lookup(self, resource_type, name):
        for _,o in self.inventory[resource_type].items():
            if o.get("display_name") == name:
                return copy.deepcopy(o)
