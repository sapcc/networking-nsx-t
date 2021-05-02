import json
import hashlib
import copy
from urlparse import urlparse, parse_qs

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

    CHILD_RULES = "rules"
    CHILD_RULES_CREATE = "rules?action=create_multiple"

    def __init__(self, base_url):
        self.url = urlparse(base_url)
        self.inventory = {
            Inventory.ZONES: {
                "97C47802-2781-4CBF-825B-08689269B077": {
                    "id": "97C47802-2781-4CBF-825B-08689269B077",
                    "resource_type": "TransportZone",
                    "display_name": "openstack-tz"
                }
            },
            Inventory.PROFILES: {},
            Inventory.PORTS: {},
            Inventory.SWITCHES: {},
            Inventory.IPSETS: {},
            Inventory.NSGROUPS: {},
            Inventory.SECTIONS: {}
        }

    def resp(self, code, data=dict()):
        return (code, dict(), json.dumps(data))

    def identifier(self, inventory, content):
        """
        Generate predictable IDs based on inventory keys and content
        """
        return  hashlib.md5("{}{}".format(
            str(inventory.keys()),str(content)
        )).hexdigest()

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
            inventory[resource["id"]] = resource
            return self.resp(200, resource)

    def id(self, request, inventory, id, resource):
        o = inventory.get(id)
        if request.method == "GET":    
            return self.resp(200, o) if o else self.resp(404)
        if request.method == "PUT":
            if o:
                if resource.get("id") and resource.get("id") != id:
                    self.resp(422)
                o.update(resource)
                return self.resp(200, o)
            else:
                return self.resp(404)
        if request.method == "DELETE":
            if o:
                del inventory[id]
            return self.resp(200) if o else self.resp(404)
    
    def version(self, request):
        if "api/v1/node/version" in request.url and request.method == "GET":
            return self.resp(200, {"product_version": "2.4.2.0.0.14269501"})

    def api(self, request):
        version = self.version(request)
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
        if paths:
            version = paths.pop(0)
        if paths:
            type = paths.pop(0)
            if type == "firewall" and paths:
                type = "{}/{}".format(type, paths.pop(0))
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
                    for item in resource.get(child):
                        self.type(request, inventory, item)
                    return self.resp(200)
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
