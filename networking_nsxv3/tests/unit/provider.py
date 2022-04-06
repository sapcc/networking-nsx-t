import copy
import hashlib
import json
import re
import time
from typing import Dict, List, Tuple
from wsgiref.util import request_uri
from requests.models import PreparedRequest as Request
from urllib.parse import parse_qs, urlparse

from oslo_log import log as logging

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class Inventory(object):
    class POLICY_RESOURCE_TYPES:
        SEGMENT = "Segment"
        SEGMENT_PORT = "SegmentPort"
        QOS_PROFILE = "QoSProfile"
        MAC_PROFILE = "MacDiscoveryProfile"
        IP_PROFILE = "IPDiscoveryProfile"
        SPOOF_PROFILE = "SpoofGuardProfile"
        SEC_PROFILE = "SegmentSecurityProfile"
        MIRRONRING_PROFILE = "PortMirroringProfile"

    ZONES = "api/v1/transport-zones"
    PROFILES = "api/v1/switching-profiles"
    PORTS = "api/v1/logical-ports"
    SWITCHES = "api/v1/logical-switches"
    SEGMENTS = "policy/api/v1/infra/segments"
    SEGMENT_PORTS = f"policy/api/v1/search/query/{POLICY_RESOURCE_TYPES.SEGMENT_PORT}"
    SEGMENT_QOS = "policy/api/v1/infra/qos-profiles"
    SEGMENT_PROFILES_QOS = f"policy/api/v1/search/query/{POLICY_RESOURCE_TYPES.QOS_PROFILE}"
    SEGMENT_PROFILES_MAC = f"policy/api/v1/search/query/{POLICY_RESOURCE_TYPES.MAC_PROFILE}"
    SEGMENT_PROFILES_IP = f"policy/api/v1/search/query/{POLICY_RESOURCE_TYPES.IP_PROFILE}"
    SEGMENT_PROFILES_SPOOF = f"policy/api/v1/search/query/{POLICY_RESOURCE_TYPES.SPOOF_PROFILE}"
    SEGMENT_PROFILES_SEC = f"policy/api/v1/search/query/{POLICY_RESOURCE_TYPES.SEC_PROFILE}"
    SEGMENT_PROFILES_MIRR = f"policy/api/v1/search/query/{POLICY_RESOURCE_TYPES.MIRRONRING_PROFILE}"
    IPSETS = "api/v1/ip-sets"
    NSGROUPS = "api/v1/ns-groups"
    SECTIONS = "api/v1/firewall/sections"
    POLICIES = "policy/api/v1/infra/domains/default/security-policies"
    GROUPS = "policy/api/v1/infra/domains/default/groups"

    CHILD_RULES = "rules"
    CHILD_RULES_CREATE = "rules?action=create_multiple"

    SUPPORTED_MIGRATION_TYPES = {
         "SEGMENT_SECURITY_PROFILES": ("SwitchSecuritySwitchingProfile", POLICY_RESOURCE_TYPES.SEC_PROFILE, PROFILES, SEGMENT_PROFILES_SEC),
         "SPOOFGUARD_PROFILES": ("SpoofGuardSwitchingProfile", POLICY_RESOURCE_TYPES.SPOOF_PROFILE, PROFILES, SEGMENT_PROFILES_SPOOF),
         "IPDISCOVERY_PROFILES": ("IpDiscoverySwitchingProfile", POLICY_RESOURCE_TYPES.IP_PROFILE, PROFILES, SEGMENT_PROFILES_IP),
         "MACDISCOVERY_PROFILES": ("MacManagementSwitchingProfile", POLICY_RESOURCE_TYPES.IP_PROFILE, PROFILES, SEGMENT_PROFILES_MAC),
         "QOS_PROFILES": ("QosSwitchingProfile", POLICY_RESOURCE_TYPES.QOS_PROFILE, PROFILES, SEGMENT_PROFILES_QOS),
         "LOGICAL_SWITCH": ("LogicalSwitch", POLICY_RESOURCE_TYPES.SEGMENT, SWITCHES, SEGMENTS),
         "LOGICAL_PORT": ("LogicalPort", POLICY_RESOURCE_TYPES.SEGMENT_PORT, PORTS, SEGMENT_PORTS)
    }

    def __init__(self, base_url, version):
        self.url = urlparse(base_url)
        self.version = version
        self.prepared_migration: Dict[Tuple[str, str], dict] = None
        qos_inv = dict()
        self.inv: Dict[str, Dict[str, dict]] = {
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
            Inventory.SEGMENT_PROFILES_QOS: qos_inv,
            Inventory.SEGMENT_QOS: qos_inv,
            Inventory.SEGMENT_PROFILES_MAC: dict(),
            Inventory.SEGMENT_PROFILES_IP: dict(),
            Inventory.SEGMENT_PROFILES_SPOOF: dict(),
            Inventory.SEGMENT_PROFILES_SEC: dict(),
            Inventory.SEGMENT_PROFILES_MIRR: dict(),
            Inventory.IPSETS: dict(),
            Inventory.NSGROUPS: dict(),
            Inventory.SECTIONS: dict(),
            Inventory.POLICIES: {
                "default-layer3-section": {
                    "id": "default-layer3-section",
                    "rules": [{"action": "DROP"}],
                    "_create_user": "system"
                }
            },
            Inventory.GROUPS: dict(),
        }

    @staticmethod
    def find_by_type_and_id(inventory: Dict[str, dict], resource_type: str, resource_id: str) -> Tuple[str, dict]:
        for k in inventory:
            resource = inventory.get(k)
            if resource.get("resource_type") == resource_type and resource.get("id") == resource_id:
                return k, resource
        return ()

    @staticmethod
    def resp(code, data=dict()):
        """
        Mocked response returns tuple containing (code, headers, body)
        """
        return code, dict(), json.dumps(data)  # (code, headers, body)

    @staticmethod
    def identifier(inventory, content):
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
            elif params.get("attachment_id"):
                objects = [o for id, o in inventory.items() if o.get("attachment", {}).get("id")
                           == params.get("attachment_id")[0]]

            return self.resp(200, {"results": objects})

        if request.method == "POST":
            resource["id"] = self.identifier(inventory, resource)
            resource["unique_id"] = self.identifier(inventory, resource)
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
                    return self.resp(412, {"message":
                        "Object _revision mismatch! (current: {}, requested: {}). Fetch the latest copy of the object and retry!"
                                           .format(o.get("_revision"), resource.get("_revision"))})
                resource["_revision"] = int(resource["_revision"]) + 1 if resource.get("_revision") else 1
                resource["id"] = id
                resource["unique_id"] = id
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
                    resource["path"] = request.path_url.split("?")[0]
                    return self.resp(200, resource)
                else:
                    return self.resp(404)
        if request.method == "DELETE":
            if o:
                del inventory[id]
                inventory_dump = json.dumps(self.inv, indent=2)
                if id in inventory_dump:
                    inventory[id] = o
                    return self.resp(417, "Object with ID:{} still in use Inventory".format(id))
            return self.resp(200) if o else self.resp(404)

    def api(self, request: Request):
        policy_status = self._policy_status(request)
        version = self._version(request)
        search = self._search_query(request)
        migration = self._migration(request)
        infra = self._infra(request)

        if search:
            return search
        if policy_status:
            return policy_status
        if version:
            return version
        if migration:
            return migration
        if infra:
            return infra

        url = urlparse(request.url)
        if url.scheme != self.url.scheme or url.netloc != self.url.netloc:
            return self.resp(404)

        paths = url.path.lstrip("/").split("/")
        if len(paths) == 0:
            return self.resp(404)

        version, api, obj_type, obj_id, child_type, child_id = self._get_api_elements(paths)

        path = "/".join([api, version, obj_type])  # policy/api/v1/{type}
        LOG.info(f"Using Test Inventory Path: {path}")
        if path not in self.inv:
            return self.resp(404)

        inventory = self.inv[path]
        resource = json.loads(request.body) if request.body else dict()

        if child_id or child_type:
            child = self._get_child_resource(inventory, obj_id, child_id, child_type, request, resource)
            if child:
                return child

        if obj_id:
            LOG.info(f"Using Test obj_id: {obj_id}, {request.method}")
            return self.id(request, inventory, obj_id, resource)
        if obj_type:
            LOG.info(f"Using Test obj_type: {obj_type}, {request.method}")
            return self.type(request, inventory, resource)

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
            LOG.info("Search query: " + q)
            if not q:
                return self.resp(404)
            matches = re.findall(r'resource_type:(\w+)', q)
            if not matches:
                return self.resp(404)

            resources = list()
            for resource_type in matches:
                LOG.info(f"Searching for resource resource_type: \"{resource_type}\"")
                inventory: dict = self.inv.get("policy/api/v1/search/query/{}".format(resource_type))
                if not inventory:
                    continue

                if resource_type == self.POLICY_RESOURCE_TYPES.SEGMENT_PORT:
                    re_port = re.search(r'attachment.id:([\w-]+)', q)
                    if re_port:
                        o = list(filter(lambda v, r=re_port:
                            v.get("attachment", {}).get("id") == r.group(1), inventory.values()))
                        if o:
                            resources.append(o[0])
                        continue

                for o in inventory.values():
                    resources.append(o)

            if len(resources):
                return self.resp(
                    200, {"results": resources, "result_count": len(resources), "cursor": f"{len(resources)}"})

            return self.resp(404)

    def _infra(self, request: Request):
        path_url = request.path_url.split("?")[0]
        if "/policy/api/v1/infra" == path_url and request.method == "PATCH":
            payload: dict = json.loads(request.body)
            if not payload:
                return self.resp(500, "Provide payload!")

            resource_type = payload.get("resource_type")
            if resource_type != "Infra":
                return self.resp(500, "Only 'Infra' resource types supported!")

            children: List[dict] = payload.get("children")
            if not children:
                return self.resp(500, "Provide 'children' in the payload!")

            for child in children:
                _children: List[dict] = child.get("children")
                if _children:
                    self._traverse_infra_children(_children)

            return self.resp(200)

    def _traverse_infra_children(self, _children):
        for _child in _children:
            child_key = _child.get("resource_type")[5:]
            resource = _child.get(child_key)
            resource_id = resource.get("id")
            if child_key == self.POLICY_RESOURCE_TYPES.SEGMENT_PORT:
                if _child.get("marked_for_delete"):
                    if self.inv[Inventory.SEGMENT_PORTS].get(resource_id):
                        del self.inv[Inventory.SEGMENT_PORTS][resource_id]
                    if self.inv[Inventory.PORTS].get(resource_id):
                        del self.inv[Inventory.PORTS][resource_id]

    def _migration(self, request: Request):
        if "/api/v1/migration" in request.url:
            params: dict = request.params
            data = json.loads(request.body) if request.body else dict()

            if "/mp-to-policy" in request.url and request.method == "POST":
                if "/workflow" in request.url:
                    if params.get("action") == "INITIATE":
                        return self._active_migr_err_resp() if self.prepared_migration else self.resp(200)
                    if params.get("action") == "DONE":
                        self.prepared_migration = None
                        return self.resp(200)
                if "/rollback" in request.url:
                    return self.resp(200, data=json.loads(request.body))
                else:
                    if not data:
                        return self.resp(200)
                    else:
                        self._check_migration_data(data)
                        return self._mp_to_policy_prepare(data.get("migration_data"))

            if "/plan" in request.url:
                if request.method == "POST":
                    if params.get("action") == "abort":
                        self.prepared_migration = None
                        return self.resp(200)
                    if params.get("action") == "start":
                        if not self.prepared_migration:
                            return self.resp(500, "There is no running migration")
                        return self._mp_to_policy_promote()
                    if params.get("action") == "continue":
                        return self.resp(200)

            if "/migration-unit-groups/MP_TO_POLICY_MIGRATION" in request.url:
                if request.method == "GET" and params.get("summary") == "true":
                    return self.resp(200, {"enabled": True})

            if "/status-summary" in request.url and request.method == "GET":
                if "?component_type=MP_TO_POLICY_PRECHECK" in request.url:
                    return self.resp(200, self._migration_status_response())
                if "?component_type=MP_TO_POLICY_MIGRATION" in request.url:
                    return self.resp(200, self._migration_status_response())

            return self._not_implemented_err_resp(request)

    def _migration_status_response(self):
        return {
            "overall_migration_status": "SUCCESS",
            "component_status": [
                {
                    "status": "SUCCESS", "percent_complete": 100
                }
            ]}

    def _check_migration_data(self, data: dict):
        migr_data = data.get("migration_data")
        if not migr_data:
            raise Exception("No migration data provided 'migration_data'!")
        for d in migr_data:
            res_type = d.get("type")
            if not res_type or res_type not in self.SUPPORTED_MIGRATION_TYPES:
                raise Exception("Not supported or empty migration 'type'!")
            resource_ids: List[dict] = d.get("resource_ids")
            if not resource_ids:
                raise Exception("Missing or empty 'resource_ids'!")
            for rid in resource_ids:
                if not rid.get("policy_id"):
                    raise Exception("Missing or empty 'policy_id' key in the provided resource_ids!")
                if not rid.get("manager_id"):
                    raise Exception("Missing or empty 'manager_id' key in the provided resource_ids!")
                if rid.get("policy_id") != rid.get("manager_id"):
                    raise Exception("NOT MATCH: 'manager_id' and 'policy_id' in the provided resource_ids!")

    def _mp_to_policy_prepare(self, data: List[dict]):
        if self.prepared_migration:
            return self._active_migr_err_resp()
        self.prepared_migration = dict()
        for d in data:
            r_type: str = d.get("type")

            mngr_res_type, plcy_res_type, mngr_inv_path, plcy_inv_path = self.SUPPORTED_MIGRATION_TYPES.get(r_type)
            mngr_inv = self.inv.get(mngr_inv_path)
            plcy_inv = self.inv.get(plcy_inv_path)

            resource_ids: List[dict] = d.get("resource_ids")
            for rid in resource_ids:
                res_id = rid.get("policy_id")
                mngr_resource = self.find_by_type_and_id(
                    inventory=mngr_inv, resource_id=res_id, resource_type=mngr_res_type)
                if not mngr_resource:
                    return self.resp(
                        500, f"Manager Resource not exists! (resource_id={res_id}, resource_type={mngr_res_type})")
                plcy_resource = self.find_by_type_and_id(
                    inventory=plcy_inv, resource_id=res_id, resource_type=plcy_res_type)
                if plcy_resource:
                    return self.resp(
                        500, f"Policy Resource already exists! (resource_id={res_id}, resource_type={plcy_res_type})")
                if (mngr_resource[0], plcy_res_type, plcy_inv_path, mngr_inv_path) in self.prepared_migration:
                    return self.resp(
                        500, f"Duplicated migration resources! (resource_id={res_id}, resource_type={mngr_res_type})")

                self.prepared_migration[(mngr_resource[0],
                                         plcy_res_type,
                                         plcy_inv_path,
                                         mngr_inv_path)] = mngr_resource[1]

        return self.resp(200)

    def _mp_to_policy_promote(self):
        for os_id, plcy_res_type, plcy_inv_path, mngr_inv_path in self.prepared_migration:
            resource = self.prepared_migration.get((os_id, plcy_res_type, plcy_inv_path, mngr_inv_path))
            plcy_inv = self.inv.get(plcy_inv_path)
            mngr_inv = self.inv.get(mngr_inv_path)

            now = int(time.time() * 1000)
            tags: list = mngr_inv[os_id].get("tags", [])
            attachment: dict = mngr_inv[os_id].get("attachment")
            vlan = mngr_inv[os_id].get("vlan")
            path, parent_path = self._get_paths_for_promoted(mngr_inv[os_id])
            tags.append({"scope": "policyPath", "tag": path})

            plcy_inv[os_id] = {
                "id": resource.get("id"),
                "display_name": mngr_inv[os_id]["display_name"],
                "resource_type": plcy_res_type,
                "tags": tags,
                "path": path,
                "parent_path": parent_path,
                "_create_user": "admin",
                "_last_modified_time": now,
                "_revision": 0
            }
            if attachment:
                plcy_inv[os_id]["attachment"] = {
                    "id": attachment.get("id"),
                    "type": attachment.get("context").get("vif_type"),
                    "hyperbus_mode": "DISABLE"
                }
            if vlan:
                plcy_inv[os_id]["vlan_ids"] = [
                    str(vlan)
                ]

            mngr_inv[os_id]["_create_user"] = "nsx_policy"
            mngr_inv[os_id]["_last_modified_time"] = now
            mngr_inv[os_id]["_revision"] = mngr_inv.get(os_id).get("_revision", 0) + 1

        return self.resp(200)

    def _get_paths_for_promoted(self, mngr_resource: dict) -> Tuple[str, str]:
        """
        Returns:
            Tuple[str, str]: (path, parent_path)
        """
        path, parent_path = "TODO", "TODO"
        if mngr_resource.get("resource_type") == "LogicalPort":
            vlan = mngr_resource.get("attachment", {}).get("context", {}).get("traffic_tag")
            switch = list(filter(lambda v: v.get("vlan") == vlan, self.inv[self.SWITCHES].values()))
            if switch:
                parent_path = f"/infra/segments/{switch[0].get('id')}"
                path = f"{parent_path}/ports/{mngr_resource.get('id')}"
        # TODO: handle more resource types
        return path, parent_path

    def _get_child_resource(self, inventory, obj_id, child_id, child_type, request, resource):
        LOG.info(f"Getting child resource: {child_type}, {child_id}")
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

    def _get_api_elements(self, paths):
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
                obj_type = f"search/query/{self.POLICY_RESOURCE_TYPES.SEGMENT_PORT}"
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

    def _not_implemented_err_resp(self, request: Request):
        body = json.loads(request.body) if request.body else None
        return self.resp(500,
            f"NOT IMPLEMENTED MIGRATION TEST CASE for {request.method} {request.url}, body: {body}")

    def _active_migr_err_resp(self):
        self.resp(500, "Previous migration not cleared! Please abort or finish current migration")

    def lookup(self, resource_type, name):
        for _, o in self.inv[resource_type].items():
            if o.get("display_name") == name:
                return copy.deepcopy(o)
