import copy
import json
import uuid

from oslo_log import log as logging
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import agent

LOG = logging.getLogger(__name__)


class Notifier(object):
    def notify(self, resource_type, resource):
        pass


class TestNSXv3AgentManagerRpcCallBackBase(Notifier):

    ADD = "add"
    UPDATE = "update"
    DELETE = "delete"

    def __init__(self, rpc: agent.NSXv3AgentManagerRpcCallBackBase):
        self.rpc: agent.NSXv3AgentManagerRpcCallBackBase = rpc

    def notify(self, resource_type, resource, operation):
        o = copy.deepcopy(resource)

        if resource_type == NeutronMock.NETWORK:
            self.rpc.get_network_bridge(
                None, current=o.get("current"), network_segments=o.get("network_segments"), network_current=None
            )

        if resource_type == NeutronMock.PORT:
            if operation == self.ADD:
                self.rpc.port_create(None, port=o)
            else:
                self.rpc.port_update(None, port=o)
            self.rpc.security_groups_member_updated(None, security_groups=o.get("security_groups"))

        if resource_type == NeutronMock.QOS:
            # Create and update RPC calls are handled also by update_policy
            self.rpc.update_policy(None, o)

        if resource_type == NeutronMock.SECURITY_GROUP:
            self.rpc.security_groups_rule_updated(None, security_groups=[o.get("id")])

        if resource_type == NeutronMock.SECURITY_GROUP_RULE:
            self.rpc.security_groups_rule_updated(None, security_groups=[o.get("security_group_id")])


class NeutronMock(object):

    NETWORK = "network"
    PORT = "port"
    QOS = "qos"
    SECURITY_GROUP = "security-group"
    SECURITY_GROUP_RULE = "security-group-rule"

    def __init__(self):
        self.notifier: TestNSXv3AgentManagerRpcCallBackBase = None
        self.reload_inventory()

    def _get_by_name(self, resource_type, name):
        resources = [o for id, o in self.inventory.get(resource_type, {}).items() if o.get("name") == name]
        if len(resources) > 1:
            raise Exception("Ambiguous '{}' '{}'".format(resource_type, name))
        elif len(resources) == 1:
            return resources.pop()

    def _add(self, resource_type, resource, id=None):
        id = id if id else str(uuid.uuid1())
        name = resource.get("name")
        if self._get_by_name(resource_type, name):
            raise Exception("Ambiguous '{}' '{}'".format(resource_type, name))
        resource["id"] = id
        resource["revision_number"] = "0"
        self.inventory.get(resource_type)[resource["id"]] = resource
        self.notifier.notify(resource_type, resource, operation=self.notifier.ADD)

    def _update(self, resource_type, resource):
        name = resource.get("name")
        old_resource = self._get_by_name(resource_type, name)
        revision_number = int(old_resource.get("revision_number", 0))
        resource["revision_number"] = str(revision_number + 1)
        old_resource.update(resource)
        self.notifier.notify(resource_type, old_resource, operation=self.notifier.UPDATE)

    def _delete(self, resource_type, name):
        resource = self._get_by_name(resource_type, name)
        if resource:
            del self.inventory[resource_type][resource["id"]]
            self.notifier.notify(resource_type, resource, operation=self.notifier.DELETE)

    def reload_inventory(self, inventory=None):
        self.inventory = (
            inventory
            if inventory
            else {self.PORT: {}, self.QOS: {}, self.SECURITY_GROUP: {}, self.SECURITY_GROUP_RULE: {}, self.NETWORK: {}}
        )

    def register(self, notifier):
        self.notifier = notifier

    def get_by_id(self, resource_type, id):
        resource = self.inventory.get(resource_type, {}).get(id)
        return copy.deepcopy(resource) if resource else None

    def get_all(self, resource_type):
        return copy.deepcopy(list(self.inventory.get(resource_type, {}).items()))

    def port_create(
        self,
        name,
        segmentation_id,
        parent_name=None,
        qos_name=None,
        security_group_names=[],
        address_bindings=[],
        allowed_address=[],
    ):
        self._add(
            self.PORT,
            {
                "name": name,
                "parent_id": self._get_by_name(self.PORT, parent_name).get("id") if parent_name else None,
                "mac_address": "fa:16:3e:e4:11:f1",
                "admin_state_up": "UP",
                "qos_policy_id": self._get_by_name(self.QOS, qos_name).get("id") if qos_name else None,
                "security_groups": [
                    self._get_by_name(self.SECURITY_GROUP, gname).get("id") for gname in security_group_names
                ],
                "address_bindings": address_bindings,
                "_allowed_address": allowed_address,
            },
        )
        return self._get_by_name(self.PORT, name)

    def port_update(self, name, qos_name=None, security_group_names=[]):
        self._update(
            self.PORT,
            {
                "name": name,
                "qos_policy_id": self._get_by_name(self.QOS, qos_name).get("id") if qos_name else None,
                "security_groups": [
                    self._get_by_name(self.SECURITY_GROUP, gname).get("id") for gname in security_group_names
                ],
            },
        )
        return self._get_by_name(self.PORT, name)

    def port_delete(self, name):
        self._delete(self.PORT, name)

    def qos_create(self, name):
        self._add(self.QOS, {"name": name, "rules": []})
        return self._get_by_name(self.QOS, name)

    def qos_update(self, name, dscp=None, direction=None, max_kbps=None, max_burst_kbps=None):
        rules = []
        if dscp:
            rules.append({"dscp_mark": dscp})

        if direction:
            rules.append({"direction": direction, "max_kbps": max_kbps, "max_burst_kbps": max_burst_kbps})

        self._update(self.QOS, {"name": name, "rules": rules})
        return self._get_by_name(self.PORT, name)

    def qos_delete(self, name):
        self._delete(self.QOS, name)

    def security_group_create(self, name, tags=[]):
        self._add(
            self.SECURITY_GROUP,
            {
                "name": name,
                "tags": tags,
            },
        )
        return self._get_by_name(self.SECURITY_GROUP, name)

    def security_group_update(self, name, tags=[]):
        self._update(self.SECURITY_GROUP, {"name": name, "tags": tags})
        return self._get_by_name(self.SECURITY_GROUP, name)

    def security_group_rule_add(
        self,
        sg_name,
        rule_name,
        protocol=None,
        ethertype=None,
        direction=None,
        remote_group_id=None,
        remote_ip_prefix=None,
        port_range_min=None,
        port_range_max=None,
    ):

        name = "{}-{}".format(sg_name, rule_name)

        sg = self._get_by_name(self.SECURITY_GROUP, sg_name)

        self._add(
            self.SECURITY_GROUP_RULE,
            {
                "name": name,
                "ethertype": ethertype,
                "direction": direction,
                "remote_group_id": remote_group_id,
                "remote_ip_prefix": remote_ip_prefix,
                "security_group_id": sg.get("id"),
                "port_range_min": port_range_min,
                "port_range_max": port_range_max,
                "protocol": protocol,
            },
        )

        # Update security group version of rule update
        self._update(self.SECURITY_GROUP, {"name": sg_name})

        return self._get_by_name(self.SECURITY_GROUP_RULE, name)

    def security_group_rule_delete(self, sg_name, rule_name):
        name = "{}-{}".format(sg_name, rule_name)
        self._delete(self.SECURITY_GROUP_RULE, name)

        # Update security group version of rule delete
        self._update(self.SECURITY_GROUP, {"name": sg_name})

    def security_group_delete(self, name):
        self._delete(self.SECURITY_GROUP, name)

    def network_create(self, segmentation_id):
        self.notifier.rpc.realizer.network(segmentation_id)

    def port_bind(self, name, segmentation_id):
        port = self._get_by_name(NeutronMock.PORT, name)

        vif = self.notifier.rpc.realizer.network(segmentation_id)

        if not vif.get("external-id"):
            raise Exception("Unable to bind Port:{} VIF:{}".format(name, vif))

        client = self.notifier.rpc.realizer.mngr_provider.client
        client.post("/api/v1/logical-ports", data={
            "logical_switch_id": vif.get("external-id"),
            "display_name": port.get("id"),
            "attachment": {
                "attachment_type": "VIF",
                "id": port.get("id")
            },
            "admin_state": "UP"
        })

        port["vif_details"] = vif

    def test_synchronous_port_create(self, name, segmentation_id):
        port = self._get_by_name(NeutronMock.PORT, name)
        network_segments = [
            {
                "id": "57a75c56-5c77-4650-a93c-d9e66e0316af",
                "network_type": "vlan",
                "physical_network": "physnet1",
                "segmentation_id": segmentation_id,
                "network_id": "11208e2b-8662-4c99-a303-3d71b39e165c",
            }
        ]
        self.notifier.notify(self.NETWORK, {"current": port, "network_segments": network_segments}, None)


class TestNSXv3ServerRpcApi(object):
    def __init__(self, inventory):
        self.inventory = inventory

    def _get_revisions(self, resource_type):
        id_o = self.inventory.get_all(resource_type)
        return [(id, o.get("revision_number"), None) for id, o in id_o]

    def get_qos_policies_with_revisions(self, limit, offset):
        qos_policies = set()
        for _, port in self.inventory.get_all(NeutronMock.PORT):
            qos_id = port.get("qos_policy_id")
            if qos_id:
                qos_policies.add(qos_id)

        effective_qos_policies = []
        for id, rev, cursor in self._get_revisions(NeutronMock.QOS):
            if id in qos_policies:
                effective_qos_policies.append((id, rev, cursor))

        return effective_qos_policies

    def get_ports_with_revisions(self, limit, offset):
        return self._get_revisions(NeutronMock.PORT)

    def get_security_groups_with_revisions(self, limit, offset):
        sgs = set()
        for _, port in self.inventory.get_all(NeutronMock.PORT):
            port_sgs = port.get("security_groups")
            if port_sgs:
                sgs.update(port_sgs)

        effective_sgs = []
        for id, rev, cursor in self._get_revisions(NeutronMock.SECURITY_GROUP):
            if id in sgs:
                effective_sgs.append((id, rev, cursor))
        return effective_sgs

    def has_security_group_used_by_host(self, os_id):
        sgs = set()
        for _, port in self.inventory.get_all(NeutronMock.PORT):
            port_sgs = port.get("security_groups")
            if port_sgs:
                sgs.update(port_sgs)
        if os_id in sgs:
            return True

        for _, rule in self.inventory.get_all(NeutronMock.SECURITY_GROUP_RULE):
            if rule.get("remote_group_id") == os_id and rule.get("security_group_id") in sgs:
                return True
        return False

    def get_security_group_port_ids(self, os_id):
        ports = set()
        for port_id, port in self.inventory.get_all(NeutronMock.PORT):
            port_sgs = port.get("security_groups")
            if port_sgs and os_id in port_sgs:
                ports.update(port_id)
        return ports

    def get_security_group_members_effective_ips(self, os_id):
        sg = self.inventory.get_by_id(NeutronMock.SECURITY_GROUP, os_id)
        if not sg:
            return []
        effective_ips = []
        id_o = self.inventory.get_all(NeutronMock.PORT)
        for _, o in id_o:
            if os_id in o.get("security_groups"):
                ips_bindings = [b["ip_address"] for b in o.get("address_bindings", [])]
                ips_allowed = o.get("_allowed_address")
                if ips_bindings:
                    effective_ips.extend(ips_bindings)
                if ips_allowed:
                    effective_ips.extend(ips_allowed)
        return effective_ips

    def get_security_group(self, os_id):
        sg = self.inventory.get_by_id(NeutronMock.SECURITY_GROUP, os_id)
        if not sg:
            return None
        id_o = self.inventory.get_all(NeutronMock.PORT)
        sg["ports"] = [o.get("id") for _, o in id_o if os_id in o.get("security_groups")]
        return sg

    def get_rules_for_security_group_id(self, os_id):
        id_o = self.inventory.get_all(NeutronMock.SECURITY_GROUP_RULE)
        return [o for _, o in id_o if os_id == o.get("security_group_id")]

    def get_port(self, id):
        return self.inventory.get_by_id(NeutronMock.PORT, id)

    def get_port_with_children(self, id):
        # TODO: return some real children
        port = self.inventory.get_by_id(NeutronMock.PORT, id)
        return port.update({
            "child_port_ids": []
        }) if port else None

    def get_qos(self, os_id):
        """
        Return QoS only if associated with port
        """
        id_o = self.inventory.get_all(NeutronMock.PORT)
        if [o for _, o in id_o if o.get("qos_policy_id") == os_id]:
            return self.inventory.get_by_id(NeutronMock.QOS, os_id)

    def has_security_group_logging(self, security_group_id):
        return security_group_id is not None
