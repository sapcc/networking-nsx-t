import logging
import openstack
import operator
from networking_nsxv3.common import config

from networking_nsxv3.common import config
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import Provider as PolicyProvider
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_mgmt import Provider as MgmtProvider
from networking_nsxv3.tests.integration.utility.exceptions import ServerNotActive, WrongTrunkStatus, PortNotActive, \
    WrongLogicalPortBinding

LOG = logging.getLogger(__name__)


class e2eTest():
    def __init__(self):
        self.validator = None

    def _connect_to_openstack(self):
        return openstack.connect()


class e2eTestValidator():
    ops = {'>': operator.gt,
           '<': operator.lt,
           '>=': operator.ge,
           '<=': operator.le,
           '!=': operator.ne,
           '==': operator.eq}


    def _convert_to_list(self, conf):
        tmp = []
        if isinstance(conf, dict):
            tmp.append(conf)
            return tmp
        else:
            return conf

    def _validate_port(self, con, ports):
        ports = self._convert_to_list(ports)

        for port in ports:
            p = con.network.find_port(port.get('PORT'))
            if p:
                if not p.status == "ACTIVE":
                    return PortNotActive(p.name, p.status)
        return None

    def _validate_server(self, con, servers):
        ports = self._convert_to_list(servers)
        for server in servers:
            s = con.compute.find_server(server.get("NAME"))
            s = con.compute.get_server(s.id)
            if not s.status == "ACTIVE":
                return ServerNotActive(s.name, s.status)
        return None

    def _validate_trunk(self, con, cfg_trunk, status="ACTIVE", expr="=="):
        trunk = con.network.find_trunk(cfg_trunk.get("NAME"))

        if not self.ops[expr](trunk.status, status):
            return WrongTrunkStatus(trunk.name, trunk.status)
        return None

    def validate_nsxt_ports_by_port_id(self, ports, expr="=="):
        policy_provider = PolicyProvider()
        mgmt_provider = MgmtProvider()

        for port in ports:
            _, policy_lp = policy_provider.get_port(port.id)
            mgmt_lp = mgmt_provider.get_port(port.id)

            if self.ops[expr](mgmt_lp, None) and self.ops[expr](policy_lp, None):
                return WrongLogicalPortBinding(port.name, port.id)
        return None


    def validate_nsxt_ports_by_server_name(self, con, servers, expr="=="):

        servers = self._convert_to_list(servers)

        ports = []
        for server in servers:
            server = con.compute.find_server(server.get('NAME'))
            for port in con.network.ports(device_id=server.id):
                ports.append(port)
        return self.validate_nsxt_ports_by_port_id(ports, expr)


    def validate_success(self, con, server_objects, trunk):
        _errors = []

        tmp_err = self.validate_nsxt_ports_by_server_name(con, server_objects)
        if tmp_err:
            _errors.append(str(tmp_err))

        tmp_err = self._validate_port(con, server_objects)
        if tmp_err:
            _errors.append(str(tmp_err))

        tmp_err = self._validate_trunk(con, trunk)
        if tmp_err:
            _errors.append(str(tmp_err))

        return not _errors,  "\n{}".format("\n".join(_errors))

