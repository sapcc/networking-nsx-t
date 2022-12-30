import logging
import openstack

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_policy import Provider as PolicyProvider
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.provider_nsx_mgmt import Provider as MgmtProvider
from networking_nsxv3.tests.testcli.exceptions import ServerNotActive, TrunkNotActive, PortNotActive, LogicalPortNotFound

LOG = logging.getLogger(__name__)




class e2eTest():
    def __init__(self):
        self.validator = None

    def _connect_to_openstack(self):
        return openstack.connect()

    def _prepare_test(self):
        LOG.info("Prepare test")

    def _prepare_server_conf(self, server_name, config):
        server = config.get(server_name)
        server["IMAGE"] = config.get("IMAGE")
        server["FLAVOR"] = config.get("FLAVOR")
        server["KEY"] = config.get("KEY")
        return server


    def run_test(self):
        LOG.info("Run test")



class e2eTestValidator():

    def _validate_port(self,con, ports):
        for port in ports:
            p = con.network.find_port(port.get('PORT'))
            if p:
                if not p.status == "ACTIVE":
                    raise PortNotActive(p.name, p.status)


    def _validate_server(self,con, servers):
        for server in servers:
            s = con.compute.find_server(server.get("NAME"))
            s = con.compute.get_server(s.id)
            if not s.status == "ACTIVE":
                raise ServerNotActive(s.name, s.status)

    def _validate_trunk(self, con, trunk):
        trunk = con.network.find_trunk(trunk.get("NAME"))

        if not trunk.status == "ACTIVE":
            raise TrunkNotActive(trunk.name, trunk.status)

    def _validate_nsxt_ports(self, con, ports):
        policy_provider = PolicyProvider()
        mgmt_provider = MgmtProvider()

        for port in ports:
            p = con.network.find_port(port.get('PORT'))
            policy_lp = policy_provider.get_port(p.id)
            mgmt_lp = mgmt_provider.get_port(p.id)


            if mgmt_lp == None and policy_lp == None:
                raise LogicalPortNotFound(p.name, p.id)

