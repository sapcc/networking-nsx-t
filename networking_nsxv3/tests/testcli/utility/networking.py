import openstack
import logging

logger = logging.getLogger(__name__)

def prepare_networks(con, networks):
    for network in networks:
        prepare_network(con=con,
                        net_name=network["SERVER_NET"],
                        subnet_name=network["SUBNET_NAME"],
                        subnet_range=network["SUBNET_RANGE"],
                        port_name=network["PORT"])

def prepare_network(con, net_name, subnet_name, subnet_range, port_name):
    create_network(con, net_name)
    create_subnet(con, net_name, subnet_name, subnet_range)
    create_port(con, net_name=net_name, port_name=port_name)


    #create router

##  openstack subnet create --network red --subnet-range 10.180.10.0/24 red_subnet
def create_subnet(con, net_name, subnet_name, net_subnet_range):
    subnet = con.network.find_subnet(subnet_name)

    if subnet == None:
        con.network.create_subnet(network_name_or_id=net_name, subnet_name=subnet_name, cidr=net_subnet_range, ip_version=4)
    else:
        logger.debug(f"subnet {subnet_name} is already there")


##openstack network create red
def create_network(con, net_name):
    net = con.network.find_network(net_name)

    if net == None:
        #create network if it does not exists
        con.network.create_network(name=net_name)
    else:
        logger.debug(f"network {net_name} is already there")

#os port create --network red red_parent_port
def create_port(con, port_name, net_name):
    network = con.network.find_network(net_name)
    port = con.network.find_port(port_name)
    if port == None:
        con.network.create_port(network_id=network.id, name=port_name)
    else:
        logger.debug(f"port {port_name} is already there")

def create_trunk(con, trunk_config):
    trunk_name = trunk_config.get("NAME")
    parent_port_name = trunk_config.get("PARENT_PORT")
    segmentation_id = trunk_config.get("SEGMENTATION_ID")
    child_port_name = trunk_config.get("CHILD_PORT")
    segmentation_type = "vlan"

    trunk = con.network.find_trunk(trunk_name)

    parent_port = con.network.find_port(parent_port_name)
    if trunk == None and not parent_port == None:
        trunk = con.network.create_trunk(name=trunk_name,
                                 port_id=parent_port.id)
        if not child_port_name == None:
            attatch_subport_to_trunk(con, child_port_name=child_port_name, trunk_name=trunk_name, segmentation_id=segmentation_id, segmentation_type=segmentation_type)
    else:
        logger.debug(f"trunk {trunk_name} is already there ")

def attatch_subport_to_trunk(con, trunk_config):
    trunk_name = trunk_config.get("NAME")
    parent_port_name = trunk_config.get("PARENT_PORT")
    segmentation_id = trunk_config.get("SEGMENTATION_ID")
    child_port_name = trunk_config.get("CHILD_PORT")
    segmentation_type = "vlan"

    trunk = con.network.find_trunk(trunk_name)

    child_port = con.network.find_port(child_port_name)
    if not trunk == None and not child_port == None and not segmentation_id == None:
        logger.debug(f"add subport {child_port.name} to trunk {trunk_name}")
        subports = [
            {
                "segmentation_id": segmentation_id,
                "port_id": child_port.id,
                "segmentation_type": segmentation_type
            }
        ]
        con.network.add_trunk_subports(trunk=trunk,subports=subports)
    else:
        logger.debug("subport %s not added to trunk %s " % (child_port_name, trunk_name))

def delete_trunk(con, trunk_config):
    trunk = con.network.find_trunk(trunk_config["NAME"])

    if not trunk == None:
        con.network.delete_trunk(trunk.id)
        parent_port_id = trunk.port_id
        subports = trunk.sub_ports

        con.network.delete_port(port=parent_port_id)
        for subport in subports:
            con.network.delete_port(port=subport["port_id"])
    else:
        logger.debug("no trunk to clean up")