import openstack
import logging

logger = logging.getLogger(__name__)


def delete_servers(con: object, servers: object = []) -> object:
    # delete server
    logger.debug("delete servers")
    for s in servers:

        server = con.compute.find_server(s.get("NAME"))
        if not server == None:
            con.compute.delete_server(server)
            logger.debug(f"Deleted server {s.get('NAME')}")
        else:
            logger.debug(f"No server with name {s.get('NAME')} found.")


def create_servers(con, server_config):
    if isinstance(server_config, dict):
        tmp = server_config
        server_config = []
        server_config.append(tmp)

    servers = []
    for server in server_config:
        s = create_server(con, server_name=server["NAME"], port_name=server["PORT"], image=server['IMAGE'],
                          flavor=server["FLAVOR"], key_name=server["KEY"])
        servers.append(s)
    return servers


def create_server(con, server_name, port_name, image, flavor, key_name):
    logger.info(f"create server {server_name}  bind to port {port_name}")
    image = con.compute.find_image(image)
    flavor = con.compute.find_flavor(flavor)
    port = con.network.find_port(port_name)

    server = con.compute.create_server(
        name=server_name, image_id=image.id, flavor_id=flavor.id, key_name=key_name,
        networks=[{'port': port.id}]
    )
    return server


def change_port(con, server_name, new_port_name):
    new_port = con.network.find_port(new_port_name)
    server = con.compute.find_server(server_name)
    connected_ports = con.network.ports(device_id=server.id)

    stop_server(con, server_name)
    for p in connected_ports:
        logger.debug(f"Removing port {p.id} -- {p.name} from server {server.name}")
        con.compute.delete_server_interface(server=server, server_interface=p.id, ignore_missing=False)
    logger.debug(f"Adding port {new_port.name} -- {new_port.id} to server {server.name}")

    try:
        con.compute.create_server_interface(server=server, port_id=new_port.id)
        start_server(con, server_name)
    except openstack.exceptions.ConflictException as e:
        logger.error(e)


def start_server(con, server_name):
    server = con.compute.find_server(server_name)
    con.compute.start_server(server.id)
    wait_for_server(con=con, server=server, status="ACTIVE")


def stop_server(con, server_name):
    server = con.compute.find_server(server_name)
    con.compute.stop_server(server.id)
    wait_for_server(con=con, server=server, status="SHUTOFF")


def wait_for_server(con, servers, status="ACTIVE"):
    try:
        if isinstance(servers, list):
            for s in servers:
                logger.info(f"start waiting for server {s.name} turning into status {status}")
                server = con.compute.wait_for_server(s, status=status)
        else:
            logger.info(f"start wating for server {servers.name} turning into status {status}")
            server = con.compute.wait_for_server(servers, status=status)
    except openstack.exceptions.ResourceFailure as e:
        logger.error(f"could not start server {server} due to {e}")
