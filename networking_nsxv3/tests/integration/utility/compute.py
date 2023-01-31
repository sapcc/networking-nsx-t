import openstack
import logging

LOG = logging.getLogger(__name__)


def delete_servers(con, server_configs):
    if isinstance(server_configs, dict):
        tmp = server_configs
        server_configs = []
        server_configs.append(tmp)

    servers = []
    for server_config in server_configs:
        server = con.compute.find_server(server_config.get("NAME"))
        if not server == None:
            servers.append(server)
            LOG.info(f"Try to delete server {server.name} with ID {server.id}")
            con.compute.delete_server(server)

        else:
            LOG.info(f"No server with name {server_config.get('NAME')} found.")
        return servers


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
    LOG.info(f"create server {server_name}  bind to port {port_name}")
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
        LOG.debug(f"Removing port {p.id} -- {p.name} from server {server.name}")
        con.compute.delete_server_interface(server=server, server_interface=p.id, ignore_missing=False)
    LOG.debug(f"Adding port {new_port.name} -- {new_port.id} to server {server.name}")

    try:
        con.compute.create_server_interface(server=server, port_id=new_port.id)
        start_server(con, server_name)
    except openstack.exceptions.ConflictException as e:
        LOG.error(e)


def start_server(con, server_name):
    server = con.compute.find_server(server_name)
    con.compute.start_server(server.id)
    wait_for_server(con=con, server=server, status="ACTIVE")


def stop_server(con, server_name):
    server = con.compute.find_server(server_name)
    con.compute.stop_server(server.id)
    wait_for_server(con=con, server=server, status="SHUTOFF")


def retry(times, exceptions):
    def decorator(func):
        def newfn(*args, **kwargs):
            attempt = 0
            while attempt < times:
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    LOG.warning(f"cleanup attemp {attempt}/{times} failed")
                    #LOG.warn(
                    #    'Exception thrown when attempting to run %s, attempt '
                    #    '%d of %d' % (func, attempt, times)
                    #)
                    attempt += 1

            if attempt >= times:
                LOG.error("cleanup failed - cloud not delete server after n times - shuttin down" )
                exit(1)
            return func(*args, **kwargs)
        return newfn
    return decorator


@retry(times=3, exceptions=(openstack.exceptions.ResourceFailure, openstack.exceptions.ResourceTimeout))
def wait_for_server_deletion(con=None, server_config=[]):
    servers = delete_servers(con, server_config)
    for s in servers:
        LOG.info(f"Wait for server deletion {s.name}  with id {s.id}" )
        con.compute.wait_for_delete(s)



def wait_for_server(con, servers, status="ACTIVE"):
    try:
        server_name = ""
        if isinstance(servers, list):
            for s in servers:
                server_name = s.name
                LOG.info(f"start waiting for server {s.name} turning into status {status}")
                con.compute.wait_for_server(s, status=status)
        else:
            server_name = servers.name
            LOG.info(f"start wating for server {servers.name} turning into status {status}")
            con.compute.wait_for_server(servers, status=status)
    except openstack.exceptions.ResourceFailure as e:
        LOG.error(f"could not start server {server_name} due to {e}")
        exit(1)
