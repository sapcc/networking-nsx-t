
class ServerNotActive(Exception):
    def __init__(self, server_name, server_state):
        error_msg = f"Server {server_name} in state {server_state}"
        super().__init__(error_msg)

class TrunkNotActive(Exception):
    def __init__(self, trunk_name, trunk_status):
        error_msg = f"Server {trunk_name} in state {trunk_status}"
        super().__init__(error_msg)

class PortNotActive(Exception):
    def __init__(self,  port_name, port_status):
        error_msg = f"Port {port_name} in state {port_status}"
        super().__init__(error_msg)


class LogicalPortNotFound(Exception):
    def __init__(self,  port_name, port_id):
        error_msg = f"Logical port {port_name} with id {port_id} not found"
        super().__init__(error_msg)