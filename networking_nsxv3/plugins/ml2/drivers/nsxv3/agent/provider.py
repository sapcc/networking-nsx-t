import abc


class Provider:
    """
    Provider interface used for realization of OpenStack objects 
    """

    __metaclass__ = abc.ABCMeta

    PORT = "Port"
    QOS = "QoS"
    SG_MEMBERS = "Security Group (Members)"
    SG_RULES = "Security Group (Rules)"
    SG_RULE = "Rule"
    NETWORK = "Network"

    @abc.abstractmethod
    def metadata_refresh(self, resource_type):
        """
        Fetch fresh metadata out from the provider
        """

    @abc.abstractmethod
    def metadata(self, resource_type, os_id):
        """
        Get metadata for a resource from cached metadata
        :resource_type: str -- One of the RESOURCE types
        :os_id: str -- OpenStack resource ID
        :return: {"os_id": (self, provider_id, revision_number)}
        """

    @abc.abstractmethod
    def outdated(self, resource_type, os_meta):
        """
        Get outdated OpenStack IDs for a resource
        :resource_type: str -- One of the RESOURCE types
        :os_meta: {os_id:os_revision} -- OpenStack resource ID
        :return: (set(<outdated>), set(<current>)) -- Outdated OpenStack IDs
        """
    
    @abc.abstractmethod
    def age(self, resource_type, os_ids):
        """
        Get OpenStack resources IDs and their provider last updated age
        :resource_type: str -- One of the RESOURCE types
        :os_ids: list(<os_ids>) -- OpenStack resource IDs
        :return: {os_id:provider_age} -- OpenStack resource ID and provider age
        """

    @abc.abstractmethod
    def port_realize(self, os_port, delete=False):
        """
        Realize OpenStack Port in provider

        Port := {
            "id": <GUID>,
            "revision_number": <Number>,
            "parent_id": <ID>,
            "mac_address": <MAC>,
            "admin_state_up": UP|DOWN,
            "qos_policy_id": <QoS ID>,
            "security_groups": [<Security Group ID>, ...],
            "address_bindings": [<IP>, ...],
            "vif_details": {
                "nsx-logical-switch-id": "<ID>",
                "segmentation_id": "<VLAN>"
            }
        }

        :os_port: Port -- OpenStack Port
        :delete: bool -- If True will remove Port
        """

    @abc.abstractmethod
    def qos_realize(self, os_qos, delete=False):
        """
        Realize OpenStack QoS in provider

        QoS := {
            "id": <GUID>,
            "revision_number": <Number>,
            "name": <str>,
            "rules": [
                {
                    "dscp_mark": "<Number>" 
                } |
                {
                    "direction": "ingress|egress", 
                    "max_kbps": "<Float>", 
                    "max_burst_kbps": "<Float>"
                }, ...
            ]
        }

        :os_qos: QoS -- OpenStack QoS Policy
        :delete: bool -- If True will remove QoS
        """

    @abc.abstractmethod
    def sg_members_realize(self, os_sg, delete=False):
        """
        Realize OpenStack Security Group Members in provider

        SG_Members := {
            "id": <GUID>,
            "cidrs": [<CIDR, ...>],
            "revision_number": "<Number>"
        }

        :os_sg: SG_Members -- OpenStack Security Group Members
        :delete: bool -- If True will remove Security Group Members
        """

    @abc.abstractmethod
    def sg_rules_realize(self, os_sg, delete=False):
        """
        Realize OpenStack Security Group Rules in provider

        SG_Rules := {
            "id": <GUID>,
            "revision_number": <Number>,
            "tags": [<str>, ...],
            "rules": [
                {
                    "id": <GUID>,
                    "ethertype": "IPv4|IPv6",
                    "direction": "ingress|egress",
                    "remote_group_id": <GUID>,
                    "remote_ip_prefix": <CIDR>,
                    "security_group_id": <GUID>,
                    "port_range_min": <Number>,
                    "port_range_max": <Number>,
                    "protocol": "icmp|tcp|udp|<Number>",
                }, ...
            ]
        }

        :os_sg: SG_Rules -- OpenStack Security Group Rules
        :delete: bool -- If True will remove Security Group Rules
        """

    def network_realize(self, segmentation_id):
        """
        Realize OpenStack Network in provider 

        :segmentation_id: number - VLAN network segment ID
        """

    @abc.abstractmethod
    def sanitize(self, slice):
        """
        Mark provider resources target of cleanup.

        :slice: number - the number of objects that can be cleaned up at this time
        :returns: (list, function) - list of IDs target of removal and remove function accepting single ID
        """
    