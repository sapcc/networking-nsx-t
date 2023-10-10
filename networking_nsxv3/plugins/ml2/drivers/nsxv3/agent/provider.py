import abc
import time
from oslo_config import cfg
from oslo_log import log as logging
from typing import Callable, Dict, List, Set, Tuple

from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.client_nsx import Client

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class ResourceMeta(abc.ABC):

    def __init__(self, id: str, rev: List[str], age: int, revision: int, last_modified_time: int):
        self.id: str = id
        self.unique_id: str = id
        self.rev: List[str] = rev
        self.age: int = age
        self.revision: int = revision
        self.last_modified_time: int = last_modified_time
        self._duplicates = []

    def add_ambiguous(self, resource):
        self._duplicates.append(resource)

    def get_all_ambiguous(self):
        return self._duplicates


class Resource(abc.ABC):

    @property
    @abc.abstractclassmethod
    def is_managed(self) -> bool:
        """Indicates if the resource is managed by the NSX-T Agent

        Returns:
            bool: True if managed
        """

    @property
    @abc.abstractclassmethod
    def type(self) -> str:
        """NSX-T Resource Type

        Returns:
            str: Object's property - 'resource_type'
        """

    @property
    @abc.abstractclassmethod
    def id(self) -> str:
        """NSX-T Resource ID

        Returns:
            str: Object's property - 'id'
        """

    @property
    @abc.abstractclassmethod
    def unique_id(self) -> str:
        """NSX-T Resource ID

        Returns:
            str: Object's property - 'unique_id'
        """

    @property
    @abc.abstractclassmethod
    def has_valid_os_uuid(self) -> bool:
        """Indicates if the resource has valid UUID according to ISO/IEC 11578:1996

        Returns:
            bool: True if valid
        """

    @property
    @abc.abstractclassmethod
    def os_id(self) -> str:
        """OpenStack Resource ID

        Returns:
            str: Object's property - 'id'
        """

    @property
    @abc.abstractclassmethod
    def tags(self) -> dict:
        """NSX-T Resource Tags

        Returns:
            dict: {
                "<TAG_SCOPE>": [<TAG>, <TAG> , ...]
            }
        """

    @property
    @abc.abstractclassmethod
    def meta(self) -> ResourceMeta:
        """Custom Resource Metadata

        Returns:
            ResourceMeta: Resource Metadata
        """


class Meta(object):
    """
    Resource mapping between OpenStack and Provider objects

    Meta is refreshed by __enter__, reset, add, __exit__
    """

    def __init__(self):
        self.meta = dict()
        self.meta_transaction = None

    def __enter__(self):
        self.meta_transaction = dict()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.meta.update(self.meta_transaction)
        self.meta_transaction = None

    def reset(self):
        self.meta = dict()

    def keys(self) -> List[str]:
        keys = self.meta.keys()
        if self.meta_transaction:
            keys += self.meta_transaction.keys()
        return keys

    def add(self, resource: Resource) -> ResourceMeta:
        old_meta = self.meta.get(resource.os_id)
        if resource.type == "LogicalSwitch" and old_meta:
            LOG.critical("Resource type: %s, OS_ID: %s, ID: %s, Meta: %s",
                         resource.type, resource.os_id, resource.id, resource.meta)
            # self.meta[resource.os_id] = resource.meta
            # return resource.meta

        if old_meta:
            old_meta.add_ambiguous(resource.meta)
            LOG.warning("Duplicate resource with OS_ID: %s ID: %s", resource.os_id, resource.id)
        elif not resource.os_id:
            LOG.warning("Invalid object %s without OS_ID, ID: %s", resource.type, resource.id)
        else:
            if resource.is_managed:
                self.meta[resource.os_id] = resource.meta
        return old_meta

    def update(self, resource: Resource) -> ResourceMeta:
        meta: ResourceMeta = resource.meta
        old_meta: ResourceMeta = self.meta.get(resource.os_id)
        if old_meta:
            for m in old_meta.get_all_ambiguous():
                meta.add_ambiguous(m)
            self.meta[resource.os_id] = meta
        else:
            if resource.is_managed:
                self.add(resource)
        return old_meta

    def get(self, os_id) -> ResourceMeta:
        os_id = str(os_id)
        meta = self.meta.get(os_id)
        if not meta and self.meta_transaction:
            meta = self.meta_transaction.get(os_id)
        return meta

    def rm(self, os_id) -> ResourceMeta:
        os_id = str(os_id)
        meta = self.meta.get(os_id)
        if meta:
            del self.meta[os_id]
        if self.meta_transaction:
            meta = self.meta_transaction.rm(os_id)
        return meta


class MetaProvider(object):
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.meta = Meta()


class Provider(abc.ABC):
    """Provider interface used for realization of OpenStack objects
    """

    QOS = "Segment QoS"
    NETWORK = "Segment"
    PORT = "SegmentPort"
    ADDR_GROUPS = "Address Group"
    SG_MEMBERS = "Security Group (Members)"
    SG_RULES = "Security Group (Rules)"
    SG_RULE = "Rule"
    SG_RULES_REMOTE_PREFIX = "Security Group (Rules Remote IP Prefix)"

    def __init__(self, client: Client):
        super(Provider, self).__init__()

        self.provider: str = ""
        self.client: Client = client
        self._metadata: Dict[str, MetaProvider] = self._metadata_loader()
        self.zone_name: str = cfg.CONF.NSXV3.nsxv3_transport_zone_name
        self.zone_id, self.zone_tags = self._load_zones()
        if not self.zone_id:
            raise Exception("Not found Transport Zone {}".format(self.zone_name))

    def orphan_ports_tmout_passed(self, stamp: int) -> bool:
        delay = cfg.CONF.NSXV3.nsxv3_remove_orphan_ports_after
        return (time.time() - int(stamp)) / 3600 > delay

    @abc.abstractmethod
    def _load_zones(self) -> Tuple[str, List[Dict[str, str]]]:
        """Load Transport Zone ID and zone tags

        Returns:
            str: Transport Zone ID, TZ tags list
        """

    @abc.abstractclassmethod
    def get_port(self, os_id: str) -> Tuple[ResourceMeta, dict] or None:
        """Get Port from NSX-T

        Args:
            os_id (str): Openstack Port ID

        Returns:
            Tuple[ResourceMeta, dict]: Resource meta, NSX-T json obj
        """

    @abc.abstractmethod
    def _create_sg_provider_rule_remote_prefix(self, cidr: str) -> dict:
        """"""

    @abc.abstractmethod
    def _metadata_loader(self) -> Dict[str, MetaProvider]:
        """Metadata loader"""

    @abc.abstractmethod
    def metadata_refresh(self, resource_type: str) -> None:
        """
        Fetch fresh metadata out from the provider
        """

    @abc.abstractmethod
    def metadata_delete(self, resource_type: str, os_id: str) -> None:
        """
        Delete obsolated data
        """

    @abc.abstractmethod
    def metadata(self, resource_type: str, os_id: str) -> ResourceMeta:
        """
        Get metadata for a resource from cached metadata
        :resource_type: str -- One of the RESOURCE types
        :os_id: str -- OpenStack resource ID
        :return: {"os_id": (self, provider_id, revision_number)}
        """

    @abc.abstractmethod
    def metadata_update(self, resource_type: str, os_id: str) -> ResourceMeta:
        """
        Update and get metadata for a resource from cached metadata
        :resource_type: str -- One of the RESOURCE types
        :os_id: str -- OpenStack resource ID
        :return: {"os_id": (self, provider_id, revision_number)}
        """

    @abc.abstractmethod
    def outdated(self, resource_type: str, os_meta: Dict[str, dict]) -> Tuple[Set[str], Set[str]]:
        """
        Get outdated OpenStack IDs for a resource
        :resource_type: str -- One of the RESOURCE types
        :os_meta: {os_id:os_revision} -- OpenStack resource ID
        :return: (set(<outdated>), set(<current>)) -- Outdated OpenStack IDs
        """

    @abc.abstractmethod
    def age(self, resource_type: str, os_ids: List[str]) -> List[Tuple[str, str, int]]:
        """
        Get OpenStack resources IDs and their provider last updated age
        :resource_type: str -- One of the RESOURCE types
        :os_ids: list(<os_ids>) -- OpenStack resource IDs
        :return: [(resource_type, os_id, age)] -- OpenStack resource ID and provider age
        """

    @abc.abstractmethod
    def port_realize(self, os_port: dict, delete=False):
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
    def qos_realize(self, os_qos: dict, delete=False):
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
    def sg_members_realize(self, os_sg: dict, delete=False):
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
    def sg_rules_realize(self, os_sg: dict, delete=False, logged=False):
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

    def network_realize(self, segmentation_id: int):
        """
        Realize OpenStack Network in provider

        :segmentation_id: number - VLAN network segment ID
        """

    @abc.abstractmethod
    def sanitize(self, slice: int) -> List[Tuple[str, Callable[[str], None]]]:
        """
        Get provider resources target of cleanup.

        :slice: number - the number of objects that can be cleaned up at this time
        :returns: list(id, callback) - where callback is a function accepting the ID
        """

    @abc.abstractmethod
    def enable_policy_logging(self, log_obj: dict):
        """
        Enable policy logging in provider

        :log_obj: dict - policy logging object
        """

    @abc.abstractmethod
    def disable_policy_logging(self, log_obj: dict):
        """
        Disable policy logging in provider

        :log_obj: dict - policy logging object
        """

    @abc.abstractmethod
    def update_policy_logging(self, log_obj: dict):
        """
        Update policy logging in provider

        :log_obj: dict - policy logging object
        """

    @abc.abstractmethod
    def address_group_realize(self, os_ag: dict, delete=False):
        """
        Realize OpenStack Address Group in provider

        :os_ag: dict - OpenStack Address Group
        :delete: bool - If True will remove Address Group
        """

    @abc.abstractmethod
    def get_port_meta_by_ids(self, port_ids: Set[str]) -> Set[ResourceMeta]:
        """
        Get Port metadata by IDs

        :port_ids: set - Port IDs
        :return: set - Port metadata
        """