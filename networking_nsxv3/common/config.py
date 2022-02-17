from neutron.conf import service
from oslo_config import cfg

DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []
DEFAULT_TUNNEL_TYPES = []

nsxv3_dfw_connectivity_strategy = [
    "NONE",
    "BLACKLIST",
    "BLACKLIST_ENABLE_LOGGING",
    "WHITELIST",
    "WHITELIST_ENABLE_LOGGING"
]

agent_opts = [
    cfg.StrOpt(
        'agent_id',
        default='nsxm-l-01a.corp.local',
        help="NSXv3 Manager ID"
    ),
    cfg.IntOpt(
        'locking_coordinator_url',
        default=None,
        help='Url of the distributed locking coordinator. None for local.'
    ),
    # Provided by neutron.plugins.ml2.drivers.agent._agent_manager_base
    # (duplicate option)
    # cfg.IntOpt(
    #     'polling_interval',
    #     default=5,
    #     help="NSXv3 Manager pooling interval in seconds."
    # ),
    # cfg.IntOpt(
    #     'quitting_rpc_timeout',
    #     default=5,
    #     help="NSXv3 agent RPC timeout in seconds."
    # ),
    cfg.IntOpt(
        'rpc_max_records_per_query',
        default=1000,
        help="Neutron RPC maximum records per query."
    ),
    cfg.IntOpt(
        'agent_prometheus_exporter_port',
        default='8000',
        help="Prometheus exporter port"
    ),
    cfg.IntOpt(
        'synchronization_queue_size',
        default=20,
        help="The maximum amount of objects witing in the queue for update."
    ),
    cfg.BoolOpt(
        'force_mp_to_policy',
        default=False,
        help="Force NSX-T Manager API objects to be promoted to Policy API objects."
    )
]

agent_cli_opts = [
    cfg.MultiStrOpt('neutron_security_group_id',
                    default=[],
                    help="Neutron Security Group IDs synchronization targets. Use '*' to match all."
                    ),
    cfg.MultiStrOpt('neutron_port_id',
                    default=[],
                    help="Neutron Port IDs synchronization targets. Use '*' to match all."),
    cfg.MultiStrOpt('neutron_qos_policy_id',
                    default=[],
                    help="Neutron QoS Policy IDs synchronization targets. Use '*' to match all.")
]

nsxv3_opts = [
    cfg.IntOpt(
        'nsxv3_connection_retry_count',
        default=10,
        help='NSXv3 Manager client connection retry-count.'
    ),
    cfg.IntOpt(
        'nsxv3_connection_retry_sleep',
        default=5,
        help='NSXv3 Manager client connection retry-sleep in seconds.'
    ),
    cfg.IntOpt(
        'nsxv3_request_timeout',
        default=60,
        help='NSXv3 Manager client native request timeout in seconds.'
    ),
    cfg.IntOpt(
        'nsxv3_realization_timeout',
        default=900,
        help='NSXv3 Manager client (policy) realization timeout.'
    ),
    cfg.IntOpt(
        'nsxv3_operation_retry_count',
        default=3,
        help='NSXv3 Manager failed operation retry-count.'
    ),
    cfg.IntOpt(
        'nsxv3_operation_retry_sleep',
        default=5,
        help='NSXv3 Manager failed operation retry-sleep in seconds.'
    ),
    cfg.IntOpt(
        'nsxv3_requests_per_second',
        default=90,
        help='''Requests per second to NSXv3 Manager. NSXv3 limit 100 req/s'''
    ),
    cfg.IntOpt(
        'nsxv3_requests_per_second_timeout',
        default=5,
        help='''Number of seconds trying to send the request to NSXv3 Manager.'''
    ),
    cfg.IntOpt(
        'nsxv3_concurrent_requests',
        default=40,
        help='''Concurrent requests to NSXv3 Manager. NSXv3 limit 40'''
    ),
    cfg.StrOpt(
        'nsxv3_login_user',
        default='admin',
        help="NSXv3 Manager login user"
    ),
    cfg.StrOpt(
        'nsxv3_login_password',
        default='',
        secret=True,
        help="NSXv3 Manager login password."
    ),
    cfg.HostAddressOpt(
        'nsxv3_login_hostname',
        default='nsxm-l-01a.corp.local',
        help="NSXv3 Manager hostname or IP address."
    ),
    cfg.PortOpt(
        'nsxv3_login_port',
        default=443,
        help="NSXv3 Manager port."
    ),
    cfg.StrOpt(
        'nsxv3_transport_zone_name',
        default='openstack-tz',
        help="NSXv3 Manager transport zone name."
    ),
    cfg.StrOpt(
        'nsxv3_spoof_guard_switching_profile',
        default='nsx-default-spoof-guard-vif-profile',
        help="NSXv3 Spoof guard profile to use (or create if not existing)."
    ),
    cfg.StrOpt(
        'nsxv3_ip_discovery_switching_profile',
        default='nsx-default-ip-discovery-vlan-profile',
        help="NSXv3 ip discovery profile to use (or create if not existing)."
    ),
    cfg.BoolOpt(
        'nsxv3_suppress_ssl_warnings',
        default=True,
        help="NSXv3 Manager disables ssl host validation. [Development Mode]",
        deprecated_name='nsxv3_suppress_ssl_wornings'
    ),
    cfg.ListOpt(
        'nsxv3_managed_hosts',
        default=[],
        help="NSXv3 Managed hosts. List of vSphere cluster/host names."
    ),
    cfg.IntOpt(
        'nsxv3_max_records_per_query',
        default=1000,
        help="NSXv3 Managed maximum records per query request."
    ),
    cfg.IntOpt(
        'nsxv3_remove_orphan_ports_after',
        default=12,
        help="Remove NSX-T orphan ports not before configured hours."
    ),
    cfg.StrOpt(
        'nsxv3_dfw_connectivity_strategy',
        default='NONE',
        help="NSXv3 Manager DFW connectivity strategy: {}"
        .format(str(nsxv3_dfw_connectivity_strategy))
    ),
    cfg.BoolOpt(
        'nsxv3_default_policy_infrastructure_rules',
        default=False,
        help="Enable create of default infrastructure rules like ICMP allow, "
             "DHCP and Metadata Agent access"
    ),
    cfg.IntOpt(
        'mp_to_policy_retry_count',
        default=10,
        help="NSX-T Mp-to-Policy client migration request retry-count."
    ),
    cfg.IntOpt(
        'mp_to_policy_retry_sleep',
        default=2,
        help="NSX-T Mp-to-Policy client migration request retry-sleep in seconds."
    )
]

vsphere_opts = [
    cfg.StrOpt(
        'vsphere_login_username',
        default='administrator@vsphere.local',
        help="vSphere client login user"
    ),
    cfg.StrOpt(
        'vsphere_login_password',
        default='VMware1!',
        help="vSphere client login password."
    ),
    cfg.HostAddressOpt(
        'vsphere_login_hostname',
        default='vc-l-01a.corp.local',
        help="vSphere client hostname or IP address."
    ),
    cfg.BoolOpt(
        'vsphere_suppress_ssl_wornings',
        default=True,
        help="vSphere client disables ssl host validattion. [Development Mode]"
    ),
]


cfg.CONF.register_opts(agent_opts, "AGENT")
cfg.CONF.register_opts(agent_cli_opts, "AGENT_CLI")
cfg.CONF.register_opts(nsxv3_opts, "NSXV3")
cfg.CONF.register_opts(service.RPC_EXTRA_OPTS)
cfg.CONF.register_opts(vsphere_opts, "vsphere")
