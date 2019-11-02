from oslo_config import cfg

try:
    from neutron.conf.agent import common as config
except ImportError:
    from neutron.agent.common import config

DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []
DEFAULT_TUNNEL_TYPES = []

agent_opts = [
    cfg.StrOpt(
        'agent_id',
        default='nsxm-l-01a.corp.local',
        help="NSXv3 Manager ID"
    ),
    cfg.IntOpt(
        'sync_pool_size',
        default=10,
        help='Number of synchronization workers'
    ),
    cfg.IntOpt(
        'sync_queue_size',
        default=-1,
        help='The size of synchronization queue'
    ),
    cfg.IntOpt(
        'sync_requests_per_second',
        default=10,
        help='''Objects per second synchronizing OpenStack and NSXv3.'''
    ),
    cfg.IntOpt(
        'sync_full_schedule',
        default=24,
        help='''Full-sync schedule in hours between OpenStack and NSXv3.'''
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
        default=2000,
        help="Neutron RPC maximum records per query."
    ),
    cfg.BoolOpt(
        'enable_runtime_migration_from_dvs_driver',
        default=False,
        help="Enable runtime migration from DVS ML2 Driver."
    )
]

agent_cli_opts = [
    cfg.MultiStrOpt('neutron_security_group_id',
                    default=[],
                    help="Neutron Security Group IDs synchronization targets."
                    ),
    cfg.MultiStrOpt('neutron_port_id',
                    default=[],
                    help="Neutron Port IDs synchronization targets."),
    cfg.MultiStrOpt('neutron_qos_policy_id',
                    default=[],
                    help="Neutron QoS Policy IDs synchronization targets.")
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
    cfg.StrOpt(
        'nsxv3_login_user',
        default='admin',
        help="NSXv3 Manager login user"
    ),
    cfg.StrOpt(
        'nsxv3_login_password',
        default='VMware1!',
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
    cfg.BoolOpt(
        'nsxv3_enable_spoof_guard',
        default=False,
        help="NSXv3 Manager enables SpoofGuard protection."
    ),
    cfg.BoolOpt(
        'nsxv3_suppress_ssl_wornings',
        default=True,
        help="NSXv3 Manager disables ssl host validattion. [Development Mode]"
    ),
    cfg.ListOpt(
        'nsxv3_managed_hosts',
        default=[],
        help="NSXv3 Managed hosts. List of vSphere cluster/host names."
    ),
    cfg.IntOpt(
        'nsxv3_max_records_per_query',
        default=2000,
        help="Neutron RPC maximum records per query request."
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
cfg.CONF.register_opts(vsphere_opts, "vsphere")
config.register_agent_state_opts_helper(cfg.CONF)
