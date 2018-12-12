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
        help='Number of threads doing synchronization in background (OS to NSXv3).'
    ),
    cfg.IntOpt(
        'locking_coordinator_url',
        default=None,
        help='Url of the distributed locking coordinator. None for local.'
    ),
    # Provided by neutron.plugins.ml2.drivers.agent._agent_manager_base (duplicate option)
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
        'db_max_records_per_query',
        default=2000,
        help="Neutron DB maximum rows per query request."
    )
]

nsxv3_opts = [
    cfg.IntOpt(
        'nsxv3_connection_retry_count',
        default=10,
        help='NSXv3 Manager client retry count on session/connection error.'
    ),
    cfg.IntOpt(
        'nsxv3_connection_retry_sleep',
        default=5,
        help='NSXv3 Manager client retry sleep on session/connection error in seconds.'
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
        'nsxv3_suppress_ssl_wornings',
        default=True,
        help="NSXv3 Manager connection disables ssl host validattion. [Development Mode]"
    ),
    cfg.ListOpt(
        'nsxv3_managed_hosts',
        default=[],
        help="NSXv3 Managed hosts. List of vSphere cluster/host names."
    ),
    cfg.IntOpt(
        'nsxv3_max_records_per_query',
        default=2000,
        help="Neutron DB maximum rows per query request."
    )
]


cfg.CONF.register_opts(agent_opts, "AGENT")
cfg.CONF.register_opts(nsxv3_opts, "NSXV3")
config.register_agent_state_opts_helper(cfg.CONF)
