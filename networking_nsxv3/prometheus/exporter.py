from prometheus_client import CollectorRegistry, start_http_server, Gauge
from networking_nsxv3.common.synchronization import Runner
from oslo_config import cfg
import time
import os
import eventlet

# Prometheus Metrics

REGISTRY = CollectorRegistry()

ACTIVE_QUEUE_SIZE = Gauge(
    'nsxv3_agent_active_queue_size', 
    'Active synchronization queue size', 
    ['nsxv3_manager_hostname'],
    registry=REGISTRY
    ).labels(nsxv3_manager_hostname=cfg.CONF.NSXV3.nsxv3_login_hostname)
PASSIVE_QUEUE_SIZE = Gauge(
    'nsxv3_agent_passive_queue_size', 
    'Passive synchronization queue size', 
    ['nsxv3_manager_hostname'],
    registry=REGISTRY
    ).labels(nsxv3_manager_hostname=cfg.CONF.NSXV3.nsxv3_login_hostname)


def nsxv3_agent_exporter(runner):
    nsxv3_hostname = cfg.CONF.NSXV3.nsxv3_login_hostname

    os.environ['PATH_INFO'] = "/metrics"
    start_http_server(cfg.CONF.AGENT.agent_prometheus_exporter_port, 
                      registry=REGISTRY)

    while True:
        ACTIVE_QUEUE_SIZE.set(runner.active())
        PASSIVE_QUEUE_SIZE.set(runner.passive())
        eventlet.greenthread.sleep(5)