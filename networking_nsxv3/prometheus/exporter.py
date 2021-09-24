import os
import threading

from oslo_config import cfg
from prometheus_client import CollectorRegistry, Gauge, MetricsHandler, Counter

# Prometheus Metrics

REGISTRY = CollectorRegistry()

ACTIVE_QUEUE_SIZE = Gauge(
    'nsxv3_agent_active_queue_size', 
    'Active synchronization queue size', 
    registry=REGISTRY
    )
PASSIVE_QUEUE_SIZE = Gauge(
    'nsxv3_agent_passive_queue_size', 
    'Passive synchronization queue size', 
    registry=REGISTRY
    )
JOB_SIZE = Gauge(
    'nsxv3_agent_job_size',
    'Current job size',
    registry=REGISTRY
    )
IN_REALIZATION = Gauge(
    'nsxv3_agent_in_realization',
    'Policies currently in realization',
    registry=REGISTRY
    )
REALIZED = Counter(
    'nsxv3_agent_realized',
    'Policies realized',
    ['resource_type', 'status'],
    registry=REGISTRY
)


def nsxv3_agent_exporter():
    os.environ['PATH_INFO'] = "/metrics"
    CustomMetricsHandler = MetricsHandler.factory(REGISTRY)
    from eventlet.green.http.server import HTTPServer
    server = HTTPServer(('', cfg.CONF.AGENT.agent_prometheus_exporter_port), CustomMetricsHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
