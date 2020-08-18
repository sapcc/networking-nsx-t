import redis
from oslo_config import cfg
from oslo_log import log
from datetime import timedelta

LOG = log.getLogger(__name__)


class LoggingMetadata(object):
    _socket = cfg.CONF.AGENT.logging_socket
    _expire = cfg.CONF.AGENT.logging_expire

    def __init__(self):
        self._client = redis.Redis(unix_socket_path=self._socket)

    def set_port(self, vif, port_id, project_id):
        """Sets Redis port context

        Parameters:
        vif (string): the last 8 characters from NSX-T port attachment id
                      NSX-T DFW logs contain only this 8 characters

        port_id (string): the OpenStack port ID

        project_id (string): the OpenStack project ID
        """
        try:
            self._client.hset(vif, mapping={
                "port": port_id,
                "project": project_id
            })
            self._client.expire(vif, timedelta(days=self._expire))
        except Exception as e:
            LOG.error(e)

    def set_security_group(self, rules):
        """Sets Redis Security Group Rule context

        Parameters:
            rules (list(Rule))
        """
        expiration_delta = timedelta(days=self._expire)
        for rule in rules:
            try:
                self._client.set(rule.identifier, 
                                rule.security_group_id,
                                ex=expiration_delta)
            except Exception as e:
                LOG.error(e)

    def remove(self, key):
        """Removes data associated with key

        Parameters:
            key (string): the key of the logging object
        """
        try:
            self._client.delete(key)
        except Exception as e:
            LOG.error(e)