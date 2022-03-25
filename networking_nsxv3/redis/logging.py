import redis
from oslo_config import cfg
from oslo_log import log
from datetime import timedelta

LOG = log.getLogger(__name__)


class LoggingMetadata(object):
    expiration_delta = timedelta(days=cfg.CONF.AGENT.logging_expire)

    def __init__(self):
        self._client = redis.from_url(cfg.CONF.AGENT.logging_url)

    def set_port(self, vif, port_id, project_id):
        """Sets Redis port context
        Parameters:
            vif (string): the last 8 characters from NSX-T port attachment id
                          NSX-T DFW logs contain only this 8 characters
            port_id (string): the OpenStack port ID
            project_id (string): the OpenStack project ID
        """
        try:
            self._client.hmset(vif, mapping={
                "port": port_id,
                "project": project_id
            })
            self._client.expire(vif, self.expiration_delta)
        except Exception as e:
            LOG.error(e)

    def set_security_group(self, rules):
        """Sets Redis Security Group Rule context
        Parameters:
            rules (list(Rule)): the OpenStack rules
        """
        for rule in rules:
            try:
                self._client.set(rule.identifier, rule.security_group_id, ex=self.expiration_delta)
            except Exception as e:
                LOG.error(e)

    def set_security_group_project(self, security_group_id, project_id):
        """Sets Project ID by security group ID
        Parameters:
            security_group_id (string): the OpenStack security group ID
            project_id (string): the OpenStack project ID

        ATTENTION: THIS METHOD ASSUMES ALL THE SECURITY GROUPS IDS ARE UNIQUE ACROSS ALL THE PROJECTS
        """
        try:
            self._client.set(security_group_id, project_id, ex=self.expiration_delta)
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
