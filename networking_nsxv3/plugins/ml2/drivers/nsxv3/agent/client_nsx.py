import json
import re
import time

import eventlet
import requests
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.common.synchronization import Scheduler
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import versionutils
from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError

LOG = logging.getLogger(__name__)


def is_not_found(response):
    return re.search("The path.*is invalid", response.text)

def is_atomic_request_error(response):
    return response.status_code == 400 and re.search("The object AtomicRequest", response.text)


class RetryPolicy(object):

    def __call__(self, func):

        def decorator(self, *args, **kwargs):

            requestInfo = ""

            if 'path' in kwargs and 'session/create' in kwargs.get('path'):
                requestInfo = "Function {} Argumetns {}".format(
                    func.__name__.upper(), str(kwargs))
            else:
                requestInfo = "Function {} Argumetns {}".format(
                    func.__name__.upper(), str(kwargs))

            until = cfg.CONF.NSXV3.nsxv3_connection_retry_count
            pause = cfg.CONF.NSXV3.nsxv3_connection_retry_sleep

            method = "{}.{}".format(self.__class__.__name__, func.__name__)

            pattern = "Retrying connection ({}/{}) with timeout {}s for {}"
            msg = None
            last_err = None

            for attempt in range(1, until + 1):
                try:
                    response = func(self, *args, **kwargs)

                    if response.status_code in [404]:
                        LOG.error("Error Code=%s Message=%s", response.status_code, response.content)

                    if 200 <= response.status_code < 300 or response.status_code in [404]:
                        return response

                    last_err = "Error Code={} Message={}"\
                        .format(response.status_code, response.content)
                    log_msg = "Request={} Response={}".format(requestInfo,
                                                              last_err)

                    # Handle resource not found gently
                    if is_not_found(response):
                        LOG.info("Unable to find Resource={}"\
                            .format(kwargs["path"]))
                        LOG.debug(log_msg)
                        return response

                    if response.status_code in [401, 403]:
                        self._login()
                        continue

                    # Retry for The object AtomicRequest/10844 is already present in the system.
                    if not is_atomic_request_error(response):
                        # skip retry on the ramaining NSX errors
                        LOG.error(log_msg)
                        break
                except (HTTPError, ConnectionError, ConnectTimeout) as err:
                    last_err = err
                    LOG.error("Request={} Response={}".format(requestInfo,
                                                              last_err))

                msg = pattern.format(attempt, until, pause, method)

                LOG.debug(msg)
                eventlet.sleep(pause)

            raise Exception(msg, last_err)

        return decorator



class Client:

    def __init__(self):
        rate=cfg.CONF.NSXV3.nsxv3_requests_per_second
        timeout=cfg.CONF.NSXV3.nsxv3_requests_per_second_timeout
        limit=1

        self._api_scheduler = Scheduler(rate, limit, timeout)

        self._timeout = cfg.CONF.NSXV3.nsxv3_request_timeout

        self._base_path = 'https://{}:{}'.format(
            cfg.CONF.NSXV3.nsxv3_login_hostname,
            cfg.CONF.NSXV3.nsxv3_login_port
        )

        self._login_timestamp = 0
        self._login_path = "/api/session/create"
        self._login_data = {
            "j_username": cfg.CONF.NSXV3.nsxv3_login_user,
            "j_password": cfg.CONF.NSXV3.nsxv3_login_password
        }

        self._session = requests.session()

        if cfg.CONF.NSXV3.nsxv3_suppress_ssl_wornings:
            self._session.verify = False
            requests.packages.urllib3.disable_warnings()

        self._version = None

    @property
    def version(self, refresh=False):
        if not self._version or refresh:
            resp = self.get(path="/api/v1/node/version")
            if resp.ok:
                self._version = resp.json()['product_version']
        return versionutils.convert_version_to_tuple(self._version)

    def _login(self):
        LOG.info("Session token - acquiring")
        now = int(time.time())
        with LockManager.get_lock(self._base_path):
            if now > self._login_timestamp:
                resp = requests.post(**self._params(path=self._login_path,
                                                    data=self._login_data,
                                                    verify=self._session.verify))
                
                resp.raise_for_status()

                self._session.headers["Cookie"] = \
                    resp.headers.get("Set-Cookie")
                self._session.headers["X-XSRF-TOKEN"] = \
                    resp.headers.get("X-XSRF-TOKEN")
                self._session.headers["Accept"] = "application/json"
                self._session.headers["Content-Type"] = "application/json"

                self._login_timestamp = int(time.time())

        try:
            # Refresh version after login
            self.version(refresh=True)
        except Exception:
            pass
        LOG.info("Session token - acquired, connected to NSX-T {}".format(self._version))

    def _params(self, **kwargs):
        kwargs["timeout"] = self._timeout
        kwargs["url"] = "{}{}".format(self._base_path, kwargs["path"])
        del kwargs["path"]
        return kwargs

    @RetryPolicy()
    def post(self, path, data):
        with self._api_scheduler:
            return self._session.post(**self._params(path=path, json=data))

    @RetryPolicy()
    def patch(self, path, data):
        with self._api_scheduler:
            return self._session.patch(**self._params(path=path, json=data))

    @RetryPolicy()
    def put(self, path, data):
        with self._api_scheduler:
            return self._session.put(**self._params(path=path, json=data))
    
    @RetryPolicy()
    def delete(self, path, params=dict()):
        with self._api_scheduler:
            return self._session.delete(**self._params(path=path, params=params))

    @RetryPolicy()
    def get(self, path, params=dict()):
        with self._api_scheduler:
            return self._session.get(**self._params(path=path, params=params))

    def get_unique(self, path, params=dict()):
        results = self.get(path=path, params=params).json().get("results")
        if isinstance(results, list):
            if results:
                result = results.pop()
                if results:
                    LOG.warning("Ambiguous. %s", results)
                return result
        elif results:
            return results

    def get_all(self, path, params=dict(), cursor=""):
        # FYI - NSX does not allow to filter by custom property
        # Search API has hard limit of 50k objects (with cursor)
        PAGE_SIZE = cfg.CONF.NSXV3.nsxv3_max_records_per_query
        params.update({"page_size": PAGE_SIZE, "cursor": cursor})

        response = self.get(path=path, params=params)
        if is_not_found(response):
            return []

        content = response.json()
        cursor = content.get("cursor", None)

        all = content.get("results", [])
        return self.get_all(path, params, cursor) + all if cursor else all
