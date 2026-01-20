import eventlet

eventlet.monkey_patch()

from requests import Response
from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError, ReadTimeout
from oslo_utils import versionutils
from oslo_log import log as logging
from oslo_config import cfg
from networking_nsxv3.common.synchronization import Scheduler
from networking_nsxv3.common.locking import LockManager
from networking_nsxv3.prometheus import exporter
import requests
import uuid
import time
import re


LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


def is_not_found(response):
    return re.search("The path.*is invalid", response.text)


def is_atomic_request_error(response):
    return response.status_code == 400 and re.search("The object AtomicRequest", response.text)


def is_revision_error(response):
    return response.status_code == 412 and re.search("Fetch the latest copy of the object and retry", response.text)


def is_child_deps_error(response):
    return response.status_code == 400 and re.search("cannot be deleted as either it has children or it is being referenced by other objects path", response.text)


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class RetryPolicy(object):
    BASE = "/policy/api/v1"
    BASE_INFRA = f"{BASE}/infra"
    RULES = [
        # Regex Order matters
        # Match security_rule before security_policy
        # Match ports before segments
        ('security_rule', re.compile(f"^{BASE_INFRA}/domains/default/security-policies/.*/rules.*")),
        ('security_policy', re.compile(f"^{BASE_INFRA}/domains/default/security-policies.*")),
        ('group', re.compile(f"^{BASE_INFRA}/domains/default/groups.*")),
        ('port', re.compile(f"^{BASE_INFRA}/segments/.*/ports.*")),
        ('segments', re.compile(f"^{BASE_INFRA}/segments.*")),
        ('realized_state', re.compile(f'^{BASE_INFRA}/realized-state/status.*')),
        ('services', re.compile(f"^{BASE_INFRA}/services.*")),
        ('search', re.compile(f"^{BASE}/search.*")),
        ('transport_zone', re.compile(f"^{BASE_INFRA}/sites/default/enforcement-points/default/transport-zones.*")),
        ('qos_profile', re.compile(f"^{BASE_INFRA}/default/qos-profiles.*")),
    ]

    @classmethod
    def _create_sentry_fingerprint(cls, path: str, placeholder: str = "{}") -> str:
        # check if uuid is part of path -> replace with placeholder
        for sub in path.split("/"):
            try:
                uuid.UUID(sub)
                path = path.replace(sub, placeholder)
            except ValueError:
                pass
        return path

    @classmethod
    def _get_resource_type(cls, path: str) -> str:
        for name, rule in cls.RULES:
            match = rule.match(path)
            if match:
                return name
        return "unknown"

    @classmethod
    def _update_metric(cls, metric, path='', status='UNKNOWN', method='UNKNOWN', response_time=0, exception_type='UNKNOWN'):
        fp_path = cls._create_sentry_fingerprint(path=path, placeholder="<uuid>")
        resource = cls._get_resource_type(path)

        if exporter.API_CALLS == metric:
            metric.labels(method=method, bb=cfg.CONF.host, resource_type=resource, path=fp_path, status=status).observe(response_time)

        if exporter.API_CALL_EXCEPTIONS == metric:
            metric.labels(bb=cfg.CONF.host, resource_type=resource, path=path, exception_type=exception_type).inc()

    def __call__(self, func):

        def decorator(self, *args, **kwargs):
            request_info = "Function {} Arguments {}".format(func.__name__.upper(), str(kwargs))

            until = cfg.CONF.NSXV3.nsxv3_connection_retry_count
            pause = cfg.CONF.NSXV3.nsxv3_connection_retry_sleep

            method = "{}.{}".format(self.__class__.__name__, func.__name__)

            pattern = "Retrying connection ({}/{}) with timeout {}s for {}"
            msg = None
            last_err = None

            sentry_extra = {

            }
            response = None
            for attempt in range(1, until + 1):
                try:
                    response = func(self, *args, **kwargs)
                    # LOG.debug("REQUEST: %s STATUS: %s, RESPONSE.CONTENT %s", requestInfo, response.status_code, response.content)
                    RetryPolicy._update_metric(exporter.API_CALLS, path=kwargs.get("path", ''), method=response.request.method,
                                               status=response.status_code,
                                               response_time=response.elapsed.total_seconds())
                    if response.status_code in [404]:
                        LOG.warning("Warning Code=%s Message=%s", response.status_code, response.content)
                        return response

                    if 200 <= response.status_code < 300:
                        return response

                    last_err = "Error Code={} Message={}".format(response.status_code, response.content)

                    # Handle resource not found gently
                    if is_not_found(response):
                        LOG.info("Unable to find Resource={}".format(kwargs["path"]))
                        LOG.debug("Request=%s Response=%s", request_info, last_err)
                        return response

                    if is_revision_error(response):
                        return response

                    if is_child_deps_error(response):
                        return response

                    if response.status_code in [401, 403]:
                        self._login()
                        continue

                    # Retry for The object AtomicRequest/10844 is already present in the system.
                    # Retry for Migration coordinator backend is busy. Please try again after some time.
                    if not is_atomic_request_error(response):
                        # skip retry on the ramaining NSX errors
                        sentry_extra["fingerprint"] = [RetryPolicy._create_sentry_fingerprint(kwargs.get("path", '')),
                                                       response.request.method]
                        LOG.error("Request=%s Response=%s", request_info, last_err, extra=sentry_extra)
                        break
                except (HTTPError, ConnectionError, ConnectTimeout, ReadTimeout) as err:
                    last_err = err
                    m = response.request.method if response else "UNKNOWN"
                    sentry_extra["fingerprint"] = [RetryPolicy._create_sentry_fingerprint(kwargs.get("path", '')), m]
                    RetryPolicy._update_metric(exporter.API_CALL_EXCEPTIONS, path=kwargs.get("path", ''),
                                               exception_type=type(err).__name__)
                    LOG.error("Request=%s Response=%s", request_info, last_err, extra=sentry_extra)

                msg = pattern.format(attempt, until, pause, method)

                LOG.debug(msg)
                eventlet.sleep(pause)

            m = response.request.method if response else "UNKNOWN"
            sentry_extra["fingerprint"] = [RetryPolicy._create_sentry_fingerprint(kwargs.get("path", '')), m]
            LOG.exception(last_err, extra=sentry_extra)
            raise RuntimeError(msg, last_err)

        return decorator


class Client(metaclass=Singleton):

    def __init__(self):
        rate = cfg.CONF.NSXV3.nsxv3_requests_per_second
        timeout = cfg.CONF.NSXV3.nsxv3_requests_per_second_timeout

        self._api_scheduler = Scheduler(rate=rate, timeout=timeout)

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

        if cfg.CONF.NSXV3.nsxv3_suppress_ssl_warnings:
            self._session.verify = False
            requests.packages.urllib3.disable_warnings()

        self._version = None

    def __del__(self) -> None:
        self._session.close()

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
    def post(self, path: str, data: dict) -> Response:
        with self._api_scheduler:
            return self._session.post(**self._params(path=path, json=data))

    @RetryPolicy()
    def patch(self, path: str, data: dict) -> Response:
        with self._api_scheduler:
            return self._session.patch(**self._params(path=path, json=data))

    @RetryPolicy()
    def put(self, path: str, data: dict) -> Response:
        with self._api_scheduler:
            return self._session.put(**self._params(path=path, json=data))

    @RetryPolicy()
    def delete(self, path: str, params: dict = dict()) -> Response:
        with self._api_scheduler:
            return self._session.delete(**self._params(path=path, params=params))

    @RetryPolicy()
    def get(self, path: str, params: dict = dict()) -> Response:
        with self._api_scheduler:
            return self._session.get(**self._params(path=path, params=params))

    def get_unique(self, path: str, params: dict = dict()) -> dict:
        results = self.get(path=path, params=params).json().get("results")
        if isinstance(results, list):
            if results:
                if len(results) > 1:
                    LOG.error("Ambiguous. %s", results)
                result = results.pop()
                return result
        elif results:
            return results

    def get_all(self, path: str, params: dict = None, cursor: str = ""):
        # FYI - NSX does not allow to filter by custom property
        # Search API has hard limit of 50k objects (with cursor)
        PAGE_SIZE = cfg.CONF.NSXV3.nsxv3_max_records_per_query
        params = params or dict()
        params.update({"page_size": PAGE_SIZE, "cursor": cursor})

        response = self.get(path=path, params=params)
        if is_not_found(response):
            return []

        content = response.json()
        cursor = content.get("cursor", "")
        page_size = content.get("result_count", 0)

        _all = content.get("results", [])
        plcy_cond = (cursor.isdigit() and int(cursor) != page_size)
        mgmt_cond = (cursor and not cursor.isdigit())
        return self.get_all(path, params, cursor) + _all if (plcy_cond or mgmt_cond) else _all

    def get_unique_with_retry(self, path: str, retries: int = 5, params: dict = dict()):
        retry = 0
        ex = None
        while retry < retries:
            try:
                o = self.get_unique(path=path, params=params)
                if not o:
                    raise Exception("Not found")
                return o
            except Exception as e:
                ex = e
                retry += 1
                eventlet.sleep(seconds=10)
        raise ex
