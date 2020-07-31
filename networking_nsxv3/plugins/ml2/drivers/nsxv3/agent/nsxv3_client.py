import json
import requests
import inspect
import eventlet

from oslo_config import cfg
from oslo_log import log as logging

from requests.exceptions import HTTPError
from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout

from vmware.vapi.lib import connect
from vmware.vapi.stdlib.client.factories import StubConfigurationFactory

from com.vmware.nsx_client import Batch
from com.vmware.nsx.model_client import BatchRequest
from com.vmware.nsx.model_client import QosSwitchingProfile
from com.vmware.nsx.model_client import IpDiscoverySwitchingProfile
from com.vmware.nsx.model_client import SpoofGuardSwitchingProfile

from com.vmware.vapi.std.errors_client import Unauthorized

from networking_nsxv3.common.synchronization import Scheduler

LOG = logging.getLogger(__name__)

POLYMORPHIC_TYPES = (
    QosSwitchingProfile,
    IpDiscoverySwitchingProfile,
    SpoofGuardSwitchingProfile
)


class HttpUnsuccessfulException(Exception):
    """Exception raised for errors in the response."""


# Decorator
class connection_retry_policy(object):

    def __init__(self, driver="sdk"):
        self.driver = driver

    def __call__(self, func):
        driver = self.driver

        def decorator(self, *args, **kwargs):

            method = "{}.{}".format(self.__class__.__name__, func.__name__)
            now = 1
            until = cfg.CONF.NSXV3.nsxv3_connection_retry_count
            pause = cfg.CONF.NSXV3.nsxv3_connection_retry_sleep

            pattern = "Retrying connection ({}/{}) with timeout {}s for {}"

            now = 1
            while True:
                try:
                    resp = func(self, *args, **kwargs)
                    if "sdk" in driver:
                        return resp

                    LOG.debug(
                        "HTTP Response URL={} Method={} Code={} Reason={}"
                        .format(resp.url, resp.request.method,
                                resp.status_code, resp.reason))

                    if resp.status_code == 404:
                        return resp

                    if resp.status_code > 400 and resp.status_code < 500:
                        raise Unauthorized(resp.content)

                    if resp.status_code >= 300:
                        msg = "HTTP Response URL={} Code={} Reason={} \
                            Content={}".format(resp.url, resp.status_code,
                                               resp.reason, resp.content)
                        raise HttpUnsuccessfulException(msg)
                    return resp
                except (HTTPError, ConnectionError, ConnectTimeout) as err:
                    LOG.error("Unable to connect. Error: {}".format(err))
                except Unauthorized as err:
                    if err.messages:
                        error = json.loads(err.messages)
                    else:
                        error = {
                            "error_message": "None",
                            "error_code": "-1"
                        }

                    error_msg = error["error_message"]
                    error_code = int(error["error_code"])
                    if error_code > 400 and error_code < 500:
                        LOG.error("Unauthorized: {}".format(error_msg))
                        self.login()
                    else:
                        LOG.error("Error: {}".format(error_msg))
                        raise err

                now += 1
                msg = pattern.format(now, until, pause, method)
                if now > until:
                    raise Exception("Failed. {}".format(msg))
                LOG.debug(msg)
                eventlet.sleep(pause)
            return None

        return decorator


class NSXv3Client(object):

    def retry_until_result(self, operation, kwargs,
                           retry_max=None, retry_sleep=None):
        if retry_max is None:
            retry_max = cfg.CONF.NSXV3.nsxv3_operation_retry_count
        if retry_sleep is None:
            retry_sleep = cfg.CONF.NSXV3.nsxv3_operation_retry_sleep

        resp = None
        for _ in range(1, retry_max + 1):
            resp = operation(**kwargs)
            if resp:
                return resp
            eventlet.sleep(retry_sleep)
        return resp

    def get(self, sdk_service, sdk_model):
        pass

    def create(self, sdk_service, sdk_model):
        pass

    def update(self, sdk_service, sdk_model):
        pass

    def delete(self, sdk_service, sdk_model):
        pass

    def batch(self, request_items, continue_on_error=True, atomic=True):
        pass

    def is_batch_successful(self, status):
        pass


class NSXv3ClientImpl(NSXv3Client):

    def __init__(self, api_scheduler):
        self.session = None
        self.stub_config = None
        self.api_scheduler = api_scheduler

        self.base_url = 'https://{}:{}'.format(
            cfg.CONF.NSXV3.nsxv3_login_hostname,
            cfg.CONF.NSXV3.nsxv3_login_port
        )

    def login(self):
        LOG.info("Initializing NSXv3 session context.")

        login_path = "/api/session/create"
        login_data = {
            "j_username": cfg.CONF.NSXV3.nsxv3_login_user,
            "j_password": cfg.CONF.NSXV3.nsxv3_login_password
        }

        self.session = requests.session()

        if cfg.CONF.NSXV3.nsxv3_suppress_ssl_wornings:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()

        resp = self._post(path=login_path, data=login_data, asJson=False)
        if resp.status_code != requests.codes.ok:
            resp.raise_for_status()

        self.session.headers["Cookie"] = resp.headers.get("Set-Cookie")
        self.session.headers["X-XSRF-TOKEN"] = resp.headers.get("X-XSRF-TOKEN")
        self.session.headers["Accept"] = "application/json"
        self.session.headers["Content-Type"] = "application/json"

        conr = connect.get_requests_connector(session=self.session,
                                              msg_protocol='rest',
                                              url=self.base_url)
        self.stub_config = StubConfigurationFactory.new_std_configuration(conr)
        LOG.info("NSXv3 session context initalized.")

    def _get_query(self, resource_type, key, ands=[], ors=[], dsl="",
                   size=50, start=0):

        def pattern(operator, key, patterns, join_patterns=[]):
            patterns = ["{}:( {} )".format(key, val) for val in patterns]
            patterns.extend(join_patterns)
            return "( {} )".format(operator).join(patterns)

        q = []
        if resource_type:
            q.append("resource_type: ( {} )".format(resource_type))
        if ands and ors:
            q.append(pattern("AND", key, ands, pattern("OR", key, ors)))
        elif ands:
            q.append(pattern("AND", key, ands))
        elif ors:
            q.append(pattern("OR", key, ors))

        pivot = "( {} ) AND _exists_:resource_type"

        return {
            "method": "search",
            "id": "",
            "params": [
                {
                    "query": pivot.format(" AND ".join(q)),
                    "dsl": dsl,
                    "page_size": size,
                    "cursor": start
                }
            ]
        }

    def _get_url(self, path):
        return "{}{}".format(self.base_url, path)

    def _query(self, resource_type, key, ands=[], ors=[], dsl="",
               size=50, start=0):
        data = self._get_query(resource_type, key, ands, ors, dsl, size, start)
        resp = self._post(path="/nsxapi/rpc/call/SearchFacade", data=data)
        content = json.loads(resp.content)

        if content.get("result") is None\
                or content.get("result").get("results") is None:
            raise HttpUnsuccessfulException(
                "Expected 'results' in payload={}".format(resp.content))

        return content.get("result").get("results")

    @connection_retry_policy(driver="rest")
    def _get(self, path):
        with self.api_scheduler:
            return self.session.get(
                url=self._get_url(path),
                timeout=cfg.CONF.NSXV3.nsxv3_request_timeout)

    @connection_retry_policy(driver="rest")
    def _post(self, path, data, asJson=True):
        with self.api_scheduler:
            return self.session.post(
                url=self._get_url(path),
                data=json.dumps(data) if asJson else data,
                timeout=cfg.CONF.NSXV3.nsxv3_request_timeout)

    @connection_retry_policy(driver="rest")
    def _put(self, path, data):
        with self.api_scheduler:
            return self.session.put(
                url=self._get_url(path),
                data=json.dumps(data),
                timeout=cfg.CONF.NSXV3.nsxv3_request_timeout)

    @connection_retry_policy(driver="rest")
    def _delete(self, path):
        with self.api_scheduler:
            return self.session.delete(
                url=self._get_url(path),
                timeout=cfg.CONF.NSXV3.nsxv3_request_timeout)

    def _get_object(self, sdk_model, sdk_object):
        o = sdk_object
        if isinstance(sdk_model, POLYMORPHIC_TYPES):
            o = o.convert_to(sdk_model)
        return o

    @connection_retry_policy(driver="sdk")
    def get(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_id = str(sdk_model.id)
        sdk_name = str(sdk_model.display_name)
        sdk_key = "display_name"

        msg = "Getting '{}' display_name='{}' ... ".format(sdk_type, sdk_name)
        LOG.info(msg)

        if sdk_id != 'None':
            with self.api_scheduler:
                return self._get_object(sdk_model, svc.get(sdk_id))

        # SDK does not support get object by display_name
        res = self._query(resource_type=sdk_type, key=sdk_key, ands=[sdk_name])


        exact_res = None
        if len(res) > 1: 
            for resource in res:
                # Skip nsx_policy created objects
                if resource["display_name"] == sdk_name and resource["_create_user"] == 'admin':
                    LOG.error("FOUND " + str(resource["display_name"]))
                    if exact_res is not None:
                        raise Exception("{} ambiguous.".format(msg))
                    exact_res = resource
        if len(res) == 1:
            exact_res = res.pop()

        if exact_res is not None:
            with self.api_scheduler:
                sdk_object = svc.get(exact_res["id"])
            return self._get_object(sdk_model, sdk_object)
        return None

    @connection_retry_policy(driver="sdk")
    def list(self, sdk_service, **kwargs):
        svc = sdk_service(self.stub_config)
        svc_type = sdk_service.__class__

        msg = "Getting objects from service='{}' ... by '{}' ".format(svc_type,
                                                                      kwargs)
        LOG.info(msg)
        with self.api_scheduler:
            return svc.list(**kwargs)

    @connection_retry_policy(driver="sdk")
    def get_by_attr(self, sdk_service, sdk_model, attr_key, attr_val):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)

        msg = "Getting '{}' {}='{}' ... ".format(sdk_type, attr_key, attr_val)

        LOG.info(msg)
        with self.api_scheduler:
            res = svc.list(**{attr_key: attr_val})
        if res.result_count > 1:
            raise Exception("{} Ambiguous.".format(msg))
        if res.result_count == 0:
            return None
        return res.results.pop()

    @connection_retry_policy(driver="sdk")
    def create(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_name = str(sdk_model.display_name)
        msg = "Creating '{}' display_name='{}' ... " .format(
            sdk_type, sdk_name)

        sdk_obj = self.get(sdk_service=sdk_service, sdk_model=sdk_model)
        if not sdk_obj:
            LOG.info(msg)
            with self.api_scheduler:
                sdk_obj = svc.create(sdk_model)
            params = {
                "resource_type": sdk_type,
                "key": "display_name",
                "ands": [sdk_name]
            }
            # Not all NSX objects can be query by name using the SDK
            # Wait for object to appear in Elastic search
            # This is important as we search NSX objects by name
            res = self.retry_until_result(self._query, params)
            if len(res) > 1:
                msg = "{}. Reverse lookup is ambiguous. Anomaly!".format(msg)
                raise Exception(msg)
            if len(res) == 1:
                sdk_obj = self._get_object(sdk_model, sdk_obj)
        return sdk_obj

    @connection_retry_policy(driver="sdk")
    def update(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_id = str(sdk_model.id)
        sdk_name = str(sdk_model.display_name)
        msg = "Updating '{}' display_name='{}' ... ".format(sdk_type, sdk_name)

        LOG.info(msg)
        if sdk_id == 'None':
            sdk_obj = self.get(sdk_service=sdk_service, sdk_model=sdk_model)
            if sdk_obj and sdk_obj.id:
                sdk_id = sdk_obj.id
            else:
                raise Exception("{} has failed. Object not found ".format(msg))
        with self.api_scheduler:
            return svc.update(sdk_id, sdk_model)

    @connection_retry_policy(driver="sdk")
    def delete(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_id = str(sdk_model.id)
        sdk_name = str(sdk_model.display_name)
        msg = "Deleting '{}' display_name='{}' ... ".format(sdk_type, sdk_name)

        LOG.info(msg)
        if sdk_id == 'None':
            sdk_obj = self.get(sdk_service=sdk_service, sdk_model=sdk_model)
            if sdk_obj and sdk_obj.id:
                sdk_id = sdk_obj.id
            else:
                LOG.warning("{} failed. Object not found ".format(msg))
                return sdk_model

        # Not all services have cascade property
        with self.api_scheduler:
            if 'cascade' in inspect.getargspec(svc.delete).args:
                return svc.delete(sdk_id, cascade=True)
            if 'detach' in inspect.getargspec(svc.delete).args:
                return svc.delete(sdk_id, detach=True)
            else:
                return svc.delete(sdk_id)

        LOG.warning("{} failed. Object not found ".format(msg))
        return sdk_model

    @connection_retry_policy(driver="sdk")
    def batch(self, request_items, continue_on_error=True, atomic=True):
        req = BatchRequest(
            continue_on_error=continue_on_error, requests=request_items)
        with self.api_scheduler:
            status = Batch(self.stub_config).create(req, atomic=atomic)
        return status

    def is_batch_successful(self, status):
        msg = "Batch operatinos faild. Rollbacked={}. Errors={}"
        msg_sub = "(Response code={} message={})"
        if status.has_errors:
            errs = [msg_sub.format(e.code, e.body) for e in status.results]
            LOG.error(msg.format(status.rolled_back, ','.join(errs)))
            return False
        return True
