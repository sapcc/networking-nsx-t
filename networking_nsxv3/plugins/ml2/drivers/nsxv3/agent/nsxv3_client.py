from oslo_config import cfg
from oslo_log import log as logging

import time

import json
import requests
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


LOG = logging.getLogger(__name__)

POLYMORPHIC_TYPES = (
    QosSwitchingProfile,
    IpDiscoverySwitchingProfile,
    SpoofGuardSwitchingProfile
)

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
                        pass
                    elif 400 < resp.status_code and resp.status_code < 500:
                        raise Unauthorized(resp.content)
                    return resp
                except (HTTPError, ConnectionError, ConnectTimeout) as e:
                    LOG.error("Unable to connect. Error: {}".format(e))
                except Unauthorized as e:
                    error = json.loads(e.messages)
                    error_msg = error["error_message"]
                    error_code = int(error["error_code"])
                    if 400 < error_code and error_code < 500:
                        LOG.error("Unauthorized: {}".format(error_msg))
                        self._login()
                    else:
                        LOG.error("Error: {}".format(error_msg))
                        raise e

                now += 1
                msg = pattern.format(now, until, pause, method)
                if now > until:
                    raise Exception("Failed. {}".format(msg))
                LOG.debug(msg)
                time.sleep(pause)
            return None

        return decorator


class NSXv3Client(object):

    def retry_until_result(self, operation, kwargs, retry_max, retry_sleep):
        resp = None
        for _ in range(1, retry_max + 1):
            resp = operation(**kwargs)
            if resp:
                return resp
            time.sleep(retry_sleep)
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

    def __init__(self):
        self.session = requests.session()
        self.stub_config = None

        if cfg.CONF.NSXV3.nsxv3_suppress_ssl_wornings:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()

        self.base_url = 'https://{}:{}'.format(
            cfg.CONF.NSXV3.nsxv3_login_hostname,
            cfg.CONF.NSXV3.nsxv3_login_port
        )

        self.stub_config = StubConfigurationFactory.new_std_configuration(
            connect.get_requests_connector(
                session=self.session,
                msg_protocol='rest',
                url=self.base_url))

    def _login(self):
        LOG.info("Initializing NSXv3 session context.")
        login_url = ''.join((self.base_url, "/api/session/create"))
        login_data = {
            "j_username": cfg.CONF.NSXV3.nsxv3_login_user,
            "j_password": cfg.CONF.NSXV3.nsxv3_login_password
        }

        resp = self.session.post(login_url, data=login_data)
        if resp.status_code != requests.codes.ok:
            resp.raise_for_status()

        self.session.headers["Cookie"] = resp.headers.get("Set-Cookie")
        self.session.headers["X-XSRF-TOKEN"] = resp.headers.get("X-XSRF-TOKEN")
        self.session.headers["Accept"] = "application/json"
        self.session.headers["Content-Type"] = "application/json"

        connector = connect.get_requests_connector(
            session=self.session, msg_protocol='rest', url=self.base_url)
        self.stub_config = StubConfigurationFactory.new_std_configuration(
            connector)
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

    def _query(self, resource_type, key, ands=[], ors=[], dsl="",
               size=50, start=0):

        url = "{}/nsxapi/rpc/call/SearchFacade".format(self.base_url)
        query = json.dumps(self._get_query(
            resource_type, key, ands, ors, dsl, size, start))
        resp = self._post(url=url, data=query)
        return json.loads(resp.content)["result"]["results"]

    @connection_retry_policy(driver="rest")
    def _post(self, url, data):
        return self.session.post(url, data=data)

    @connection_retry_policy(driver="rest")
    def _put(self, url, data):
        return self.session.put(url, data=data)

    @connection_retry_policy(driver="sdk")
    def get(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_id = str(sdk_model.id)
        sdk_name = str(sdk_model.display_name)
        sdk_key = "display_name"

        msg = "Getting '{}' display_name='{}' ... ".format(sdk_type, sdk_name)
        LOG.info(msg)

        def get(id):
            res = svc.get(id)
            if isinstance(sdk_model, POLYMORPHIC_TYPES):
                res = res.convert_to(sdk_model)
            return res

        if sdk_id != 'None':
            params = {"id": sdk_id}
            # NSX-T object createation is an asynchronous opperation.
            # If we immediately "get" the object the result could not be found.
            return self.retry_until_result(get, params,
                                           retry_max=3, retry_sleep=5)

        # SDK does not support get object by display_name
        params = {
            "resource_type": sdk_type,
            "key": sdk_key,
            "ands": [sdk_name]
        }
        res = self.retry_until_result(self._query, params,
                                      retry_max=3, retry_sleep=5)
        if len(res) > 1:
            raise Exception("{} has failed. Ambiguous ".format(msg))
        if len(res) == 1:
            return get(res.pop()["id"])
        else:
            return None

    @connection_retry_policy(driver="sdk")
    def get_by_attr(self, sdk_service, sdk_model, attr_key, attr_val):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)

        msg = "Getting '{}' {}='{}' ... ".format(sdk_type, attr_key, attr_val)

        LOG.info(msg)

        res = svc.list(**{attr_key: attr_val})
        if res.result_count > 1:
            raise Exception("{} Ambiguous.".format(msg))
        elif res.result_count == 0:
            return None
        else:
            return res.results.pop()

    @connection_retry_policy(driver="sdk")
    def create(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_name = str(sdk_model.display_name)
        msg = "Creating '{}' display_name='{}' ... " .format(
            sdk_type, sdk_name)

        LOG.info(msg)

        get_kwargs = {
            "sdk_service": sdk_service,
            "sdk_model": sdk_model
        }
        res = self.retry_until_result(operation=self.get, kwargs=get_kwargs,
                                      retry_max=3, retry_sleep=5)

        if res:
            raise Exception("{} has failed. Object exists ".format(msg))
        return svc.create(sdk_model)

    @connection_retry_policy(driver="sdk")
    def update(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_id = str(sdk_model.id)
        sdk_name = str(sdk_model.display_name)
        msg = "Updating '{}' display_name='{}' ... ".format(sdk_type, sdk_name)

        LOG.info(msg)
        if not sdk_id:
            sdk_id = self.get(sdk_service=sdk_service, sdk_model=sdk_model).id

        if not sdk_id:
            raise Exception("{} has failed. Object not found ".format(msg))
        return svc.update(sdk_id, sdk_model)

    @connection_retry_policy(driver="sdk")
    def delete(self, sdk_service, sdk_model):
        svc = sdk_service(self.stub_config)
        sdk_type = str(sdk_model.__class__.__name__)
        sdk_id = sdk_model.id
        sdk_name = str(sdk_model.display_name)
        msg = "Deleting '{}' display_name='{}' ... ".format(sdk_type, sdk_name)

        LOG.info(msg)
        if not sdk_id:
            sdk_id = self.get(sdk_service=sdk_service, sdk_model=sdk_model).id
        if not sdk_id:
            raise Exception("{} has failed. Object not found ".format(msg))
        return svc.delete(sdk_id)

    @connection_retry_policy(driver="sdk")
    def batch(self, request_items, continue_on_error=True, atomic=True):
        req = BatchRequest(
            continue_on_error=continue_on_error, requests=request_items)
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
