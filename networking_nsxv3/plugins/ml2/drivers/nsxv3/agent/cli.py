import argparse
import json
import os
import sys
import math

from networking_nsxv3.api import rpc as nsxv3_rpc
# Implicitly used to initialize the global configuration
from networking_nsxv3.common import config
from networking_nsxv3.common import constants as nsxv3_constants
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import (
    client_nsx, provider_nsx_policy)
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.agent import NSXv3Manager
from networking_nsxv3.tests.environment import Environment
from neutron.common import config as common_config
from neutron.common import profiler
from neutron_lib import context as neutron_context
from oslo_config import cfg
from oslo_log import log as logging

# Eventlet Best Practices
# https://specs.openstack.org/openstack/openstack-specs/specs/eventlet-best-practices.html
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class NsxInventory(object):

    def __init__(self):
        self.client = client_nsx.Client()
        self.api = provider_nsx_policy.API
        self.paths = [
            self.api.ZONES, self.api.SWITCHES, self.api.PROFILES, self.api.PORTS,
            self.api.IPSETS, self.api.NSGROUPS, self.api.SECTIONS,
            self.api.GROUPS, self.api.SERVICES, self.api.POLICIES
        ]

    def _get_path(self, base_path, relative_path):
        return os.path.join(base_path, "nsx", *relative_path.split(os.path.sep))

    def cleanup(self):
        env = Environment(name="Cleanup")
        with env:
            # TODO - define more correct criteria
            eventlet.sleep(30)

    def update_database_export(self, meta_file_path, sql_file_path):
        LOG.info('Start update_database_export ...')
        try:
            # Read 'meta' file content
            LOG.info('About to open meta file %s ...', meta_file_path)
            file_handler = open(meta_file_path, 'r')
            meta_file_content = file_handler.read()
            file_handler.close()

            LOG.info('About to open neutron sql import file %s ...', sql_file_path)
            file_handler = open(sql_file_path, 'r')
            sql_file_content = file_handler.read()
            file_handler.close()
        except FileNotFoundError as e:
            # Print an error message
            LOG.error(str(e))
            # Error indicator
            return False
        # Convert the meta data to a dictionary
        try:
            meta_dict = json.loads(meta_file_content)
            meta_dict_size = len(meta_dict.items())
            meta_file_content = None
            LOG.info("About to process %s keys ...", meta_dict_size)
        except ValueError as e:
            # Print an error message
            LOG.error('JSON decoding - ' + str(e))
            # Error indicator
            return False
        # Loop the 'meta' data
        currentKey = 0
        currentPercentage = 0
        for _, contents in meta_dict.items():
            for key, value in contents.items():
                # Examine value type
                if isinstance(value, dict):
                    if 'id' in value:
                        value = value['id']
                    else:
                        LOG.info('Key "%s" has no value' % key)
                        continue
                # Here we have key & value pair
                sql_file_content = sql_file_content.replace(key, value)
                if math.trunc(currentKey / meta_dict_size * 100) != currentPercentage:
                    currentPercentage = math.trunc(currentKey / meta_dict_size * 100)
                    LOG.info("Percent done %s%%", currentPercentage)
                currentKey += 1
        # Form output sql file path
        output_sql_file_path = os.path.splitext(sql_file_path)[0] + '.final.sql'
        # Print an info message
        LOG.info('Saving the new .sql file at: %s ...' % output_sql_file_path)
        # Save the result
        try:
            # Write to the output file
            file_handler = open(output_sql_file_path, 'w')
            file_handler.write(sql_file_content)
            file_handler.close()
        except Exception as e:
            # Print an error message
            LOG.error(str(e))
            # Error indicator
            return False
        # Print an info message
        LOG.info('End matching NSX IDs.')
        return True

    def export(self, export_path):
        for path in self.paths:
            file_path = self._get_path(export_path, path)
            folder_path = os.path.dirname(file_path)
            os.makedirs(folder_path, exist_ok=True)

            with open(file_path, "w") as file:
                data = self._export_filter(path, self.client.get_all(path=path))
                if path == self.api.SECTIONS:
                    self._export_section_rules(data, folder_path)
                if path == self.api.POLICIES:
                    self._export_policy_rules(data, folder_path)
                file.writelines(json.dumps(data, indent=2))

    def _export_filter(self, path, data):
        if path in [self.api.SWITCHES, self.api.PORTS]:
            data = [o for o in data if o["_create_user"] != "nsx_policy"]
        elif path == self.api.SERVICES:
            data = [o for o in data if not o["is_default"]]
        else:
            data = [o for o in data if o["_create_user"] == "admin"]
        return data

    def _export_section_rules(self, data, folder_path):
        for o in data:
            child_path = self.api.RULES.format(o["id"])
            child_file_path = os.path.join(folder_path, o["id"])
            with open(child_file_path, "w") as child_file:
                child_data = self.client.get_all(path=child_path)
                child_file.writelines(json.dumps(child_data, indent=2))

    def _export_policy_rules(self, data, folder_path):
        for o in data:
            child_path = self.api.POLICY.format(o["id"])
            child_file_path = os.path.join(folder_path, o["id"])
            with open(child_file_path, "w") as child_file:
                child_data = self.client.get(path=child_path).json()
                child_file.writelines(json.dumps(child_data, indent=2))

    def load(self, load_path):
        meta_path = self._get_path(load_path, "meta")

        if os.path.isfile(meta_path):
            LOG.info("Loading from '%s' file...", meta_path)
            with open(meta_path, "r") as file:
                meta = json.load(file)
        else:
            meta = dict()

        try:
            self._load(load_path, meta)
        finally:
            with open(meta_path, "w") as file:
                file.writelines(json.dumps(meta, indent=2))

    def _load(self, load_path, full_meta):
        for path in self.paths:
            file_path = self._get_path(load_path, path)
            folder_path = os.path.dirname(file_path)

            meta = full_meta.get(path, {})
            with open(file_path, "r") as file:
                for o in json.load(file):
                    id = o.get("id")
                    if id in meta:
                        LOG.info("Object with ID:%s already processed.", id)
                        if isinstance(meta[id], dict) and not meta[id]["rules_processed"]:
                            self._load_section_rules(full_meta, id, self.api.RULES_CREATE.format(
                                meta[id]["id"]), os.path.join(folder_path, id))
                        continue
                    self._preprocess(full_meta, o, path)
                    LOG.info(json.dumps(o, indent=2))
                    if "policy" in path:
                        if self.api.POLICIES in path:
                            o["rules"] = self._get_policy_rules(os.path.join(folder_path, id))
                        resp = self.client.put(path="{}/{}".format(path, id), data=o).json()
                    else:
                        resp = self.client.post(path=path, data=o).json()

                    if self.api.SECTIONS in path:
                        meta[id] = {
                            "id": resp["id"],
                            "_revision": resp["_revision"],
                            "rules_processed": False
                        }
                        full_meta.update({path: meta})
                        self._load_section_rules(full_meta, id, self.api.RULES_CREATE.format(
                            meta[id]["id"]), os.path.join(folder_path, id))
                    else:
                        meta[id] = resp["id"]
            full_meta[path] = meta

    def _load_section_rules(self, full_meta, id, path, file_path):
        if os.path.isfile(file_path):
            with open(file_path, "r") as file:
                data = {"rules": json.load(file)}
                for o in data["rules"]:
                    self._preprocess(full_meta, o, path, full_meta[self.api.SECTIONS][id]["_revision"])
                LOG.info("%s %s", path, json.dumps(data, indent=2))
                self.client.post(path=path, data=data)
                full_meta[self.api.SECTIONS][id]["rules_processed"] = True

    def _get_policy_rules(self, file_path):
        if os.path.isfile(file_path):
            with open(file_path, "r") as file:
                rules = json.load(file)["rules"]
                for rule in rules:
                    self._preprocess(None, rule, self.api.RULES)
                return rules

    def _preprocess(self, meta, o, path, revision=None):

        def remove_system_information(o):
            for key in list(o):
                if key.startswith("_") or key == "id":
                    del o[key]

        def substitute_id(meta, o, directions):
            for direction in o[directions]:
                if direction["target_type"] in ["IPSet", "NSGroup"]:
                    direction["target_id"] = meta[direction["target_id"]]

        remove_system_information(o)

        if revision is not None:
            o["_revision"] = revision

        if self.api.ZONES in path:
            del o["host_switch_id"]
            del o["transport_zone_profile_ids"]

        if self.api.SWITCHES in path:
            o["transport_zone_id"] = meta[self.api.ZONES][o["transport_zone_id"]]
            o["switching_profile_ids"] = []

        if self.api.PROFILES in path:
            pass

        if self.api.PORTS in path:
            o["logical_switch_id"] = meta[self.api.SWITCHES][o["logical_switch_id"]]
            o["switching_profile_ids"] = []
            del o["internal_id"]

        if self.api.IPSETS in path:
            pass

        if self.api.NSGROUPS in path:
            pass

        if self.api.SERVICES in path:
            del o["path"]
            del o["parent_path"]
            for e in o["service_entries"]:
                del e["path"]
                del e["parent_path"]
                del e["relative_path"]
                remove_system_information(e)

        if self.api.SECTIONS in path:
            if "applied_tos" in o:
                for target in o["applied_tos"]:
                    target["target_id"] = meta[self.api.SECTIONS][target["target_id"]]
            if "sources" in o:
                substitute_id(meta[self.api.SECTIONS], o, "sources")
            if "destinations" in o:
                substitute_id(meta[self.api.SECTIONS], o, "destinations")


class NeutronInventory(object):

    def __init__(self):
        self.context = neutron_context.get_admin_context()
        self.host = cfg.CONF.host
        self.step = cfg.CONF.AGENT.rpc_max_records_per_query

    def _get_neutron_ids(self, query):
        cursor = 0
        ids = []
        while cursor != -1:
            result = query(self.context, cfg.CONF.host, self.step, cursor)
            ids += [id for id, _, _ in result]
            cursor = result[-1][2] if len(result) >= self.step else -1
        return ids

    def export(self, export_path):

        rpc = nsxv3_rpc.NSXv3ServerRpcCallback()

        ports_ids = self._get_neutron_ids(rpc.get_ports_with_revisions)
        qos_ids = self._get_neutron_ids(rpc.get_qos_policies_with_revisions)
        groups_ids = self._get_neutron_ids(rpc.get_security_groups_with_revisions)

        def _as_dict(result):
            return [{c.name: getattr(o, c.name) for c in o.__table__.columns} for o in result]

        ports = {id: rpc.get_port(self.context, self.host, id) for id in ports_ids}
        qos = {id: rpc.get_qos(self.context, self.host, id) for id in qos_ids}
        groups = {id: rpc.get_security_group(self.context, self.host, id) for id in groups_ids}
        rules = dict()
        for id in groups.keys():
            rules.update({rule["id"]: rule for rule in _as_dict(
                rpc.get_rules_for_security_group_id(self.context, id))})

        path = os.path.join(export_path, "neutron")
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "w") as file:
            file.writelines(json.dumps({
                "port": ports,
                "qos": qos,
                "security-group": groups,
                "security-group-rule": rules
            }, indent=2))


class CLI(object):

    def __init__(self):
        LOG.info("VMware NSXv3 Agent CLI")
        parser = argparse.ArgumentParser(
            description="Neutron ML2 NSX-T Agent command line interface",
            usage='''neutron-nsxv3-agent-cli-sync COMMAND
                update - Force synchronization between Neutron and NSX-T objects
                export - Export Neutron and NSX-T inventories
                load - Loads the exported NSX-T Inventory
                updateDatabaseExport - Update neutron sql file NSXT object IDs
                run - Runs the NSX-T Agent with the exported Neutron inventory
                clean - Clean up NSX-T objects
            ''')
        parser.add_argument('command', help='Subcommand update|export|load|updateDatabaseExport|run|clean')
        args = parser.parse_args(sys.argv[1:2])
        if hasattr(self, args.command):
            getattr(self, args.command)()
        else:
            LOG.error("Unrecognized command")
            parser.print_help()
            exit(1)

    def _init_(self, args):
        neutron_config = []
        for file in args.config_file:
            neutron_config.extend(["--config-file", file])

        common_config.init(neutron_config)
        common_config.setup_logging()
        profiler.setup(nsxv3_constants.NSXV3_BIN, cfg.CONF.host)

    def update(self):
        """
        Force synchronization between Neutron and NSX-T objects
        cfg.CONF.AGENT_CLI for options
        """

        PORT = "port"
        QOS = "qos"
        SECURITY_GROUP_RULES = "security_group_rules"
        SECURITY_GROUP_MEMBERS = "security_group_members"

        description = 'Update object state'
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "--config-file", action="append",
            help="OpenStack Neutron configuration file(s) location(s)")
        parser.add_argument(
            "-T", "--type", required=True,
            help="OpenStack object type target of synchronization",
            choices=[PORT, QOS, SECURITY_GROUP_RULES, SECURITY_GROUP_MEMBERS])
        parser.add_argument(
            "-I", "--ids", required=True,
            help="OpenStack object IDs, separated by ','")
        args = parser.parse_args(sys.argv[2:])

        self._init_(args)

        self.manager = NSXv3Manager(rpc=nsxv3_rpc.NSXv3ServerRpcApi(),
                                    synchronization=False, monitoring=False)
        self.rpc = self.manager.get_rpc_callbacks(context=None, agent=None,
                                                  sg_agent=None)

        ids = args.ids.split(",")
        context = None

        # Enforce synchronization
        if args.type == SECURITY_GROUP_RULES:
            self.rpc.security_groups_rule_updated(context, security_groups=ids)

        if args.type == SECURITY_GROUP_MEMBERS:
            self.rpc.security_groups_member_updated(context, security_groups=ids)

        if args.type == PORT:
            for id in ids:
                self.rpc.port_update(context, port={"id": id})

        if args.type == QOS:
            for id in ids:
                self.rpc.update_policy(context, policy={"id": id})

        self.manager.shutdown()

    def clean(self):
        """
        Clean up NSX-T inventory
        """
        description = "Clean up NSX-T inventory"
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "--config-file", action="append",
            help="OpenStack Neutron configuration file(s) location(s)")
        args = parser.parse_args(sys.argv[2:])

        self._init_(args)

        NsxInventory().cleanup()

    def updateDatabaseExport(self):
        """
        Update neutron sql file with the newly created IDs from NSX-T
        """
        description = "Update neutron sql file NSXT object IDs"
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "--config-file", action="append",
            help="OpenStack Neutron configuration file(s) location(s)")
        parser.add_argument(
            "--sql-file", action="append",
            help="OpenStack Neutron DB SQL file")
        args = parser.parse_args(sys.argv[2:])

        self._init_(args)
        meta_path = os.path.join(os.getcwd(), "inventory/nsx/meta")
        if args.sql_file == None or args.sql_file[0] == None:
            LOG.error("Please specify neutron database export file using --sql-file")
            exit(1)
        if not NsxInventory().update_database_export(meta_path, args.sql_file[0]):
            LOG.error('update_database_export finished with error. Please check the logs for details')
            exit(1)

    def export(self):
        """
        Export Neutron and NSX-T inventories
        """
        description = "Export Neutron and NSX-T inventories"
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "--config-file", action="append",
            help="OpenStack Neutron configuration file(s) location(s)")
        args = parser.parse_args(sys.argv[2:])

        self._init_(args)

        export_path = os.path.join(os.getcwd(), "inventory")
        NsxInventory().export(export_path)
        NeutronInventory().export(export_path)

    def load(self):
        """
        Load the exported NSX-T inventory
        """
        description = "Load NSX-T inventory"
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "--config-file", action="append",
            help="OpenStack Neutron configuration file(s) location(s)")
        args = parser.parse_args(sys.argv[2:])

        self._init_(args)

        load_path = os.path.join(os.getcwd(), "inventory")

        NsxInventory().load(load_path)

    def run(self):
        """
        Run NSX-T Agent with exported Neutron inventory
        """
        description = "Run NSX-T Agent"
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "--config-file", action="append",
            help="OpenStack Neutron configuration file(s) location(s)")
        args = parser.parse_args(sys.argv[2:])

        self._init_(args)

        load_path = os.path.join(os.getcwd(), "inventory")

        with open(os.path.join(load_path, "neutron"), "r") as file:
            dataset = json.load(file)

            # Add name to the port to be able to use port binding mock
            for id, port in dataset["port"].items():
                port["name"] = id

        env = Environment(inventory=dataset)
        with env:
            i = env.openstack_inventory
            for id, port in dataset["port"].items():
                if "segmentation_id" in port["vif_details"]:
                    i.port_bind(port["name"], port["vif_details"]["segmentation_id"])
                else:
                    LOG.error("Port:%s does not have segmentation_id", id)
