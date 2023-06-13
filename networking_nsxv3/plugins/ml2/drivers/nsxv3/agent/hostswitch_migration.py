import eventlet
eventlet.monkey_patch()

import copy
from typing import List, Tuple
from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.common.constants import *
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent import provider
from networking_nsxv3.plugins.ml2.drivers.nsxv3.agent.constants_nsx import *
from networking_nsxv3.prometheus import exporter


LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


class HostswitchMigrationProvider(object):
    """Hostswitch migration provider"""

    def __init__(self, provider: provider.Provider, migr_tracker: provider.MigrationTracker):
        self.provider = provider
        self.migr_tracker = migr_tracker

    def check_tz_migration(self):
        """Check if ens migration is needed

        Returns:
            bool: True if ens migration is needed, False otherwise
        """
        if bool(cfg.CONF.NSXV3.nsxv3_new_hostswitch_transport_zone_name):
            if not self.provider.zone_tags:
                LOG.info(f"Hostswitch migration is needed for the transport zone '{self.provider.new_tz_name}'.")
                return True
            for zone_tag in self.provider.zone_tags:
                if zone_tag.get(NSXV3_HOSTSWITCH_MIGRATION_SCOPE) == NSXV3_MIGRATION_SUCCESS_TAG:
                    LOG.info(
                        f"Hostswitch migration is already done for the transport zone '{self.provider.new_tz_name}'.")
                    return False
            LOG.info(f"Hostswitch migration is needed for the transport zone '{self.provider.new_tz_name}'.")
            return True
        LOG.info("Hostswitch migration is not needed.")
        return False

    def try_hostswitch_migration(self):
        """Try to migrate to ENS switch"""
        self.migr_tracker.set_migration_in_progress(True)
        eventlet.greenthread.spawn(self.migrate_to_new_hostswitch).link(self.hostswitch_migr_callback)

    def migrate_to_new_hostswitch(self):
        # List of tuples (new_port, old_port).
        migrated_ports: List[Tuple[dict, dict]] = []
        eventlet.sleep(10)
        try:
            # Get all networks for the old TZ
            old_nets = self.provider.get_all_networks(tz_id=self.provider.tz_id)
            LOG.info(f"Found {len(old_nets)} networks on the old transport zone.")

            # Refresh metadata with the new TZ networks if any
            self.provider.metadata_refresh(self.provider.NETWORK)

            # List of tuples (new_port, new_net, old_port, old_net)
            switchover_grp: List[Tuple[dict, dict, dict, dict]] = []
            for old_net in old_nets:
                # Get all ports for the network
                ports = self.provider.get_all_ports_for_network(old_net["id"])
                LOG.info(f"Found {len(ports)} ports on the network '{old_net['display_name']}'.")

                for old_port in ports:
                    if not old_net.get("vlan"):
                        raise RuntimeError(f"Network '{old_net['display_name']}' has no vlan ID.")
                    # Prepare the nwtwork
                    new_net = self.provider.network_realize(old_net["vlan"])
                    # Precreate the new port
                    switchover_grp.append((self.provider.port_precreate_empty(
                        old_port, new_net), new_net, old_port, old_net))

            self.provider.metadata_refresh(self.provider.NETWORK)
            # TODO: await all netowrk config state to be successfull

            # TODO: filter the parent ports to be handled first
            for new_port, new_net, old_port, old_net in switchover_grp:
                attachment = copy.deepcopy(old_port.get("attachment"))
                address_bindings = copy.deepcopy(old_port.get("address_bindings"))
                self.provider.port_unbind(old_port)
                self.provider.port_bind(new_port, attachment, address_bindings)
                migrated_ports.append((new_port, old_port))
                # 2.5.1. If binding is successful, delete the old port
                # 2.5.2. If binding is not successful, delete the new port. Realize the old port on the old switch.
            # 3. If migration is successful, tag the transport zone with NSXV3_MIGRATION_SUCCESS_TAG
            # 4. If migration is not successful, tag the transport zone with NSXV3_MIGRATION_FAIL_TAG
        except Exception as e:
            LOG.error("Error while migrating to NEW host switch.")
            LOG.error(str(e))
        return False

    def hostswitch_migr_callback(self, gt: eventlet.greenthread.GreenThread):
        try:
            success = gt.wait()
            if not success:
                # TODO: tag the transport zone with NSXV3_MIGRATION_FAIL_TAG
                raise RuntimeWarning("ENS migration failed.")
            LOG.info("ENS Migration finished successfully.")
            # TODO: tag the transport zone with NSXV3_MIGRATION_SUCCESS_TAG
        except Exception as e:
            LOG.error(str(e))
        finally:
            self.migr_tracker.set_migration_in_progress(False)
