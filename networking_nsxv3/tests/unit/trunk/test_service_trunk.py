from neutron.tests import base
from oslo_config import cfg
from oslo_log import log as logging
from networking_nsxv3.tests.unit.call_tracker import CallTracker
from networking_nsxv3.services.trunk.drivers.nsxv3.trunk import NSXv3TrunkDriver
from networking_nsxv3.common import constants as nsxv3_constants
from neutron_lib.api.definitions import portbindings
from neutron_lib.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base as base_driver
from neutron_lib.plugins import directory
from neutron_lib.callbacks import events, registry, resources, priority_group
from neutron_lib import context
from unittest.mock import patch

LOG = logging.getLogger(__name__)


class SimpleObject(object):
    pass


class TestNSXv3TrunkDriver(base.BaseTestCase):

    def setUp(self):

        # Test trunk driver setup
        super(TestNSXv3TrunkDriver, self).setUp()

        # Logging setup
        logging.setup(cfg.CONF, 'demo')

        # Create call tracker
        self.call_tracker = CallTracker()

    def test_is_loaded(self):
        nsx_trunc_driver = NSXv3TrunkDriver.create()
        cfg.CONF.core_plugin = 'Ml2'
        self.assertEquals(nsx_trunc_driver.is_loaded, True)
        cfg.CONF.core_plugin = 'BlaBla'
        self.assertEquals(nsx_trunc_driver.is_loaded, False)

    def test_create(self):
        nsx_trunc_driver = NSXv3TrunkDriver.create()
        self.assertEquals(isinstance(nsx_trunc_driver, NSXv3TrunkDriver), True)
        self.assertEquals(nsx_trunc_driver.name == nsxv3_constants.NSXV3, True)
        self.assertEquals(nsx_trunc_driver.interfaces[0] == portbindings.VIF_TYPE_OVS, True)
        self.assertEquals(nsx_trunc_driver.segmentation_types[0] == trunk_consts.SEGMENTATION_TYPE_VLAN, True)
        self.assertEquals(nsx_trunc_driver.agent_type is None, True)
        self.assertEquals(nsx_trunc_driver.can_trunk_bound_port, True)

    def test_register(self):

        def mocked_register_of_base_driver(self_mocked, resource, event, trigger, payload=None):

            # To check parameters passed to 'super.register' method
            self.call_tracker.add_step(
                'trunk_register',
                'call:mocked_register_of_base_driver:parameters'
                + ':resource:' + str(resource)
                + ':event:' + str(event)
                + ':trigger:' + str(trigger)
                + ':payload:' + str(payload)
            )

        def mocked_subscribe_of_register(callback, resource, event,
                                         priority=priority_group.PRIORITY_DEFAULT):
            # To check parameters passed to 'subscribe' method
            self.call_tracker.add_step(
                'trunk_register',
                'call:mocked_subscribe_of_register:parameters'
                + ':callback:' + str(callback)
                + ':resource:' + str(resource)
                + ':event:' + str(event)
                + ':priority:' + str(priority)
            )

        with patch.object(base_driver.DriverBase, 'register', new=mocked_register_of_base_driver):
            with patch.object(registry, 'subscribe', new=mocked_subscribe_of_register):

                # Initialize the track
                self.call_tracker.init_track('trunk_register')

                # Create the driver
                nsx_trunc_driver = NSXv3TrunkDriver.create()

                # Prepare parameters and make a test call
                par_resource = 'MyResource'
                par_event = 'MyEvent'
                par_trigger = 'MyTrigger'
                par_payload = 'MyPayload'
                nsx_trunc_driver.register(par_resource, par_event, par_trigger, payload=par_payload)

                # Check property "core_plugin" content
                self.assertEquals(directory.get_plugin() == nsx_trunc_driver.core_plugin, True)

                # Check calls inside "register" method
                self.assertEquals(
                    self.call_tracker.steps_passed(
                        'trunk_register',
                        [
                            # Check parameters passed to 'super.register' method
                            'call:mocked_register_of_base_driver:parameters'
                            + ':resource:' + par_resource
                            + ':event:' + par_event
                            + ':trigger:' + par_trigger
                            + ':payload:' + par_payload,

                            # Check parameters passed to 'subscribe' method - call number 1
                            'call:mocked_subscribe_of_register:parameters'
                            + ':callback:' + str(nsx_trunc_driver.trunk_create)
                            + ':resource:' + str(resources.TRUNK)
                            + ':event:' + str(events.AFTER_CREATE)
                            + ':priority:' + str(priority_group.PRIORITY_DEFAULT),

                            # Check parameters passed to 'subscribe' method - call number 2
                            'call:mocked_subscribe_of_register:parameters'
                            + ':callback:' + str(nsx_trunc_driver.trunk_delete)
                            + ':resource:' + str(resources.TRUNK)
                            + ':event:' + str(events.AFTER_DELETE)
                            + ':priority:' + str(priority_group.PRIORITY_DEFAULT),

                            # Check parameters passed to 'subscribe' method - call number 3
                            'call:mocked_subscribe_of_register:parameters'
                            + ':callback:' + str(nsx_trunc_driver.subport_create)
                            + ':resource:' + str(resources.SUBPORTS)
                            + ':event:' + str(events.AFTER_CREATE)
                            + ':priority:' + str(priority_group.PRIORITY_DEFAULT),

                            # Check parameters passed to 'subscribe' method - call number 4
                            'call:mocked_subscribe_of_register:parameters'
                            + ':callback:' + str(nsx_trunc_driver.subport_delete)
                            + ':resource:' + str(resources.SUBPORTS)
                            + ':event:' + str(events.AFTER_DELETE)
                            + ':priority:' + str(priority_group.PRIORITY_DEFAULT)
                        ]
                    ),
                    True
                )

    def test__get_context_and_parent_port(self):

        def mocked_get_admin_context_of_context():
            return 'MyAdminContextObject'

        def mocked_get_port(ctx, parent_port_id):
            return {
                portbindings.VIF_TYPE: {
                    'MyParentPortIDInterfaceCompatible': 'MyParentPortInterfaceCompatible',
                    'MyParentPortIDInterfaceInCompatible': 'MyParentPortInterfaceIncompatible'
                }[parent_port_id]
            }

        def mocked_is_interface_compatible_of_base_driver(self_mocked, interface):
            return interface == 'MyParentPortInterfaceCompatible'

        with patch.object(context, 'get_admin_context', new=mocked_get_admin_context_of_context):
            with patch.object(
                    base_driver.DriverBase,
                    'is_interface_compatible',
                    new=mocked_is_interface_compatible_of_base_driver
            ):

                # Create NSX driver
                nsx_trunc_driver = NSXv3TrunkDriver.create()

                # Mocking core_plugin
                nsx_trunc_driver.core_plugin = SimpleObject()
                nsx_trunc_driver.core_plugin.get_port = mocked_get_port

                # Simulate successful call
                ctx, parent_port = nsx_trunc_driver._get_context_and_parent_port('MyParentPortIDInterfaceCompatible')

                # Check context
                self.assertEquals(ctx == mocked_get_admin_context_of_context(), True)

                # Check port
                self.assertEquals(parent_port is not None, True)
                self.assertEquals(portbindings.VIF_TYPE in parent_port, True)
                self.assertEquals(parent_port[portbindings.VIF_TYPE] == 'MyParentPortInterfaceCompatible', True)

                # # Simulate unsuccessful call
                ctx, parent_port = nsx_trunc_driver._get_context_and_parent_port('MyParentPortIDInterfaceInCompatible')

                # Check context
                self.assertEquals(ctx is None, True)

                # Check port
                self.assertEquals(parent_port is None, True)

    @staticmethod
    def mocked__get_context_and_parent_port(parent_port_id):
        if not parent_port_id:
            return None, None
        return 'context_for_' + parent_port_id, 'parent_for_' + parent_port_id

    def test_trunk_create(self):

        def mocked_current_trunk_update(status):
            self.call_tracker.add_step('trunk_create', 'mocked_current_trunk_update:status:' + status)

        def mocked__bind_subports(ctx, parent, trunk, subports, delete=False):
            self.call_tracker.add_step(
                'trunk_create',
                'mocked__bind_subports'
                + ':ctx:' + str(ctx)
                + ':parent:' + str(parent)
                + ':trunk:' + str(trunk)
                + ':subports:' + str(subports)
                + ':delete:' + str(delete)
            )

        # Create NSX driver
        nsx_trunc_driver = NSXv3TrunkDriver.create()

        with patch.object(
                nsx_trunc_driver,
                '_get_context_and_parent_port',
                new=self.mocked__get_context_and_parent_port
        ):
            with patch.object(nsx_trunc_driver, '_bind_subports', new=mocked__bind_subports):

                # Prepare parameters
                par_resource = 'MyResource'
                par_payload = SimpleObject()
                par_payload.states = []
                par_payload.states[0] = SimpleObject()
                par_payload.states[0].sub_ports = 'MyCurrentTrunkSubPorts'
                par_payload.trunk_id = 'MyTrunkID'
                par_payload.states[0].update = mocked_current_trunk_update

                # Initialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('trunk_create')

                # Make test call number 1
                par_payload.states[0].port_id = None
                nsx_trunc_driver.trunk_create(par_resource, None, None, par_payload)

                # No activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('trunk_create')) == 0, True)

                # Reinitialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('trunk_create')

                # Make test call number 2
                par_payload.states[0].port_id = 'MyCurrentTrunkPortID'
                nsx_trunc_driver.trunk_create(par_resource, None, None, par_payload)

                # Activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('trunk_create')) == 2, True)
                self.assertEquals(
                    self.call_tracker.steps_passed(
                        'trunk_create',
                        [
                            'mocked__bind_subports'
                            + ':ctx:' + 'context_for_' + str(par_payload.states[0].port_id)
                            + ':parent:' + 'parent_for_' + str(par_payload.states[0].port_id)
                            + ':trunk:' + str(par_payload.states[0])
                            + ':subports:' + str(par_payload.states[0].sub_ports)
                            + ':delete:' + str(False),
                            'mocked_current_trunk_update:status:' + trunk_consts.TRUNK_ACTIVE_STATUS
                        ]
                    ),
                    True
                )

    def test_trunk_delete(self):

        def mocked__bind_subports(ctx, parent, trunk, subports, delete=False):
            self.call_tracker.add_step(
                'trunk_delete',
                'mocked__bind_subports'
                + ':ctx:' + str(ctx)
                + ':parent:' + str(parent)
                + ':trunk:' + str(trunk)
                + ':subports:' + str(subports)
                + ':delete:' + str(delete)
            )

        # Create NSX driver
        nsx_trunc_driver = NSXv3TrunkDriver.create()

        with patch.object(
                nsx_trunc_driver,
                '_get_context_and_parent_port',
                new=self.mocked__get_context_and_parent_port
        ):
            with patch.object(nsx_trunc_driver, '_bind_subports', new=mocked__bind_subports):

                # Prepare parameters
                par_resource = 'MyResource'
                par_payload = SimpleObject()
                par_payload.states = []
                par_payload.states[0] = SimpleObject()
                par_payload.states[0].sub_ports = 'MyOriginalTrunkSubPorts'
                par_payload.trunk_id = 'MyTrunkID'

                # Initialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('trunk_delete')

                # Make test call number 1
                par_payload.states[0].port_id = None
                nsx_trunc_driver.trunk_delete(par_resource, None, None, par_payload)

                # No activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('trunk_delete')) == 0, True)

                # Reinitialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('trunk_delete')

                # Make test call number 2
                par_payload.states[0].port_id = 'MyCurrentTrunkPortID'
                nsx_trunc_driver.trunk_delete(par_resource, None, None, par_payload)

                # Activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('trunk_delete')) == 1, True)
                self.assertEquals(
                    self.call_tracker.steps_passed(
                        'trunk_delete',
                        [
                            'mocked__bind_subports'
                            + ':ctx:' + 'context_for_' + str(par_payload.states[0].port_id)
                            + ':parent:' + 'parent_for_' + str(par_payload.states[0].port_id)
                            + ':trunk:' + str(par_payload.states[0])
                            + ':subports:' + str(par_payload.states[0].sub_ports)
                            + ':delete:' + str(True)
                        ]
                    ),
                    True
                )

    def test_subport_create(self):

        def mocked__bind_subports(ctx, parent, trunk, subports, delete=False):
            self.call_tracker.add_step(
                'subport_create',
                'mocked__bind_subports'
                + ':ctx:' + str(ctx)
                + ':parent:' + str(parent)
                + ':trunk:' + str(trunk)
                + ':subports:' + str(subports)
                + ':delete:' + str(delete)
            )

        # Create NSX driver
        nsx_trunc_driver = NSXv3TrunkDriver.create()

        with patch.object(
                nsx_trunc_driver,
                '_get_context_and_parent_port',
                new=self.mocked__get_context_and_parent_port
        ):
            with patch.object(nsx_trunc_driver, '_bind_subports', new=mocked__bind_subports):

                # Prepare parameters
                par_resource = 'MyResource'
                par_payload = SimpleObject()
                par_payload.states = []
                par_payload.states[0] = SimpleObject()
                par_payload.subports = 'MyTrunkSubPorts'
                par_payload.trunk_id = 'MyTrunkID'

                # Initialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('subport_create')

                # Make test call number 1
                par_payload.states[0].port_id = None
                nsx_trunc_driver.subport_create(par_resource, None, None, par_payload)

                # No activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('subport_create')) == 0, True)

                # Reinitialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('subport_create')

                # Make test call number 2
                par_payload.states[0].port_id = 'MyCurrentTrunkPortID'
                nsx_trunc_driver.subport_create(par_resource, None, None, par_payload)

                # Activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('subport_create')) == 1, True)
                self.assertEquals(
                    self.call_tracker.steps_passed(
                        'subport_create',
                        [
                            'mocked__bind_subports'
                            + ':ctx:' + 'context_for_' + str(par_payload.states[0].port_id)
                            + ':parent:' + 'parent_for_' + str(par_payload.states[0].port_id)
                            + ':trunk:' + str(par_payload.states[0])
                            + ':subports:' + str(par_payload.subports)
                            + ':delete:' + str(False)
                        ]
                    ),
                    True
                )

    def test_subport_delete(self):

        def mocked__bind_subports(ctx, parent, trunk, subports, delete=False):
            self.call_tracker.add_step(
                'subport_delete',
                'mocked__bind_subports'
                + ':ctx:' + str(ctx)
                + ':parent:' + str(parent)
                + ':trunk:' + str(trunk)
                + ':subports:' + str(subports)
                + ':delete:' + str(delete)
            )

        # Create NSX driver
        nsx_trunc_driver = NSXv3TrunkDriver.create()

        with patch.object(
                nsx_trunc_driver,
                '_get_context_and_parent_port',
                new=self.mocked__get_context_and_parent_port
        ):
            with patch.object(nsx_trunc_driver, '_bind_subports', new=mocked__bind_subports):

                # Prepare parameters
                par_resource = 'MyResource'
                par_payload = SimpleObject()
                par_payload.states = []
                par_payload.states[0] = SimpleObject()
                par_payload.subports = 'MyTrunkSubPorts'
                par_payload.trunk_id = 'MyTrunkID'
                par_payload.context = None

                # Initialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('subport_delete')

                # Make test call number 1
                par_payload.states[0].port_id = None
                nsx_trunc_driver.subport_delete(par_resource, None, None, par_payload)

                # Activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('subport_delete')), 1)

                # Reinitialize/Prepare the call tracker for test call number 1
                self.call_tracker.init_track('subport_delete')

                # Make test call number 2
                par_payload.states[0].port_id = 'MyCurrentTrunkPortID'
                nsx_trunc_driver.subport_delete(par_resource, None, None, par_payload)

                # Activity is expected
                self.assertEquals(len(self.call_tracker.get_steps('subport_delete')) == 1, True)
                self.assertEquals(
                    self.call_tracker.steps_passed(
                        'subport_delete',
                        [
                            'mocked__bind_subports'
                            + ':ctx:' + 'context_for_' + str(par_payload.states[0].port_id)
                            + ':parent:' + 'parent_for_' + str(par_payload.states[0].port_id)
                            + ':trunk:' + str(par_payload.states[0])
                            + ':subports:' + str(par_payload.subports)
                            + ':delete:' + str(True)
                        ]
                    ),
                    True
                )

    def test__bind_subports(self):

        def mock_trunk_update(status):
            self.call_tracker.add_step('_bind_subports', 'mock_trunk_update:status:' + status)

        def mocked_core_plugin_update_port(ctx, subport_port_id, port_data):
            self.call_tracker.add_step(
                '_bind_subports',
                'mocked_core_plugin_update_port:subport_port_id:' + subport_port_id
            )

        # Create NSX driver
        nsx_trunc_driver = NSXv3TrunkDriver.create()

        # Prepare parameters
        ctx = 'MyContext'
        parent = {
            portbindings.PROFILE: {
                'key': 'value'
            },
            portbindings.HOST_ID: portbindings.HOST_ID,
            portbindings.VNIC_TYPE: portbindings.VNIC_TYPE,
            'device_id': 'device_id'
        }
        trunk = SimpleObject()
        trunk.port_id = 'TrunkPortID'
        trunk.id = 'ID'
        trunk.update = mock_trunk_update
        subports = list()
        for i in range(10):
            subport = SimpleObject()
            subport.port_id = 'SubPortPortID_' + str(i)
            subports.append(subport)

        # Mock NSX driver object "core_plugin.update_port" method
        nsx_trunc_driver.core_plugin = SimpleObject()
        nsx_trunc_driver.core_plugin.update_port = mocked_core_plugin_update_port

        # Make test call number 1
        self.call_tracker.init_track('_bind_subports')
        trunk.sub_ports = ['x']
        nsx_trunc_driver._bind_subports(ctx, parent, trunk, subports, delete=False)
        self.assertEquals(
            self.call_tracker.steps_passed(
                '_bind_subports',
                ['mock_trunk_update:status:' + trunk_consts.TRUNK_ACTIVE_STATUS]
            ),
            True
        )

        # Make test call number 2
        self.call_tracker.init_track('_bind_subports')
        trunk.sub_ports = []
        nsx_trunc_driver._bind_subports(ctx, parent, trunk, subports, delete=False)
        self.assertEquals(
            self.call_tracker.steps_passed(
                '_bind_subports',
                ['mock_trunk_update:status:' + trunk_consts.TRUNK_ACTIVE_STATUS]
            ),
            False
        )

        # Make test call number 3
        self.call_tracker.init_track('_bind_subports')
        nsx_trunc_driver._bind_subports(ctx, parent, trunk, subports, delete=False)
        self.assertEquals(
            self.call_tracker.steps_passed(
                '_bind_subports',
                ['mocked_core_plugin_update_port:subport_port_id:SubPortPortID_5']
            ),
            True
        )

        # Make test call number 4
        self.call_tracker.init_track('_bind_subports')
        nsx_trunc_driver._bind_subports(ctx, parent, trunk, [], delete=False)
        self.assertEquals(
            self.call_tracker.steps_passed(
                '_bind_subports',
                ['mocked_core_plugin_update_port:subport_port_id:SubPortPortID_5']
            ),
            False
        )
