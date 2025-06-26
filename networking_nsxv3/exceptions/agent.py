
from neutron_lib._i18n import _
from neutron_lib import exceptions

class MultipleSegmentPorts(exceptions.NeutronException):
    message = _("More thant 2 segment ports found for OpenStack Port %(port_id)s")

class NoneUniqueObjectFound(exceptions.NeutronException):
    message = _("Found multiple objects for query %(query) found for %(objects)s. "
                "Please use a more specific query to return a single object.")
