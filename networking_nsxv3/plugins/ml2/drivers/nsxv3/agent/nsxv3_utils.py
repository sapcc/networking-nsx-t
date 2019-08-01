# Utility methods converting NSX-T SDK model objects into REST payloads

# Some NSX-T activities require uage of REST instead of SDK.
# Bellow is a quote from NSX-T SDK providing justification.
#
# createwithrules(firewall_section_rule_list, id=None, operation=None)
# Creates a new firewall section with rules. The limit on the number of rules
# is defined by maxItems in collection types for FirewallRule
# (FirewallRuleXXXList types).
# When invoked on a section with a large number of rules,
# this API is supported only at low rates of invocation
# (not more than 4-5 times per minute). The typical latency of this API with
# about 1024 rules is about 4-5 seconds.
# This API should not be invoked with large payloads at automation speeds.
# More than 50 rules with a large number of rule references is not supported.
# Instead, to create sections,
# use: POST /api/v1/firewall/sections To create rules,
# use: POST /api/v1/firewall/sections/<section-id>/rules
from uuid import UUID


def get_firewall_rule(sdk_model):
    rule = {}
    rule["action"] = sdk_model.action
    rule["display_name"] = sdk_model.display_name
    rule["direction"] = sdk_model.direction
    rule["ip_protocol"] = sdk_model.ip_protocol
    rule["sources"] = sdk_model.sources
    rule["destinations"] = sdk_model.destinations
    rule["services"] = sdk_model.services
    rule["applied_tos"] = sdk_model.applied_tos

    ref = get_resource_reference
    svc = get_service_reference

    if sdk_model.sources:
        rule["sources"] = [ref(o) for o in sdk_model.sources]
    if sdk_model.destinations:
        rule["destinations"] = [ref(o) for o in sdk_model.destinations]
    if sdk_model.services:
        rule["services"] = [svc(o) for o in sdk_model.services]
    if sdk_model.applied_tos:
        rule["applied_tos"] = [ref(o) for o in sdk_model.applied_tos]
    return rule


def get_resource_reference(sdk_model):
    ref = {}
    ref["target_type"] = sdk_model.target_type
    ref["target_id"] = sdk_model.target_id
    ref["target_display_name"] = sdk_model.target_display_name
    if sdk_model.is_valid:
        ref["is_valid"] = sdk_model.is_valid
    return ref


def get_service_reference(sdk_model):
    json = {}
    for key, val in vars(sdk_model.service).iteritems():
        if not key.startswith("_"):
            json[key] = val
    return {"service": json}


def is_valid_uuid(uuid, version=4):
    try:
        uuid_obj = UUID(uuid, version=version)
    except ValueError:
        return False

    return str(uuid_obj) == uuid


def get_segmentation_id_lock(segmentation_id):
    return "segmentation_id-{}".format(segmentation_id)
