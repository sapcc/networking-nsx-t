import json

from networking_nsxv3.common import constants as nsxv3_constants
from neutron.db.models import allowed_address_pair
from neutron.db.models import securitygroup as sg_db
from neutron.db.models import tag as tag_model
from neutron.db.models.loggingapi import Log
from neutron.db.models.allowed_address_pair import AllowedAddressPair
from neutron.db.models_v2 import IPAllocation, Port
from neutron.db.qos.models import (QosBandwidthLimitRule, QosDscpMarkingRule,
                                   QosPolicy, QosPortPolicyBinding)
from neutron_lib.db.standard_attr import StandardAttribute
from neutron.plugins.ml2.models import PortBinding, PortBindingLevel
from neutron.services.trunk import models as trunk_model
from neutron_lib.api.definitions import portbindings
# from sqlalchemy.orm.session import Session


def get_ports_with_revisions(context, host, limit, cursor):
    return set(context.session.query(
        Port.id,
        StandardAttribute.revision_number,
        Port.standard_attr_id
    ).join(
        PortBindingLevel
    ).order_by(
        Port.standard_attr_id.asc()
    ).filter(
        StandardAttribute.id == Port.standard_attr_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        Port.standard_attr_id > cursor,
    ).limit(
        limit
    ).all())


def get_qos_policies_with_revisions(context, host, limit, cursor):
    return context.session.query(
        QosPolicy.id,
        StandardAttribute.revision_number,
        QosPolicy.standard_attr_id
    ).join(
        QosPortPolicyBinding
    ).join(
        Port
    ).join(
        PortBindingLevel
    ).order_by(
        QosPolicy.standard_attr_id.asc()
    ).filter(
        StandardAttribute.id == QosPolicy.standard_attr_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        QosPolicy.standard_attr_id > cursor
    ).limit(
        limit
    ).all()


def get_security_groups_with_revisions(context, host, limit, cursor):
    return context.session.query(
        sg_db.SecurityGroup.id,
        StandardAttribute.revision_number,
        sg_db.SecurityGroup.standard_attr_id
    ).join(
        sg_db.SecurityGroupPortBinding
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id
    ).order_by(
        sg_db.SecurityGroup.standard_attr_id.asc()
    ).filter(
        StandardAttribute.id == sg_db.SecurityGroup.standard_attr_id,
        PortBindingLevel.host == host,
        PortBindingLevel.level == 1,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        sg_db.SecurityGroup.standard_attr_id > cursor
    ).limit(
        limit
    ).all()


def get_security_group_revision(context, security_group_id):
    return context.session.query(
        sg_db.SecurityGroup.id,
        StandardAttribute.revision_number,
        sg_db.SecurityGroup.stateful
    ).join(
        StandardAttribute
    ).filter(
        sg_db.SecurityGroup.id == security_group_id
    ).one_or_none()


def get_security_group_tag(context, security_group_id):
    return context.session.query(
        tag_model.Tag.tag
    ).join(
        sg_db.SecurityGroup,
        tag_model.Tag.standard_attr_id == sg_db.SecurityGroup.standard_attr_id
    ).filter(
        sg_db.SecurityGroup.id == security_group_id
    ).all()


def get_qos(context, qos_id):
    return context.session.query(
        QosPolicy.name,
        StandardAttribute.revision_number
    ).filter(
        QosPolicy.id == qos_id
    ).join(
        StandardAttribute
    ).one_or_none()


def get_qos_ports_by_host(context, host, qos_id):
    return context.session.query(
        Port.id,
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == Port.id
    ).join(
        QosPortPolicyBinding,
        QosPortPolicyBinding.port_id == Port.id
    ).filter(
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        QosPolicy.id == qos_id
    ).limit(1).one_or_none()


def get_qos_bwl_rules(context, qos_id):
    return context.session.query(
        QosBandwidthLimitRule.direction,
        QosBandwidthLimitRule.max_kbps,
        QosBandwidthLimitRule.max_burst_kbps
    ).filter(
        QosBandwidthLimitRule.qos_policy_id == qos_id
    ).all()


def get_qos_dscp_rules(context, qos_id):
    return context.session.query(
        QosDscpMarkingRule.qos_policy_id,
        QosDscpMarkingRule.dscp_mark
    ).filter(
        QosDscpMarkingRule.qos_policy_id == qos_id
    ).all()


def get_port(context, host, port_id):
    port = context.session.query(
        Port.id,
        Port.mac_address,
        Port.admin_state_up,
        Port.status,
        StandardAttribute.revision_number,
        PortBinding.host,
        PortBinding.vif_details,
    ).join(
        StandardAttribute,
        PortBinding
    ).filter(
        Port.id == port_id,
        PortBinding.host == host
    ).one_or_none()

    qos_id = context.session.query(
        QosPolicy.id
    ).join(
        QosPortPolicyBinding
    ).filter(
        QosPortPolicyBinding.port_id == port_id
    ).one_or_none()

    parent_port = context.session.query(
        trunk_model.Trunk.port_id,
        trunk_model.SubPort.segmentation_id
    ).join(
        trunk_model.SubPort
    ).filter(
        trunk_model.SubPort.port_id == port_id,
    ).one_or_none()

    if not port:
        return None

    (id, mac, up, status, rev, binding_host, vif_details) = port

    return {
        "id": id,
        "parent_id": parent_port[0] if parent_port else "",
        "traffic_tag": parent_port[1] if parent_port else None,
        "mac_address": mac,
        "admin_state_up": up,
        "status": status,
        "qos_policy_id": qos_id[0] if qos_id else "",
        "security_groups": [],
        "address_bindings": [],
        "revision_number": rev,
        "binding:host_id": binding_host,
        "vif_details": json.loads(vif_details) if vif_details else vif_details,
        portbindings.VNIC_TYPE: portbindings.VNIC_NORMAL,
        portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS
    }


def get_port_security_groups(context, port_id):
    return context.session.query(
        sg_db.SecurityGroupPortBinding.security_group_id
    ).filter(
        sg_db.SecurityGroupPortBinding.port_id == port_id
    ).all()


def get_port_allowed_pairs(context, port_id):
    return context.session.query(
        allowed_address_pair.AllowedAddressPair.ip_address,
        allowed_address_pair.AllowedAddressPair.mac_address
    ).filter(
        allowed_address_pair.AllowedAddressPair.port_id == port_id
    ).all()


def get_port_addresses(context, port_id):
    return context.session.query(
        IPAllocation.ip_address
    ).filter(
        IPAllocation.port_id == port_id
    ).all()


def get_rules_for_security_group_id(context, security_group_id):
    return context.session.query(
        sg_db.SecurityGroupRule
    ).filter(
        sg_db.SecurityGroupRule.security_group_id == security_group_id
    ).all()


def get_port_id_by_sec_group_id(context, host, security_group_id):
    result = context.session.query(
        sg_db.SecurityGroupPortBinding.port_id
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id
    ).filter(
        sg_db.SecurityGroupPortBinding.security_group_id == security_group_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3
    ).all()

    return [o[0] for o in result]


def get_security_groups_for_host(context, host, limit, cursor):
    return context.session.query(
        sg_db.SecurityGroupPortBinding.security_group_id,
        StandardAttribute.id
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id
    ).order_by(
        StandardAttribute.id.asc()
    ).filter(
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        StandardAttribute.id > cursor
    ).distinct().limit(limit).all()


def get_remote_security_groups_for_host(context, host, limit, cursor):
    return context.session.query(
        sg_db.SecurityGroupRule.remote_group_id,
        StandardAttribute.id
    ).join(
        sg_db.SecurityGroupPortBinding,
        sg_db.SecurityGroupPortBinding.security_group_id == sg_db.SecurityGroupRule.security_group_id
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id
    ).order_by(
        StandardAttribute.id.asc()
    ).filter(
        sg_db.SecurityGroupRule.remote_group_id.isnot(None),
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        StandardAttribute.id > cursor
    ).distinct().limit(limit).all()


def has_security_group_used_by_host(context, host, security_group_id):
    if context.session.query(
        sg_db.SecurityGroup.id
    ).join(
        sg_db.SecurityGroupPortBinding,
        sg_db.SecurityGroupPortBinding.security_group_id == sg_db.SecurityGroup.id
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id,
    ).filter(
        sg_db.SecurityGroup.id == security_group_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
    ).limit(1).first() is not None:
        return True

    if context.session.query(
        sg_db.SecurityGroupRule.remote_group_id,
    ).join(
        sg_db.SecurityGroupPortBinding,
        sg_db.SecurityGroupPortBinding.security_group_id == sg_db.SecurityGroupRule.security_group_id
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id
    ).filter(
        sg_db.SecurityGroupRule.remote_group_id == security_group_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
    ).limit(1).first() is not None:
        return True

    return False


def get_security_group_members_ips(context, security_group_id):
    port_id = sg_db.SecurityGroupPortBinding.port_id
    group_id = sg_db.SecurityGroupPortBinding.security_group_id
    return context.session.query(
        IPAllocation.ip_address
    ).join(
        sg_db.SecurityGroupPortBinding,
        IPAllocation.port_id == port_id
    ).filter(
        security_group_id == group_id
    ).all()


def get_security_group_port_ids(context, host, security_group_id):
    # ses: Session = context.session
    ses = context.session
    res = ses.query(
        sg_db.SecurityGroupPortBinding.port_id
    ).distinct(
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id,
    ).filter(
        sg_db.SecurityGroupPortBinding.security_group_id == security_group_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
    ).all()

    return [port_id for (port_id,) in res]


def get_security_group_members_address_bindings_ips(context,
                                                    security_group_id):
    port_id = sg_db.SecurityGroupPortBinding.port_id
    group_id = sg_db.SecurityGroupPortBinding.security_group_id
    return context.session.query(
        AllowedAddressPair.ip_address
    ).join(
        sg_db.SecurityGroupPortBinding,
        AllowedAddressPair.port_id == port_id
    ).filter(
        security_group_id == group_id
    ).all()


def get_port_logging(context, port_id):
    return context.session.query(
        Log.project_id,
        Log.resource_id,
        Log.enabled
    ).filter(
        Log.target_id == port_id
    ).one_or_none()


def has_security_group_logging(context, security_group_id):
    result = context.session.query(
        Log.resource_id,
        Log.enabled
    ).filter(
        Log.resource_id == security_group_id,
        Log.enabled
    ).count()
    return True if result else False
