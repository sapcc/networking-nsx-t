from datetime import datetime

from neutron.db.models import securitygroup as sg_db
from neutron.db.models import allowed_address_pair
from neutron.db.models import tag as tag_model
from neutron.db.qos.models import QosPortPolicyBinding
from neutron.db.qos.models import QosPolicy
from neutron.db.qos.models import QosBandwidthLimitRule
from neutron.db.qos.models import QosDscpMarkingRule
from neutron.db.models_v2 import Port
from neutron.db.standard_attr import StandardAttribute
from neutron.plugins.ml2.models import PortBindingLevel
from neutron.db.models_v2 import IPAllocation
from neutron.db.models.allowed_address_pair import AllowedAddressPair
from neutron.services.trunk import models as trunk_model

from neutron.plugins.ml2.models import PortBinding

from networking_nsxv3.common import constants as nsxv3_constants
from neutron_lib import exceptions


def _validate_one(result, error):
    if result:
        return result
    else:
        raise exceptions.ObjectNotFound(id=error)


def _get_datetime(datetime_value):
    if isinstance(datetime_value, datetime):
        return datetime_value
    elif isinstance(datetime_value, basestring):
        return datetime.strptime(datetime_value, '%Y-%m-%dT%H:%M:%S.%f')
    else:
        raise Exception(
            "datetime_value object should be datetime or string in isoformat")


def get_port_revision_tuples(
        context,
        host,
        limit,
        created_after):
    return context.session.query(
        Port.id,
        StandardAttribute.revision_number,
        StandardAttribute.created_at
    ).join(
        StandardAttribute,
        PortBindingLevel
    ).order_by(
        StandardAttribute.created_at
    ).filter(
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        StandardAttribute.created_at >= _get_datetime(created_after)
    ).limit(
        limit
    ).all()


def get_qos_policy_revision_tuples(
        context,
        limit,
        created_after):
    return context.session.query(
        QosPolicy.id,
        StandardAttribute.revision_number,
        StandardAttribute.created_at
    ).join(
        StandardAttribute
    ).order_by(
        StandardAttribute.created_at
    ).filter(
        StandardAttribute.created_at >= _get_datetime(created_after)
    ).limit(
        limit
    ).all()


def get_security_group_revision(context, security_group_id):
    result = context.session.query(
        sg_db.SecurityGroup.id,
        StandardAttribute.revision_number
    ).join(
        StandardAttribute
    ).filter(
        sg_db.SecurityGroup.id == security_group_id
    ).one_or_none()
    return _validate_one(result,
                         "Security Group ID='{}'".format(security_group_id))


def get_security_group_revision_tuples(
        context,
        limit,
        created_after):
    return context.session.query(
        sg_db.SecurityGroup.id,
        StandardAttribute.revision_number,
        StandardAttribute.created_at
    ).join(
        StandardAttribute
    ).order_by(
        StandardAttribute.created_at
    ).filter(
        StandardAttribute.created_at >= _get_datetime(created_after)
    ).limit(
        limit
    ).all()


def has_security_group_tag(context, security_group_id, tag_name):
    result = context.session.query(
        sg_db.SecurityGroup.id
    ).join(
        tag_model.Tag,
        tag_model.Tag.standard_attr_id == sg_db.SecurityGroup.standard_attr_id
    ).filter(
        tag_model.Tag.tag == tag_name,
        sg_db.SecurityGroup.id == security_group_id
    ).all()
    return len(result) != 0


def get_qos(context, qos_id):
    result = context.session.query(
        QosPolicy.name,
        StandardAttribute.revision_number
    ).filter(
        QosPolicy.id == qos_id
    ).join(
        StandardAttribute
    ).one_or_none()
    return _validate_one(result,
                         "QoS Policy ID='{}'".format(qos_id))


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


def get_port(context, port_id):
    result = context.session.query(
        Port.id,
        Port.mac_address,
        Port.admin_state_up,
        Port.status,
        QosPolicy.id,
        StandardAttribute.revision_number,
        PortBinding.host,
        PortBinding.vif_details,
        trunk_model.Trunk.port_id
    ).filter(
        Port.id == port_id
    ).join(
        StandardAttribute,
        PortBinding,
    ).outerjoin(
        QosPortPolicyBinding,
        QosPolicy
    ).outerjoin(
        trunk_model.SubPort,
        trunk_model.SubPort.port_id == port_id
    ).outerjoin(
        trunk_model.Trunk
    ).one_or_none()
    return _validate_one(result,
                         "Port ID='{}'".format(port_id))


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
        IPAllocation.ip_address,
        IPAllocation.subnet_id
    ).filter(
        IPAllocation.port_id == port_id
    ).all()


def _query_securitygrouprules(context, ids):
    return context.session.query(
        sg_db.SecurityGroupRule.project_id,
        sg_db.SecurityGroupRule.id,
        sg_db.SecurityGroupRule.security_group_id,
        sg_db.SecurityGroupRule.remote_group_id,
        sg_db.SecurityGroupRule.direction,
        sg_db.SecurityGroupRule.ethertype,
        sg_db.SecurityGroupRule.protocol,
        sg_db.SecurityGroupRule.port_range_min,
        sg_db.SecurityGroupRule.port_range_max,
        sg_db.SecurityGroupRule.remote_ip_prefix,
        sg_db.SecurityGroupRule.id
    ).filter(
        sg_db.SecurityGroupRule.id in ids
    ).all()


def _query_standardattributes(context, created_at):
    return context.session.query(
        StandardAttribute.id,
        StandardAttribute.resource_type,
        StandardAttribute.created_at,
        StandardAttribute.updated_at,
        StandardAttribute.description,
        StandardAttribute.revision_number
    ).filter(
        StandardAttribute.created_at >= created_at
    ).all()


def _get_latest_changes(context, resource_type, updated_at):
    return context.session.query(
        sg_db.SecurityGroupRule.project_id,
        sg_db.SecurityGroupRule.id,
        sg_db.SecurityGroupRule.security_group_id,
        sg_db.SecurityGroupRule.remote_group_id,
        sg_db.SecurityGroupRule.direction,
        sg_db.SecurityGroupRule.ethertype,
        sg_db.SecurityGroupRule.protocol,
        sg_db.SecurityGroupRule.port_range_min,
        sg_db.SecurityGroupRule.port_range_max,
        sg_db.SecurityGroupRule.remote_ip_prefix,
        sg_db.SecurityGroupRule.id,
        StandardAttribute.id,
        StandardAttribute.resource_type,
        StandardAttribute.created_at,
        StandardAttribute.updated_at,
        StandardAttribute.description,
        StandardAttribute.revision_number
    ).join(
        StandardAttribute,
        sg_db.SecurityGroupRule.id == StandardAttribute.id
    ).filter(
        StandardAttribute.updated_at >= updated_at
    ).filter(
        StandardAttribute.resource_type == resource_type
    ).all()


def get_rules_for_security_groups_id(context, security_group_id):
    return context.session.query(
        sg_db.SecurityGroupRule
    ).filter(
        sg_db.SecurityGroupRule.security_group_id == security_group_id
    ).all()


def _get_port_id_by_sec_group_id(context, sec_group_id):
    return context.session.query(
        sg_db.SecurityGroupPortBinding.port_id
    ).filter(
        sg_db.SecurityGroupPortBinding.security_group_id == sec_group_id
    ).all()


def get_security_group_members_ips(context, security_group_id):
    port_id = sg_db.SecurityGroupPortBinding.port_id
    group_id = sg_db.SecurityGroupPortBinding.security_group_id
    return list(
        context.session.query(
            IPAllocation.ip_address
        ).join(
            sg_db.SecurityGroupPortBinding,
            IPAllocation.port_id == port_id
        ).filter(
            security_group_id == group_id
        ).all())


def get_security_group_members_address_bindings_ips(context,
                                                    security_group_id):
    port_id = sg_db.SecurityGroupPortBinding.port_id
    group_id = sg_db.SecurityGroupPortBinding.security_group_id
    return list(
        context.session.query(
            AllowedAddressPair.ip_address
        ).join(
            sg_db.SecurityGroupPortBinding,
            AllowedAddressPair.port_id == port_id
        ).filter(
            security_group_id == group_id
        ).all())
