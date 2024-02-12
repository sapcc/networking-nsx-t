import json

from networking_nsxv3.common import constants as nsxv3_constants
from neutron.db.models import allowed_address_pair
from neutron.db.models import securitygroup as sg_db
from neutron.db.models import address_group as ag_db
from neutron.db.models import tag as tag_model
from neutron.db.models.loggingapi import Log
from neutron.db.models.allowed_address_pair import AllowedAddressPair
from neutron.db.models_v2 import IPAllocation, Port
from neutron.db.qos.models import (QosBandwidthLimitRule, QosDscpMarkingRule,
                                   QosPolicy, QosPortPolicyBinding)
from neutron.plugins.ml2.models import PortBinding, PortBindingLevel
from neutron.services.trunk import models as trunk_model
from neutron_lib.api.definitions import portbindings
from neutron_lib.db.standard_attr import StandardAttribute
from sqlalchemy.orm.session import Session
from sqlalchemy.sql import text
from sqlalchemy import func


def get_ports_with_revisions(context, host, limit, cursor):
    return context.session.query(
        Port.id,
        StandardAttribute.revision_number,
        Port.standard_attr_id
    ).join(
        PortBindingLevel
    ).order_by(
        Port.standard_attr_id.asc()
    ).filter(
        StandardAttribute.id == Port.standard_attr_id,
        StandardAttribute.resource_type == 'ports',
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        Port.standard_attr_id > cursor,
    ).limit(
        limit
    ).all()


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
        StandardAttribute.resource_type == 'qos_policies',
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
        StandardAttribute.resource_type == 'securitygroups',
        PortBindingLevel.host == host,
        PortBindingLevel.level == 1,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
        sg_db.SecurityGroup.standard_attr_id > cursor
    ).distinct().limit(
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
        PortBinding.status
    ).join(
        StandardAttribute,
        PortBinding
    ).filter(
        Port.id == port_id,
    )
    if host:
        port = port.filter(
            PortBinding.host == host
        )
    else:
        port = port.filter(
            PortBinding.status == 'ACTIVE'
        )
    port = port.one_or_none()

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

    (id, mac, up, status, rev, binding_host, vif_details, binding_status) = port

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
        portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
        "binding_status": binding_status,
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

def fetch_security_group_information(context, host, security_group_id, max_tags):
    """
    Fetch all relevant information for realizing SG Groups on NSX-T.
    CASE1: At least one Port, bound to host, references SG Group
    CASE2: No Port bound by host references the SG Group. SG Group might be part of a remote SG Group.
    :param context:
    :param host:
    :param security_group_id:
    :param max_tags: Maximum number of tags allowed per port (NSX-T limitation)
    :return: Related CIDRS, Ports SG Group Count referencing security_group_id
    """
    ## Case 1: SG needs to be bound by Host
    ## Case 2: SG not bound by host --> only CIDRs relevant --> no need to check max
    #if sg is related to the host

    remote_group = False
    sg_count_per_port = None

    # Case 1
    ports_on_host = context.session.query(
            sg_db.SecurityGroupPortBinding.port_id
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id,
    ).filter(
        sg_db.SecurityGroupPortBinding.security_group_id == security_group_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
    ).all()

    port_ids = [port_id for (port_id,) in ports_on_host]

    # Case 2
    if not port_ids or len(port_ids) == 0:
        remote_sg = context.session.query(
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
        ).limit(1).first()

        if remote_sg is None:
            return None, None
        remote_group = True

    #Fetch all ips related to the SG
    allowed_address_pairs = context.session.query(
        AllowedAddressPair.ip_address
    ).join(
        sg_db.SecurityGroupPortBinding,
        AllowedAddressPair.port_id ==  sg_db.SecurityGroupPortBinding.port_id
    ).filter(
        security_group_id == sg_db.SecurityGroupRule.security_group_id
    ).all()

    allocated_ipds = context.session.query(
        IPAllocation.ip_address
    ).join(
        sg_db.SecurityGroupPortBinding,
        IPAllocation.port_id == sg_db.SecurityGroupPortBinding.port_id
    ).filter(
        security_group_id == sg_db.SecurityGroupRule.security_group_id
    ).all()

    cidrs = [ip[0] for ip in allowed_address_pairs] + [ip[0] for ip in allocated_ipds]

    if not remote_group:
        #Static membership realization is not needed for groups only referenced as remote SG
        sg_count_per_port = context.session.query(
            sg_db.SecurityGroupPortBinding.port_id,
            func.count(sg_db.SecurityGroupPortBinding.port_id)
        ).filter(
            sg_db.SecurityGroupPortBinding.port_id.in_(port_ids),
        ).group_by(
            sg_db.SecurityGroupPortBinding.port_id
        ).having(func.count(sg_db.SecurityGroupPortBinding.port_id) > max_tags).all()

    return cidrs, sg_count_per_port

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
    ses: Session = context.session
    res = ses.query(
        sg_db.SecurityGroupPortBinding.port_id
    ).join(
        PortBindingLevel,
        PortBindingLevel.port_id == sg_db.SecurityGroupPortBinding.port_id,
    ).filter(
        sg_db.SecurityGroupPortBinding.security_group_id == security_group_id,
        PortBindingLevel.host == host,
        PortBindingLevel.driver == nsxv3_constants.NSXV3,
    ).group_by(
        sg_db.SecurityGroupPortBinding.port_id
    ).all()

    port_ids = [port_id for (port_id,) in res]
    if not port_ids or len(port_ids) == 0:
        return []

    # For each port get the number of the security groups it is a member of
    port_ids_str = [f"'{port_id}'" for port_id in port_ids]
    sql = text(
        "SELECT port_id, COUNT(port_id) as sg_count " +
        "FROM securitygroupportbindings " +
        f"WHERE port_id IN ({', '.join(port_ids_str)}) " +
        "GROUP BY port_id"
    )

    ports_with_sg_count = ses.execute(sql)
    return ports_with_sg_count


def get_security_group_members_address_bindings_ips(context, security_group_id):
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


def get_addresses_for_address_group_id(context, addr_group_id):
    return context.session.query(
        ag_db.AddressAssociation.address
    ).filter(
        ag_db.AddressAssociation.address_group_id == addr_group_id
    ).all()


def get_address_group_revision_number(context, addr_group_id):
    return context.session.query(
        StandardAttribute.revision_number
    ).select_from(
        ag_db.AddressGroup
    ).join(
        StandardAttribute
    ).filter(
        ag_db.AddressGroup.id == addr_group_id
    ).one_or_none()
