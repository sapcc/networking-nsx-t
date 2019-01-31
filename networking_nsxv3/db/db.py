from neutron.db.models import securitygroup as sg_db
from neutron.db.models import allowed_address_pair
from neutron.db.qos.models import QosPortPolicyBinding
from neutron.db.qos.models import QosPolicy
from neutron.db.qos.models import QosBandwidthLimitRule
from neutron.db.qos.models import QosDscpMarkingRule
from neutron.db.qos.models import QosMinimumBandwidthRule
from neutron.db.models import portbinding as pmodels
from neutron.db.models_v2 import Port
from neutron.db.standard_attr import StandardAttribute
from neutron.plugins.ml2.models import PortBindingLevel
from neutron.db.models_v2 import IPAllocation
from neutron.db.models.allowed_address_pair import AllowedAddressPair
from neutron.db.qos.models import QosPolicy

from networking_nsxv3.common import constants as nsxv3_constants

import datetime


class DB(object):

    def __init__(self, config, context):
        self.context = context
        self.config = config

    def _validate_one(self, result, error):
        msg = "{} not found in Neutron."
        if result:
            return result
        else:
            raise Exception(msg.format(error))

    def get_port_revision_tuples(
            self,
            limit=100,
            created_after=datetime.datetime(1970, 1, 1)):
        return self.context.session.query(
            Port.id,
            StandardAttribute.revision_number,
            StandardAttribute.created_at
        ).join(
            StandardAttribute,
            PortBindingLevel
        ).order_by(
            StandardAttribute.created_at
        ).filter(
            PortBindingLevel.host == self.config.host,
            PortBindingLevel.driver == nsxv3_constants.NSXV3,
            StandardAttribute.created_at >= created_after
        ).limit(
            limit
        ).all()

    def get_qos_policy_revision_tuples(
            self,
            limit=100,
            created_after=datetime.datetime(1970, 1, 1)):
        return self.context.session.query(
            QosPolicy.id,
            StandardAttribute.revision_number,
            StandardAttribute.created_at
        ).join(
            StandardAttribute
        ).order_by(
            StandardAttribute.created_at
        ).filter(
            StandardAttribute.created_at >= created_after
        ).limit(
            limit
        ).all()

    def get_security_group_revision(self, security_group_id):
        result = self.context.session.query(
            sg_db.SecurityGroup.id,
            StandardAttribute.revision_number
        ).join(
            StandardAttribute
        ).filter(
            sg_db.SecurityGroup.id == security_group_id
        ).one_or_none()
        return self._validate_one(result, 
            "Security Group ID='{}'".format(security_group_id))

    def get_security_group_revision_tuples(
            self,
            limit=100,
            created_after=datetime.datetime(1970, 1, 1)):
        return self.context.session.query(
            sg_db.SecurityGroup.id,
            StandardAttribute.revision_number,
            StandardAttribute.created_at
        ).join(
            StandardAttribute
        ).order_by(
            StandardAttribute.created_at
        ).filter(
            StandardAttribute.created_at >= created_after
        ).limit(
            limit
        ).all()

    def get_qos(self, qos_id):
        result = self.context.session.query(
            QosPolicy.name,
            StandardAttribute.revision_number
        ).filter(
            QosPolicy.id == qos_id
        ).join(
            StandardAttribute
        ).one_or_none()
        return self._validate_one(result, 
            "QoS Policy ID='{}'".format(qos_id))

    def get_qos_bwl_rules(self, qos_id):
        return self.context.session.query(
            QosBandwidthLimitRule.direction,
            QosBandwidthLimitRule.max_kbps,
            QosBandwidthLimitRule.max_burst_kbps
        ).filter(
            QosBandwidthLimitRule.qos_policy_id == qos_id
        ).all()

    def get_qos_dscp_rules(self, qos_id):
        return self.context.session.query(
            QosDscpMarkingRule.qos_policy_id,
            QosDscpMarkingRule.dscp_mark
        ).filter(
            QosDscpMarkingRule.qos_policy_id == qos_id
        ).all()

    def get_port(self, port_id):
        result = self.context.session.query(
            Port.id,
            Port.mac_address,
            Port.admin_state_up,
            Port.status,
            QosPolicy.id,
            StandardAttribute.revision_number
        ).join(
            StandardAttribute
        ).filter(
            Port.id == port_id
        ).outerjoin(
            QosPortPolicyBinding,
            QosPolicy
        ).one_or_none()
        return self._validate_one(result, 
            "Port ID='{}'".format(port_id))

    def get_port_security_groups(self, port_id):
        return self.context.session.query(
            sg_db.SecurityGroupPortBinding.security_group_id
        ).filter(
            sg_db.SecurityGroupPortBinding.port_id == port_id
        ).all()

    def get_port_allowed_pairs(self, port_id):
        return self.context.session.query(
            allowed_address_pair.AllowedAddressPair.ip_address,
            allowed_address_pair.AllowedAddressPair.mac_address
        ).filter(
            allowed_address_pair.AllowedAddressPair.port_id == port_id
        ).all()
    
    def get_port_addresses(self, port_id):
        return self.context.session.query(
            IPAllocation.ip_address,
            IPAllocation.subnet_id
        ).filter(
            IPAllocation.port_id == port_id
        ).all()

    def _query_securitygrouprules(self, ids):
        return self.context.session.query(
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

    def _query_standardattributes(self, created_at):
        return self.context.session.query(
            StandardAttribute.id,
            StandardAttribute.resource_type,
            StandardAttribute.created_at,
            StandardAttribute.updated_at,
            StandardAttribute.description,
            StandardAttribute.revision_number
        ).filter(
            StandardAttribute.created_at >= created_at
        ).all()

    def _get_latest_changes(self, resource_type, updated_at):
        return self.context.session.query(
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

    def _get_rules_for_security_groups_id(self, security_group_id):
        return self.context.session.query(
            sg_db.SecurityGroupRule
        ).filter(
            sg_db.SecurityGroupRule.security_group_id == security_group_id
        ).all()

    def _get_port_id_by_sec_group_id(self, sec_group_id):
        return self.context.session.query(
            sg_db.SecurityGroupPortBinding.port_id
        ).filter(
            sg_db.SecurityGroupPortBinding.security_group_id == sec_group_id
        ).all()

    def _get_security_group_members_ips(self, security_group_id):
        return list(
            self.context.session.query(
                IPAllocation.ip_address
            ).join(
                sg_db.SecurityGroupPortBinding,
                IPAllocation.port_id == sg_db.SecurityGroupPortBinding.port_id
            ).filter(
                security_group_id == sg_db.SecurityGroupPortBinding.security_group_id
            ).all())

    def _get_security_group_members_address_bindings_ips(
            self, security_group_id):
        return list(
            self.context.session.query(
                AllowedAddressPair.ip_address
            ).join(
                sg_db.SecurityGroupPortBinding,
                AllowedAddressPair.port_id == sg_db.SecurityGroupPortBinding.port_id
            ).filter(
                security_group_id == sg_db.SecurityGroupPortBinding.security_group_id
            ).all())
