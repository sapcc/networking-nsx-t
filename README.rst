networking-nsxv3
================

Openstack L2 network components for VMware NSX-T (NSXv3)

This project allowes an OpenStack region to implement complex L2 network topology distributed accross many VMware NSX-T managers, where at the same time all these managers will share the same security context.


NSX-T ML2 Mechanism Dirver
--------------------------

NSX-T ML2 Mechanism Dirver is an extension to the Modular Layer 2 (ml2) plugin framework. This driver enables OpenStack Neutron to simultaneously utilize NSX-T network technology in combination with other technologies to reach the goal of Hierarchical Port Binding.


NSX-T L2 Agent
--------------

NSX-T L2 Agent implements OpenStack network related events into VMware NSX-T constructions.
- OpenStack network segments are mapped to NSX-T Logical Switches (VLAN backed)
- OpenStack ports are mapped NSX-T Logical Ports
- OpenStack port security is mapped to NSX-T IP Discovery and SpoofGuard Switching Profiles (applied per port)
- OpenStack QoS Profiles are mapped to NSX-T QoS Switching Profiles
- OpenStack Security Groups are mapped to NSX-T Firewall Sections, NS Groups and IP Sets
- OpenStack Security Groups Rules are mapped to NSX-T Firewall Section Rules
- OpenStack Security Groups Members are mapped to NSX-T IP Sets
- OpenStack Security Groups Membership is mapped to NSX-T NS Groups Membership Tags


Installation
------------

Install NSX-T 2.3 SDK (download SDK from VMware web site)
::

    sudo pip install vapi_common-2.9.0-py2.py3-none-any.whl
    sudo pip install vapi_runtime-2.9.0-py2.py3-none-any.whl
    sudo pip install vapi_common-2.9.0-py2.py3-none-any.whl
    sudo pip install vapi_common_client-2.9.0-py2.py3-none-any.whl
    sudo pip install nsx_python_sdk-2.3.0.0.0.10085514-py2.py3-none-any.whl


Install on devstack

clone repo into /opt/stack
::

    cd ./networking-nsx-t
    python setup.py install


Modify::

    /etc/neutron/neutron.conf as described in /opt/stack/networking-nsx-t/etc/neutron/neutron.conf
    /etc/neutron/plugins/ml2/ml2_conf.ini as described in /opt/stack/networking-nsx-t/etc/neutron/plugins/ml2/ml2_conf.ini

For Full list of the agent configuration options check::

    /opt/stack/networking-nsx-t/networking_nsxv3/common/config.py

restart neutron server with NSX-T ml2 config::

  /usr/local/bin/neutron-server --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini


Start DVS agent::
 
  /usr/local/bin/neutron-nsxv3-agent --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini


Playground
-------------------


QoS Policy
^^^^^^^^^^^^^^^^^^^
::

    openstack network qos policy create <qos_name>
    openstack network qos rule create --type bandwidth-limit --max-kbps 64000 --max-burst-kbits 0 --ingress <qos_name>
    openstack network qos rule set --max-kbps 64000 --max-burst-kbits 0 --ingress <qos_name> <id>
    openstack network qos rule set --max-kbps 32000 --max-burst-kbits 0 --egress <qos_name> <id>
    openstack network qos rule create --type dscp-marking --dscp-mark 26 <qos_name>
    openstack network qos rule delete
    openstack network qos policy delete <qos_name>

Security Groups
^^^^^^^^^^^^^^^^^^^
::

    openstack security group create <sg_name>
    openstack security group rule create --ingress --protocol tcp --remote-ip 192.168.253.253 --dst-port 8281 <sg_name>
    openstack security group rule create --ingress --protocol tcp --remote-group <remote_sg_name> --dst-port 443 <sg_name>
    openstack security group rule create --egress  --protocol udp --remote-ip 192.168.253.253 --dst-port 8080 <sg_name>
    openstack security group rule create --egress  --protocol udp --remote-group <remote_sg_name> --dst-port 9443 <sg_name>
    openstack security group rule create           --protocol icmp
    openstack security group rule delete <sg_rule_name>
    openstack security group delete <sg_name>

Port Binding (Standard)
^^^^^^^^^^^^^^^^^^^^^^^
::

    openstack port create --network <network_name> \
        --allowed-address "ip-address=192.168.253.10,mac-address=fa:16:3e:5f:7d:0b" \
        --allowed-address "ip-address=192.168.253.10,mac-address=ff:16:3e:5f:7d:0b" \
        --qos-policy <qos_policy_id> \
        --security-group <sg_id> \ 
        <port_name>
    openstack server create --image <image_name> --flavor "1" --nic "port-id=<port_id>" <server-name>

Port Binding (Trunk)
^^^^^^^^^^^^^^^^^^^^
::

    openstack port create --network <network_native> <trunk_parent_port_name>
    openstack port create --network <network_sub_1> \
        --allowed-address "ip-address=192.168.253.10,mac-address=fa:16:3e:5f:7d:0b" \
        --allowed-address "ip-address=192.168.253.10,mac-address=ff:16:3e:5f:7d:0b" \
        --qos-policy <qos_policy_id> \
        --security-group <sg_id> \ 
        <trunk_subport_name_1>
    openstack port create --network <netwrok_sub_2> \
        <trunk_subport_name_2>

::

    openstack network trunk create \
    --parent-port <trunk_parent_port_id> \
    --subport port=<trunk_subport_id_1>,segmentation-type=vlan,segmentation-id=100  \
    --subport port=<trunk_subport_id_2>,segmentation-type=vlan,segmentation-id=200 
    openstack server create --image <image_name> --flavor "1" --nic "port-id=<trunk-parent-port-id>" <server-name>