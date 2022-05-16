SECURITY_GROUP_AUTH = {
    "id": "22D4CB40-31A6-4C61-A527-76B7867E221B",
    "name": "22D4CB40-31A6-4C61-A527-76B7867E221B",
    "tags": ["capability_tcp_strict"],
    "revision_number": 1,
    "rules": [
        {   # HTTPS IPv4 -> SECURITY_GROUP_FRONTEND
            "id": "C1D3F5C2-6C02-4BA1-B4C9-27BCD78AD8E0",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "remote_ip_prefix": "",
            "security_group_id": "22D4CB40-31A6-4C61-A527-76B7867E221B",
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp"
        }
    ]
}

SECURITY_GROUP_FRONTEND = {
    "id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
    "name": "ED75FC68-69BB-4034-A6E9-A7586792B229",
    "tags": ["capability_tcp_strict"],
    "revision_number": 1,
    "rules": [
        {   # HTTPS IPv4
            "id": "70AECE1F-B4AE-4142-9D3E-66CACB714398",
            "ethertype": "IPv4",
            "direction": "egress",
            "remote_group_id": SECURITY_GROUP_AUTH["id"],
            "remote_ip_prefix": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp"
        },
        {   # ICMP Echo
            "id": "D94DDD70-010B-4593-BBF9-B79319095450",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_ip_prefix": "0.0.0.0/0",
            "remote_group_id": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "8",
            "port_range_max": "0",
            "protocol": "icmp"
        },
        {   # ICMP IPv6 Echo Request
            "id": "EA3B6012-EFB3-4E3F-A311-A8FC8AC6D255",
            "ethertype": "IPv6",
            "direction": "ingress",
            "remote_ip_prefix": "::0/0",
            "remote_group_id": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "128",
            "port_range_max": "0",
            "protocol": "icmp"
        },
        {   # Invalid ICMP
            "id": "AA45801C-96A4-4BC1-BEBA-B799060A7186",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "0.0.0.0/0",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "5",
            "port_range_max": "",
            "protocol": "icmp"
        },
        {   # Generic ICMP 1
            "id": "AA45801C-96A4-4BC1-BEBA-B799060A7187",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "0.0.0.0/0",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": None,
            "port_range_max": None,
            "protocol": "icmp"
        },
        {   # Generic ICMP 2
            "id": "AA45801C-96A4-4BC1-BEBA-B799060A7188",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_ip_prefix": "0.0.0.0/0",
            "remote_group_id": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": None,
            "port_range_max": "0",
            "protocol": "icmp"
        },
        {   # Generic ICMP 3
            "id": "AA45801C-96A4-4BC1-BEBA-B799060A7189",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_ip_prefix": "0.0.0.0/0",
            "remote_group_id": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "8",
            "port_range_max": None,
            "protocol": "icmp"
        },
        {   # RDP
            "id": "B554B8F1-38D0-4D2B-86C3-D135FE9E1446",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "10.0.0.1/32",
            "port_range_min": "",
            "port_range_max": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "protocol": "rdp"
        },
        {   # Mobility
            "id": "98AD3E92-1270-4D09-9DF3-54CFC65A7B1D",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "10.0.0.1/32",
            "port_range_min": "",
            "port_range_max": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "protocol": "55"
        },
        {   # HTTPS IPv4
            "id": "9C3896B6-616A-4B2F-8ED0-3287F00564E3",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "0.0.0.0/24",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp"
        },
        {   # HTTPS IPv6
            "id": "0FB3E5F3-F83D-4605-94E8-F5557444C09C",
            "ethertype": "IPv6",
            "direction": "ingress",
            "remote_group_id": "",
            "remote_ip_prefix": "::0/96",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "443",
            "port_range_max": "443",
            "protocol": "tcp"
        },
        {   # HTTP
            "id": "981F34DA-319C-42C1-BC05-317D1FB97EFA",
            "ethertype": "IPv4",
            "direction": "egress",
            "remote_group_id": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
            "remote_ip_prefix": "",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "80",
            "port_range_max": "80",
            "protocol": "tcp"
        },
        {   # SSH Operations
            "id": "42926DF3-7BC3-4970-9B4D-21FB971080A7",
            "ethertype": "IPv6",
            "direction": "ingress",
            "remote_ip_prefix": "",
            "remote_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "tcp"
        },
        {   # ANY UDP
            "id": "9961B0AE-53EC-4E54-95B6-2F440D243F7B",
            "ethertype": "IPv6",
            "direction": "egress",
            "remote_ip_prefix": "",
            "remote_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "security_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "protocol": "udp"
        }
    ]
}

SECURITY_GROUP_BACKEND = {
    "id": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
    "name": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
    "tags": [],
    "revision_number": 2,
    "rules": [
        {   # HTTP
            "id": "F6D6BB70-5210-4645-A8A5-0FAEE4B91F28",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_group_id": SECURITY_GROUP_FRONTEND["id"],
            "remote_ip_prefix": "",
            "security_group_id": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
            "port_range_min": "80",
            "port_range_max": "80",
            "protocol": "tcp"
        },
        {   # PostgreSQL
            "id": "9105C630-6B32-42E0-9D71-074F918F5AEF",
            "ethertype": "IPv4",
            "direction": "egress",
            "remote_group_id": "EDE7338F-9AE3-445C-96D3-D8EDDEBC8277",
            "remote_ip_prefix": "",
            "security_group_id": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
            "port_range_min": "5432",
            "port_range_max": "5432",
            "protocol": "tcp"
        },
        {   # SSH Operations
            "id": "D93B1222-2444-4EFA-A4EA-381DFD70A51D",
            "ethertype": "IPv6",
            "direction": "ingress",
            "remote_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "remote_ip_prefix": "",
            "security_group_id": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "tcp"
        }
    ]
}

SECURITY_GROUP_DB = {
    "id": "EDE7338F-9AE3-445C-96D3-D8EDDEBC8277",
    "name": "EDE7338F-9AE3-445C-96D3-D8EDDEBC8277",
    "tags": [],
    "revision_number": 3,
    "rules": [
        {   # PostgreSQL
            "id": "C48BA8FA-EF8B-4756-81C1-208B6DFDF067",
            "ethertype": "IPv4",
            "direction": "ingress",
            "remote_ip_prefix": "",
            "remote_group_id": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
            "security_group_id": "EDE7338F-9AE3-445C-96D3-D8EDDEBC8277",
            "port_range_min": "5432",
            "port_range_max": "5432",
            "protocol": "tcp"
        },
        {   # SSH Operations
            "id": "C07B7C14-B52A-450A-A073-463A4DD30205",
            "ethertype": "IPv6",
            "direction": "ingress",
            "remote_ip_prefix": "",
            "remote_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "security_group_id": "EDE7338F-9AE3-445C-96D3-D8EDDEBC8277",
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "tcp"
        },
    ]
}


SECURITY_GROUP_OPERATIONS = {
    "id": "34B87931-F273-4C6D-96D0-B3979E30254A",
    "name": "34B87931-F273-4C6D-96D0-B3979E30254A",
    "tags": [],
    "revision_number": 1,
    "rules": [
        {   # SSH DB
            "id": "FEF26A36-123D-433A-B827-39FC0966418C",
            "ethertype": "IPv6",
            "direction": "egress",
            "remote_ip_prefix": "",
            "remote_group_id": "EDE7338F-9AE3-445C-96D3-D8EDDEBC8277",
            "security_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "tcp"
        },
        {   # SSH Backend
            "id": "51ECB132-84DD-42A8-A762-C14FBBBE816E",
            "ethertype": "IPv6",
            "direction": "egress",
            "remote_ip_prefix": "",
            "remote_group_id": "28778C62-C22F-47DD-801F-CF06DF3D07AD",
            "security_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "tcp"
        },
        {   # SSH Frontend
            "id": "9B536BE3-F8CF-4B03-B7C4-648BAEE758AB",
            "ethertype": "IPv6",
            "direction": "egress",
            "remote_ip_prefix": "",
            "remote_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "security_group_id": "34B87931-F273-4C6D-96D0-B3979E30254A",
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "tcp"
        }
    ]
}

SECURITY_GROUP_OPERATIONS_NOT_REFERENCED = {
    "id": "FE6C80A3-D68F-4770-A2F3-D068AC9C0A40",
    "name": "FE6C80A3-D68F-4770-A2F3-D068AC9C0A40",
    "tags": [],
    "revision_number": 1,
    "rules": [
        {   # SSH Frontend
            "id": "81A4AB9E-99AF-493E-9455-CAD31B22C81D",
            "ethertype": "IPv6",
            "direction": "egress",
            "remote_ip_prefix": "",
            "remote_group_id": "ED75FC68-69BB-4034-A6E9-A7586792B229",
            "security_group_id": "FE6C80A3-D68F-4770-A2F3-D068AC9C0A40",
            "port_range_min": "22",
            "port_range_max": "22",
            "protocol": "tcp"
        }
    ]
}


QOS_EXTERNAL = {
    "id": "3A9D6B1D-3645-4DE8-B9A2-D333B6261F08",
    "revision_number": "11",
    "name": "qos-public",
    "rules": [
        {
            "dscp_mark": "5"
        },
        {
            "direction": "ingress",
            "max_kbps": "4800",
            "max_burst_kbps": "100000"
        },
        {
            "direction": "egress",
            "max_kbps": "6400",
            "max_burst_kbps": "128000"
        }
    ]
}


QOS_INTERNAL = {
    "id": "87D2C425-EB50-4E23-A864-4D65254EA958",
    "revision_number": "23",
    "name": "qos-internal",
    "rules": [
        {
            "dscp_mark": "2"
        },
        {
            "direction": "ingress",
            "max_kbps": "2400",
            "max_burst_kbps": "64000"
        }
    ]
}


QOS_NOT_REFERENCED = {
    "id": "28EC8F37-533D-48F5-9CE8-E970C897234E",
    "revision_number": "12",
    "name": "qos-not-referenced",
    "rules": [
        {
            "dscp_mark": "2"
        },
        {
            "direction": "ingress",
            "max_kbps": "2400",
            "max_burst_kbps": "64000"
        }
    ]
}


PORT_FRONTEND_EXTERNAL = {
    "id": "582AEF71-8F19-4D5E-ADDB-FDC81909B411",
    "name": "frontend-external",
    "revision_number": "2",
    "parent_id": "",
    "mac_address": "fa:16:3e:e4:11:f1",
    "admin_state_up": "UP",
    "qos_policy_id": QOS_EXTERNAL["id"],
    "security_groups": [
        SECURITY_GROUP_FRONTEND["id"],
    ],
    "address_bindings": [{
        "ip_address": "10.1.1.10",
        "mac_address": "fa:16:3e:e4:11:f1"
    }],
    "vif_details": {
        "segmentation_id": "1000"
    }
}


PORT_FRONTEND_INTERNAL = {
    "id": "2DD31A2C-A93A-4EE8-BD2E-2375E5CA1659",
    "name": "frontend-internal",
    "revision_number": "2",
    "parent_id": PORT_FRONTEND_EXTERNAL["id"],
    "mac_address": "fa:16:3e:e4:11:f2",
    "admin_state_up": "UP",
    "qos_policy_id": QOS_INTERNAL["id"],
    "security_groups": [
        SECURITY_GROUP_FRONTEND["id"],
        SECURITY_GROUP_OPERATIONS["id"]
    ],
    "address_bindings": [{
        "ip_address": "172.16.0.10",
        "mac_address": "fa:16:3e:e4:11:f2"
    }],
    "vif_details": {
        "segmentation_id": "3200"
    }
}

PORT_WITH_3_SG = {
    "id": "2DD31A2C-A93A-4EE8-BD2E-2375E5CA1661",
    "name": "2DD31A2C-A93A-4EE8-BD2E-2375E5CA1661",
    "revision_number": "2",
    "parent_id": "",
    "mac_address": "fa:16:3e:e4:11:f5",
    "admin_state_up": "UP",
    "qos_policy_id": "",
    "security_groups": [
        SECURITY_GROUP_FRONTEND["id"],
        SECURITY_GROUP_OPERATIONS["id"],
        SECURITY_GROUP_DB["id"]
    ],
    "address_bindings": [{
        "ip_address": "172.16.0.12",
        "mac_address": "fa:16:3e:e4:11:f5"
    }],
    "vif_details": {
        "segmentation_id": "1000"
    }
}

PORT_BACKEND = {
    "id": "A29F3249-DE62-4357-8A6A-A49B9F48434E",
    "name": "backend",
    "revision_number": "2",
    "parent_id": "",
    "mac_address": "fa:16:3e:e4:11:f3",
    "admin_state_up": "UP",
    "qos_policy_id": "",
    "security_groups": [
        SECURITY_GROUP_BACKEND["id"],
        SECURITY_GROUP_OPERATIONS["id"]
    ],
    "address_bindings": [{
        "ip_address": "172.16.0.20",
        "mac_address": "fa:16:3e:e4:11:f3"
    }],
    "vif_details": {
        "segmentation_id": "3200"
    }
}

PORT_DB = {
    "id": "27A5C174-9A2F-468C-88FA-37D1C0669F30",
    "name": "db",
    "revision_number": "2",
    "parent_id": "",
    "mac_address": "fa:16:3e:e4:11:f4",
    "admin_state_up": "UP",
    "qos_policy_id": "",
    "security_groups": [
        SECURITY_GROUP_DB["id"],
        SECURITY_GROUP_OPERATIONS["id"]
    ],
    "address_bindings": [{
        "ip_address": "172.16.0.30",
        "mac_address": "fa:16:3e:e4:11:f4"
    }],
    "vif_details": {
        "segmentation_id": "3200"
    }
}


def load_security_groups_rules(*groups):
    rules = dict()
    for group in groups:
        rules.update({rule["id"]: rule for rule in group.get("rules")})
    return rules


def load_security_groups(*groups):
    return {g["id"]: g for g in groups}


def load_qos_profiles(*qos_profiles):
    return {q["id"]: q for q in qos_profiles}


def load_ports(*ports):
    return {p["id"]: p for p in ports}


OPENSTACK_INVENTORY = {
    "security-group-rule": load_security_groups_rules(
        SECURITY_GROUP_FRONTEND,
        SECURITY_GROUP_BACKEND,
        SECURITY_GROUP_DB,
        SECURITY_GROUP_OPERATIONS,
        SECURITY_GROUP_AUTH,
        SECURITY_GROUP_OPERATIONS_NOT_REFERENCED),
    "security-group": load_security_groups(
        SECURITY_GROUP_FRONTEND,
        SECURITY_GROUP_BACKEND,
        SECURITY_GROUP_DB,
        SECURITY_GROUP_OPERATIONS,
        SECURITY_GROUP_AUTH,
        SECURITY_GROUP_OPERATIONS_NOT_REFERENCED),
    "port": load_ports(
        PORT_FRONTEND_EXTERNAL,
        PORT_FRONTEND_INTERNAL,
        PORT_BACKEND,
        PORT_DB,
        PORT_WITH_3_SG
    ),
    "qos": load_qos_profiles(
        QOS_EXTERNAL,
        QOS_INTERNAL,
        QOS_NOT_REFERENCED)
}
