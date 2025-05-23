import neutron_lib.constants as neutron_constants

# IP_PROTOCOL_NUMBERS source
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
IP_PROTOCOL_NUMBERS = {
    "hopopt": 0,
    "icmp": 1,
    "igmp": 2,
    "ggp": 3,
    "ip-in-ip": 4,
    "st": 5,
    "tcp": 6,
    "cbt": 7,
    "egp": 8,
    "igp": 9,
    "bbn-rcc-mon": 10,
    "nvp-ii": 11,
    "pup": 12,
    "argus": 13,
    "emcon": 14,
    "xnet": 15,
    "chaos": 16,
    "udp": 17,
    "mux": 18,
    "dcn-meas": 19,
    "hmp": 20,
    "prm": 21,
    "xns-idp": 22,
    "trunk-1": 23,
    "trunk-2": 24,
    "leaf-1": 25,
    "leaf-2": 26,
    "rdp": 27,
    "irtp": 28,
    "iso-tp4": 29,
    "netblt": 30,
    "mfe-nsp": 31,
    "merit-inp": 32,
    "dccp": 33,
    "3pc": 34,
    "idpr": 35,
    "xtp": 36,
    "ddp": 37,
    "idpr-cmtp": 38,
    "tp++": 39,
    "il": 40,
    "ipv6": 41,
    "sdrp": 42,
    "ipv6-route": 43,
    "ipv6-frag": 44,
    "idrp": 45,
    "rsvp": 46,
    "gre": 47,
    "dsr": 48,
    "bna": 49,
    "esp": 50,
    "ah": 51,
    "i-nlsp": 52,
    "swipe": 53,
    "narp": 54,
    "mobile": 55,
    "tlsp": 56,
    "skip": 57,
    "ipv6-icmp": 58,
    "ipv6-nonxt": 59,
    "ipv6-opts": 60,
    "cftp": 62,
    "sat-expak": 64,
    "kryptolan": 65,
    "rvd": 66,
    "ippc": 67,
    "sat-mon": 69,
    "visa": 70,
    "ipcu": 71,
    "cpnx": 72,
    "cphb": 73,
    "wsn": 74,
    "pvp": 75,
    "br-sat-mon": 76,
    "sun-nd": 77,
    "wb-mon": 78,
    "wb-expak": 79,
    "iso-ip": 80,
    "vmtp": 81,
    "secure-vmtp": 82,
    "vines": 83,
    "ttp": 84,
    "iptm": 84,
    "nsfnet-igp": 85,
    "dgp": 86,
    "tcf": 87,
    "eigrp": 88,
    "ospf": 89,
    "sprite-rpc": 90,
    "larp": 91,
    "mtp": 92,
    "ax.25": 93,
    "os": 94,
    "micp": 95,
    "scc-sp": 96,
    "etherip": 97,
    "encap": 98,
    "gmtp": 100,
    "ifmp": 101,
    "pnni": 102,
    "pim": 103,
    "aris": 104,
    "scps": 105,
    "qnx": 106,
    "a/n": 107,
    "ipcomp": 108,
    "snp": 109,
    "compaq-peer": 110,
    "ipx-in-ip": 111,
    "vrrp": 112,
    "pgm": 113,
    "l2tp": 115,
    "ddx": 116,
    "iatp": 117,
    "stp": 118,
    "srp": 119,
    "uti": 120,
    "smp": 121,
    "sm": 122,
    "ptp": 123,
    "fire": 125,
    "crtp": 126,
    "crudp": 127,
    "sscopmce": 128,
    "iplt": 129,
    "sps": 130,
    "pipe": 131,
    "sctp": 132,
    "fc": 133,
    "rsvp-e2e-ignore": 134,
    "mobility header": 135,
    "udplite": 136,
    "mpls-in-ip": 137,
    "manet": 138,
    "hip": 139,
    "shim6": 140,
    "wesp": 141,
    "rohc": 142
}

VALID_ICMP_RANGES = {
    'IPv4': {
        0: [0],  # Echo Reply
        3: range(16),  # Destination Unreachable
        4: [0],  # Source Quench (Deprecated)
        5: [0, 1, 2, 3],  # Redirect
        8: [0],  # Echo
        9: [0],  # Router Advertisement
        10: [0],  # Router Selection
        11: [0, 1],  # Time Exceeded
        12: [0, 1, 2],  # Parameter Problem
        13: [0],  # Timestamp
        14: [0],  # Timestamp Reply
    },
    'IPv6': {
        1: [0, 2, 3, 4, 5, 6, 7],  # Destination Unreachable
        2: None,  # Packet Too Big
        3: [0, 1],  # Time Exceeded
        4: [0, 1, 2],  # Parameter Problem
        128: None,
        129: None,
        130: None,
        131: None,
        132: None,
        133: None,
        134: None,
        135: None,
        136: None,
        137: None,
        138: None,
        139: None,
        140: None,
        141: None,
        142: None,
        144: None,
        145: None,
        146: None,
        147: None,
        157: None,
        158: None
    }
}

# WARNING: Changes to this policies using the same `id`
# won't be reflected to previously provisioned NSX-T Managers.
DEFAULT_INFRASTRUCTURE_POLICIES = [
    {
        "resource_type": "SecurityPolicy",
        "display_name": "ICMP Allow",
        "id": "ICMP_Allow",
        "category": "Infrastructure",
        "stateful": False,
        "tcp_strict": False,
        "locked": True,
        "scope": ["ANY"],
        "rules": [
            {
                "action": "ALLOW",
                "resource_type": "Rule",
                "id": "ICMP",
                "display_name": "ICMP",
                "source_groups": ["ANY"],
                "destination_groups": ["ANY"],
                "services": ["/infra/services/ICMP-ALL"],
                "service_entries": [],
                "profiles": ["ANY"],
                "logged": False,
                "scope": ["ANY"],
                "disabled": False,
                "direction": "IN_OUT",
                "ip_protocol": "IPV4_IPV6",
            }
        ],
    },
    {
        "resource_type": "SecurityPolicy",
        "display_name": "Metadata Allow",
        "id": "Metadata_Allow",
        "category": "Infrastructure",
        "stateful": True,
        "tcp_strict": False,
        "locked": True,
        "scope": ["ANY"],
        "rules": [
            {
                "action": "ALLOW",
                "resource_type": "Rule",
                "id": "HTTP",
                "display_name": "HTTP",
                "source_groups": ["ANY"],
                "destination_groups": [neutron_constants.METADATA_V4_IP, neutron_constants.METADATA_V6_IP],
                "services": ["/infra/services/HTTP"],
                "service_entries": [],
                "profiles": ["ANY"],
                "logged": False,
                "scope": ["ANY"],
                "disabled": False,
                "direction": "OUT",
                "ip_protocol": "IPV4_IPV6",
            }
        ],
    },
    {
        "resource_type": "SecurityPolicy",
        "display_name": "DHCP Allow",
        "id": "DHCP_Allow",
        "category": "Infrastructure",
        "stateful": True,
        "tcp_strict": False,
        "locked": True,
        "scope": ["ANY"],
        "rules": [
            {
                "action": "ALLOW",
                "resource_type": "Rule",
                "id": "DHCP_Client",
                "display_name": "DHCP Client",
                "source_groups": ["ANY"],
                "destination_groups": ["ANY"],
                "services": [
                    "/infra/services/DHCPv6_Client",
                    "/infra/services/DHCP-Client"
                ],
                "service_entries": [],
                "profiles": ["ANY"],
                "logged": False,
                "scope": ["ANY"],
                "disabled": False,
                "direction": "IN",
                "ip_protocol": "IPV4_IPV6",
            },
            {
                "action": "ALLOW",
                "resource_type": "Rule",
                "id": "DHCP_Server",
                "display_name": "DHCP Server",
                "source_groups": ["ANY"],
                "destination_groups": ["ANY"],
                "services": [
                    "/infra/services/DHCPv6_Server",
                    "/infra/services/DHCP-Server"
                ],
                "service_entries": [],
                "profiles": ["ANY"],
                "logged": False,
                "scope": ["ANY"],
                "disabled": False,
                "direction": "OUT",
                "ip_protocol": "IPV4_IPV6",
            }
        ],
    },
]

NSXV3_DEFAULT_L3_SECTION = "default-layer3-section"

DEFAULT_APPLICATION_DROP_POLICY = {
    "rules": [],
    # "logging_enabled": True,
    "resource_type": "SecurityPolicy",
    "id": "default-layer3-logged-drop-section",
    "display_name": "Default Layer3 Logged Drop Section",
    "path": "/infra/domains/default/security-policies/default-layer3-logged-drop-section",
    "relative_path": "default-layer3-logged-drop-section",
    "parent_path": "/infra/domains/default",
    "marked_for_delete": False,
    "overridden": False,
    "sequence_number": 999999,  # MAX ALLOWED
    "internal_sequence_number": 999999,  # MAX ALLOWED
    "category": "Application",
    "stateful": True,
    "tcp_strict": False,
    "locked": False,
    "scope": ["ANY"],
    "rule_count": 1,
    "is_default": True
}

DEFAULT_APPLICATION_DROP_RULE = {
    "action": "DROP",
    "resource_type": "Rule",
    "id": None,
    "display_name": None,
    "path": None,
    "marked_for_delete": False,
    "overridden": False,
    "sequence_number": 2147483647,  # MAX INT
    "sources_excluded": False,
    "destinations_excluded": False,
    "source_groups": [
        "ANY"
    ],
    "destination_groups": [
        "ANY"
    ],
    "services": [
        "ANY"
    ],
    "service_entries": [],
    "profiles": [
        "ANY"
    ],
    "logged": True,
    "tag": None,
    "scope": None,
    "disabled": False,
    "direction": "IN_OUT",
    "ip_protocol": "IPV4_IPV6",
    "_revision": None
}
