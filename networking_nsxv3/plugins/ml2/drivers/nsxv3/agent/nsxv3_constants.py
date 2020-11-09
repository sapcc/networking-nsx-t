QOS_SPEC_SHAPER_CONFIGURATION = {
    "IngressRateShaper": {
        "resource_type": "IngressRateShaper",
        "enabled": False,
        "average_bandwidth_mbps": 0,
        "peak_bandwidth_mbps": 0,
        "burst_size_bytes": 0
    },
    "IngressBroadcastRateShaper": {
        "resource_type": "IngressBroadcastRateShaper",
        "enabled": False,
        "burst_size_bytes": 0,
        "peak_bandwidth_kbps": 0,
        "average_bandwidth_kbps": 0
    },
    "EgressRateShaper": {
        "resource_type": "EgressRateShaper",
        "enabled": False,
        "average_bandwidth_mbps": 0,
        "peak_bandwidth_mbps": 0,
        "burst_size_bytes": 0
    }
}

QOS_SPEC_DSCP = {
    "mode": "TRUSTED",
    "priority": 0
}

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


ICMP_PROTOCOLS = {
    "IPv4": "ICMPv4",
    "IPv6": "ICMPv6"
}

VALID_ICMP_RANGES = {
    'IPv4': {
        0: [0],  # Echo Reply
        3: range(16),  # Destination Unreachable
        4: [0],  # Source Quench (Deprecated)
        5: [0, 1, 2, 3],  # Redirect
        6: [0],  # Alternate Host Address (Deprecated)
        8: [0],  # Echo
        9: [0, 16],  # Router Advertisement
        10: [0, 1],  # Router Selection
        11: [0, 1, 2],  # Time Exceeded
        12: [0, 1, 2],  # Parameter Problem
        13: [0],  # Timestamp
        14: [0],  # Timestamp Reply
        40: range(6),  # Photuris
        42: [0],  # Extended Echo Request
        43: range(5),  # Extended Echo Reply
    },
    'IPv6': {
        1: range(8),  # Destination Unreachable
        2: [0],  # Packet Too Big
        3: [0, 1],  # Time Exceeded
        4: range(5),  # Parameter Problem
        128: [0],
        129: [0],
        130: [0],
        131: [0],
        132: [0],
        133: [0],
        134: [0],
        135: [0],
        136: [0],
        137: [0],
        138: [0, 1, 255],
        139: [0, 1, 2],
        140: [0, 1, 2],
        141: [0],
        142: [0],
        144: [0],
        145: [0],
        146: [0],
        147: [0],
        157: range(5),  # Duplicate Address Request Code Suffix
        158: range(5),  # Duplicate Address Confirmation Code Suffix
        160: [0],  # Extended Echo Request
        161: range(5),  # Extended Echo Reply
    }
}
