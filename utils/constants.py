#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ###############################################
# General default configurations
# ###############################################
DEFAULT_PLOTS_OUTPUT_FILEPATH = "data-analysis/output/"
DEFAULT_AVRO_FILE_EXTENSION = ".avro"
DEFAULT_AVRO_NFCAP_FLOWS_SCHEMA_FILEPATH = "schemas/nfcapd.avsc"
DEFAULT_AVRO_SHRINK_NFCAP_FLOWS_SCHEMA_FILEPATH = "schemas/nfcapd-shrink.avsc"

# ###############################################
# List of supported fields (subset of NFDUMP)
# ###############################################
DEFAULT_FIELDS = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "fwd", "stos", "ipkt", "ibyt", "opkt", "obyt",
                  "in", "out", "sas", "das", "smk", "dmk", "dtos", "dir", "nh", "nhb", "svln", "dvln", "ismc", "odmc",
                  "idmc", "osmc", "ra", "tr"]

DEFAULT_SHRINK_FIELDS = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "ipkt", "ibyt", "svln", "ismc", "odmc", "ra"]

DEFAULT_FLOW_SIGNATURE = ["sa", "da", "pr", "sp", "dp"]

# 'fl' = indicates the number of times the flow occurred
DEFAULT_STATS = ["ibyt", "obyt", "ipkt", "opkt", "ts", "te", "td", "fl", "flg"]

# ###############################################
# Default filter configuration of flow traffic
# ###############################################
DEFAULT_IPV4_ONLY_FILTER = {'ip': 4}
DEFAULT_IPV6_ONLY_FILTER = {'ip': 6}

# ###############################################
# Default paths for IXP related datasets
# ###############################################
# mac2asn dataset
DEFAULT_MACADDRESS_ASN_MAPPING = "data/input/macaddress-asn-list/mac2asn-DEMO.json"
# Remote peering identifiers
SET_OF_VLANS_RELATED_TO_REMOTE_PEERING = {}
FPATHS_VLANS_RELATED_TO_REMOTE_PEERING = {2019: 'data/input/vlans-remote-peering/remote-vlans-Month-Year-DEMO.txt'}
DEFAULT_BRAZIL_SIBLING_ASES_MAPPING = "data/input/as-organizations/sibling-ases-mapping-data-DEMO.jsonl"
DEFAULT_IXPS_CFS_CRAFTED_MAPPING = "data/input/asn-types-mapping/ixps-cfs-mapping-data-DEMO.jsonl"
ID_IXP_BR1 = 1
# ###############################################
# Default paths for most of the datasets
# ###############################################
DEFAULT_MARTIANS_BOGONS_FILEPATH_V4 = "data/input/bogon-prefixes-list/bogon-bn-nonagg-ipv4.txt"
DEFAULT_MARTIANS_BOGONS_FILEPATH_V6 = "data/input/bogon-prefixes-list/bogon-bn-nonagg-ipv6.txt"
DEFAULT_UNASSIGNED_BASEDIR = "data/input/unassigned-prefixes-list/"

DEFAULT_AS2ORG_CAIDA_MAPPING = {'2019': "data/input/as-organizations/20190401.as-org2info.txt.gz"}

DEFAULT_AS2TYPE_CAIDA_MAPPING = {'201905': "data/input/as2types/20190501.as2types.txt.gz"}

DEFAULT_IXPS_LAN_PREFIXES_PEERINGDB_MAPPING = "data/input/asn-types-mapping/ixps-lan-mapping-data-peeringdb.json.gz"

DEFAULT_CDNS_CRAFTED_MAPPING = "data/input/asn-types-mapping/cdns-mapping-data-DEMO.jsonl"

DICT_OF_ROUTEVIEWS_IP2PREFIX_DATABASES = {'20195': 'data/input/asn-lookup-db/ipasn_db_20190510.0000.gz',
                                          '20196': 'data/input/asn-lookup-db/ipasn_db_20190601.0000.gz'}

DEFAULT_ROUTER_PREFIXES_CAIDA_ITDK = {'2019': "data/input/ITDK-ifaces-routers/ITDK-2019-04_midar-iff-ifaces_router-prefixes-db.txt.gz"}

DEFAULT_PATH_TO_GEOLITE2_DATABASE = {'20195': "data/input/geolocation-db/maxmind-lite2/GeoLite2-Country/2019-05-16.GeoLite2-Country.mmdb"}

DICT_DEFAULT_PATH_TO_NETACQEDGE_DATABASE = {'20195': ['data/input/geolocation-db/netacq-edge/2019-05-17.netacq-4-blocks.csv.gz', 'data/input/geolocation-db/netacq-edge/2019-05-17.netacq-4-locations.csv.gz']}

# ###############################################
# Default ID parameter to run w/ distinct Customer
# Cone datasets (generated w/ different algorithms
# ###############################################
ID_CUSTOMERCONE_IMC2013 = 1
ID_CUSTOMERCONE_SIBLINGS = 2
ID_CUSTOMERCONE_RECURSIVE = 3
ID_FULLCONE_IMC2017 = 4
ID_CUSTOMERCONE_PLCC_CONEXT2019 = 8

# ###############################################
# Traffic Classification main categories
# ###############################################
BOGON_ID_CLASS = 0
UNASSIGNED_ID_CLASS = 1
AS_SPECIFIC_ID_CLASS_OUT_OF_CONE = 2
AS_SPECIFIC_ID_CLASS_IN_CONE = 3

# ###############################################
# Traffic Classification sub-categories
# ###############################################
UNVERIFIABLE_ROUTER_IP_ID_CLASS = 4
UNVERIFIABLE_IXP_ASES_ID_CLASS = 5
UNVERIFIABLE_CF_ASES_ID_CLASS = 6
UNVERIFIABLE_CDN_ASES_ID_CLASS = 7
UNVERIFIABLE_P2C_INGRESS_EGRESS_ID_CLASS = 8
UNKNOWN_INGRESS_MACADDRESS_ID_CLASS = 9
UNKNOWN_EGRESS_MACADDRESS_ID_CLASS = 10
UNVERIFIABLE_NO_INFERRED_ASREL_INGRESS_EGRESS = 11
UNVERIFIABLE_TRANSPORT_PROVIDER_ID_CLASS = 12
UNVERIFIABLE_BOGON_VLAN_ID_CLASS = 13
UNVERIFIABLE_UNASSIGNED_VLAN_ID_CLASS = 14
UNVERIFIABLE_P2C_DIR_TRAFFIC_VALIDIN_PROVIDERCONE_ID_CLASS = 15
UNVERIFIABLE_P2C_DIR_TRAFFIC_NOTVALIDIN_PROVIDERCONE_ID_CLASS = 16
UNVERIFIABLE_MAC2ASN_RECORD_NOTACCURATE_ID_CLASS = 17
SET_OF_ASES_WITH_NOTACCURATE_MAC2ASN_RECORD = set([])
UNVERIFIABLE_REMOTE_PEERING_ID_CLASS = 18
UNVERIFIABLE_SIBLING_TO_SIBLING_ID_CLASS = 19

# ###############################################
# Traffic Classification Aggregation tag labels
# ###############################################
LABEL_BOGON_ID_CLASS = "is_bogon"
LABEL_UNASSIGNED_ID_CLASS = "is_unassigned"
LABEL_AS_SPECIFIC_ID_CLASS = "is_outofcone"
LABEL_UNVERIFIABLE_ID_CLASS = "is_unverifiable"

CATEGORY_LABEL_BOGON_CLASS = "bogon"
CATEGORY_LABEL_UNASSIGNED_CLASS = "unassigned"
CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE = "outofcone"
CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE = "incone"
CATEGORY_LABEL_UNVERIFIABLE_CLASS = "unverifiable"


def reverse_dict(d_orig):
    d_rev = {}
    for k in d_orig:
        v = d_orig[k]
        d_rev[v] = k
    return d_rev


d_proto_str_int = {
    "0": 0,  # masked out - no protocol info - set to '0'
    "ICMP": 1,  # Internet Control Message
    "IGMP": 2,  # Internet Group Management
    "GGP": 3,  # Gateway-to-Gateway
    "IPIP": 4,  # IP in IP (encapsulation)
    "ST": 5,  # Stream
    "TCP": 6,  # Transmission Control
    "CBT": 7,  # CBT
    "EGP": 8,  # Exterior Gateway Protocol
    "IGP": 9,  # any private interior gateway (used by Cisco for their IGRP)
    "BBN": 10,  # BBN RCC Monitoring
    "NVPII": 11,  # Network Voice Protocol
    "PUP": 12,  # PUP
    "ARGUS": 13,  # ARGUS
    "ENCOM": 14,  # EMCON
    "XNET": 15,  # Cross Net Debugger
    "CHAOS": 16,  # Chaos
    "UDP": 17,  # User Datagram
    "MUX": 18,  # Multiplexing
    "DCN": 19,  # DCN Measurement Subsystems
    "HMP": 20,  # Host Monitoring
    "PRM": 21,  # Packet Radio Measurement
    "XNS": 22,  # XEROX NS IDP
    "Trnk1": 23,  # Trunk-1
    "Trnk2": 24,  # Trunk-2
    "Leaf1": 25,  # Leaf-1
    "Leaf2": 26,  # Leaf-2
    "RDP": 27,  # Reliable Data Protocol
    "IRTP": 28,  # Internet Reliable Transaction
    "ISO-4": 29,  # ISO Transport Protocol Class 4
    "NETBK": 30,  # Bulk Data Transfer Protocol
    "MFESP": 31,  # MFE Network Services Protocol
    "MEINP": 32,  # MERIT Internodal Protocol
    "DCCP": 33,  # Datagram Congestion Control Protocol
    "3PC": 34,  # Third Party Connect Protocol
    "IDPR": 35,  # Inter-Domain Policy Routing Protocol
    "XTP": 36,  # XTP
    "DDP": 37,  # Datagram Delivery Protocol
    "IDPR": 38,  # IDPR Control Message Transport Proto
    "TP++": 39,  # TP++ Transport Protocol
    "IL": 40,  # IL Transport Protocol
    "IPv6": 41,  # IPv6
    "SDRP": 42,  # Source Demand Routing Protocol
    "Rte6": 43,  # Routing Header for IPv6
    "Frag6": 44,  # Fragment Header for IPv6
    "IDRP": 45,  # Inter-Domain Routing Protocol
    "RSVP": 46,  # Reservation Protocol
    "GRE": 47,  # General Routing Encapsulation
    "MHRP": 48,  # Mobile Host Routing Protocol
    "BNA": 49,  # BNA
    "ESP": 50,  # Encap Security Payload
    "AH": 51,  # Authentication Header
    "INLSP": 52,  # Integrated Net Layer Security  TUBA
    "SWIPE": 53,  # IP with Encryption
    "NARP": 54,  # NBMA Address Resolution Protocol
    "MOBIL": 55,  # IP Mobility
    "TLSP": 56,  # Transport Layer Security Protocol
    "SKIP": 57,  # SKIP
    "ICMP6": 58,  # ICMP for IPv6
    "NOHE6": 59,  # No Next Header for IPv6
    "OPTS6": 60,  # Destination Options for IPv6
    "HOST": 61,  # any host internal protocol
    "CFTP": 62,  # CFTP
    "NET": 63,  # any local network
    "SATNT": 64,  # SATNET and Backroom EXPAK
    "KLAN": 65,  # Kryptolan
    "RVD": 66,  # MIT Remote Virtual Disk Protocol
    "IPPC": 67,  # Internet Pluribus Packet Core
    "FS": 68,  # any distributed file system
    "SATM": 69,  # SATNET Monitoring
    "VISA": 70,  # VISA Protocol
    "IPCV": 71,  # Internet Packet Core Utility
    "CPNX": 72,  # Computer Protocol Network Executive
    "CPHB": 73,  # Computer Protocol Heart Beat
    "WSN": 74,  # Wang Span Network
    "PVP": 75,  # Packet Video Protocol
    "BSATM": 76,  # Backroom SATNET Monitoring
    "SUNND": 77,  # SUN ND PROTOCOL-Temporary
    "WBMON": 78,  # WIDEBAND Monitoring
    "WBEXP": 79,  # WIDEBAND EXPAK
    "ISOIP": 80,  # ISO Internet Protocol
    "VMTP": 81,  # VMTP
    "SVMTP": 82,  # SECURE-VMTP
    "VINES": 83,  # VINES
    "TTP": 84,  # TTP
    "NSIGP": 85,  # NSFNET-IGP
    "DGP": 86,  # Dissimilar Gateway Protocol
    "TCP": 87,  # TCF
    "EIGRP": 88,  # EIGRP
    "OSPF": 89,  # OSPFIGP
    "S-RPC": 90,  # Sprite RPC Protocol
    "LARP": 91,  # Locus Address Resolution Protocol
    "MTP": 92,  # Multicast Transport Protocol
    "AX.25": 93,  # AX.25 Frames
    "IPIP": 94,  # IP-within-IP Encapsulation Protocol
    "MICP": 95,  # Mobile Internetworking Control Protocol
    "SCCSP": 96,  # Semaphore Communications Sec. Protocol
    "ETHIP": 97,  # Ethernet-within-IP Encapsulation
    "ENCAP": 98,  # Encapsulation Header
    "99": 99,  # any private encryption scheme
    "GMTP": 100,  # GMTP
    "IFMP": 101,  # Ipsilon Flow Management Protocol
    "PNNI": 102,  # PNNI over IP
    "PIM": 103,  # Protocol Independent Multicast
    "ARIS": 104,  # ARIS
    "SCPS": 105,  # SCPS
    "QNX": 106,  # QNX
    "A/N": 107,  # Active Networks
    "IPcmp": 108,  # IP Payload Compression Protocol
    "SNP": 109,  # Sitara Networks Protocol
    "CpqPP": 110,  # Compaq Peer Protocol
    "IPXIP": 111,  # IPX in IP
    "VRRP": 112,  # Virtual Router Redundancy Protocol
    "PGM": 113,  # PGM Reliable Transport Protocol
    "0hop": 114,  # any 0-hop protocol
    "L2TP": 115,  # Layer Two Tunneling Protocol
    "DDX": 116,  # D-II Data Exchange (DDX)
    "IATP": 117,  # Interactive Agent Transfer Protocol
    "STP": 118,  # Schedule Transfer Protocol
    "SRP": 119,  # SpectraLink Radio Protocol
    "UTI": 120,  # UTI
    "SMP": 121,  # Simple Message Protocol
    "SM": 122,  # SM
    "PTP": 123,  # Performance Transparency Protocol
    "ISIS4": 124,  # ISIS over IPv4
    "FIRE": 125,  # FIRE
    "CRTP": 126,  # Combat Radio Transport Protocol
    "CRUDP": 127,  # Combat Radio User Datagram
    "128": 128,  # SSCOPMCE
    "IPLT": 129,  # IPLP
    "SPS": 130,  # Secure Packet Shield
    "PIPE": 131,  # Private IP Encapsulation within IP
    "SCTP": 132,  # Stream Control Transmission Protocol
    "FC": 133,  # Fibre Channel
    "134": 134,  # RSVP-E2E-IGNORE
    "MHEAD": 135,  # Mobility Header
    "UDP-L": 136,  # UDPLite
    "MPLS": 137,  # MPLS-in-IP
}

# Source of protocol selection: https://www.us-cert.gov/ncas/alerts/TA14-017A
d_proto_l7_str_int = {
    "HTTP": 80,
    "HTTPS/QUIC": 443,
    "DNS": 53,
    "NTP": 123,
    "TELNET": 23,
    "SSH": 22,
    "CHARGEN": 19,
    "MEMCACHED": 11211,
    "SNMP": 161,
    "QOTD": 17,
    "STEAM": 27015,
    "NetBIOS": 137,
    "SSDP": 1900,
    "QUAKE": 26000,
    "mDNS": 5353,
    "RIPv1": 520,
    "Portmap": 111,
    "LDAP": 389,
    "TFTP": 69,
    "UDP FRAG": 0,
    "OTHER": -1
}

# protocols reversed mappings
d_proto_int_str = reverse_dict(d_proto_str_int)
d_proto_l7_int_str = reverse_dict(d_proto_l7_str_int)


d_flow_key_to_idx = {
    # 0 - 14 = ts - obyt: #L1363
    "ts": 0,
    "te": 1,
    "td": 2,
    "sa": 3,
    "da": 4,
    "sp": 5,
    "dp": 6,
    "pr": 7,
    "flg": 8,
    "fwd": 9,
    "stos": 10,
    "ipkt": 11,
    "ibyt": 12,
    "opkt": 13,
    "obyt": 14,
    # 15, 16 = in, out: #L1375
    "in": 15,
    "out": 16,
    # 17, 18 = sas, das: #L1382
    "sas": 17,
    "das": 18,
    # 19 - 22 = smk - dir: #L1382
    "smk": 19,
    "dmk": 20,
    "dtos": 21,
    "dir": 22,
    # 23 = nh: #L1401 (v6) / #L1413 (v4)
    "nh": 23,
    # 24 = nhb: #L1427 (v6) / #L1439 (v4)
    "nhb": 24,
    # 25, 26 = svlan, dvlan: #L1447
    "svln": 25,
    "dvln": 26,
    # 27, 28 = ismc, odmc: #L1472
    "ismc": 27,
    "odmc": 28,
    # 29, 30 = idmc, osmc: #L1492
    "idmc": 29,
    "osmc": 30,
    # 31 - 40 = mpls1 - mpls10: #L1504
    "mpls1": 31,
    "mpls2": 32,
    "mpls3": 33,
    "mpls4": 34,
    "mpls5": 35,
    "mpls6": 36,
    "mpls7": 37,
    "mpls8": 38,
    "mpls9": 39,
    "mpls10": 40,
    # 41 - 43 = cl -  al: #L1518
    "cl": 41,
    "sl": 42,
    "al": 43,
    # 44 = ra: #L1536 (v6) / #L1548 (v4)
    "ra": 44,
    # 45 = eng #L1555
    "eng": 45,
    # 46 = exp #L1561
    "exp": 46,
    # 47 = tr #L1571
    "tr": 47,
}

# reversed mapping
d_flow_idx_to_key = reverse_dict(d_flow_key_to_idx)

# ###############################################
# Traffic Proprieties Analysis Constants Definitions
# ###############################################
BYTES_TOTAL = "BYTES_TOTAL"
PACKETS_TOTAL = "PACKETS_TOTAL"

TCP_BYTES_TOTAL = "TCP_BYTES_TOTAL"
TCP_FLAG_SYN_BYTES_TOTAL = "TCP_FLAG_SYN_BYTES_TOTAL"
TCP_FLAG_SYNACK_BYTES_TOTAL = "TCP_FLAG_SYNACK_BYTES_TOTAL"
TCP_FLAG_ACK_BYTES_TOTAL = "TCP_FLAG_ACK_BYTES_TOTAL"
TCP_FLAG_RESET_BYTES_TOTAL = "TCP_FLAG_RESET_BYTES_TOTAL"
TCP_FLAG_PUSH_BYTES_TOTAL = "TCP_FLAG_PUSH_BYTES_TOTAL"
TCP_FLAG_FIN_BYTES_TOTAL = "TCP_FLAG_FIN_BYTES_TOTAL"
TCP_FLAG_UNUSUALL_BYTES_TOTAL = "TCP_FLAG_UNUSUALL_BYTES_TOTAL"
TCP_NO_FLAGS_BYTES_TOTAL = "TCP_NO_FLAGS_BYTES_TOTAL"

TCP_PACKETS_TOTAL = "TCP_PACKETS_TOTAL"
TCP_FLAG_SYN_PACKETS_TOTAL = "TCP_FLAG_SYN_PACKETS_TOTAL"
TCP_FLAG_SYNACK_PACKETS_TOTAL = "TCP_FLAG_SYNACK_PACKETS_TOTAL"
TCP_FLAG_ACK_PACKETS_TOTAL = "TCP_FLAG_ACK_PACKETS_TOTAL"
TCP_FLAG_RESET_PACKETS_TOTAL = "TCP_FLAG_RESET_PACKETS_TOTAL"
TCP_FLAG_PUSH_PACKETS_TOTAL = "TCP_FLAG_PUSH_PACKETS_TOTAL"
TCP_FLAG_FIN_PACKETS_TOTAL = "TCP_FLAG_FIN_PACKETS_TOTAL"
TCP_FLAG_UNUSUALL_PACKETS_TOTAL = "TCP_FLAG_UNUSUALL_PACKETS_TOTAL"
TCP_NO_FLAGS_PACKETS_TOTAL = "TCP_NO_FLAGS_PACKETS_TOTAL"

UDP_BYTES_TOTAL = "UDP_BYTES_TOTAL"
UDP_PACKETS_TOTAL = "UDP_PACKETS_TOTAL"
