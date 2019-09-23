#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
from json import load


def build_dict_mapping_macaddress_members_asns(fn_mac2asn_path):
    """
    Build the mapping dict cache to retrive the ASN given a specific Mac Address to lookup.
    :return: dict[str(MACADDR)] = int(ASN)
    """
    print ("Mapping file mac2asn: {}".format(fn_mac2asn_path))
    with open(fn_mac2asn_path) as f:
        mac2asn = load(f)

        d_map_macaddress_member_asns = dict()
        for k, v in mac2asn.items():
            macaddress = k.upper()
            l_asn_id_cf_label = v

            if macaddress not in d_map_macaddress_member_asns:
                d_map_macaddress_member_asns[macaddress] = [int(v[0]) for v in l_asn_id_cf_label]

    return d_map_macaddress_member_asns


def load_alldata_dict_mapping_macaddress_members_asns(fn_mac2asn_path):
    """
    Build the mapping dict cache to retrive all the ASN information given a specific Mac Address to lookup.
    :return: {macaddress: [[asn_id, cf, ixp_id, presence_in_how_many_ixps]]}
    """
    print ("Loading all mapping data from MAC2AS: {}".format(fn_mac2asn_path))
    with open(fn_mac2asn_path) as f:
        mac2asn = load(f)

        d_map_macaddress_member_asns = dict()
        for k, v in mac2asn.items():
            macaddress = k.upper()
            l_asn_data = v

            if macaddress not in d_map_macaddress_member_asns:
                d_map_macaddress_member_asns[macaddress] = l_asn_data

    return d_map_macaddress_member_asns


def query_member_presence_in_multiple_locations(d_map_macaddress_member_asns, s_macaddress, i_ingress_asn):
    """
    Query the count of presence of a given macaddress and IXP member.
    Goal to validate potential situations of IP Transport.

    d_map_macaddress_member_asns { macaddress: [[asn_id, cf, ixp_id, presence_in_how_many_ixps], ... ], ... }
    """

    i_count_presence = 0

    if s_macaddress in d_map_macaddress_member_asns:

        for member_ases in d_map_macaddress_member_asns[s_macaddress]:
            as_member = int(member_ases[0])
            index_macadd_asn = d_map_macaddress_member_asns[s_macaddress].index(member_ases)

            if i_ingress_asn == as_member:
                i_count_presence = d_map_macaddress_member_asns[s_macaddress][index_macadd_asn][3]
                break
    else:
        print ("ERROR: mac2asn entry not located -- macaddress {}".format(s_macaddress))

    return i_count_presence


def build_dict_member_colocation_location(d_mac2asn_alldata):
    """
    From mac2asn mapping data build a dict with each member and the colocation facility
    which is connected to at the IXP.
    :param d_mac2asn_alldata:
    :return:
    """

    d_members_pix_location = dict()
    for k_macadd, v_asn_data in d_mac2asn_alldata.items():
        for record in v_asn_data:
            i_asn = record[0]
            s_cf_name = record[1]

            if i_asn not in d_members_pix_location:
                d_members_pix_location[i_asn] = s_cf_name

    return d_members_pix_location


def query_member_colocation_location(d_members_pix_location, i_asn):
    return d_members_pix_location[i_asn]


def load_members_ixp(p_ixp_members_file):
    """
    Given a mapping file with the IXP members loads it to memory in a dict format to receive data from cone.
    :param p_ixp_members_file:
    :return:
    """

    d_uniq_member_asns = dict()

    if p_ixp_members_file.lower().endswith('.json'):
        with open(p_ixp_members_file) as f:
            mac2asn = load(f)

        for record in mac2asn.values():
            if len(record) == 1:
                asn_id = int(record[0][0])

                if asn_id not in d_uniq_member_asns:
                    d_uniq_member_asns[asn_id] = []
            elif len(record) > 1:
                for r in record:
                    asn_id = int(r[0])
                    if asn_id not in d_uniq_member_asns:
                        d_uniq_member_asns[asn_id] = []

    if p_ixp_members_file.lower().endswith('.txt'):
        with open(p_ixp_members_file) as f:
            reader = csv.reader(f)

            for line in reader:
                member_asn = int(line[0].strip())
                d_uniq_member_asns[member_asn] = []

    return d_uniq_member_asns


