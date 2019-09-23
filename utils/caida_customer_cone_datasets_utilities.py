#!/usr/bin/env python
# -*- coding: utf-8 -*-

import bz2
import gzip
from netaddr import IPNetwork, IPAddress
import csv


def gen_str_list_prefixes_from_int_representation(l_l_prefixes_intformat):
    """
    Given a compact representation of a list of prefixes (int representation) convert the list back to string format.
    :param l_l_prefixes_intformat:
    :return:
    """
    l_str_prefix = list()
    str_asn_prefix = "{ipaddress}/{prefixlen}"
    for asn_prefix in l_l_prefixes_intformat:
        prefix = str_asn_prefix.format(ipaddress=str(IPAddress(asn_prefix[0])), prefixlen=str(asn_prefix[1]))
        l_str_prefix.append(prefix)

    return l_str_prefix


def load_ppdc_prefix_data_customercone_intformat(p_ppdc_prefix_datafile_path):
    """
    Load data from ppdc-prefix Customer Cone file format but convert all the data to int format.
    To reconstruct the information back to string format just call `gen_str_list_prefixes_from_int_representation()`.

    :param p_ppdc_prefix_datafile_path:
    :return:
    """

    d_uniq_asns_prefixes = dict()

    if p_ppdc_prefix_datafile_path.lower().endswith('.txt'):
        fin = open(p_ppdc_prefix_datafile_path)

    elif p_ppdc_prefix_datafile_path.lower().endswith('.gz'):
        fin = gzip.open(p_ppdc_prefix_datafile_path, "rb")

    # reads the prefixes file, store all values in dict
    for line in fin:
        if not line.startswith("#"):
            lf = line.strip().split(" ")
            if len(lf) >= 2:
                k_asn = int(lf[0])
                prefixlist = list(map(str, lf[1:]))

                d_uniq_asns_prefixes[k_asn] = list()
                for p in prefixlist:
                    prefix = IPNetwork(p)
                    d_uniq_asns_prefixes[k_asn].append([prefix.value, prefix.prefixlen])

    return d_uniq_asns_prefixes


def load_prefix2as_data_from_customercone(prefix2as_datafile_path):
    """
    Load prefix2as mapping.
    :param prefix2as_datafile_path:
    :return:
    """

    d_prefix2as_customercone = dict()
    with bz2.BZ2File(prefix2as_datafile_path, "r") as fin:
        for line in fin:
            if not line.startswith("#"):
                lf = line.strip().split("\t")

                prefix = "{}/{}".format(lf[0], lf[1])
                asn = lf[2]
                if "_" in asn:
                    l_asn = asn.split("_")
                else:
                    l_asn = [int(lf[2])]

                for asn in l_asn:
                    if asn not in d_prefix2as_customercone:
                        d_prefix2as_customercone[asn] = list()
                        d_prefix2as_customercone[asn].append(prefix)
                    else:
                        d_prefix2as_customercone[asn].append(prefix)

    return d_prefix2as_customercone


def build_dict_as_specific_ppdcases_per_member(path_to_file):
    """
    Build a dict with the key being the member ASN and the value a set of the ASNs belonging to its customer cone.
    """

    print "Cones ASes dataset: {}".format(path_to_file)

    if path_to_file.lower().endswith('.txt'):   # customer cone datasets
        f = open(path_to_file)
    elif path_to_file.lower().endswith('.gz'):  # full cone datasets
        f = gzip.open(path_to_file, 'rb')
    elif path_to_file.lower().endswith('.bz2'): # full cone datasets
        f = bz2.BZ2File(path_to_file, "r")

    d_members_as_cc_ppdcases_finder = dict()
    for line in f:
        if not line.startswith("#"):
            lf = line.strip().split(" ")
            if len(lf) >= 2:
                asn_key = int(lf[0])
                data_cone = lf[1:]
                ases_cone = set()

                for asn in data_cone:
                    ases_cone.add(int(asn))

                # create a set of ASNs to each member
                if asn_key not in d_members_as_cc_ppdcases_finder:
                    d_members_as_cc_ppdcases_finder[int(asn_key)] = ases_cone

    return d_members_as_cc_ppdcases_finder


def build_dict_as_specific_ppdcprefix_per_member(path_to_file):
    """
    Build a dict with the key being the member ASN and the value a set of prefixes belonging to its customer cone.
    """

    d_members_as_cc_ppdcprefix_finder = dict()

    if path_to_file.lower().endswith('.txt'):
        fin = open(path_to_file)

    elif path_to_file.lower().endswith('.gz'):
        fin = gzip.open(path_to_file, "rb")

    elif path_to_file.lower().endswith('.bz2'): # full cone datasets
        fin = bz2.BZ2File(path_to_file, "r")

    for line in fin:
        if not line.startswith("#"):
            lf = line.strip().split(" ")
            if len(lf) >= 2:
                asn_key = int(lf[0])
                data_cone = list(map(str, lf[1:]))
                prefixes_cone = set(data_cone)

                # create a set of prefixes to each member
                if asn_key not in d_members_as_cc_ppdcprefix_finder:
                    d_members_as_cc_ppdcprefix_finder[int(asn_key)] = prefixes_cone

    return d_members_as_cc_ppdcprefix_finder


def build_dict_as_rel_customercone(path_to_file):
    """
    Build a dict with the data from as-rel CAIDA customer cone inference algorithm.
    The as-rel files contain p2p and p2c relationships.

    The format is:
    <provider-as>|<customer-as>|-1
    <peer-as>|<peer-as>|0

    """
    d_asrel_data = dict()
    with bz2.BZ2File(path_to_file, "r") as asrel_data:
        reader = csv.reader(asrel_data, delimiter='|')

        for line in reader:
            if "#" not in line[0]:
                if len(line) == 3:
                    asn1 = int(line[0])
                    asn2 = int(line[1])
                    rel_type = int(line[2])

                    d_asrel_data[(asn1, asn2)] = rel_type
                else:
                    print "AS-REL-DATA - something wrong with the len of this record: ", line

    return d_asrel_data
