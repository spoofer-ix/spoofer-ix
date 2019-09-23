#!/usr/bin/env python
# -*- coding: utf-8 -*-

import radix
import gzip
import utils.constants as cons
from timeit import default_timer as timer


def get_prefix(ip_addr, rt_prefixes):
    return rt_prefixes.search_best(ip_addr)


def ipaddress_is_in_customercone_prefixes(ipaddress_str, rt_prefixes):
    rnode_tree = rt_prefixes.search_best(ipaddress_str)

    if rnode_tree is not None:
        return False, None
    else:
        return True, ipaddress_str


def ipaddress_is_in_prefixes(ipaddress_str, rt_prefixes):
    rnode_tree = rt_prefixes.search_best(ipaddress_str)

    if rnode_tree is not None:
        return True, rnode_tree.prefix
    else:
        return False, None


def update_radixtree_from_list(l_prefixes, rtree):
    """
    Updates a radix three with the prefixes from file, allowing optimized searches over it.
    E.g. how to perform search:
        rnode = rtree.search_best('138.122.37.244')
    :param l_prefixes: list of prefixes
    :return: radix tree with the prefixes loaded.
    """

    for prefix in l_prefixes:
        try:
            rtree.add(str(prefix))
        except ValueError:
            raise ValueError("Radix Tree failed to add: ", "'" + prefix + "'")

    return rtree


def gen_radixtree_from_list(l_prefixes):
    """
    Create a radix three with the prefixes from list, allowing optimized searches over it.
    E.g. how to perform search:
        rnode = rtree.search_best('138.122.37.244')
    :param prefixes_file_path: prefixes file path on disk (one prefix per line).
    :return: radix tree with the prefixes loaded.
    """
    rtree = update_radixtree_from_list(l_prefixes, rtree=radix.Radix())
    return rtree


def update_radixtree_from_file(prefixes_file_path, rtree):
    """
    Updates a radix three with the prefixes from file, allowing optimized searches over it.
    E.g. how to perform search:
        rnode = rtree.search_best('138.122.37.244')
    :param prefixes_file_path: prefixes file path on disk (one prefix per line).
    :return: radix tree with the prefixes loaded.
    """

    start = timer()

    if prefixes_file_path.lower().endswith('.txt'):
        prefixes_file = open(prefixes_file_path, 'r')

        l_prefixes = []
        for line in prefixes_file:
            l_prefixes += [line.strip()]
        prefixes_file.close()

    elif prefixes_file_path.lower().endswith('.gz'):
        with gzip.open(prefixes_file_path, 'r') as f:
            f.readline()  # skip header

            l_prefixes = []
            for line in f:
                l_prefixes += [line.strip()]
            f.close()

    update_radixtree_from_list(l_prefixes, rtree)

    end = timer()
    print(end - start)

    return rtree


def gen_radixtree_from_file(prefixes_file_path):
    """
    Create a radix three with the prefixes from file, allowing optimized searches over it.
    E.g. how to perform search:
        rnode = rtree.search_best('138.122.37.244')
    :param prefixes_file_path: prefixes file path on disk (one prefix per line).
    :return: radix tree with the prefixes loaded.
    """
    rtree = update_radixtree_from_file(prefixes_file_path, rtree=radix.Radix())
    return rtree


def gen_radixtree_from_prefix2as_caidacc_file(d_prefix2as_cc_data):
    """
    Create a radix three with the prefixes from file, allowing optimized searches over it.
    E.g. how to perform search:
        rnode = rtree.search_best('138.122.37.244')
    :param prefixes_file_path: prefixes file path on disk (one prefix per line).
    :return: radix tree with the prefixes loaded.
    """
    rtree = radix.Radix()

    for k_asn, v_l_prefixes in d_prefix2as_cc_data.iteritems():
        for prefix in v_l_prefixes:
            rnode = rtree.add(prefix)
            rnode.data["asn"] = k_asn

    return rtree


def query_rt_prefix2as_caidacc_get_asn_from_prefix(ip_addr, rt_prefixes):
    """
    Query the CAIDA CC prefix2as dataset to get the associated ASN and prefix to a given IP.
    :param ip_addr:
    :param rt_prefixes:
    :return:
    """
    rnode_tree = rt_prefixes.search_best(ip_addr)

    if rnode_tree is not None:
        return rnode_tree.data["asn"], rnode_tree.prefix
    else:
        return None, None


def remove_bogon_prefixes_from_fullbogons_radixtree(rtree, p_ip_version):
    """
    Removes from a radix three the existing bogon prefixes loaded with the fullbogons (unrouted) prefixes list.
    :return: radix tree with the prefixes loaded.
    """
    if p_ip_version == 4:
        prefixes_file_path = cons.DEFAULT_MARTIANS_BOGONS_FILEPATH_V4
    elif p_ip_version == 6:
        prefixes_file_path = cons.DEFAULT_MARTIANS_BOGONS_FILEPATH_V6

    prefixes_file = open(prefixes_file_path, 'r')

    for prefix in prefixes_file:
        try:
            rtree.delete(str(prefix.strip()))
        except KeyError:
            continue
        except ValueError:
            raise ValueError("Radix Tree failed to remove: ", "'" + prefix + "'")

    return rtree
