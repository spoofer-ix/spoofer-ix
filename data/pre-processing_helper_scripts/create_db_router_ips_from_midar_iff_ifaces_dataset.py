#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import sys
reload(sys)
sys.setdefaultencoding('utf8')

import argparse
import sys
import bz2
import csv
from netaddr import IPSet, cidr_merge

"""
---------------------------------------ABOUT----------------------------------------
Reads 'midar-iff.ifaces.bz2' file and extract IP addresses that belongs to Routers.

.ifaces

     This file provides additional information about all interfaces
     included in the provided router-level graphs:

      Format:  <address> [<node_id>] [<link_id>] [T] [D]  
------------------------------------------------------------------------------------
"""


def extract_router_ipaddress(in_file):

    d_router_ipaddress_data = dict()
    with bz2.BZ2File(in_file, "r") as asrel_data:
        reader = csv.reader(asrel_data, delimiter=' ')

        for line in reader:
            if "#" not in line[0]:
                # if theres something more than just the ipaddress
                if len(line) > 1:
                    for attribute in line:
                        if attribute == "T":
                            router_interface_ipaddress = line[0]
                            if router_interface_ipaddress not in d_router_ipaddress_data:
                                d_router_ipaddress_data[router_interface_ipaddress] = 1

    routers_ips_set = IPSet()
    for k, v in d_router_ipaddress_data.iteritems():
        routers_ips_set.add(k)

    routers_prefixes = cidr_merge(routers_ips_set)

    for prefix in routers_prefixes:
        print prefix


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Reads midar-iff.ifaces.bz2 file and extract IP '
                                                                   'addresses that belongs to Routers.')
    parser.add_argument('-f', dest='input_prefixesmatch_file', required=True,
                        help="Input midar-iff.ifaces.bz2 file to read and extract data.")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    fn_path = parsed_args.input_prefixesmatch_file

    extract_router_ipaddress(fn_path)

