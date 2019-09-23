#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding('utf8')

import argparse
import json
import gzip
from peeringdb import PeeringDB

"""
Export useful PeeringDB data.
    - list of IXP route servers
    - list of LAN prefixes per IXP 
    - CF ASNs 
"""


def get_all_ases_where_involved_with_routeservers(o_peeringdb):
    """
    Query PeeringDB to extract all existing IXP ASes involved in managing Route Servers.
    These ASes should be removed from AS-Paths along with the AS-Relationship inferences, and their traffic should
    not be considered during the traffic classification processing.
    """

    d_ixp_ases_routeserver_data_export = dict()

    # query database request all Route Servers available and save data
    l_d_nets_route_servers = o_peeringdb.all('net', name_search='route server')

    for record in l_d_nets_route_servers:
        # 'id', 'asn' , 'name', 'aka'
        s_asn = record['asn']

        d_ixp_rs_ases_entry = dict()
        d_ixp_rs_ases_entry['name'] = record['name']
        d_ixp_rs_ases_entry['aka'] = record['aka']
        d_ixp_rs_ases_entry['id'] = record['id']

        d_ixp_ases_routeserver_data_export[s_asn] = d_ixp_rs_ases_entry

    return d_ixp_ases_routeserver_data_export


def get_all_lan_prefixes_from_ixps(o_peeringdb):
    """
    Query PeeringDB to extract for all existing IXPs their respective LAN prefixes (v4 and v6 available).
    The traffic classification processing should be filtered making them unverifiable.
    """

    d_ixp_lan_data_export = dict()

    # query PeeringDB requesting all existing IXP records
    l_d_ixps_worldwide = o_peeringdb.all('ix')

    # for each IXP record, extract the LAN prefixes
    for record in l_d_ixps_worldwide:

        print "{}: {}".format(record['id'], record['name'])

        d_ixp_lan_entry = dict()
        d_ixp_lan_entry['name'] = record['name']

        """
        [{u'ixpfx_set': [{u'status': u'ok', u'updated': u'2016-03-14T21:24:52Z', u'protocol': u'IPv4', 
        u'created': u'2013-06-16T00:00:00Z', u'prefix': u'200.219.143.0/24', u'id': 439}, {u'status': u'ok', 
        u'updated': u'2016-03-14T21:15:03Z', u'protocol': u'IPv6', u'created': u'2013-06-16T00:00:00Z', 
        u'prefix': u'2001:12f8:0:6::/64', u'id': 440}]}]
        """
        try:
            l_d_ixp_lan_data = o_peeringdb.get('ixlan', id=record['id'], fields='ixpfx_set')

            # check all LAN entries for each IXP and save them
            for lan_entry in l_d_ixp_lan_data[0]['ixpfx_set']:

                if lan_entry['protocol'] == 'IPv4':

                    if 'IPv4' not in d_ixp_lan_entry:
                        d_ixp_lan_entry['IPv4'] = list()
                        d_ixp_lan_entry['IPv4'].append(lan_entry['prefix'])
                    else:
                        d_ixp_lan_entry['IPv4'].append(lan_entry['prefix'])

                elif lan_entry['protocol'] == 'IPv6':

                    if 'IPv6' not in d_ixp_lan_entry:
                        d_ixp_lan_entry['IPv6'] = list()
                        d_ixp_lan_entry['IPv6'].append(lan_entry['prefix'])
                    else:
                        d_ixp_lan_entry['IPv6'].append(lan_entry['prefix'])

        except Exception as e:
            continue

        i_id_ixp_peeringdb = record['id']
        d_ixp_lan_data_export[i_id_ixp_peeringdb] = d_ixp_lan_entry

    return d_ixp_lan_data_export


def save_results_to_jsonfile(l_d_post_results, fn_fullpath):
    """
    Save data to a json file.
    :param p_dest_filepath:
    :param p_file_name:
    :param p_location_id:
    :return:
    """

    # write dict result info to a json file
    with gzip.open(fn_fullpath, 'wb') as f:
        json.dump(l_d_post_results, f)
    f.close()


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    # instantiate PeeringDB database
    pdb = PeeringDB()

    fn_path_save_files = 'data/input/asn-types-mapping/'

    # Star processing PeeringDB IXP lan prefixes mapping data file
    d_results_ixp_lan = get_all_lan_prefixes_from_ixps(pdb)

    f_ixplans = "{}ixps-lan-mapping-data-peeringdb.json.gz".format(fn_path_save_files)
    save_results_to_jsonfile(d_results_ixp_lan, f_ixplans)

    # Star processing PeeringDB IXP ASNs where there are Routing Servers mapping data file
    d_results_ixp_rs_ases = get_all_ases_where_involved_with_routeservers(pdb)

    f_ixp_rs_ases = "{}ixps_routeservers-ases-mapping-data-peeringdb.json.gz".format(fn_path_save_files)
    save_results_to_jsonfile(d_results_ixp_rs_ases, f_ixp_rs_ases)
