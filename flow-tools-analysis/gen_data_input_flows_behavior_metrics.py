#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import utils.multiprocessing_poll as mpPool
import utils.geolocation_utilities as geoutil
import utils.prefixes_utilities as putil
import utils.constants as cons
import utils.filters_utilities as futil
import utils.fileparsing_utilities as fputil
import utils.notification_utilities as notifutil
import argparse
import sys
import utils.cmdline_interface_utilities as cmdutil
import utils.ixp_members_mappings_utilities as ixp_member_util
import ast
import traceback
import gzip
import pyasn
from netaddr import IPNetwork
from operator import add
import cProfile
from timeit import default_timer as timer

"""
---------------------------------------ABOUT----------------------------------------
Process original traffic flow data, transforming and aggregating data to export 
in 5-min bins, allowing distinct analysis of network behavior metrics.
------------------------------------------------------------------------------------
"""


def count_ipv4_prefix24_forip(ip_prefix):
    """
    Given a prefix match, get the correspondent /24 IPv4 prefix count.
    :param ip_prefix:
    :return:
    """

    ipv4_prefixlen_desired = 24

    ip_prefix_fields = ip_prefix.split('/')
    # Check if we have range id with the prefix
    if len(ip_prefix_fields) == 2:
        # Generate prefix object
        cidr_block = ip_prefix_fields[1]
        prefix_net = IPNetwork(ip_prefix)

        if int(cidr_block) < 24:
            # create a list of all possible subnets /24 for IPv4
            subnets = list(prefix_net.subnet(ipv4_prefixlen_desired))
            return len(subnets)

        elif int(cidr_block) == 24:
            return 1

        # In case they are bigger leave as is (more specific naturally)
        elif int(cidr_block) > 24:
            return 0

    else:
        print("ALERT: classfull IP range (A, B, C) found.")


def load_database_ip2prefixasn_routeviews_by_timewindow(p_tw_start):
    """
    Load the IPAddress to Prefix/ASN lookup database from Routeviews.
    :return:
    """
    str_key = str(p_tw_start.year) + str(p_tw_start.month)

    if str_key in cons.DICT_OF_ROUTEVIEWS_IP2PREFIX_DATABASES:
        path_to_file = cons.DICT_OF_ROUTEVIEWS_IP2PREFIX_DATABASES[str_key]
    else:
        print "> ERROR: fail to load Routeviews ip2prefixasn database file."
        path_to_file = ""

    return pyasn.pyasn(path_to_file)


def do_prefix_lookup_forip(str_ip_address):
    """
    For a given ip address execute a lookup on routeviews db to get the prefix and asn information.
    :param str_ip_address:
    :return:
    """

    try:
        prefix_lookup_result = f_global_asndb_routeviews.lookup(str_ip_address)
        origin_asn = prefix_lookup_result[0]
        ip_prefix = prefix_lookup_result[1]
        return origin_asn, ip_prefix

    except:
        print "Routeviews DB lookup failed! Double check if the file is ok."
        return None, None


def update_log_ip_dict_per_ingress_egress_point(flow_ingress_asn, flow_ip, origin_asn, ip_prefix, country_code, flow_bytes, flow_packets, d_ipsrc_level_analysis_perpoint):
    """
    Account for unique IPAddresses, BGP prefixes, origin_asn per ingress/egress points.
    :param flow_ingress_asn:
    :param flow_ip:
    :param origin_asn:
    :param ip_prefix:
    :param d_ipsrc_level_analysis_perpoint:
    :return: dict of dict {'1234': {('10.10.10.1', 23456, '10.0.0.0/8'): [1]},
                           '5678': {('181.3.50.1', 98765, '181.3.50.0/20'): [1]}, ...}
    """

    k = (flow_ip, origin_asn, ip_prefix, country_code)
    values = [1, flow_bytes, flow_packets]

    flow_ingress_asn = frozenset(flow_ingress_asn)

    if flow_ingress_asn not in d_ipsrc_level_analysis_perpoint.keys():
        d_ipsrc_level_analysis_perpoint[flow_ingress_asn] = dict()
        d_ipsrc_level_analysis_perpoint[flow_ingress_asn][k] = values
    else:
        if k not in d_ipsrc_level_analysis_perpoint[flow_ingress_asn]:
            d_ipsrc_level_analysis_perpoint[flow_ingress_asn][k] = values
        else:
            d_ipsrc_level_analysis_perpoint[flow_ingress_asn][k] = map(add, d_ipsrc_level_analysis_perpoint[flow_ingress_asn][k], values)

    return d_ipsrc_level_analysis_perpoint


def update_log_ip_ports_protocols_dict_per_ingress_egress_point(flow_ingress_asn, flow_ip, flow_port, str_flow_pr, d_analysis_perpoint_ports_protocols):


    k = flow_ip
    flow_port = [(flow_port)]
    str_flow_pr = [(str_flow_pr)]

    flow_ingress_asn = frozenset(flow_ingress_asn)

    if flow_ingress_asn not in d_analysis_perpoint_ports_protocols.keys():
        d_analysis_perpoint_ports_protocols[flow_ingress_asn] = dict()
        d_analysis_perpoint_ports_protocols[flow_ingress_asn][k] = {0: set(), 1: set()}
        d_analysis_perpoint_ports_protocols[flow_ingress_asn][k][0].update(flow_port)
        d_analysis_perpoint_ports_protocols[flow_ingress_asn][k][1].update(str_flow_pr)
    else:
        if k not in d_analysis_perpoint_ports_protocols[flow_ingress_asn]:
            d_analysis_perpoint_ports_protocols[flow_ingress_asn][k] = {0: set(), 1: set()}
            d_analysis_perpoint_ports_protocols[flow_ingress_asn][k][0].update(flow_port)
            d_analysis_perpoint_ports_protocols[flow_ingress_asn][k][1].update(str_flow_pr)

        else:
            d_analysis_perpoint_ports_protocols[flow_ingress_asn][k][0].update(flow_port)
            d_analysis_perpoint_ports_protocols[flow_ingress_asn][k][1].update(str_flow_pr)

    return d_analysis_perpoint_ports_protocols


def update_log_ip_dict(flow_ip, origin_asn, ip_prefix, country_code, flow_bytes, flow_packets, d_ip_level_analysis):
    """
    Counts the unique IPAddresses, BGP prefixes, origin_asn for all the traffic that is seen.
    :param flow_ip:
    :param origin_asn:
    :param ip_prefix:
    :param d_ip_level_analysis:
    :return:
    """

    k = (flow_ip, origin_asn, ip_prefix, country_code)
    values = [1, flow_bytes, flow_packets]

    if k not in d_ip_level_analysis:
        d_ip_level_analysis[k] = values
    else:
        d_ip_level_analysis[k] = map(add, d_ip_level_analysis[k], values)

    return d_ip_level_analysis


def update_log_ip_ports_protocols_dict(str_flow_sa, flow_port, str_flow_pr, d_ip_ports_protocols):


    flow_port = [(flow_port)]
    str_flow_pr = [(str_flow_pr)]
    if str_flow_sa in d_ip_ports_protocols:
        d_ip_ports_protocols[str_flow_sa][0].update(flow_port)
        d_ip_ports_protocols[str_flow_sa][1].update(str_flow_pr)
    else:
        d_ip_ports_protocols[str_flow_sa] = {0: set(), 1: set()}
        d_ip_ports_protocols[str_flow_sa][0].update(flow_port)
        d_ip_ports_protocols[str_flow_sa][1].update(str_flow_pr)

    return d_ip_ports_protocols


def count_uniq_ip(l_d_flow_records, d_filters={}):
    """
    Filter the traffic flow data and execute the processing analysis logic for network behavior metrics.
    """

    d_ipsrc_level_analysis = dict()
    d_ipsrc_ports_protocols = dict()

    d_ipdst_level_analysis = dict()
    d_ipdst_ports_protocols = dict()

    d_ipsrc_level_analysis_peringress = dict()
    d_ipsrc_peringress_ports_protocols = dict()

    d_ipdst_level_analysis_peregress = dict()
    d_ipdst_peregress_ports_protocols = dict()

    for flow in l_d_flow_records:
        if futil.matches_desired_set(flow, d_filters):

            str_flow_sa = fputil.record_to_ip(flow['sa'])
            str_flow_da = fputil.record_to_ip(flow['da'])

            flow_bytes = fputil.record_to_numeric(flow['ibyt'])
            flow_packets = fputil.record_to_numeric(flow['ipkt'])

            flow_sp = fputil.record_to_numeric(flow['sp'])
            flow_dp = fputil.record_to_numeric(flow['dp'])
            str_flow_pr = fputil.proto_int_to_str(flow['pr'])

            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc']).replace(':', '').upper()
            flow_egress_dst_macaddr = fputil.record_to_mac(flow['odmc']).replace(':', '').upper()

            flow_ingress_asn = ""
            if flow_ingress_src_macaddr in d_mapping_macaddress_member_asn:
                flow_ingress_asn = d_mapping_macaddress_member_asn[flow_ingress_src_macaddr]

            flow_egress_asn = ""
            if flow_egress_dst_macaddr in d_mapping_macaddress_member_asn:
                flow_egress_asn = d_mapping_macaddress_member_asn[flow_egress_dst_macaddr]

            sa_origin_asn, sa_ip_prefix = do_prefix_lookup_forip(str_flow_sa)
            da_origin_asn, da_ip_prefix = do_prefix_lookup_forip(str_flow_da)

            sa_country_code = None
            if sa_ip_prefix is not None:
                if str_flow_sa in d_global_get_ip_country:
                    sa_country_code = d_global_get_ip_country[str_flow_sa]
                else:
                    sa_country_code = geoutil.get_country_netacq_edge_from_ip(str_flow_sa, ipm_netacq_db, i_geodb_id)
                    d_global_get_ip_country[str_flow_sa] = sa_country_code

            da_country_code = None
            if da_ip_prefix is not None:
                if str_flow_da in d_global_get_ip_country:
                    da_country_code = d_global_get_ip_country[str_flow_da]
                else:
                    da_country_code = geoutil.get_country_netacq_edge_from_ip(str_flow_da, ipm_netacq_db, i_geodb_id)
                    d_global_get_ip_country[str_flow_da] = da_country_code

            # save data processed
            #######
            # SRC
            #######
            d_ipsrc_level_analysis = update_log_ip_dict(str_flow_sa,
                                                        sa_origin_asn,
                                                        sa_ip_prefix,
                                                        sa_country_code,
                                                        flow_bytes,
                                                        flow_packets,
                                                        d_ipsrc_level_analysis)

            # save info about src ports and flow protocols
            d_ipsrc_ports_protocols = update_log_ip_ports_protocols_dict(str_flow_sa,
                                                                         flow_sp,
                                                                         str_flow_pr,
                                                                         d_ipsrc_ports_protocols)
            #######
            # DST
            #######
            d_ipdst_level_analysis = update_log_ip_dict(str_flow_da,
                                                        da_origin_asn,
                                                        da_ip_prefix,
                                                        da_country_code,
                                                        flow_bytes,
                                                        flow_packets,
                                                        d_ipdst_level_analysis)

            # save info about dst ports and flow protocols
            d_ipdst_ports_protocols = update_log_ip_ports_protocols_dict(str_flow_da,
                                                                         flow_dp,
                                                                         str_flow_pr,
                                                                         d_ipdst_ports_protocols)

            if is_to_process_data_per_ingress_egress:
                ##############
                # INGRESS/SRC
                ##############
                if flow_ingress_asn != "":
                    d_ipsrc_level_analysis_peringress = update_log_ip_dict_per_ingress_egress_point(flow_ingress_asn,
                                                                                                    str_flow_sa,
                                                                                                    sa_origin_asn,
                                                                                                    sa_ip_prefix,
                                                                                                    sa_country_code,
                                                                                                    flow_bytes,
                                                                                                    flow_packets,
                                                                                                    d_ipsrc_level_analysis_peringress)

                    # save info about src ports and flow protocols
                    d_ipsrc_peringress_ports_protocols = update_log_ip_ports_protocols_dict_per_ingress_egress_point(flow_ingress_asn,
                                                                                                                     str_flow_sa,
                                                                                                                     flow_sp,
                                                                                                                     str_flow_pr,
                                                                                                                     d_ipsrc_peringress_ports_protocols)

                ##############
                # EGRESS/DST
                ##############
                if flow_egress_asn != "":
                    d_ipdst_level_analysis_peregress = update_log_ip_dict_per_ingress_egress_point(flow_egress_asn,
                                                                                                   str_flow_da,
                                                                                                   da_origin_asn,
                                                                                                   da_ip_prefix,
                                                                                                   da_country_code,
                                                                                                   flow_bytes,
                                                                                                   flow_packets,
                                                                                                   d_ipdst_level_analysis_peregress)

                    d_ipdst_peregress_ports_protocols = update_log_ip_ports_protocols_dict_per_ingress_egress_point(flow_egress_asn,
                                                                                                                    str_flow_da,
                                                                                                                    flow_dp,
                                                                                                                    str_flow_pr,
                                                                                                                    d_ipdst_peregress_ports_protocols)

    return d_ipsrc_level_analysis, d_ipdst_level_analysis, \
           d_ipsrc_level_analysis_peringress, d_ipdst_level_analysis_peregress,\
           d_ipsrc_ports_protocols, d_ipdst_ports_protocols, \
           d_ipsrc_peringress_ports_protocols, d_ipdst_peregress_ports_protocols


def profile_worker(fn_input):
    cProfile.runctx('do_iplevel_analysis(fn_input)', globals(), locals(), 'profile-%s.out' %fn_input.split("/")[-1:])


def do_iplevel_analysis(fn_input):
    """
    Execute analysis over the IP level information from the file.
    :param fn_input:
    :return:
    """

    fn_output_pattern_src_addr = "ip=src"
    fn_output_pattern_dst_addr = "ip=dst"

    fn_output_pattern_src_addr_ingress = "point=ingress"
    fn_output_pattern_dst_addr_egress = "point=egress"

    try:
        reader = fputil.get_flowrecords_from_flowdata_file(fn_input)

        d_ipsrc_level_analysis, \
        d_ipdst_level_analysis, \
        d_ipsrc_level_analysis_peringress, \
        d_ipdst_level_analysis_peregress,\
        d_ipsrc_ports_protocols, \
        d_ipdst_ports_protocols, \
        d_ipsrc_peringress_ports_protocols, \
        d_ipdst_peregress_ports_protocols = count_uniq_ip(reader, d_filters=d_filter_to_apply)

        # save data log for the whole traffic
        save_to_logfile(d_ipsrc_level_analysis, d_ipsrc_ports_protocols, fn_input, fn_output_pattern_src_addr, filter_ip_version, filter_svln)
        save_to_logfile(d_ipdst_level_analysis, d_ipdst_ports_protocols, fn_input, fn_output_pattern_dst_addr, filter_ip_version, filter_svln)

        if is_to_process_data_per_ingress_egress:
            # save data log per ingress and egress points
            save_data_per_ingress_egress_point_to_logfile(d_ipsrc_level_analysis_peringress,
                                                          d_ipsrc_peringress_ports_protocols,
                                                          fn_input,
                                                          fn_output_pattern_src_addr_ingress,
                                                          filter_ip_version, filter_svln)

            save_data_per_ingress_egress_point_to_logfile(d_ipdst_level_analysis_peregress,
                                                          d_ipdst_peregress_ports_protocols,
                                                          fn_input,
                                                          fn_output_pattern_dst_addr_egress,
                                                          filter_ip_version, filter_svln)

        d_ipsrc_level_analysis.clear()
        d_ipdst_level_analysis.clear()
        d_ipsrc_level_analysis_peringress.clear()
        d_ipdst_level_analysis_peregress.clear()
        d_ipsrc_ports_protocols.clear()
        d_ipdst_ports_protocols.clear()
        d_ipsrc_peringress_ports_protocols.clear()
        d_ipdst_peregress_ports_protocols.clear()

        return 0

    except Exception as e:
        print('Caught exception in worker thread (file = %s):' % fn_input)
        # This prints the type, value, and stack trace of the
        # current exception being handled.
        traceback.print_exc()
        print()
        raise e
    except KeyboardInterrupt:
        # Allow ^C to interrupt from any thread.
        sys.stdout.write('\033[0m')
        sys.stdout.write('user interrupt\n')


def save_data_per_ingress_egress_point_to_logfile(d_ipsrc_level_analysis_perpoint,
                                                  d_analysis_perpoint_ports_protocols,
                                                  fn_input, fn_label,
                                                  filter_ip_version, filter_svln):
    """
    Save to file the processed data correlated to an specific ingress or egress point from the IXP switching fabric.
    :param d_ipsrc_level_analysis_perpoint:
    :param fn_input:
    :param fn_label:
    :param filter_ip_version:
    :param filter_svln:
    :return: file with the following columns =

    "ingress/egress asn;ip[src,dst];origin_asn;bgp_prefix;country;bytes;packets;qty_ports;qty_protocols;flow_ip_count"

    """

    fn_output_pattern = "{file_name}.{file_label}.ipv={ip_version}.svln={filter_svln}.txt.gz"
    fn_output_name = fn_output_pattern.format(file_name=fn_input,
                                              file_label=fn_label,
                                              ip_version=filter_ip_version,
                                              filter_svln=filter_svln)

    with gzip.open(fn_output_name, 'wb') as f:
        for ixp_member_point, ixp_member_flow_traffic_data in d_ipsrc_level_analysis_perpoint.iteritems():

            ases_point_values = "|".join(str(asn) for asn in ixp_member_point)
            for k, v in ixp_member_flow_traffic_data.iteritems():
                k_values = ";".join(str(e) for e in k)
                flow_ip_count = v[0]
                flow_bytes = v[1]
                flow_packets = v[2]

                ipaddr = k[0]
                qty_ports = len(d_analysis_perpoint_ports_protocols[ixp_member_point][ipaddr][0])
                qty_protocols = len(d_analysis_perpoint_ports_protocols[ixp_member_point][ipaddr][1])

                f.write("".join("{};{};{};{};{};{};{}".format(ases_point_values, k_values, flow_bytes, flow_packets, qty_ports, qty_protocols, flow_ip_count) + "\n"))
    f.close()


def save_to_logfile(d_ip_level_analysis, d_ip_ports_protocols, fn_input, fn_label, filter_ip_version, filter_svln):
    """
    Save to file the processed data from all the traffic seem in 5-min bin.
    :param d_ip_level_analysis:
    :param fn_input:
    :param fn_label:
    :param filter_ip_version:
    :param filter_svln:
    :return: file with the following columns =

    "ip[src,dst];origin_asn;bgp_prefix;country;bytes;packets;qty_ports;qty_protocols;flow_ip_count"

    """

    fn_output_pattern = "{file_name}.{file_label}.ipv={ip_version}.svln={filter_svln}.txt.gz"
    fn_output_name = fn_output_pattern.format(file_name=fn_input,
                                              file_label=fn_label,
                                              ip_version=filter_ip_version,
                                              filter_svln=filter_svln)

    # order ip address by bytes volume desc and write dict result to log file
    sorted_d_ip_level_analysis = sorted(d_ip_level_analysis.items(), key=lambda (k, v): v[1], reverse=True)

    with gzip.open(fn_output_name, 'wb') as f:
        for record in sorted_d_ip_level_analysis:
            k_values = ";".join(str(e) for e in record[0])
            flow_ip_count = record[1][0]
            flow_bytes = record[1][1]
            flow_packets = record[1][2]

            ipaddr = record[0][0]
            qty_ports = len(d_ip_ports_protocols[ipaddr][0])
            qty_protocols = len(d_ip_ports_protocols[ipaddr][1])

            f.write("".join("{};{};{};{};{};{}".format(k_values, flow_bytes, flow_packets, qty_ports, qty_protocols, flow_ip_count) + "\n"))
    f.close()


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Traffic classification taking Apache Avro '
                                                                   'as input files.')

    parser.add_argument('-tw', dest='time_window_op', required=True,
                        help="Time window to load files to process. Format: start-end, %Y%m%d%H%M-%Y%m%d%H%M")

    parser.add_argument('-flowdir', dest='flows_dir_path', required=True,
                        help="Directory where are the flows to process")

    parser.add_argument('-tmpdir', dest='temp_path', required=True,
                        help="Temporary dir to save output files")

    parser.add_argument('-np', dest='number_concur_process',
                        help="Number of concurrent process to execute")

    parser.add_argument('-filter', dest='flow_filter', required=True,
                        help="Filter to apply over each flow file read")

    parser.add_argument('-process_ingress_egress_data', dest='to_process_data_per_ingress_egress', type=int, choices=[0, 1], required=True,
                        help="Indicates if it is necessary to break down data per category "
                             "into a view per ingress and egress ASes."
                             "Options: 1 - yes or 0 - no")

    parser.add_argument('-pc', dest='to_process_categories', type=int, choices=[0, 1], required=True,
                        help="Process the categories flow traffic data files - incone, ouf-of-cone, unverifiable. "
                             "Options: 1 - yes or 0 - no (meaning that the whole traffic will be analyzed)")

    parser.add_argument('-cat', dest='set_of_categories_to_process', required=False,
                        help="Define the set of categories that must be processed to compute the metrics. "
                             " Syntax: '[incone, out-of-cone, unverifiable]' ")

    parser.add_argument('-ccid', dest='customercone_algoid', type=int, choices=[4, 8], required=True,
                        help="Options: "
                             "4 - IMC17 FullCone "
                             "8 - CoNEXT19 Prefix-Level Customer Cone.")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    # set up of variables to generate flow file names
    if parsed_args.time_window_op:
        tw_start, tw_end = cmdutil.get_timewindow_to_process(parsed_args.time_window_op)

    # number of concurrent process (performance control)
    if parsed_args.number_concur_process:
        n_cores_to_use = int(parsed_args.number_concur_process)
    else:
        n_cores_to_use = None

    # Customer Cone method algorithm
    id_customer_cone_algo_dataset = parsed_args.customercone_algoid

    # Process data Ingress and Egress
    is_to_process_data_per_ingress_egress = parsed_args.to_process_data_per_ingress_egress

    if parsed_args.set_of_categories_to_process:
        l_set_of_filters_traffic_categories = ast.literal_eval(parsed_args.set_of_categories_to_process)

    # directory paths set up for the conversion process
    flowfiles_basedir = parsed_args.flows_dir_path
    base_tmp_dir = parsed_args.temp_path

    # Filter to apply to each flow data file
    if parsed_args.flow_filter:
        d_filter_to_apply = ast.literal_eval(parsed_args.flow_filter)
        filter_ip_version = d_filter_to_apply['ip']

        if 'svln' in d_filter_to_apply:
            filter_svln = d_filter_to_apply['svln']
        else:
            filter_svln = "all"

    # ------------------------------------------------------------------
    #   Filtering logic processes start
    # ------------------------------------------------------------------
    start = timer()

    # init global dict to avoid duplicated computation (used together with MaxMind GeoIP)
    d_global_get_prefix24 = dict()

    d_global_get_ip_country = dict()

    geolocation_db_path = cons.DEFAULT_PATH_TO_GEOLITE2_DATABASE

    print "---Loading Routeviews ip2prefix-asn database file..."
    f_global_asndb_routeviews = load_database_ip2prefixasn_routeviews_by_timewindow(tw_start)

    print "---Loading netacq-edge geo database file..."
    ipm_netacq_db, i_geodb_id = geoutil.load_netacq_edge_geodb_by_timewindow(tw_start)

    print "---Loading mac2asn mapping data..."
    d_mapping_macaddress_member_asn = ixp_member_util.build_dict_mapping_macaddress_members_asns(cons.DEFAULT_MACADDRESS_ASN_MAPPING)

    print "---Creating list of files for processing (5-min flow files):"
    # if user input choice is to process each file category generate input names to multiprocessing step
    default_flowtraffic_datafile = ".avro"
    if parsed_args.to_process_categories:
        pattern_file_extension = '{def_ext}.idcc={id_cc_version}.class={lbl_class}'

        # if enabled to lookup to a specific class, prepare the list of files for only these categories
        # possibilities and indexing [incone, out-of-cone, unverifiable]
        if parsed_args.set_of_categories_to_process:

            l_pattern_file_extensions = list()
            i_index = 0

            for lbl_category in l_set_of_filters_traffic_categories:
                #########
                # incone
                if lbl_category == 1 and i_index == 0:
                    print "Preparing to process IN-CONE traffic."

                    l_pattern_file_extensions.append(
                        pattern_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                      id_cc_version=id_customer_cone_algo_dataset,
                                                      lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE)
                    )

                ##############
                # out-of-cone
                if lbl_category == 1 and i_index == 1:
                    print "Preparing to process OUT-OF-CONE traffic."

                    l_pattern_file_extensions.append(
                        pattern_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                      id_cc_version=id_customer_cone_algo_dataset,
                                                      lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE)
                    )

                ##############
                # unverifiable
                if lbl_category == 1 and i_index == 2:
                    print "Preparing to process UNVERIFIABLE traffic."
                    l_pattern_file_extensions.append(
                        pattern_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                      id_cc_version=id_customer_cone_algo_dataset,
                                                      lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS)
                    )

                i_index += 1

        else:
            print "Preparing to process IN-CONE, OUT-OF-CONE and UNVERIFIABLE traffic flow data."
            l_pattern_file_extensions = [pattern_file_extension.format(def_ext=default_flowtraffic_datafile, id_cc_version=id_customer_cone_algo_dataset, lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE),
                                         pattern_file_extension.format(def_ext=default_flowtraffic_datafile, id_cc_version=id_customer_cone_algo_dataset, lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE),
                                         pattern_file_extension.format(def_ext=default_flowtraffic_datafile, id_cc_version=id_customer_cone_algo_dataset, lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS)]

        l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                          flowfiles_basedir,
                                                                                          l_pattern_file_extensions)
    else:
        l_filenames_to_process = cmdutil.generate_flow_filenames_to_process(tw_start, tw_end,
                                                                            flowfiles_basedir,
                                                                            default_flowtraffic_datafile)

    print "---Started multiprocessing classification of traffic..."
    mp = mpPool.MultiprocessingPool(n_cores_to_use)
    results = mp.get_results_map_multiprocessing(do_iplevel_analysis, l_filenames_to_process)

    end = timer()
    print "---Total execution time: {} seconds".format(end - start)

    print "---Sending e-mail notification about the execution status:"
    notifutil.send_notification_end_of_execution(sys.argv, sys.argv[0], start, end)
