#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path

sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import utils.multiprocessing_poll as mpPool
import utils.constants as cons
import utils.filters_utilities as futil
import utils.fileparsing_utilities as fputil
import utils.time_utilities as tutil
import utils.ixp_members_mappings_utilities as ixp_member_util
import argparse
import sys
import utils.cmdline_interface_utilities as cmdutil
import ast
import traceback
from operator import add
from timeit import default_timer as timer
import gzip
from json import dump


"""
---------------------------------------ABOUT----------------------------------------
Process original traffic flow data, cutting and aggregating data to export 
traffic proprieties for the different categories.
------------------------------------------------------------------------------------
"""


def get_asn_via_macaddress(flow_asn_macaddr):

    """
    Lookup mac2asn -- get and transform mac address to same format as mac2as mapping data
    :param flow_asn_macaddr:
    :return:
    """

    flow_mac2asn = 'UNKNOWN'
    if flow_asn_macaddr in d_mapping_macaddress_member_asn:
        flow_mac2asn = d_mapping_macaddress_member_asn[flow_asn_macaddr][0]

    return flow_mac2asn


def do_update_asymmetry_traffic_analysis(i_flow_pr_l4, int_flow_sa, int_flow_da, i_flow_sp_l7, i_flow_dp_l7,
                                         flow_ingress_src_macaddr, flow_egress_src_macaddr,
                                         d_asymmetry_traffic_props,
                                         flow_bytes, flow_packets):

    key_tuple = (i_flow_pr_l4, int_flow_sa, int_flow_da, i_flow_sp_l7, i_flow_dp_l7, flow_ingress_src_macaddr, flow_egress_src_macaddr)
    key_rev_tuple = (i_flow_pr_l4, int_flow_da, int_flow_sa, i_flow_dp_l7, i_flow_sp_l7, flow_egress_src_macaddr, flow_ingress_src_macaddr)

    values = [flow_bytes, flow_packets]

    if key_tuple in d_asymmetry_traffic_props:
        d_asymmetry_traffic_props[key_tuple]['in'] = map(add, d_asymmetry_traffic_props[key_tuple]['in'], values)

    elif key_rev_tuple in d_asymmetry_traffic_props:
        d_asymmetry_traffic_props[key_rev_tuple]['out'] = map(add, d_asymmetry_traffic_props[key_rev_tuple]['out'], values)

    else:
        d_asymmetry_traffic_props[key_tuple] = {'in': [0, 0],
                                                'out': [0, 0]}
        d_asymmetry_traffic_props[key_tuple]['in'] = values

    return d_asymmetry_traffic_props


def update_vlan_sum(d_svlan_traffic_props, vlan_tag, bytes, packets):
    values = [bytes, packets]

    if vlan_tag not in d_svlan_traffic_props:
        d_svlan_traffic_props[vlan_tag] = values
    else:
        d_svlan_traffic_props[vlan_tag] = map(add, d_svlan_traffic_props[vlan_tag], values)

    return d_svlan_traffic_props


def do_update_protocols_diversity_traffic_props(d_protocols_diversity_traffic_props, protocol,
                                                flow_bytes, flow_packets):

    values = [flow_bytes, flow_packets]

    if protocol not in d_protocols_diversity_traffic_props:
        d_protocols_diversity_traffic_props[protocol] = values
    else:
        d_protocols_diversity_traffic_props[protocol] = map(add, d_protocols_diversity_traffic_props[protocol], values)

    return d_protocols_diversity_traffic_props


def do_update_traffic_exchanged_between_members(d_members_traffic_exchanged_volume, d_members_traffic_exchanged_packets,
                                                flow_ingress_asn, flow_egress_asn, flow_bytes, flow_packets):

    k_pair_members = (flow_ingress_asn, flow_egress_asn)

    if k_pair_members not in d_members_traffic_exchanged_volume:
        d_members_traffic_exchanged_volume[k_pair_members] = flow_bytes
    else:
        d_members_traffic_exchanged_volume[k_pair_members] += flow_bytes

    if k_pair_members not in d_members_traffic_exchanged_packets:
        d_members_traffic_exchanged_packets[k_pair_members] = flow_packets
    else:
        d_members_traffic_exchanged_packets[k_pair_members] += flow_packets

    return d_members_traffic_exchanged_volume, d_members_traffic_exchanged_packets


def post_processing_overall_stats_5min_results(l_d_results):
    """
    Reduce data multi-processed by post-processing.
    :param l_d_results:
    :return:
    """
    d_output_l4protocols_perct = dict()
    d_output_l4protocols_raw = dict()

    l_src_ips_export_allentries = list()
    l_dst_ips_export_allentries = list()

    d_output_members_traffic_exchanged_volume = dict()
    d_output_members_traffic_exchanged_packets = dict()

    for dict_result in l_d_results:

        # for each timestamp dict there is a list of results to be read all in object format
        for k_timestamp, v_values in dict_result.items():

            d_vlan_agg = {10: [0, 0],
                          99: [0, 0],
                          -1: [0, 0]}

            ixp_traffic_values_bytes_pkts_in = [0, 0]
            ixp_traffic_values_bytes_pkts_return = [0, 0]

            i_bin_bytes = v_values[0]
            i_bin_pkts = v_values[1]

            if op_enable_sysout_prints:
                print "{}: {} bytes {} pkts".format(k_timestamp, i_bin_bytes, i_bin_pkts)

            d_asymmetry_traffic_props = v_values[3]
            for k, v in d_asymmetry_traffic_props.iteritems():
                ixp_traffic_values_bytes_pkts_in = map(add, ixp_traffic_values_bytes_pkts_in, v['in'])
                ixp_traffic_values_bytes_pkts_return = map(add, ixp_traffic_values_bytes_pkts_return, v['out'])

            if op_enable_sysout_prints:
                print "> in: {} return: {}".format(ixp_traffic_values_bytes_pkts_in, ixp_traffic_values_bytes_pkts_return)

            for k_vlan_tag, v_bytes_pkts in v_values[2].iteritems():
                if k_vlan_tag == 10 or k_vlan_tag == 99:
                    d_vlan_agg[k_vlan_tag] = map(add, d_vlan_agg[k_vlan_tag], v_bytes_pkts)
                else:
                    d_vlan_agg[-1] = map(add, d_vlan_agg[-1], v_bytes_pkts)

            if op_enable_sysout_prints:
                # total bytes flow in multilateral vs bilateral agreements
                i_vlan10_total_bytes = round(float(d_vlan_agg[10][0] * 100.0 / i_bin_bytes), 2)
                i_bi_vlans_total_bytes = round(float(d_vlan_agg[-1][0] * 100.0 / i_bin_bytes), 2)
                print "VLAN breakdown: {} ATM {} bilateral vlans".format(i_vlan10_total_bytes, i_bi_vlans_total_bytes)

            # raw bytes, packets per L4-protocol
            d_protocols_diversity_traffic_props = v_values[4]
            d_output_l4protocols_raw[k_timestamp] = d_protocols_diversity_traffic_props

            if op_enable_sysout_prints:
                print "{} protocol distribution: {}".format(k_timestamp, d_protocols_diversity_traffic_props)

            # percent bytes per L4-protocol
            sum_bytes_per_5min = 0
            for k_l4prot, v_values_bytes_pkts in d_protocols_diversity_traffic_props.iteritems():
                sum_bytes_per_5min += v_values_bytes_pkts[0]

            d_protocols_diversity_traffic_props_perct = dict()
            for k_l4prot, v_values_bytes_pkts in d_protocols_diversity_traffic_props.iteritems():
                d_protocols_diversity_traffic_props_perct[k_l4prot] = round(float(v_values_bytes_pkts[0] * 100.0 / sum_bytes_per_5min), 2)

            if op_enable_sysout_prints:
                print "{} protocol distribution percentage: {}".format(k_timestamp, d_protocols_diversity_traffic_props_perct)

            # account for traffic L4-protocols diversity properties
            if l_which_analysis_to_run[1] == 1:
                d_output_l4protocols_perct[k_timestamp] = d_protocols_diversity_traffic_props_perct

            # if requested to export IPs to external file
            if parsed_args.op_enable_output_src_dst_ips_timestamped:
                # deal with aggregation of raw timestamp/ips to export
                l_src_ips_export = v_values[5]
                l_dst_ips_export = v_values[6]
                if l_src_ips_export is not None:
                    for ip_flow_entry in l_src_ips_export:
                        l_src_ips_export_allentries.append(ip_flow_entry)

                if l_dst_ips_export is not None:
                    for ip_flow_entry in l_dst_ips_export:
                        l_dst_ips_export_allentries.append(ip_flow_entry)

            # account amount of traffic exchanged between members
            if l_which_analysis_to_run[2] == 1:
                d_output_members_traffic_exchanged_volume[k_timestamp] = {str(v_values[7].keys()): v_values[7].values()}
                d_output_members_traffic_exchanged_packets[k_timestamp] = {str(v_values[8].keys()): v_values[8].values()}

    return d_output_l4protocols_raw, d_output_l4protocols_perct, \
           l_src_ips_export_allentries, l_dst_ips_export_allentries, \
           d_output_members_traffic_exchanged_volume, d_output_members_traffic_exchanged_packets


def summarize_overall_traffic_profile(l_d_flow_records, d_filters={}):

    i_bytes_total = 0
    i_packets_total = 0

    d_protocols_diversity_traffic_props = dict()

    # account for [bytes, packets] per VLAN tag
    d_svlan_traffic_props = dict()

    d_asymmetry_traffic_props = dict()

    # account amount of traffic exchanged between members
    d_members_traffic_exchanged_volume = dict()
    d_members_traffic_exchanged_packets = dict()

    # export IPs to further evaluations
    l_src_ips_export = list()
    l_dst_ips_export = list()

    for flow in l_d_flow_records:
        # print "Flow:", str(flow)
        if futil.matches_desired_set(flow, d_filters):

            # get srcIP and dstIP
            int_flow_sa = flow['sa']
            int_flow_da = flow['da']

            # get bytes and packets
            flow_bytes = fputil.record_to_numeric(flow['ibyt'])
            flow_packets = fputil.record_to_numeric(flow['ipkt'])

            # get ports and protocol
            i_flow_sp_l7 = flow['sp']
            i_flow_dp_l7 = flow['dp']
            i_flow_pr_l4 = flow['pr']

            # get macaddress ingress / egress
            # ###### lookup mac2asn ######
            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc']).replace(':', '').upper()
            flow_ingress_asn = get_asn_via_macaddress(flow_ingress_src_macaddr)

            flow_egress_dst_macaddr = fputil.record_to_mac(flow['odmc']).replace(':', '').upper()
            flow_egress_asn = get_asn_via_macaddress(flow_egress_dst_macaddr)

            # get VLAN tag
            flow_svln_id = fputil.record_to_numeric(flow['svln'])

            # sum
            i_bytes_total += flow_bytes
            i_packets_total += flow_packets

            # account for traffic flow data per VLAN
            d_svlan_traffic_props = update_vlan_sum(d_svlan_traffic_props, flow_svln_id, flow_bytes, flow_packets)

            # exec and update IXP traffic asymmetry analysis
            if l_which_analysis_to_run[0] == 1:
                d_asymmetry_traffic_props = do_update_asymmetry_traffic_analysis(
                    i_flow_pr_l4, int_flow_sa, int_flow_da, i_flow_sp_l7, i_flow_dp_l7,
                    flow_ingress_src_macaddr, flow_egress_dst_macaddr,
                    d_asymmetry_traffic_props,
                    flow_bytes, flow_packets)

            # account for traffic L4-protocols diversity properties
            if l_which_analysis_to_run[1] == 1:
                d_protocols_diversity_traffic_props = do_update_protocols_diversity_traffic_props(d_protocols_diversity_traffic_props, fputil.proto_int_to_str(i_flow_pr_l4), flow_bytes, flow_packets)

            # account amount of traffic exchanged between members
            if l_which_analysis_to_run[2] == 1:
                d_members_traffic_exchanged_volume, d_members_traffic_exchanged_packets = \
                    do_update_traffic_exchanged_between_members(d_members_traffic_exchanged_volume,
                                                                d_members_traffic_exchanged_packets,
                                                                flow_ingress_asn, flow_egress_asn,
                                                                flow_bytes, flow_packets)

            if op_enable_sysout_prints:
                srcip_port = fputil.record_to_ip(int_flow_sa) + ":" + str(fputil.record_to_numeric(i_flow_sp_l7))
                dstip_port = fputil.record_to_ip(int_flow_da) + ":" + str(fputil.record_to_numeric(i_flow_dp_l7))

                print "{:<4} | SRC: {:<25} | DST: {:<25} | BYTES: {:<12} | PACKETS: {:<12} | INGRESS: {:<8} | EGRESS: {:<8} | SVLAN: {:<5}".format(
                    fputil.proto_int_to_str(i_flow_pr_l4),
                    srcip_port,
                    dstip_port,
                    flow_bytes,
                    flow_packets,
                    flow_ingress_asn,
                    flow_egress_asn,
                    flow_svln_id)

            # if requested to export IPs to external file
            if parsed_args.op_enable_output_src_dst_ips_timestamped:
                # SRC enabled
                if l_enable_output_src_dst_ips_timestamped[0] == 1:
                    l_src_ips_export.append([flow['ts'], int_flow_sa, flow_packets])

                # DST enabled
                if l_enable_output_src_dst_ips_timestamped[1] == 1:
                    l_dst_ips_export.append([flow['ts'], int_flow_da, flow_packets])

    return [i_bytes_total,
            i_packets_total,
            d_svlan_traffic_props,
            d_asymmetry_traffic_props,
            d_protocols_diversity_traffic_props,
            l_src_ips_export,
            l_dst_ips_export,
            d_members_traffic_exchanged_volume,
            d_members_traffic_exchanged_packets]


def do_traffic_overall_features_analysis(fn_input):
    """
    Execute analysis over the IP level information from the file.
    :param fn_input:
    :return:
    """

    try:
        reader = fputil.get_flowrecords_from_flowdata_file(fn_input)

        dt_timestamp_label_key = fputil.extract_timestamp_from_flowfilepath(fn_input)
        s_timestamp_label_key = str(tutil.formated_date(tutil.date_to_ts(dt_timestamp_label_key)))

        # print "Starting -- {}: {}".format(s_timestamp_label_key, fn_input)
        l_profile_bin_results = summarize_overall_traffic_profile(reader, d_filters=d_filter_to_apply)

        return {s_timestamp_label_key: l_profile_bin_results}

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


def save_results_to_jsonfile(s_label_file_output,
                             d_percent_bytes_per_L4protocols,
                             p_dest_filepath,
                             set_of_traffic_filters_enabled):
    """
    Export the results to json files.
    :param d_percent_bytes_per_L4protocols:
    :param p_dest_filepath:
    :param set_of_traffic_filters_enabled:
    :return:
    """

    fn_output_pattern = "{file_dest_dir}{label_filename_output}.{set_of_filter_enabled}.json.gz"

    fn_output = fn_output_pattern.format(
        label_filename_output=s_label_file_output,
        file_dest_dir=p_dest_filepath,
        set_of_filter_enabled=set_of_traffic_filters_enabled)

    # write dict result with flow traffic info to a json file
    with gzip.open(fn_output, 'wb') as f:
        dump(d_percent_bytes_per_L4protocols, f, sort_keys=True)
    f.close()


def save_results_to_txtfile(s_label_file_output,
                            l_ips_export,
                            p_dest_filepath,
                            s_set_of_traffic_filters_enabled):
    """
    Write to disk flow data timestamp, IP to further behavior analysis.
    Export: timestamp, ipaddress
    """

    fn_output_pattern = "{file_dest_dir}{label_filename_output}.{set_of_filter_enabled}.txt.gz"

    fn_output = fn_output_pattern.format(
        label_filename_output=s_label_file_output,
        file_dest_dir=p_dest_filepath,
        set_of_filter_enabled=s_set_of_traffic_filters_enabled)

    # write dict result with flow traffic info to a json file
    with gzip.open(fn_output, 'wb') as f:
        for ip_flow_entry in l_ips_export:
            # timestamp, IP
            f.write("{}\t{}\n".format(ip_flow_entry[0], fputil.record_to_ip(ip_flow_entry[1])))
    f.close()


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Reads traffic classification Apache Avro files '
                                                                   'as input files and process new outputs.')

    parser.add_argument('-tw', dest='time_window_op', required=True,
                        help="Time window to load files to process. Format: start-end, %Y%m%d%H%M-%Y%m%d%H%M")

    parser.add_argument('-flowdir', dest='flows_dir_path', required=True,
                        help="Directory where are the flows to process")

    parser.add_argument('-tmpdir', dest='temp_path', required=True,
                        help="Temporary dir to save output files")

    parser.add_argument('-np', dest='number_concur_process',
                        help="Number of concurrent process to execute")

    parser.add_argument('-filter', dest='flow_filter', required=True,
                        help="Filter to apply over each flow file read"
                             "Syntax: as string {'ip': 4, 'svln': 10}")

    parser.add_argument('-cat', dest='op_category_to_process', type=int, choices=[0, 1, 2, 3, 4, 99], required=True,
                        help="Define the category that must be processed and analyzed. "
                             " Syntax: '[0-bogon, 1-unrouted, 2-incone, 3-out-of-cone, 4-unverifiable, 99-raw flows]' ")

    parser.add_argument('-sbcat', dest='op_subcategory_unverifiable_to_process', type=int, required=False,
                        help="Define the subcategory that must be processed and analyzed "
                             "within the Unverifiable traffic. ")

    parser.add_argument('-ccid', dest='customercone_algoid', type=int, choices=[4, 8], required=True,
                        help="Options: "
                             "4 - IMC17 FullCone "
                             "8 - Prefix-Level Customer Cone.")

    parser.add_argument('-sysout', dest='op_enable_sysout_prints', type=int, default=0,
                        help="Options: "
                             " 0 = in case we don't want to see sysout prints."
                             " 1 = if we want to see sysout prints to eval data.")

    parser.add_argument('-outputips', dest='op_enable_output_src_dst_ips_timestamped', required=False,
                        help="Syntax: '[SRC, DST]' "
                             "e.g.: '[1, 1]' ")

    parser.add_argument('-execanalysis', dest='op_which_analysis_to_run', required=True,
                        help="Syntax: choose which analyses must be executed " 
                             "          '[ 1- IXP traffic asymmetry analysis, "
                             "             2- account for traffic protocols diversity properties,"
                             "             3- track amount of traffic/packets exchanged between members ]' "
                             "e.g.: '[0, 0, 1]' ")
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

    # directory paths set up for the conversion process
    flowfiles_basedir = parsed_args.flows_dir_path
    base_tmp_dir = parsed_args.temp_path

    # control when print to sysout information and when not.
    op_enable_sysout_prints = parsed_args.op_enable_sysout_prints

    # Filter to apply to each flow data file
    if parsed_args.flow_filter:
        d_filter_to_apply = ast.literal_eval(parsed_args.flow_filter)
        filter_ip_version = d_filter_to_apply['ip']

        # VLAN tag
        if 'svln' in d_filter_to_apply:
            filter_svln = d_filter_to_apply['svln']
        else:
            filter_svln = "all"

        # Protocol
        if 'pr' in d_filter_to_apply:
            filter_protocol_flows = d_filter_to_apply['pr']
        else:
            filter_protocol_flows = "all"

    # list of categories raw files generated after the traffic classification process
    l_categories = [cons.CATEGORY_LABEL_BOGON_CLASS, cons.CATEGORY_LABEL_UNASSIGNED_CLASS,
                    cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                    cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS]

    # check category to process
    if (not parsed_args.op_category_to_process is None) and (parsed_args.op_category_to_process != 99):
        op_category_to_process = l_categories[parsed_args.op_category_to_process]

    # if Unverifiable is set, check for subcategory to analyze
    if parsed_args.op_category_to_process == 4 and parsed_args.op_subcategory_unverifiable_to_process is not None:
        op_subcategory_unverifiable_to_process = parsed_args.op_subcategory_unverifiable_to_process

    print "---Loading mac2asn mapping data..."
    d_mapping_macaddress_member_asn = ixp_member_util.build_dict_mapping_macaddress_members_asns(
        cons.DEFAULT_MACADDRESS_ASN_MAPPING)

    # check if requested to write output timestamp IPs over time to further correlated analyzes
    if parsed_args.op_enable_output_src_dst_ips_timestamped:
        l_enable_output_src_dst_ips_timestamped = ast.literal_eval(parsed_args.op_enable_output_src_dst_ips_timestamped)

        print "Activated export IPs filters: {}".format(l_enable_output_src_dst_ips_timestamped)
        # Strict checking on param input to ensure correct execution
        if len(l_enable_output_src_dst_ips_timestamped) < 2:
            print "ERROR: parsed_args.op_enable_output_src_dst_ips_timestamped does not have all options defined, " \
                  "please revise it!"
            exit(1)

    # param which set analysis to be executed
    if parsed_args.op_which_analysis_to_run:
        l_which_analysis_to_run = ast.literal_eval(parsed_args.op_which_analysis_to_run)

        print "Activated analysis to run: {}".format(l_which_analysis_to_run)
        # Strict checking on param input to ensure correct execution
        if len(l_which_analysis_to_run) < 2:
            print "ERROR: parsed_args.op_which_analysis_to_run does not have all options defined, " \
                  "please revise it!"
            exit(1)

    # ------------------------------------------------------------------
    #   Analysis logic processes start
    # ------------------------------------------------------------------
    start = timer()

    print "---Creating list of files for processing (5-min flow files):"
    # if user input choice is to process each file category generate input names to multiprocessing step
    default_flowtraffic_datafile = ".avro"

    # process raw flow files
    if parsed_args.op_category_to_process == 99:
        l_filenames_to_process = cmdutil.generate_flow_filenames_to_process(tw_start, tw_end, flowfiles_basedir, default_flowtraffic_datafile)

    # process flow files per category
    else:
        pattern_file_extension = '{def_ext}.idcc={id_cc_version}.class={lbl_class}'

        l_pattern_file_extensions = [pattern_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                   id_cc_version=id_customer_cone_algo_dataset,
                                                                   lbl_class=op_category_to_process)]

        l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                          flowfiles_basedir,
                                                                                          l_pattern_file_extensions)

    print "---Started multiprocessing traffic data -- Overall traffic category analysis..."
    mp = mpPool.MultiprocessingPool(n_cores_to_use)
    results = mp.get_results_map_multiprocessing(do_traffic_overall_features_analysis, l_filenames_to_process)

    print "---Started post-processing: Overall traffic category analysis..."
    d_output_l4protocols_raw, \
    d_output_l4protocols_perct, \
    l_src_ips_export_allentries, \
    l_dst_ips_export_allentries, \
    d_output_members_traffic_exchanged_volume, \
    d_output_members_traffic_exchanged_packets = post_processing_overall_stats_5min_results(results)

    print "---Saving results of flow classification pipeline run: {} to {}".format(tw_start, tw_end)

    # --- set string of filters applied and send it to save processing ---
    # if Unverifiable is set, check for subcategory to analyze
    if parsed_args.op_category_to_process == 4 and parsed_args.op_subcategory_unverifiable_to_process is not None:
        set_of_traffic_filters_enabled = "{}.ipv={}.svln={}.idcc={}.ixp={}.cat={}.subcat={}".format(
            parsed_args.time_window_op,
            filter_ip_version,
            filter_svln,
            id_customer_cone_algo_dataset,
            cons.ID_IXP_BR1,
            op_category_to_process,
            op_subcategory_unverifiable_to_process)
    else:
        set_of_traffic_filters_enabled = "{}.ipv={}.svln={}.idcc={}.ixp={}.cat={}".format(
            parsed_args.time_window_op,
            filter_ip_version,
            filter_svln,
            id_customer_cone_algo_dataset,
            cons.ID_IXP_BR1,
            op_category_to_process)

    # account for traffic L4-protocols diversity properties
    if l_which_analysis_to_run[1] == 1:
        save_results_to_jsonfile("L4protocols-breakdown-rawnumbers",
                                 d_output_l4protocols_raw,
                                 base_tmp_dir,
                                 set_of_traffic_filters_enabled)

        save_results_to_jsonfile("L4protocols-breakdown-percentage",
                                 d_output_l4protocols_perct,
                                 base_tmp_dir,
                                 set_of_traffic_filters_enabled)

    # if requested to write output timestamp IPs over time to further correlated analyzes
    if parsed_args.op_enable_output_src_dst_ips_timestamped:
        # SRC enabled
        if l_enable_output_src_dst_ips_timestamped[0] == 1:
            save_results_to_txtfile("raw-list-SRC-IPs-timestamped",
                                    l_src_ips_export_allentries,
                                    base_tmp_dir,
                                    set_of_traffic_filters_enabled)

        # DST enabled
        if l_enable_output_src_dst_ips_timestamped[1] == 1:
            save_results_to_txtfile("raw-list-DST-IPs-timestamped",
                                     l_dst_ips_export_allentries,
                                     base_tmp_dir,
                                     set_of_traffic_filters_enabled)

    # account amount of traffic exchanged between members
    if l_which_analysis_to_run[2] == 1:

        save_results_to_jsonfile("traffic-volume-exchanged-members",
                                 d_output_members_traffic_exchanged_volume,
                                 base_tmp_dir,
                                 set_of_traffic_filters_enabled)

        save_results_to_jsonfile("traffic-packets-exchanged-members",
                                 d_output_members_traffic_exchanged_packets,
                                 base_tmp_dir,
                                 set_of_traffic_filters_enabled)
