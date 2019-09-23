#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path

sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import utils.multiprocessing_poll as mpPool
import utils.constants as cons
import utils.filters_utilities as futil
import utils.fileparsing_utilities as fputil
import utils.notification_utilities as notifutil
import utils.time_utilities as tutil
import utils.ixp_members_mappings_utilities as ixp_member_util
import argparse
import sys
import utils.cmdline_interface_utilities as cmdutil
import ast
import traceback
from timeit import default_timer as timer
import gzip
from json import dump


"""
---------------------------------------ABOUT----------------------------------------
Process traffic flow data classified to identify the IXP members which appear in each  
of the different categories (Bogon, Unassigned, Out-of-Cone).
------------------------------------------------------------------------------------
"""


class ListIXPmemberPresenceCategoriesTrafficBreakdown(object):
    """
    Data structure to account for the presence of each IXP member in each category, breakdown data.
    """

    def __init__(self):
        self.d_categories = {
            cons.CATEGORY_LABEL_BOGON_CLASS: 0,
            cons.CATEGORY_LABEL_UNASSIGNED_CLASS: 0,
            cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE: 0,
            cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE: 0,
            cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS: 0
        }

    def set_presence_at_category(self, id_category_label, i_member_presence_count):
        self.d_categories[id_category_label] = i_member_presence_count

    def get_members_presence_values(self):
        return self.d_categories


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


def count_map_of_members_presence_in_each_category(l_d_results, k_category, d_agg_map_aggcount_view_of_members_presence):
    """
    Creates a count presence map of each category per timestamp.
    :param l_d_results:
    :param k_category:
    :param d_agg_view_members_presence:
    :return:
    """

    # for each timestamp dict there is a list of results to be read all in object format
    for dict_result in l_d_results:
        for k_timestamp, v_values_members_ases in dict_result.items():

            if k_timestamp not in d_agg_map_aggcount_view_of_members_presence:
                d_agg_map_aggcount_view_of_members_presence[k_timestamp] = ListIXPmemberPresenceCategoriesTrafficBreakdown()

            d_agg_map_aggcount_view_of_members_presence[k_timestamp].set_presence_at_category(k_category, len(v_values_members_ases))

    return d_agg_map_aggcount_view_of_members_presence


def process_map_of_traffic_category_entry_members_presence(l_d_results, k_category, d_agg_map_binary_view_members_presence):
    """
    Creates a binary presence map of each located member in the distinct categories in analysis.
    :param l_d_results: 
    :param k_category: 
    :param d_agg_map_binary_view_members_presence: 
    :return: 
    """

    # for each timestamp dict there is a list of results to be read all in object format
    for dict_result in l_d_results:
        for k_timestamp, v_values_members_ases in dict_result.items():

            if k_timestamp not in d_agg_map_binary_view_members_presence:
                d_agg_map_binary_view_members_presence[k_timestamp] = dict()

            # for each member located in the specific 5min-bin set its presence in the category in analysis
            for member_asn in v_values_members_ases:
                if member_asn not in d_agg_map_binary_view_members_presence[k_timestamp]:
                    d_agg_map_binary_view_members_presence[k_timestamp][member_asn] = ListIXPmemberPresenceCategoriesTrafficBreakdown()
                    d_agg_map_binary_view_members_presence[k_timestamp][member_asn].set_presence_at_category(k_category, 1)

                elif member_asn in d_agg_map_binary_view_members_presence[k_timestamp]:
                    d_agg_map_binary_view_members_presence[k_timestamp][member_asn].set_presence_at_category(k_category, 1)

    return d_agg_map_binary_view_members_presence


def post_processing_overall_stats_5min_results(d_l_d_results):

    """
    Perform post-processing aggregating data in two distinct ways:
    1) raw count number of members in each category;
    2) for each time-bin, set each member which have appeared indicating in which classes the member appears.

    :param d_l_d_results:
    :return: d_agg_view_members_presence

    { timestamp: {
                  member_asn: [exist_bogon, exist_unassigned, exist_outofcone, exist_unverifiable],
                  member_asn: [], ...},
                  ...
                 },
      timestamp: ...
    }

    """

    d_agg_map_binary_view_members_presence = dict()
    d_agg_map_aggcount_view_of_members_presence = dict()

    # each element in this dict represent one category, where each has a list of dicts inside
    for k_category, v_l_d_results in d_l_d_results.items():

        print "Category being post-processed: {}".format(k_category)
        d_agg_map_binary_view_members_presence = process_map_of_traffic_category_entry_members_presence(v_l_d_results, k_category, d_agg_map_binary_view_members_presence)
        d_agg_map_aggcount_view_of_members_presence = count_map_of_members_presence_in_each_category(v_l_d_results, k_category, d_agg_map_aggcount_view_of_members_presence)

    return d_agg_map_binary_view_members_presence, d_agg_map_aggcount_view_of_members_presence


def summarize_overall_members_presence_into_categories(l_d_flow_records, d_filters={}):
    """
    Read flow traffic data and save the ingress ASN.
    :param l_d_flow_records:
    :param d_filters:
    :return:
    """

    s_members_presence = set()

    for flow in l_d_flow_records:
        # print "Flow:", str(flow)
        if futil.matches_desired_set(flow, d_filters):

            # ###### lookup mac2asn ######
            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc']).replace(':', '').upper()
            flow_ingress_asn = get_asn_via_macaddress(flow_ingress_src_macaddr)

            if (flow_ingress_asn not in s_members_presence) and (flow_ingress_asn != 'UNKNOWN'):
                s_members_presence.add(flow_ingress_asn)

    return s_members_presence


def do_check_members_presence_into_traffic_categories(fn_input):
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
        l_members_presence_bin_results = summarize_overall_members_presence_into_categories(reader,
                                                                                            d_filters=d_filter_to_apply)

        return {s_timestamp_label_key: l_members_presence_bin_results}

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


def convert_object_to_commondata_types_to_save(d_agg_map_binary_view_members_presence,
                                               d_agg_map_aggcount_view_of_members_presence):
    """
    Convert part that is a object Class to save results to json data file.
    :param d_agg_map_binary_view_members_presence:
    :param d_agg_map_aggcount_view_of_members_presence:
    :return:
    """

    d_agg_map_binary_view_output = dict()
    d_agg_map_aggcount_view_output = dict()

    # convert -- agg_map_binary_view
    for k_timestamp, d_members_presence in d_agg_map_binary_view_members_presence.items():

        d_agg_map_binary_view_output[k_timestamp] = dict()

        for k_member_asn, v_o_categories_presence in d_members_presence.items():
            d_agg_map_binary_view_output[k_timestamp][k_member_asn] = v_o_categories_presence.get_members_presence_values()

    # convert -- agg_map_aggcount_view
    for k_timestamp, v_o_members_presence in d_agg_map_aggcount_view_of_members_presence.items():
        d_agg_map_aggcount_view_output[k_timestamp] = v_o_members_presence.get_members_presence_values()

    return d_agg_map_binary_view_output, d_agg_map_aggcount_view_output


def save_results_to_jsonfile(d_agg_map_binary_view_members_presence,
                             d_agg_map_aggcount_view_of_members_presence,
                             p_dest_filepath, p_file_name, p_ixp_lbl):
    """
    Generate the output files.
    :param d_agg_map_binary_view_members_presence:
    :param d_agg_map_aggcount_view_of_members_presence:
    :param p_dest_filepath:
    :param p_file_name:
    :param p_ixp_lbl:
    :return:
    """

    fn_output_agg_map_binary_view_members_presence_pattern = "{file_dest_dir}{file_name}{location_id}.binarymap.json.gz"
    fn_output_agg_map_aggcount_view_of_members_presence_pattern = "{file_dest_dir}{file_name}{location_id}.aggcountview.json.gz"

    fn_output_agg_map_binary_view = fn_output_agg_map_binary_view_members_presence_pattern.format(
                                                             file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             location_id=p_ixp_lbl)

    fn_output_agg_map_aggcount_view_ = fn_output_agg_map_aggcount_view_of_members_presence_pattern.format(
                                                             file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             location_id=p_ixp_lbl)

    # write dict result with flow traffic info to a json file
    with gzip.open(fn_output_agg_map_binary_view, 'wb') as f:
        dump(d_agg_map_binary_view_members_presence, f, sort_keys=True)
    f.close()

    # write dict result with flow traffic info to a json file
    with gzip.open(fn_output_agg_map_aggcount_view_, 'wb') as f:
        dump(d_agg_map_aggcount_view_of_members_presence, f, sort_keys=True)
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

    parser.add_argument('-cat', dest='op_categories_to_process', required=True,
                        help="Define the category that must be processed and analyzed. "
                             " Syntax: '[0-bogon, 1-unassigned, 2-out-of-cone]' "
                             "[0-bogon, 1-unassigned, 2-out-of-cone, 3-incone, 4-unverifiable]")

    parser.add_argument('-ccid', dest='customercone_algoid', type=int, choices=[4, 8], required=True,
                        help="Options: "
                             "4 - IMC17 FullCone "
                             "8 - Prefix-Level Customer Cone.")

    parser.add_argument('-sysout', dest='op_enable_sysout_prints', type=int, default=0,
                        help="Options: "
                             " 0 = in case we don't want to see sysout prints."
                             " 1 = if we want to see sysout prints to eval data.")

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
    l_categories = [cons.CATEGORY_LABEL_BOGON_CLASS,
                    cons.CATEGORY_LABEL_UNASSIGNED_CLASS,
                    cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                    cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                    cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS]

    if not parsed_args.op_categories_to_process is None:
        l_categories_to_process = ast.literal_eval(parsed_args.op_categories_to_process)

    print "---Loading mac2asn mapping data..."
    d_mapping_macaddress_member_asn = ixp_member_util.build_dict_mapping_macaddress_members_asns(
        cons.DEFAULT_MACADDRESS_ASN_MAPPING)

    # ------------------------------------------------------------------
    #   Analysis logic processes start
    # ------------------------------------------------------------------
    start = timer()

    print "---Creating list of files for processing (5-min flow files):"
    # if user input choice is to process each file category generate input names to multiprocessing step
    default_flowtraffic_datafile = ".avro"
    pattern_file_extension = '{def_ext}.idcc={id_cc_version}.class={lbl_class}'

    # loop over all traffic categories as defined in the input param
    d_results_from_multiprocessing = dict()
    for i_op_category in l_categories_to_process:

        op_category_to_process = l_categories[i_op_category]

        l_pattern_file_extensions = [pattern_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                   id_cc_version=id_customer_cone_algo_dataset,
                                                                   lbl_class=op_category_to_process)]

        l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                          flowfiles_basedir,
                                                                                          l_pattern_file_extensions)

        print "---Started multiprocessing: overall IXP members presence into the distinct categories."
        mp = mpPool.MultiprocessingPool(n_cores_to_use)
        results = mp.get_results_map_multiprocessing(do_check_members_presence_into_traffic_categories, l_filenames_to_process)

        # save all results per traffic Category to after processing all categories desired, do a post processing
        # putting all together in one mapping file.
        d_results_from_multiprocessing[op_category_to_process] = results

    print "---Started post-processing: group results from the distinct categories."
    d_agg_map_binary_view_members_presence, \
    d_agg_map_aggcount_view_of_members_presence = post_processing_overall_stats_5min_results(d_results_from_multiprocessing)

    print "---Saving results of flow classification pipeline run: ", tw_start, " to ", tw_end

    results_filename_pattern = "ixpmembers-presence-categories.{timestamp}.ipv={ip_version}.svln={filter_svln}.idcc={id_ccversion}.ixp="
    results_filename = results_filename_pattern.format(timestamp=parsed_args.time_window_op,
                                                       ip_version=filter_ip_version,
                                                       filter_svln=filter_svln,
                                                       id_ccversion=id_customer_cone_algo_dataset)

    d_agg_map_binary_view_output, \
    d_agg_map_aggcount_view_output = convert_object_to_commondata_types_to_save(d_agg_map_binary_view_members_presence,
                                               d_agg_map_aggcount_view_of_members_presence)

    save_results_to_jsonfile(d_agg_map_binary_view_output,
                             d_agg_map_aggcount_view_output,
                             base_tmp_dir, results_filename, cons.ID_IXP_BR1)

    end = timer()
    print "---Total execution time: {} seconds".format(end - start)

    print "---Sending e-mail notification about the execution status:"
    notifutil.send_notification_end_of_execution(sys.argv, sys.argv[0], start, end)
