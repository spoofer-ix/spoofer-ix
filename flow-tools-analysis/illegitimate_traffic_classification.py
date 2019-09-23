#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import multiprocessing as mp
import utils.time_utilities as tutil
import utils.prefixes_utilities as putil
import utils.aggregation_utilities as autil
import utils.fileparsing_utilities as fputil
import utils.cmdline_interface_utilities as cmdutil
import utils.constants as cons
import utils.notification_utilities as notifutil
import utils.ixp_members_mappings_utilities as ixp_member_util
import utils.siblings_mapbr_dataset_utilities as siblingsmapixp
import argparse
import sys
from json import dump, load
import traceback
import ast
import datetime
from operator import add
import jsonlines
import gzip
import bz2
import pyasn
from timeit import default_timer as timer


"""
---------------------------------------ABOUT----------------------------------------
Implements the proposed Spoofer-IX methodology: traffic classification pipeline.
------------------------------------------------------------------------------------
"""


def do_traffic_classification(list_of_files, max_concurrent_jobs):
    """
    Manage the filtering of multiple files asynchronously in parallel.
    :param list_of_files:
    :param max_concurrent_jobs:
    :return:
    """
    # Create a pool of workers equaling cores on the machine
    pool = mp.Pool(processes=max_concurrent_jobs, maxtasksperchild=1)
    result = pool.imap(do_filter_illegitimate_traffic, list_of_files, chunksize=1)

    # Close the pool
    pool.close()

    # Combine the results of the workers
    pool.join()

    return result


def get_unassigned_prefixes_list_teamcrymu_by_timewindow(p_filename, p_ip_proto_version):
    """
    Get the file that contains the unassigned prefixes list to load for traffic classification.
    Given the file name, extract the timestamp and check which must be the file with the unassigned prefixes to load.
    """
    fl_ts_fields = fputil.extract_timestamp_from_flowfilepath(p_filename)

    if fl_ts_fields is not None:
        ts_hour_min_flow = datetime.time(fl_ts_fields.hour, fl_ts_fields.minute)

        file_to_read_str = "{unassignedprefixes_dir}fullbogons-ipv{version}.{year}{month:02d}{day:02d}{hour}{minute}.txt.gz"
        # fullbogons-ipv6.201705012000.txt.gz
        # nfcapd.201705310000.avro

        # 00:00 to 04:00
        if tutil.time_in_range(datetime.time(00,00), datetime.time(03,59), ts_hour_min_flow):
            p_hour = "00"

        # 04:00 to 08:00
        elif tutil.time_in_range(datetime.time(04,00), datetime.time(07,59), ts_hour_min_flow):
            p_hour = "04"

        # 08:00 to 12:00
        elif tutil.time_in_range(datetime.time(8,00), datetime.time(11,59), ts_hour_min_flow):
            p_hour = "08"

        # 12:00 to 16:00
        elif tutil.time_in_range(datetime.time(12,00), datetime.time(15,59), ts_hour_min_flow):
            p_hour = "12"

        # 16:00 to 20:00
        elif tutil.time_in_range(datetime.time(16,00), datetime.time(19,59), ts_hour_min_flow):
            p_hour = "16"

        # 20:00 to 00:00
        elif tutil.time_in_range(datetime.time(20,00), datetime.time(23,59), ts_hour_min_flow):
            p_hour = "20"

        id_fpath_unassigned_prefixes = datetime.datetime(fl_ts_fields.year, fl_ts_fields.month, fl_ts_fields.day, int(p_hour), 00)
        fpath_unassigned_prefixes = file_to_read_str.format(unassignedprefixes_dir=cons.DEFAULT_UNASSIGNED_BASEDIR,
                                                          version=p_ip_proto_version,
                                                          month=fl_ts_fields.month, day=fl_ts_fields.day,
                                                          year=fl_ts_fields.year, hour=p_hour, minute="00")

        return id_fpath_unassigned_prefixes, fpath_unassigned_prefixes

    else:
        print("Error: trying to extract timestamp from flow filepath.")
        exit(1)


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


def getpath_to_dataset_ITDK_iifaces_stray_traffic_by_timewindow(p_tw_start):
    """
    Get path to related dataset to routers interfaces extracted with CAIDA ITDK.
    :return:
    """
    str_key = str(p_tw_start.year)

    if str_key in cons.DEFAULT_ROUTER_PREFIXES_CAIDA_ITDK:
        path_to_file = cons.DEFAULT_ROUTER_PREFIXES_CAIDA_ITDK[str_key]
    else:
        path_to_file = ""
        print "> ERROR: fail to load ITDK dataset file; key: {} - path: {}".format(str_key, path_to_file)
        exit(1)

    return path_to_file


def build_dict_unassigned_radixtrees(p_list_flowfilepath_to_process, p_ip_proto_version):
    """
    Prepare (create optimized object to memory) dict with the radixtrees to be ready to perform classification by
    multiprocessing multiple files simultaneously.
    :param p_list_flowfilepath_to_process:
    :param p_ip_proto_version:
    :return:
    """
    # format: [datetime_id_of_fullbogons_file] = radixtree_object_in_memory
    d_unassigned_prefixes_finder = dict()

    for flowfilepath in p_list_flowfilepath_to_process:
        id_fpath_unassigned_prefixes, fpath_unassigned_prefixes = get_unassigned_prefixes_list_teamcrymu_by_timewindow(flowfilepath, p_ip_proto_version)

        if id_fpath_unassigned_prefixes not in d_unassigned_prefixes_finder:
            d_unassigned_prefixes_finder[id_fpath_unassigned_prefixes] = create_unassigned_radixtree(fpath_unassigned_prefixes, p_ip_proto_version)

    return d_unassigned_prefixes_finder


def create_unassigned_radixtree(p_unassigned_filepath, p_ip_proto_version):
    """
    Create the radixtree with unassigned prefixes exclusively (remove the bogon prefixes from the radixtree).
    :param p_unassigned_filepath:
    :param p_ip_proto_version:
    :return:
    """
    unassigned_prefixes_finder = putil.gen_radixtree_from_file(p_unassigned_filepath)
    only_unassigned_prefixes_finder = putil.remove_bogon_prefixes_from_fullbogons_radixtree(unassigned_prefixes_finder,
                                                                                          p_ip_proto_version)
    return only_unassigned_prefixes_finder


def do_filter_illegitimate_traffic(fn_input):
    """
    Execute the filtering process for each input traffic flow input file (AVRO format)
    :param fn_input:
    :return:
    """
    try:
        reader = fputil.get_flowrecords_from_flowdata_file(fn_input)

        # Bogon, unassigned, Out-of-cone classes all together
        if parsed_args.classification_class == 3:
            id_unassigned_radixtree, fpath = get_unassigned_prefixes_list_teamcrymu_by_timewindow(fn_input, filter_ip_version)
            unassigned_prefixes_finder = d_global_unassigned_prefixes_finder[id_unassigned_radixtree]

            d_aggregated_flows, \
            d_prefixes_matchs, \
            d_count_unknown_macadd, \
            l_d_breakdown_unverifiable_traffic,\
            l_d_record_status_inferred_asrel, \
            l_p2c_flow_validation_stats, \
            l_d_record_status_p2c_asrels_matches = autil.aggregate_classify_illegitimate_full(
                                                                       reader,
                                                                       bogon_prefixes_finder,
                                                                       unassigned_prefixes_finder,
                                                                       d_mapping_macaddress_member_asn,
                                                                       d_mac2asn_alldata,
                                                                       d_global_members_as_specific_prefixes_finder,
                                                                       d_global_members_as_specific_ppdcases_finder,
                                                                       f_global_asndb_routeviews,
                                                                       d_global_ixps_cfs_known,
                                                                       d_global_sibling_ases_mapixp,
                                                                       global_ixp_lan_prefixes_finder,
                                                                       d_global_cdns_known,
                                                                       global_router_prefixes_finder,
                                                                       global_set_of_filters_unverifiable_traffic,
                                                                       gen_intermediate_flowfiles_bycategories,
                                                                       fn_input,
                                                                       id_customer_cone_algo_dataset,
                                                                       log_inferred_asrel,
                                                                       log_p2c_flow_matches,
                                                                       l_stats=["ibyt", "ipkt"],
                                                                       d_filters=d_filter_to_apply)

        d_results_filtering = dict()
        d_results_unverifiable_breakdown = dict()
        d_results_status_inferred_asrels = dict()
        d_results_p2c_flow_validation_stats = dict()
        d_results_status_p2c_asrels_matches = dict()

        n_unverifiable_bytes = 0
        n_out_of_cone_bytes = 0
        n_unassigned_bytes = 0
        n_bogon_bytes = 0
        n_regular_incone_bytes = 0

        n_unclassifiable_packets = 0
        n_out_of_cone_packets = 0
        n_unassigned_packets = 0
        n_bogon_packets = 0
        n_regular_incone_packets = 0

        for k in d_aggregated_flows:
            # fl indicates the number of times the flow occured
            # l_fields = ["fl", cons.LABEL_BOGON_ID_CLASS, "ibyt", "ipkt", "td", "ts", "te"]
            # print autil.str_flow_record(d_aggregated_flows[k], l_fields)

            # All classes together
            if parsed_args.classification_class == 3:
                if d_aggregated_flows[k][cons.LABEL_BOGON_ID_CLASS]:
                    n_bogon_bytes = d_aggregated_flows[k]['ibyt']
                    n_bogon_packets = d_aggregated_flows[k]['ipkt']

                elif d_aggregated_flows[k][cons.LABEL_UNASSIGNED_ID_CLASS]:
                    n_unassigned_bytes = d_aggregated_flows[k]['ibyt']
                    n_unassigned_packets = d_aggregated_flows[k]['ipkt']

                elif d_aggregated_flows[k][cons.LABEL_AS_SPECIFIC_ID_CLASS]:
                    n_out_of_cone_bytes = d_aggregated_flows[k]['ibyt']
                    n_out_of_cone_packets = d_aggregated_flows[k]['ipkt']

                elif d_aggregated_flows[k][cons.LABEL_UNVERIFIABLE_ID_CLASS]:
                    n_unverifiable_bytes = d_aggregated_flows[k]['ibyt']
                    n_unclassifiable_packets = d_aggregated_flows[k]['ipkt']

                elif (not d_aggregated_flows[k][cons.LABEL_BOGON_ID_CLASS]) and \
                        (not d_aggregated_flows[k][cons.LABEL_UNASSIGNED_ID_CLASS]) and \
                        (not d_aggregated_flows[k][cons.LABEL_AS_SPECIFIC_ID_CLASS]) and \
                        (not d_aggregated_flows[k][cons.LABEL_UNVERIFIABLE_ID_CLASS]):
                    n_regular_incone_bytes = d_aggregated_flows[k]['ibyt']
                    n_regular_incone_packets = d_aggregated_flows[k]['ipkt']

                # ======= compute some initial statistics ========

                # percentage of each category over the total traffic recorded
                v_total_traffic = n_regular_incone_bytes + n_bogon_bytes + n_unassigned_bytes + n_out_of_cone_bytes + n_unverifiable_bytes
                v_percentage_regular_incone_traffic = round(float(n_regular_incone_bytes * 100.0 / v_total_traffic), 5)
                v_percentage_bogon_traffic = round(float(n_bogon_bytes * 100.0 / v_total_traffic), 5)
                v_percentage_unassigned_traffic = round(float(n_unassigned_bytes * 100.0 / v_total_traffic), 5)
                v_percentage_outofcone_traffic = round(float(n_out_of_cone_bytes * 100.0 / v_total_traffic), 5)
                v_percentage_unverifiable_traffic = round(float(n_unverifiable_bytes * 100.0 / v_total_traffic), 5)

        s_timestamp_label_key = str(fputil.extract_timestamp_from_flowfilepath(fn_input))

        # All classes together
        if parsed_args.classification_class == 3:
            d_results_filtering[s_timestamp_label_key] = \
                [n_regular_incone_bytes, n_bogon_bytes, n_unassigned_bytes, n_out_of_cone_bytes, n_unverifiable_bytes,
                 n_regular_incone_packets, n_bogon_packets, n_unassigned_packets, n_out_of_cone_packets, n_unclassifiable_packets,
                 v_percentage_regular_incone_traffic, v_percentage_bogon_traffic, v_percentage_unassigned_traffic,
                 v_percentage_outofcone_traffic, v_percentage_unverifiable_traffic]

            # add timestamp 5-min bin results -- unverifiable breakdown
            d_results_unverifiable_breakdown[s_timestamp_label_key] = l_d_breakdown_unverifiable_traffic

            # add timestamp 5-min bin results -- inferred vs no-inferred AS-rel
            if log_inferred_asrel:
                d_results_status_inferred_asrels[s_timestamp_label_key] = l_d_record_status_inferred_asrel

            # add timestamp 5-min bin results -- P2C matched AS-rels traffic stats and as-rel counts
            if log_p2c_flow_matches:
                d_results_p2c_flow_validation_stats[s_timestamp_label_key] = l_p2c_flow_validation_stats
                d_results_status_p2c_asrels_matches[s_timestamp_label_key] = l_d_record_status_p2c_asrels_matches

        del reader
        del d_aggregated_flows
        # Print the info
        # print('Results {}'.format(d_results_filtering))
        return [d_results_filtering, d_prefixes_matchs, d_count_unknown_macadd,
                d_results_unverifiable_breakdown, d_results_status_inferred_asrels,
                d_results_p2c_flow_validation_stats, d_results_status_p2c_asrels_matches]

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


def post_processing_aggregate_results(l_d_classification_results, log_inferred_asrel, log_p2c_flow_matches):
    """
    Post processing results obtained from multi-processing flow classification.
    :param l_d_classification_results: list of results organized in dictionaries
    :return:
    """
    # create output dict with all the results
    d_output_flow_traffic_info = dict()
    d_output_matched_prefixes = dict()
    d_output_unknown_macaddress = dict()
    d_output_unverifiable_breakdown = dict()
    d_output_status_inferred_asrels = dict()
    d_output_p2c_flow_validation_stats = dict()
    d_output_status_p2c_asrels_matches = dict()

    # prepare seven dictionaries as output
    for dict_result in l_d_classification_results:

        # prepare aggregated flow statistics computed from traffic classification pipeline
        for k, v in dict_result[0].items():
            d_output_flow_traffic_info[k] = v

        # aggregate and prepare prefixesmatch to be saved
        for k, v in dict_result[1].items():
            if k not in d_output_matched_prefixes:
                d_output_matched_prefixes[k] = v
            else:
                d_output_matched_prefixes[k] = map(add, d_output_matched_prefixes[k], v)

        # aggregate and prepare unknown macaddress to be saved
        for k, v in dict_result[2].items():
            if k not in d_output_unknown_macaddress:
                d_output_unknown_macaddress[k] = v
            else:
                d_output_unknown_macaddress[k] = map(add, d_output_unknown_macaddress[k], v)

        # unverifiable flow stats breakdown
        for k, v in dict_result[3].items():
            d_output_unverifiable_breakdown[k] = v.get_breakdown_list_dict_results()

        # as-relationship inferred vs no-inferred
        if log_inferred_asrel:
            for k, v in dict_result[4].items():
                d_output_status_inferred_asrels[k] = v.get_listdict_asrelationship_inference_analysis()

        # add timestamp 5-min bin results -- P2C matched AS-rels traffic stats and as-rel counts
        if log_p2c_flow_matches:
            for k, v in dict_result[5].items():
                d_output_p2c_flow_validation_stats[k] = v

            for k, v in dict_result[6].items():
                d_output_status_p2c_asrels_matches[k] = v.get_listdict_asrelationship_inference_analysis()

    # compute more statistics and add to the end of the list for each timestamp
    for k, stats in d_output_flow_traffic_info.items():
        n_regular_incone_bytes = stats[0]
        n_bogon_bytes = stats[1]
        n_unassigned_bytes = stats[2]
        n_out_of_cone_bytes = stats[3]

        n_total_traffic_classifiable = n_regular_incone_bytes + n_bogon_bytes + n_unassigned_bytes + n_out_of_cone_bytes
        v_percentage_regular_incone_over_total_traffic = round(float(n_regular_incone_bytes * 100.0 / n_total_traffic_classifiable), 5)
        v_percentage_bogon_over_regular_traffic = round(float(n_bogon_bytes * 100.0 / n_regular_incone_bytes), 5) if n_regular_incone_bytes > 0 else 0
        v_percentage_unassigned_over_regular_traffic = round(float(n_unassigned_bytes * 100.0 / n_regular_incone_bytes), 5) if n_regular_incone_bytes > 0 else 0
        v_percentage_outofcone_over_regular_traffic = round(float(n_out_of_cone_bytes * 100.0 / n_regular_incone_bytes), 5) if n_regular_incone_bytes > 0 else 0

        d_output_flow_traffic_info[k].append(v_percentage_regular_incone_over_total_traffic)
        d_output_flow_traffic_info[k].append(v_percentage_bogon_over_regular_traffic)
        d_output_flow_traffic_info[k].append(v_percentage_unassigned_over_regular_traffic)
        d_output_flow_traffic_info[k].append(v_percentage_outofcone_over_regular_traffic)

    return d_output_flow_traffic_info, d_output_matched_prefixes, d_output_unknown_macaddress, \
           d_output_unverifiable_breakdown, d_output_status_inferred_asrels, \
           d_output_p2c_flow_validation_stats, d_output_status_p2c_asrels_matches


def save_results_to_jsonfile(d_output_flow_traffic_info, d_output_matched_prefixes,
                             d_output_unknown_macaddress, d_output_unverifiable_breakdown,
                             d_output_status_inferred_asrels,
                             d_output_p2c_flow_validation_stats, d_output_status_p2c_asrels_matches,
                             p_dest_filepath, p_file_name, log_inferred_asrel, log_p2c_flow_matches,
                             set_of_filters_unverifiable_traffic,
                             p_location_id):
    """
    Export the results to a json file.
    :param d_output_matched_prefixes:
    :param d_output_flow_traffic_info:
    :param p_results:
    :param p_dest_filepath:
    :param p_file_name:
    :param set_of_filters_unverifiable_traffic, pattern = [IXP/CF, P2C-INGRESS-EGRESS, STRAY-TRAFFIC, CDNs]
    :param p_location_id:
    :return:
    """

    fn_output_flow_info_pattern = "{file_dest_dir}{file_name}{location_id}.asnfilter={filter_set}.json.gz"
    fn_output_prefixes_matched_info_pattern = "{file_dest_dir}{file_name}{location_id}.asnfilter={filter_set}.prefixmatch.txt.gz"
    fn_output_unknown_macaddress_info_pattern = "{file_dest_dir}{file_name}{location_id}.asnfilter={filter_set}.unknownmac.txt.gz"
    fn_output_unverifiable_breakdown_info_pattern = "{file_dest_dir}{file_name}{location_id}.asnfilter={filter_set}.unverfiablebreakdown.json.gz"
    fn_output_status_inferred_asrels_info_pattern = "{file_dest_dir}{file_name}{location_id}.asnfilter={filter_set}.status_asrels.json.gz"
    fn_output_status_inferred_p2c_flowstats_info_pattern = "{file_dest_dir}{file_name}{location_id}.asnfilter={filter_set}.p2cmatch_flowstats.json.gz"
    fn_output_status_inferred_p2c_asrels_count_info_pattern = "{file_dest_dir}{file_name}{location_id}.asnfilter={filter_set}.p2cmatch_asrelscount.json.gz"

    filterset_values = "-".join(str(e) for e in set_of_filters_unverifiable_traffic)
    fn_output_flow_info = fn_output_flow_info_pattern.format(file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             location_id=p_location_id,
                                                             filter_set=filterset_values)
    fn_output_prefix_matches = fn_output_prefixes_matched_info_pattern.format(file_dest_dir=p_dest_filepath,
                                                                              file_name=p_file_name,
                                                                              location_id=p_location_id,
                                                                              filter_set=filterset_values)
    fn_output_unknown_macaddress = fn_output_unknown_macaddress_info_pattern.format(file_dest_dir=p_dest_filepath,
                                                                                    file_name=p_file_name,
                                                                                    location_id=p_location_id,
                                                                                    filter_set=filterset_values)
    fn_output_unverifiable_breakdown = fn_output_unverifiable_breakdown_info_pattern.format(
                                                             file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             location_id=p_location_id,
                                                             filter_set=filterset_values)
    fn_output_status_inferred_asrels = fn_output_status_inferred_asrels_info_pattern.format(
                                                             file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             location_id=p_location_id,
                                                             filter_set=filterset_values)

    fn_output_status_inferred_p2c_flowstats = fn_output_status_inferred_p2c_flowstats_info_pattern.format(
                                                             file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             location_id=p_location_id,
                                                             filter_set=filterset_values)
    fn_output_status_inferred_p2c_asrels_count = fn_output_status_inferred_p2c_asrels_count_info_pattern.format(
                                                             file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             location_id=p_location_id,
                                                             filter_set=filterset_values)

    # write dict result with flow traffic info to a json file
    with gzip.open(fn_output_flow_info, 'wb') as f:
        dump(d_output_flow_traffic_info, f, sort_keys=True)
    f.close()

    # write dict result with unverifiable breakdown info to a json file
    with gzip.open(fn_output_unverifiable_breakdown, 'wb') as f:
        dump(d_output_unverifiable_breakdown, f, sort_keys=True)
    f.close()

    # write dict result with AS-Relationship status to a json file
    if log_inferred_asrel:
        with gzip.open(fn_output_status_inferred_asrels, 'wb') as f:
            dump({x: repr(y) for x, y in d_output_status_inferred_asrels.items()}, f, sort_keys=True)
        f.close()

    # write dict result with P2C flow matches statistics and P2C AS-Rels count to a json file
    if log_p2c_flow_matches:
        with gzip.open(fn_output_status_inferred_p2c_flowstats, 'wb') as f:
            dump(d_output_p2c_flow_validation_stats, f, sort_keys=True)
        f.close()

        with gzip.open(fn_output_status_inferred_p2c_asrels_count, 'wb') as f:
            dump({x: repr(y) for x, y in d_output_status_p2c_asrels_matches.items()}, f, sort_keys=True)
        f.close()

    # write dict result with matched prefixes info to a txt file
    with gzip.open(fn_output_prefix_matches, 'wb') as f:
        for k, v in d_output_matched_prefixes.iteritems():
            if isinstance(k, int):
                k_values = "{}".format(str(k))
            elif isinstance(k, tuple):
                k_values = ";".join(str(e) for e in k)

            v_values = ";".join(str(e) for e in v)

            f.write("".join("{};{}".format(k_values, v_values) + "\n"))
    f.close()

    # order mac address by bytes volume desc and write dict result to log file
    sorted_d_unknown_macaddress = sorted(d_output_unknown_macaddress.items(), key=lambda (k, v): v[1], reverse=True)
    with gzip.open(fn_output_unknown_macaddress, 'wb') as f:
        for record in sorted_d_unknown_macaddress:
            k_values = ";".join(str(e) for e in record[0])
            v_values = ";".join(str(e) for e in record[1])

            f.write("".join("{};{}".format(k_values, v_values) + "\n"))
    f.close()


def load_ixp_lan_prefixes_peeringdb_data(fn_ixp_lan_prefixes):
    """
    Load IXP LAN prefixes from PeeringDB.
    """

    s_output_prefixes_ixps = set()

    with gzip.open(fn_ixp_lan_prefixes, 'rb') as results_data:
        d_ixp_lan_prefixes = load(results_data)

    for k_id, d_data in d_ixp_lan_prefixes.items():
        if 'IPv4' in d_data:
            l_prefixes_v4 = d_data['IPv4']
            for s_prefix in l_prefixes_v4:
                s_output_prefixes_ixps.add(str(s_prefix))

    return s_output_prefixes_ixps


def build_dict_mapping_known_ases_types_crafted(fn_mapping_input_jsonl):
    """
    Build the mapping dict cache to retrive the ASN given a specific Mac Address to lookup.
    :return:
    """

    d_ases_known = dict()
    with jsonlines.open(fn_mapping_input_jsonl) as reader:
        for obj in reader:
            asn = int(obj['asn'])
            asname = obj['asname']
            asn_type = obj['type']

            if asn not in d_ases_known:
                d_ases_known[asn] = [asname, asn_type]

    return d_ases_known


def build_dict_as_specific_radixtrees_per_member(p_path_to_cone_prefixes_dataset):
    """
    Build the dict with the key being the members ASNs and the value a RadixTree with all his Customer Cone Prefixes.
    :param p_tw_start: used to identify the key at the system configuration file.
    :param id_customercone_algo: used to identify the methodology used to build the dataset.
    :param path_to_cone_dataset: in case the user defined a specific external dataset to use load this one over
    the one configured at the system.
    :return:
    """

    path_to_file = p_path_to_cone_prefixes_dataset

    print "Cones prefix dataset: {}".format(path_to_file)

    if path_to_file.lower().endswith('.txt'):   # customer cone datasets
        f = open(path_to_file)
    elif path_to_file.lower().endswith('.gz'):
        f = gzip.open(path_to_file, 'rb')
    elif path_to_file.lower().endswith('.bz2'):
        f = bz2.BZ2File(path_to_file, "r")

    d_members_as_specific_prefixes_finder = dict()
    for line in f:
        lf = line.strip().split(" ")
        if len(lf) >= 2:
            asn = int(lf[0])
            data_cone = lf[1:]

            # create a radix tree to each member
            if asn not in d_members_as_specific_prefixes_finder:
                d_members_as_specific_prefixes_finder[asn] = putil.gen_radixtree_from_list(data_cone)

    return d_members_as_specific_prefixes_finder


def build_dict_as_specific_ppdcases_per_member(p_path_to_cone_ases_dataset):
    """
    Build a dict with the key being the member ASN and the value a set of the ASNs belonging to its customer cone.
    """

    path_to_file = p_path_to_cone_ases_dataset

    print "Cones ASes dataset: {}".format(path_to_file)

    if path_to_file.lower().endswith('.txt'):   # customer cone datasets
        f = open(path_to_file)
    elif path_to_file.lower().endswith('.gz'):  # full cone datasets
        f = gzip.open(path_to_file, 'rb')
    elif path_to_file.lower().endswith('.bz2'):
        f = bz2.BZ2File(path_to_file, "r")

    d_members_as_cc_ppdcases_finder = dict()
    for line in f:
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


def load_remote_peering_vlan_ids(d_fpaths_by_period):
    """
    Load VLAN ids which identify remote peering interconnections.
    """
    d_output = dict()

    for k_period, v_path in d_fpaths_by_period.iteritems():

        f = open(v_path)
        if k_period not in d_output:
            d_output[k_period] = set(map(int, f.read().strip().splitlines()))

    return d_output

# ----------------------------------------------------------------------------------
#                              DEFAULT CONFIGURATION
# ----------------------------------------------------------------------------------
N_JOBS = mp.cpu_count() - 1  # definition of how many cpus will be in use for the task

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

    parser.add_argument('-s', dest='schema_file_name',
                        help="Path and schema file name to process .avro files")

    parser.add_argument('-np', dest='number_concur_process',
                        help="Number of concurrent process to execute")

    parser.add_argument('-filter', dest='flow_filter', required=True,
                        help="Filter to apply over each flow file read"
                             "Syntax: as string {'ip': 4, 'svln': 10} ")

    parser.add_argument('-gcf', dest='gen_categ_trafficdata_files', type=int, choices=[0, 1], required=True,
                        help="Generate the categories flow traffic data files during classification process. "
                             "Options: 1 - yes or 0 - no")

    parser.add_argument('-fut', dest='filter_unverifiable_traffic', required=True,
                        help="Define the set of filters to be applied to isolate the unverifiable traffic. "
                             "Syntax: '[CF, IXP, P2C-INGRESS-EGRESS, STRAY-TRAFFIC, CDNs, BILATERAL-VLANS, TRANSIT-PROVIDER, SIBLING-TO-SIBLING]' "
                             "  e.g.: '[1, 1, 1, 1, 0, 1, 1, 1]' ")

    parser.add_argument('-c', dest='classification_class', type=int, choices=[0, 1, 2, 3], required=True, default=3,
                        help="Define which classes must be evaluated during the classification processing. "
                             "Options: "
                             "0 - Bogon; "
                             "1 - Unassigned; "
                             "2 - Out-of-cone;"
                             "3 - all together.")

    parser.add_argument('-ccid', dest='customercone_algoid', type=int, choices=[1, 2, 3, 4, 8], required=True,
                        help="Options: "
                             "1 - IMC-2013 Customer Cone"
                             "2 - IMC-2013 CC Siblings "
                             "3 - IMC-2013 CC Recursive "
                             "4 - IMC17 FullCone "
                             "8 - CoNEXT19 Prefix-Level Customer Cone.")

    parser.add_argument('-logasrelinferred', dest='log_inferred_asrel', default=False, required=False,
                        help="Count inferred and no-inferred AS-Relationships based on flow data Ingress/Egress ASes"
                             "and the results from the datasets generated by AS-Rel algorithm [Spoofer-IX only, since"
                             "IMC17-Full Cone does not distinguish as-relationship types]."
                             "Options: "
                             "1 - enable (generate log file)"
                             "0 - disable (do not generate log file")

    parser.add_argument('-logp2cmatches', dest='log_p2c_flow_matches', default=False, required=False,
                        help="Count inferred and no-inferred Provider-to-Customer AS-Relationships based on flow SRC-IP"
                             "matches and accumulate [bytes, packets] that match and not match cone Provider"
                             "Options: "
                             "1 - enable (generate log file)"
                             "0 - disable (do not generate log file")

    parser.add_argument('-coneases', dest='fp_cone_ases', required=False,
                        help="Define the path to the dataset of cone ASes that "
                             "should be loaded to classify the traffic.")

    parser.add_argument('-coneprefix', dest='fp_cone_prefixes', required=False,
                        help="Define the path to the dataset of cone prefixes that "
                             "should be loaded to classify the traffic.")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    # set up of variables to generate flow file names
    if parsed_args.time_window_op:
        tw_start, tw_end = cmdutil.get_timewindow_to_process(parsed_args.time_window_op)

    # avro schema filepath
    if parsed_args.schema_file_name:
        fn_schema = parsed_args.schema_file_name
    else:
        fn_schema = cons.DEFAULT_AVRO_NFCAP_FLOWS_SCHEMA_FILEPATH

    # number of concurrent process (performance control)
    if parsed_args.number_concur_process:
        n_cores_to_use = int(parsed_args.number_concur_process)
    else:
        n_cores_to_use = int(N_JOBS)

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
        # # (TCP, TCF, UDP, ICMP)
        # d_filter_to_apply['pr'] = (6, 87, 17, 1)

        print "Flow filters activated: {}".format(d_filter_to_apply)

    # Control to indicate when we want to filter and isolate the unverifiable traffic
    # pattern = [CF, IXP, P2C-INGRESS-EGRESS, STRAY-TRAFFIC, CDNs, BILATERAL-VLANS, TRANSIT-PROVIDER, SIBLING-TO-SIBLING]
    if parsed_args.filter_unverifiable_traffic:
        global_set_of_filters_unverifiable_traffic = ast.literal_eval(parsed_args.filter_unverifiable_traffic)

        print "Activated traffic filters: {}".format(global_set_of_filters_unverifiable_traffic)
        # Strict checking on param input to ensure correct execution
        if len(global_set_of_filters_unverifiable_traffic) < 8:
            print "ERROR: parsed_args.filter_unverifiable_traffic does not have all options defined, please revise it!"
            exit(1)

    if int(parsed_args.log_inferred_asrel):
        log_inferred_asrel = True
    else:
        log_inferred_asrel = False

    if int(parsed_args.log_p2c_flow_matches):
        log_p2c_flow_matches = True
    else:
        log_p2c_flow_matches = False

    id_customer_cone_algo_dataset = parsed_args.customercone_algoid
    path_to_cone_ases_dataset = parsed_args.fp_cone_ases
    path_to_cone_prefixes_dataset = parsed_args.fp_cone_prefixes

    gen_intermediate_flowfiles_bycategories = parsed_args.gen_categ_trafficdata_files

    # ------------------------------------------------------------------
    #   Filtering logic processes start
    # ------------------------------------------------------------------
    start = timer()

    print "---Creating list of files for processing (5-min flow files):"
    l_filenames_to_process = cmdutil.generate_flow_filenames_to_process(tw_start, tw_end, flowfiles_basedir, ".avro")

    # Classification: all classes
    if parsed_args.classification_class == 3:

        print "---Creating radixtree of bogon prefixes classification:"
        # ip protocol version to set the file to load the prefixes
        bogon_prefixes_finder = ""
        if filter_ip_version == 4:
            bogon_prefixes_finder = putil.gen_radixtree_from_file(cons.DEFAULT_MARTIANS_BOGONS_FILEPATH_V4)
        elif filter_ip_version == 6:
            bogon_prefixes_finder = putil.gen_radixtree_from_file(cons.DEFAULT_MARTIANS_BOGONS_FILEPATH_V6)

        print "---Creating dict of radixtree objets for unassigned prefixes classification..."
        d_global_unassigned_prefixes_finder = build_dict_unassigned_radixtrees(l_filenames_to_process, filter_ip_version)

        d_mapping_macaddress_member_asn = ixp_member_util.build_dict_mapping_macaddress_members_asns(cons.DEFAULT_MACADDRESS_ASN_MAPPING)
        d_mac2asn_alldata = ixp_member_util.load_alldata_dict_mapping_macaddress_members_asns(cons.DEFAULT_MACADDRESS_ASN_MAPPING)

        print "---Creating dict of ASes Customer Cones (ppdc-prefix) for Out-of-cone classification..."
        d_global_members_as_specific_prefixes_finder = build_dict_as_specific_radixtrees_per_member(path_to_cone_prefixes_dataset)

        print "---Creating dict of ASes Customer Cones (ppdc-ases) for Out-of-cone classification..."
        d_global_members_as_specific_ppdcases_finder = build_dict_as_specific_ppdcases_per_member(path_to_cone_ases_dataset)

        print "---Creating dict of know ASes types for Out-of-cone classification isolation..."
        # CF filter
        d_global_ixps_cfs_known = build_dict_mapping_known_ases_types_crafted(cons.DEFAULT_IXPS_CFS_CRAFTED_MAPPING)
        if global_set_of_filters_unverifiable_traffic[0] == 1:
            d_global_cdns_known = build_dict_mapping_known_ases_types_crafted(cons.DEFAULT_CDNS_CRAFTED_MAPPING)
        # filter is not active
        else:
            d_global_cdns_known = 0

        # IXP filter
        if global_set_of_filters_unverifiable_traffic[1] == 1:
            l_ixp_lan_prefixes_peeringdb = list(load_ixp_lan_prefixes_peeringdb_data(cons.DEFAULT_IXPS_LAN_PREFIXES_PEERINGDB_MAPPING))
            global_ixp_lan_prefixes_finder = putil.gen_radixtree_from_list(l_ixp_lan_prefixes_peeringdb)
        # filter is not active
        else:
            global_ixp_lan_prefixes_finder = 0

        # SIBLING TO SIBLING MAPPING DATASET LOAD
        print "Loading the unified Siblings mapping dataset: {} + {}".format(cons.DEFAULT_BRAZIL_SIBLING_ASES_MAPPING,
                                                                            cons.DEFAULT_AS2ORG_CAIDA_MAPPING[str(tw_start.year)])
        d_global_sibling_ases_mapixp = siblingsmapixp.build_dict_mapping_caidaas2org_with_local_siblings(str(tw_start.year))

        # REMOTE PEERING VLANs MAPPING LOAD
        print "Loading the Remote Peering VLANs mapping datasets:"
        cons.SET_OF_VLANS_RELATED_TO_REMOTE_PEERING = load_remote_peering_vlan_ids(cons.FPATHS_VLANS_RELATED_TO_REMOTE_PEERING)

        # CAIDA ITDK DATASET LOAD
        print "---Creating radixtree of router prefixes classification for Unverifiable classification isolation..."
        itdk_iifaces_stray_dataset_path = getpath_to_dataset_ITDK_iifaces_stray_traffic_by_timewindow(tw_start)
        print "load into memory data from: {}".format(itdk_iifaces_stray_dataset_path)
        global_router_prefixes_finder = putil.gen_radixtree_from_file(itdk_iifaces_stray_dataset_path)

        print "---Loading Routeviews ip2prefix-asn database file..."
        f_global_asndb_routeviews = load_database_ip2prefixasn_routeviews_by_timewindow(tw_start)

    # Classification: all classes
    if parsed_args.classification_class == 3:
        results_filename_pattern = "Illegitimate.traffic-volume.{timestamp}.ipv={ip_version}.svln={filter_svln}.idcc={id_ccversion}.ixp="

    print "---Started multiprocessing classification of traffic..."
    result = do_traffic_classification(l_filenames_to_process, n_cores_to_use)

    print "---Started post-processing classification results..."
    d_results_flow_traffic_info, \
    d_results_matched_prefixes, \
    d_results_unknown_macaddress, \
    d_results_unverifiable_breakdown,\
    d_results_status_inferred_asrels, \
    d_results_p2c_flow_validation_stats, \
    d_results_status_p2c_asrels_matches = post_processing_aggregate_results(result, log_inferred_asrel, log_p2c_flow_matches)

    print "---Saving results of flow classification pipeline run: ", tw_start, " to ", tw_end
    results_filename = results_filename_pattern.format(timestamp=parsed_args.time_window_op,
                                                       ip_version=filter_ip_version,
                                                       filter_svln=filter_svln,
                                                       id_ccversion=id_customer_cone_algo_dataset)

    save_results_to_jsonfile(d_results_flow_traffic_info,
                             d_results_matched_prefixes,
                             d_results_unknown_macaddress,
                             d_results_unverifiable_breakdown,
                             d_results_status_inferred_asrels,
                             d_results_p2c_flow_validation_stats, d_results_status_p2c_asrels_matches,
                             base_tmp_dir, results_filename, log_inferred_asrel, log_p2c_flow_matches,
                             global_set_of_filters_unverifiable_traffic, cons.ID_IXP_BR1)

    end = timer()
    print "---Total execution time: {} seconds".format(end - start)

    print "---Sending e-mail notification about the execution status:"
    notifutil.send_notification_end_of_execution(sys.argv, sys.argv[0], start, end)
