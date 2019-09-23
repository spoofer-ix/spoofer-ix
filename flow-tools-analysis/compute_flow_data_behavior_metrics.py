#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import utils.constants as cons
import utils.multiprocessing_poll as mpPool
import utils.cmdline_interface_utilities as cmdutil
import utils.notification_utilities as notifutil
import utils.fileparsing_utilities as fputil
import utils.time_utilities as tutil
import utils.format_utilities as fmtutil
import traceback
import gzip
import argparse
import sys
import csv
import re
from copy import deepcopy
import logging
import os
from timeit import default_timer as timer
import ast
from json import dump, load

# reset the task affinity
os.system("taskset -p 0xff %d" % os.getpid())

"""
---------------------------------------ABOUT----------------------------------------
Consumes the transformed and aggregated data exported in 5-min bins to compute
different metrics and generate input files for plots.
------------------------------------------------------------------------------------
"""


class DictResultsPerCategory(object):

    def __init__(self, op_process_categories):

        self.op_to_process_categories = op_process_categories

        if self.op_to_process_categories == 0:
            self.d = {
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 0): dict(),
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 0): dict(),
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 0): dict(),
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 1): dict(),
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 1): dict(),
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 1): dict(),
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 2): dict(),
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 2): dict(),
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 2): dict(),
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 3): dict(),
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 3): dict(),
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 3): dict()
            }
        elif self.op_to_process_categories == 1:
            self.d = {
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 0): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 0): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 0): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 1): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 1): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 1): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 2): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 2): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 2): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, 3): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE, 3): {0: set(), 1: set(), 2: set(), 3: set()},
                         (cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS, 3): {0: set(), 1: set(), 2: set(), 3: set()}
            }


class DictResultsAllTraffic(object):
    """
    The key ids are the identifiers for the sets of values being analyzed and later converted in numbers:
    0 - IPAddresses, 1 - ASN, 2 - bgp prefixes, 3 - countries
    """
    def __init__(self, op_process_categories):

        self.op_to_process_categories = op_process_categories

        if self.op_to_process_categories == 0:
            self.d = {
                        ('all', 0): dict(),
                        ('all', 1): dict(),
                        ('all', 2): dict(),
                        ('all', 3): dict(),
            }
        elif self.op_to_process_categories == 1:
            self.d = {
                        ('all', 0): {0: set(), 1: set(), 2: set(), 3: set()},
                        ('all', 1): {0: set(), 1: set(), 2: set(), 3: set()},
                        ('all', 2): {0: set(), 1: set(), 2: set(), 3: set()},
                        ('all', 3): {0: set(), 1: set(), 2: set(), 3: set()},
            }


def get_records_from_datafile(filename_path_input, op_csv_delimiter):
    """
    Read file using the informed delimiter and return a list of strings by each line.
    :param filename_path_input:
    :param op_csv_delimiter:
    :return:
    """

    if filename_path_input.lower().endswith('.gz'):

        with gzip.open(filename_path_input, "rb") as csvfile:
            reader = csv.reader(csvfile, delimiter=op_csv_delimiter)
            for line in reader:
                yield line


def count_unique_data_points_groupby_point_forall_traffic(reader):
    """
    Process 5-min traffic flow data and execute a breakdown of the data to each different ingress/egress member ASN.

    Files format:
    ".avro.point=egress.ipv=4.svln=all.txt.gz"
    ".avro.point=ingress.ipv=4.svln=all.txt.gz"

        ingress/egress_point;ipAddress;origin_asn;bgp_prefix;country;count_occurrences_ip

    :param reader:
    :return:
    """

    # result dict with unique data per ingress/egress points
    d_flow_info_perpoint = dict()

    # sets to store unique records
    s_ips = set()
    s_asns = set()
    s_bgpprefixes = set()
    s_countries = set()

    # read records from file
    for line in reader:

        # extract values per line
        asn_ie_point = line[0]
        ipaddr = line[1]
        origin_asn = line[2]
        bgp_prefix = line[3]
        country = line[4]

        n_trafficvolume_bytes = float(line[5])
        n_qty_packets = float(line[6])

        # each line at the file is guaranteed to be a unique IP entry per Ingress/Egress point
        s_ips.add(ipaddr)
        s_asns.add(origin_asn)
        s_bgpprefixes.add(bgp_prefix)
        s_countries.add(country)

        # remove None value from countries counting
        try:
            s_countries.remove('None')
        except KeyError:
            pass

        if asn_ie_point in d_flow_info_perpoint:
            d_flow_info_perpoint[asn_ie_point][0].add(ipaddr)                     # s_ips
            d_flow_info_perpoint[asn_ie_point][1].add(origin_asn)                 # s_asns
            d_flow_info_perpoint[asn_ie_point][2].add(bgp_prefix)                 # s_bgpprefixes
            d_flow_info_perpoint[asn_ie_point][3].add(country)                    # s_countries
            d_flow_info_perpoint[asn_ie_point][4] += n_trafficvolume_bytes        # traffic volume
            d_flow_info_perpoint[asn_ie_point][5] += n_qty_packets                # qty packets

        else:
            d_flow_info_perpoint[asn_ie_point] = [set(), set(), set(), set(), 0, 0]
            d_flow_info_perpoint[asn_ie_point][0].add(ipaddr)                     # s_ips
            d_flow_info_perpoint[asn_ie_point][1].add(origin_asn)                 # s_asns
            d_flow_info_perpoint[asn_ie_point][2].add(bgp_prefix)                 # s_bgpprefixes
            d_flow_info_perpoint[asn_ie_point][3].add(country)                    # s_countries
            d_flow_info_perpoint[asn_ie_point][4] = n_trafficvolume_bytes         # traffic volume
            d_flow_info_perpoint[asn_ie_point][5] = n_qty_packets                 # qty packets

    return d_flow_info_perpoint


def count_unique_data_points_forall_traffic(reader):
    """
    Process traffic 5-min traffic flow data.
    Files format:
    ".avro.ip=src.ipv=4.svln=all.txt.gz"
    ".avro.ip=dst.ipv=4.svln=all.txt.gz"

        ipAddress;origin_asn;bgp_prefix;country;count_occurrences_ip

    :param reader: avro reader object
    :return: flow traffic data post-processed
    """

    s_ips = set()
    s_asns = set()
    s_bgpprefixes = set()
    s_countries = set()
    n_trafficvolume_bytes = 0
    n_qty_packets = 0

    for line in reader:
        ipaddr = line[0]
        origin_asn = line[1]
        bgp_prefix = line[2]
        country = line[3]
        n_trafficvolume_bytes += float(line[4])
        n_qty_packets += float(line[5])

        # each line is guaranteed to be a unique IP entry
        s_ips.add(ipaddr)
        s_asns.add(origin_asn)
        s_bgpprefixes.add(bgp_prefix)
        s_countries.add(country)

    # remove None value from countries counting
    try:
        s_countries.remove('None')
    except KeyError:
        pass

    return [s_ips, s_asns, s_bgpprefixes, s_countries, n_trafficvolume_bytes, n_qty_packets]


def do_iplevel_aggregation_analysis(fn_input):
    """
    Multiprocessing call to perform account for unique information and aggregation.
    :param fn_input:
    :return: dict[(fn_name, timestamp)] = list() or dict() depending on the case
    """
    d_results_unique_agg = dict()

    # debug
    # print("{} | agg raw-file: {}".format(multiprocessing.current_process(), fn_input))

    try:
        # check if the file pattern correspond to the ones related to all traffic
        if (pattern_ipsrc in fn_input) or (pattern_ipdst in fn_input):
            reader = get_records_from_datafile(fn_input, ";")
            s_timestamp_label_key = str(fputil.extract_timestamp_from_flowfilepath(fn_input))
            k = (fn_input, s_timestamp_label_key)

            l_unique_flow_info = count_unique_data_points_forall_traffic(reader)
            d_results_unique_agg[k] = l_unique_flow_info

        if is_to_process_data_per_ingress_egress:
            # if file pattern are the ones related to the Ingress/Egress points - start different processing
            if (pattern_ingress in fn_input) or (pattern_egress in fn_input):
                reader = get_records_from_datafile(fn_input, ";")
                s_timestamp_label_key = str(fputil.extract_timestamp_from_flowfilepath(fn_input))
                k = (fn_input, s_timestamp_label_key)

                d_results_flow_info_perpoint = count_unique_data_points_groupby_point_forall_traffic(reader)
                d_results_unique_agg[k] = d_results_flow_info_perpoint

        del reader
        return d_results_unique_agg

    except Exception as e:
        print('Caught exception in worker thread (file = %s):' % fn_input)
        # This prints the type, value, and stack trace of the
        # current exception being handled.
        traceback.print_exc()
        print()
        raise e
    except KeyboardInterrupt:
        # Allow ^C to interrupt from any thread.
        sys.stdout.write('user interrupt\n')


def post_processing_aggregate_results(l_d_classification_results, op_to_process_categories):
    """
    Post processing to aggregate parcial results (reduce operation) from the multiprocessing step.
    :param l_d_classification_results:
    :return:
    """

    # create output dict with all the results
    d_output_ipsrc_alltraf_info = dict()
    d_output_ipdst_alltraf_info = dict()
    d_output_ingress_alltraf_info = dict()
    d_output_egress_alltraf_info = dict()

    fn_class_pattern = re.compile(".class=")

    # prepare four dictionaries as output
    for dict_result in l_d_classification_results:

        # prepare aggregated flow statistics computed from traffic analysis

        for k, v in dict_result.items():
            # get filename to check file extension and process it correctly
            fn_name = dict_result.keys()[0][0]
            s_timestamp = dict_result.keys()[0][1]
            lbl_class = "all"

            # if enabled per category processing save the class name attached to the filenamen 'fn_name'
            if op_to_process_categories == 1:
                result_fnclass_match = fn_class_pattern.search(fn_name)
                if result_fnclass_match is not None:
                    lbl_class = fn_name.split('.')[4].split('=')[1]

            k_post_results = (s_timestamp, lbl_class)
            if pattern_ipsrc in fn_name:
                d_output_ipsrc_alltraf_info[k_post_results] = v

            if pattern_ipdst in fn_name:
                d_output_ipdst_alltraf_info[k_post_results] = v

            if is_to_process_data_per_ingress_egress:
                if pattern_ingress in fn_name:
                    d_output_ingress_alltraf_info[k_post_results] = v

                if pattern_egress in fn_name:
                    d_output_egress_alltraf_info[k_post_results] = v

    return d_output_ipsrc_alltraf_info, d_output_ipdst_alltraf_info, \
           d_output_ingress_alltraf_info, d_output_egress_alltraf_info


def save_results_tofile(d_results_unique_agg, p_dest_filepath, p_file_name, key_dict_access, p_fn_addon=""):
    """
    Save results from multiprocessing (map/reduce) to json files, ordered by timestamp key.
    :param p_fn_addon:
    :param d_results_unique_agg:
    :param p_dest_filepath:
    :param p_file_name:
    :return:
    """

    fn_output_flow_info_pattern = "{file_dest_dir}{file_name}.class={lbl_class}{fn_addon}.json.gz"
    fn_output_flow_info = fn_output_flow_info_pattern.format(file_dest_dir=p_dest_filepath,
                                                             file_name=p_file_name,
                                                             lbl_class=key_dict_access[0],
                                                             fn_addon=p_fn_addon)

    # write dict result with flow traffic info to a json file
    with gzip.open(fn_output_flow_info, 'wb') as f:
        dump(d_results_unique_agg[key_dict_access], f, sort_keys=True)
    f.close()

    print "File created: {}.".format(fn_output_flow_info)


def save_raw_activitychurn_percategory_results_tofile(k_id, k_timestamp, c_flowfiles_to_gen_record, l_activity_timebin_status):
    """
    Save raw activity churn results for post-processing.
    :param k_id:
    :param k_timestamp:
    :param c_flowfiles_to_gen_record:
    :param l_activity_timebin_status:
    :return:
    """

    #k_id -> (k_classlabel, p_position_dict_result)
    k_classlabel = k_id[0]

    if k_id[1] == 0:
        p_position_dict_result = 'src'
    elif k_id[1] == 1:
        p_position_dict_result = 'dst'

    # E.g. raw-activitychurn-data.201704210000-201704282355.{ip, bgp}={src, dst}.agglevel=288.class={incone, outofcone}.json.gz"
    fn_output_rawdata_pattern = "{file_dest_dir}raw-activitychurn-data.{twindow}.{data_object}={data_type}.agglevel={dt_agglevel}.class={lbl_class}.txt"

    # for each set of raw data start saving them to txt files (gzip does not allow append operation)
    for set_rawdata in l_activity_timebin_status[:4]:

        # IPs lost
        if l_activity_timebin_status.index(set_rawdata) == 0:
            lbl_data_object = 'IPs-gained'

        # IPs gained
        if l_activity_timebin_status.index(set_rawdata) == 1:
            lbl_data_object = 'IPs-lost'

        # BGP prefixes lost
        if l_activity_timebin_status.index(set_rawdata) == 2:
            lbl_data_object = 'BGP-gained'

        # BGP prefixes gained
        if l_activity_timebin_status.index(set_rawdata) == 3:
            lbl_data_object = 'BGP-lost'

        fn_output_flow_info = fn_output_rawdata_pattern.format(file_dest_dir=base_tmp_dir,
                                                               twindow=parsed_args.time_window_op,
                                                               data_object=lbl_data_object,
                                                               data_type=p_position_dict_result,
                                                               lbl_class=k_classlabel,
                                                               dt_agglevel=c_flowfiles_to_gen_record)

        # create or append data if the file already exists
        f_rawdata = open(fn_output_flow_info, 'a')

        f_rawdata.write("{};{}\n".format(k_timestamp, list(set_rawdata)))


def do_compute_activity_churn_between_timebins(ip_values_timestp_current,
                                               ip_values_timestp_before,
                                               bgpprefix_values_timestp_current,
                                               bgpprefix_values_timestp_before,
                                               p_evaluate_per_iepoint):
    """
    Compute the activity and churn in active IP addresses. Get the active IP addresses and see up/down events.
    :param ip_values_timestp_current:
    :param ip_values_timestp_before:
    :param bgpprefix_values_timestp_current:
    :param bgpprefix_values_timestp_before:
    :param p_evaluate_per_iepoint: influences the format the result is returned, 0 means processing view of all traffic
    and 1 means the processing of all traffic per ingress/egress points.
    :return:
    """
    s_same_ips = ip_values_timestp_current.intersection(ip_values_timestp_before)
    s_same_bgpprefixes = bgpprefix_values_timestp_current.intersection(bgpprefix_values_timestp_before)

    s_up_ips = ip_values_timestp_current.difference(ip_values_timestp_before)  # check for who goes offline - downs
    s_down_ips = ip_values_timestp_before.difference(ip_values_timestp_current)  # check for who goes online - ups

    s_up_bgpprefixes = bgpprefix_values_timestp_current.difference(bgpprefix_values_timestp_before)
    s_down_bgpprefixes = bgpprefix_values_timestp_before.difference(bgpprefix_values_timestp_current)

    # if the analysis requested is to compute based on all traffic view return the raw sets (purpose post-processing)
    if p_evaluate_per_iepoint == 0:
        return [s_up_ips, s_down_ips, s_up_bgpprefixes, s_down_bgpprefixes, s_same_ips, s_same_bgpprefixes]

    # else if the analysis if per ingress/egress point return only the numbers
    else:
        return [len(s_up_ips), len(s_down_ips), len(s_up_bgpprefixes), len(s_down_bgpprefixes), len(s_same_ips), len(s_same_bgpprefixes)]


def get_numbers_activitychurn_timebin_status(l_sets_activity_timebin_status):
    """
    Convert list of sets to actual numbers only version tracking changes overtime.
    :param l_sets_activity_timebin_status:
    :return:
    """
    qty_ips_down = len(l_sets_activity_timebin_status[0])
    qty_ips_up = len(l_sets_activity_timebin_status[1])
    qty_bgpprefix_down = len(l_sets_activity_timebin_status[2])
    qty_bgpprefix_up = len(l_sets_activity_timebin_status[3])
    qty_same_ips = len(l_sets_activity_timebin_status[4])
    qty_same_bgpprefixes = len(l_sets_activity_timebin_status[5])
    traffic_volume_diff = l_sets_activity_timebin_status[6]
    qty_packets_diff = l_sets_activity_timebin_status[7]

    return [qty_ips_down, qty_ips_up, qty_bgpprefix_down, qty_bgpprefix_up, qty_same_ips, qty_same_bgpprefixes, traffic_volume_diff, qty_packets_diff]


def do_compute_metrics_aggregation_alltraffic(l_s_sorted_results, p_position_dict_result, op_to_process_categories, c_flowfiles_to_gen_record):
    """
    Compute the metrics aggregation for different time windows (1h, 1d, 1w) considering a view of all traffic data as
    an unique set.
    :param l_s_sorted_results:
    :param p_position_dict_result:
    :param op_to_process_categories:
    :param c_flowfiles_to_gen_record:
    :return:
    """

    # initialize the data structures to store results accordingly
    # index in the composed key refers to the position of the dict_result being processed
    # relates to `l_d_all_results_unique_agg_5min_alltraf` at main
    if op_to_process_categories == 1:
        d_all_results_unique_agg_alltraf_5min = DictResultsPerCategory(1)
        d_all_results_activity_churn_alltraf_5min = DictResultsPerCategory(0)
        d_result_unique_data_aggregated = DictResultsPerCategory(0)
    else:
        d_all_results_unique_agg_alltraf_5min = DictResultsAllTraffic(1)
        d_all_results_activity_churn_alltraf_5min = DictResultsAllTraffic(0)
        d_result_unique_data_aggregated = DictResultsAllTraffic(0)

    do_count_activity_churn = 0
    ip_values_timestp_before = list()
    bgpprefix_values_timestp_before = list()

    count_records_toagg = 0

    n_trafficvolume_bytes = 0
    n_qty_packets = 0

    # used to compute difference in activity metric
    n_trafficvolume_bytes_before = 0
    n_qty_packets_before = 0

    """
    Resulting data structure being processed after sorting operation, list composed with set key and list values
    [(('2017-05-07 00:00:00', 'incone'), [1, 2, 3, 4]),
     (('2017-05-07 00:05:00', 'incone'), [10, 11, 12]),
     (('2017-05-07 00:00:00', 'outofcone'), [4, 5, 6]),
     (('2017-05-07 00:05:00', 'outofcone'), [13, 15, 16]),
     (('2017-05-07 00:00:00', 'unverifiable'), [7, 8, 9]),
     (('2017-05-07 00:05:00', 'unverifiable'), [67, 34, 12])]
     """
    for record in l_s_sorted_results:
        k = record[0]
        values = record[1]

        k_timestamp = k[0]
        k_classlabel = k[1]
        k_id = (k_classlabel, p_position_dict_result)

        # count records being processed
        count_records_toagg += 1

        logging.info("{}, {} - Record -- IPs: {} | ASNs: {} | BGP: {} | C: {} | TrafV: {} | Pckts: {}".format(k_id,
                                                                                                              k_timestamp,
                                                                                                              len(values[0]),
                                                                                                              len(values[1]),
                                                                                                              len(values[2]),
                                                                                                              len(values[3]),
                                                                                                              fmtutil.rawnum_to_humannum(values[4]),
                                                                                                              values[5]))
        # set operations to check unique values
        d_all_results_unique_agg_alltraf_5min.d[k_id][0].update(values[0])
        d_all_results_unique_agg_alltraf_5min.d[k_id][1].update(values[1])
        d_all_results_unique_agg_alltraf_5min.d[k_id][2].update(values[2])
        d_all_results_unique_agg_alltraf_5min.d[k_id][3].update(values[3])

        # account for traffic volume and packets
        n_trafficvolume_bytes += values[4]
        n_qty_packets += values[5]

        # case the category changes during the loop reset data structure and add new values
        # control when to save aggregated data to file. E.g.: 1h, 60 min / 5 min files = 12
        if count_records_toagg % c_flowfiles_to_gen_record == 0:
            count_unique_ips = len(d_all_results_unique_agg_alltraf_5min.d[k_id][0])
            count_s_asns = len(d_all_results_unique_agg_alltraf_5min.d[k_id][1])
            count_s_bgpprefixes = len(d_all_results_unique_agg_alltraf_5min.d[k_id][2])
            count_s_countries = len(d_all_results_unique_agg_alltraf_5min.d[k_id][3])

            # Debug
            logging.info("{}, {} - Agg    -- IPs: {} | ASNs: {} | BGP: {} | C: {} | TrafV: {} | Pckts: {}".format(k_id,
                                                                                                                  k_timestamp,
                                                                                                                  count_unique_ips,
                                                                                                                  count_s_asns,
                                                                                                                  count_s_bgpprefixes,
                                                                                                                  count_s_countries,
                                                                                                                  fmtutil.rawnum_to_humannum(n_trafficvolume_bytes),
                                                                                                                  n_qty_packets))

            d_result_unique_data_aggregated.d[k_id][k_timestamp] = [count_unique_ips,
                                                                    count_s_asns,
                                                                    count_s_bgpprefixes,
                                                                    count_s_countries,
                                                                    n_trafficvolume_bytes,
                                                                    n_qty_packets]

            ################################################
            # compute activity/churn metric src/dst overall
            ################################################

            # this if is only a warm up phase
            if do_count_activity_churn == 0:
                do_count_activity_churn = 1
                ip_values_timestp_before = set(d_all_results_unique_agg_alltraf_5min.d[k_id][0])
                bgpprefix_values_timestp_before = set(d_all_results_unique_agg_alltraf_5min.d[k_id][2])

                n_trafficvolume_bytes_before = n_trafficvolume_bytes
                n_qty_packets_before = n_qty_packets
            else:
                l_activity_timebin_status = do_compute_activity_churn_between_timebins(
                    set(d_all_results_unique_agg_alltraf_5min.d[k_id][0]),
                    ip_values_timestp_before,
                    set(d_all_results_unique_agg_alltraf_5min.d[k_id][2]),
                    bgpprefix_values_timestp_before,
                    0)

                # keep the difference of the volume (if value is positive the traffic before was higher,
                # if negative the current traffic is the higher one)
                l_activity_timebin_status.append(n_trafficvolume_bytes_before - n_trafficvolume_bytes)
                l_activity_timebin_status.append(n_qty_packets_before - n_qty_packets)

                d_all_results_activity_churn_alltraf_5min.d[k_id][k_timestamp] = get_numbers_activitychurn_timebin_status(l_activity_timebin_status)

                # if requested to log raw information of ip/bgp traffic then save it
                if parsed_args.op_save_raw_dataresults_activity_churn:
                    save_raw_activitychurn_percategory_results_tofile(k_id, k_timestamp, c_flowfiles_to_gen_record, l_activity_timebin_status)

                # keep a record of time window data to compare in the next iteration
                ip_values_timestp_before = set(d_all_results_unique_agg_alltraf_5min.d[k_id][0])
                bgpprefix_values_timestp_before = set(d_all_results_unique_agg_alltraf_5min.d[k_id][2])

                n_trafficvolume_bytes_before = n_trafficvolume_bytes
                n_qty_packets_before = n_qty_packets

            # restart for count to a interval count
            n_trafficvolume_bytes = 0
            n_qty_packets = 0
            d_all_results_unique_agg_alltraf_5min.d.clear()
            if op_to_process_categories == 1:
                d_all_results_unique_agg_alltraf_5min = DictResultsPerCategory(1)
            else:
                d_all_results_unique_agg_alltraf_5min = DictResultsAllTraffic(1)

    return d_result_unique_data_aggregated, d_all_results_activity_churn_alltraf_5min


def do_compute_metrics_alltraffic(l_s_sorted_results, p_position_dict_result, op_to_process_categories):
    """
    Compute the metrics considering a view of all traffic data as an unique set.
    :param l_s_sorted_results:
    :param p_position_dict_result:
    :param op_to_process_categories:
    :return:
    """

    # initialize the data structures to store results accordingly
    # index in the composed key refers to the position of the dict_result being processed
    # relates to `l_d_all_results_unique_agg_5min_alltraf` at main

    if op_to_process_categories == 1:
        d_all_results_unique_agg_alltraf_5min = DictResultsPerCategory(0)
        d_all_results_activity_churn_alltraf_5min = DictResultsPerCategory(0)
    else:
        d_all_results_unique_agg_alltraf_5min = DictResultsAllTraffic(0)
        d_all_results_activity_churn_alltraf_5min = DictResultsAllTraffic(0)

    do_count_activity_churn = 0
    ip_values_timestp_before = list()
    bgpprefix_values_timestp_before = list()

    # used to compute difference in activity metric
    n_trafficvolume_bytes_before = 0
    n_qty_packets_before = 0

    for record in l_s_sorted_results:
        k = record[0]
        values = record[1]

        k_timestamp = k[0]
        k_classlabel = k[1]
        k_id = (k_classlabel, p_position_dict_result)

        n_trafficvolume_bytes = values[4]
        n_qty_packets = values[5]

        ##############################################
        # compute spatio-temporal Utilization (STU)
        ##############################################
        count_unique_ips = len(values[0])
        count_s_asns = len(values[1])
        count_s_bgpprefixes = len(values[2])
        count_s_countries = len(values[3])

        d_all_results_unique_agg_alltraf_5min.d[k_id][k_timestamp] = [count_unique_ips,
                                                                      count_s_asns,
                                                                      count_s_bgpprefixes,
                                                                      count_s_countries,
                                                                      n_trafficvolume_bytes,
                                                                      n_qty_packets]

        logging.info("{}, {} - Record -- IPs: {} | ASNs: {} | BGP: {} | C: {} | TrafV: {} | Pckts: {}".format(k_id, k_timestamp,
                                                                                      count_unique_ips,
                                                                                      count_s_asns,
                                                                                      count_s_bgpprefixes,
                                                                                      count_s_countries,
                                                                                      fmtutil.rawnum_to_humannum(n_trafficvolume_bytes),
                                                                                      n_qty_packets))

        ################################
        # compute activity/churn metric
        ################################
        if do_count_activity_churn == 0:  # this if is only a warm up phase
            do_count_activity_churn = 1
            ip_values_timestp_before = set(values[0])
            bgpprefix_values_timestp_before = set(values[2])
            n_trafficvolume_bytes_before = values[4]
            n_qty_packets_before = values[5]
        else:
            l_activity_timebin_status = do_compute_activity_churn_between_timebins(
                set(values[0]),
                ip_values_timestp_before,
                set(values[2]),
                bgpprefix_values_timestp_before,
                0)

            # keep the difference of the volume (if value is positive the traffic before was higher,
            # if negative the current traffic is the higher one)
            l_activity_timebin_status.append(n_trafficvolume_bytes_before - n_trafficvolume_bytes)
            l_activity_timebin_status.append(n_qty_packets_before - n_qty_packets)

            d_all_results_activity_churn_alltraf_5min.d[k_id][k_timestamp] = get_numbers_activitychurn_timebin_status(l_activity_timebin_status)

            # if requested to log raw information of ip/bgp traffic then save it
            if parsed_args.op_save_raw_dataresults_activity_churn:
                save_raw_activitychurn_percategory_results_tofile(k_id, k_timestamp, 1, l_activity_timebin_status)

            # keep a record of time window data to compare in the next iteration
            ip_values_timestp_before = set(values[0])
            bgpprefix_values_timestp_before = set(values[2])

            n_trafficvolume_bytes_before = values[4]
            n_qty_packets_before = values[5]

    return d_all_results_unique_agg_alltraf_5min, d_all_results_activity_churn_alltraf_5min


def do_compute_metrics_aggregation_traffic_per_ingress_egress(l_s_sorted_results, p_position_dict_result,
                                                              op_to_process_categories, c_flowfiles_to_gen_record):
    """
    Compute metrics aggregation for different time windows (1h, 1d, 1w) per ingress and egress points.
    :param l_s_sorted_results:
    :param p_position_dict_result:
    :param op_to_process_categories:
    :param c_flowfiles_to_gen_record:
    :return:
    """

    if op_to_process_categories == 1:
        d_result_unique_data_aggregated = DictResultsPerCategory(0)
        d_all_results_activity_churn_alltraf_5min = DictResultsPerCategory(0)
    else:
        d_result_unique_data_aggregated = DictResultsAllTraffic(0)
        d_all_results_activity_churn_alltraf_5min = DictResultsAllTraffic(0)

    d_all_results_unique_agg_alltraf_5min_perpoint = dict()

    count_records_toagg = 0

    for record in l_s_sorted_results:
        k_id_ts_class = record[0]
        d_d_values_per_point_5min = record[1]

        k_timestamp = k_id_ts_class[0]
        k_classlabel = k_id_ts_class[1]
        k_id = (k_classlabel, p_position_dict_result)

        # count records being processed
        count_records_toagg += 1

        ##############################################
        # compute spatio-temporal Utilization (STU)
        ##############################################

        # for each ingress/egress point compute the unique values
        for k_idpoint, l_values_per_point in d_d_values_per_point_5min.iteritems():

            n_trafficvolume_bytes = l_values_per_point[4]
            n_qty_packets = l_values_per_point[5]

            if k_idpoint in d_all_results_unique_agg_alltraf_5min_perpoint:
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][0].update(l_values_per_point[0])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][1].update(l_values_per_point[1])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][2].update(l_values_per_point[2])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][3].update(l_values_per_point[3])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][4] += n_trafficvolume_bytes
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][5] += n_qty_packets
            else:
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint] = [set(), set(), set(), set(), 0, 0]
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][0].update(l_values_per_point[0])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][1].update(l_values_per_point[1])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][2].update(l_values_per_point[2])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][3].update(l_values_per_point[3])
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][4] = n_trafficvolume_bytes
                d_all_results_unique_agg_alltraf_5min_perpoint[k_idpoint][5] = n_qty_packets

        # control when to save aggregated data to file. E.g.: 1h, 60 min / 5 min files = 12
        if count_records_toagg % c_flowfiles_to_gen_record == 0:

            # for each ingress/egress point compute the unique values
            d_agg_result_point = dict()
            for k_idpoint, l_values_per_point in d_all_results_unique_agg_alltraf_5min_perpoint.iteritems():

                # check to avoid empty initialization dict
                if bool(l_values_per_point):
                    count_unique_ips = len(l_values_per_point[0])
                    count_s_asns = len(l_values_per_point[1])
                    count_s_bgpprefixes = len(l_values_per_point[2])
                    count_s_countries = len(l_values_per_point[3])
                    n_trafficvolume_bytes = l_values_per_point[4]
                    n_qty_packets = l_values_per_point[5]

                    d_agg_result_point[k_idpoint] = [count_unique_ips,
                                                     count_s_asns,
                                                     count_s_bgpprefixes,
                                                     count_s_countries,
                                                     n_trafficvolume_bytes,
                                                     n_qty_packets]

                    d_result_unique_data_aggregated.d[k_id][k_timestamp] = d_agg_result_point

            # restart for perform analysis for a new time window (1h, 1d, 1w)
            d_all_results_unique_agg_alltraf_5min_perpoint.clear()

    ################################################
    # compute activity/churn metric per i/e point
    # - account for the number of existing samples
    # in the time window being computed (e.g., if a
    # given ingress point appears only two times during
    # 1h, that what will be considered to agg. Now
    # if appears only 1 time the original values will be used.
    ################################################
    logging.info("compute agg activity/churn metric per i/e point: 1h, 1d, 1w.")

    l_activity_timebin_status = dict()

    d_results_unique_traf_5min_agg_perpoint_past = dict()
    d_results_unique_traf_5min_agg_perpoint_current = dict()

    count_records_toagg = 0

    # deal with (timestamp, class)
    for record_master in l_s_sorted_results:

        k_id_ts_class_rmaster = record_master[0]
        v_dict_points_rmaster = record_master[1]

        k_timestamp_rmaster = k_id_ts_class_rmaster[0]
        k_classlabel_rmaster = k_id_ts_class_rmaster[1]
        k_id = (k_classlabel_rmaster, p_position_dict_result)

        # count records being processed per ingress/egress point
        count_records_toagg += 1

        # for each (timestamp, class) process all the ingress/egress points
        # for each ingress/egress point compute the unique values
        for id_point, values_rmaster in v_dict_points_rmaster.iteritems():

            n_trafficvolume_bytes = values_rmaster[4]
            n_qty_packets = values_rmaster[5]

            # this if is only a warm up phase (to prepare the first bin to be used in the metric computation)
            if count_records_toagg <= c_flowfiles_to_gen_record:

                if id_point in d_results_unique_traf_5min_agg_perpoint_past:
                    s_unique_ips_past = set(values_rmaster[0])
                    d_results_unique_traf_5min_agg_perpoint_past[id_point][0].update(s_unique_ips_past)

                    s_bgpprefixes_past = set(values_rmaster[2])
                    d_results_unique_traf_5min_agg_perpoint_past[id_point][1].update(s_bgpprefixes_past)

                    d_results_unique_traf_5min_agg_perpoint_past[id_point][2] += n_trafficvolume_bytes
                    d_results_unique_traf_5min_agg_perpoint_past[id_point][3] += n_qty_packets

                else:
                    # initialize data structure and respective values if the ingress/egress point doesnt
                    # exist yet in the time bin
                    d_results_unique_traf_5min_agg_perpoint_past[id_point] = [set(), set(), 0, 0]

                    s_unique_ips_past = set(values_rmaster[0])
                    d_results_unique_traf_5min_agg_perpoint_past[id_point][0].update(s_unique_ips_past)

                    s_bgpprefixes_past = set(values_rmaster[2])
                    d_results_unique_traf_5min_agg_perpoint_past[id_point][1].update(s_bgpprefixes_past)

                    d_results_unique_traf_5min_agg_perpoint_past[id_point][2] = n_trafficvolume_bytes
                    d_results_unique_traf_5min_agg_perpoint_past[id_point][3] = n_qty_packets

            # with the first bin computed start creating the second bin to compare
            else:
                if id_point in d_results_unique_traf_5min_agg_perpoint_current:
                    s_unique_ips_current = set(values_rmaster[0])
                    d_results_unique_traf_5min_agg_perpoint_current[id_point][0].update(s_unique_ips_current)

                    s_bgpprefixes_current = set(values_rmaster[2])
                    d_results_unique_traf_5min_agg_perpoint_current[id_point][1].update(s_bgpprefixes_current)

                    d_results_unique_traf_5min_agg_perpoint_current[id_point][2] += n_trafficvolume_bytes
                    d_results_unique_traf_5min_agg_perpoint_current[id_point][3] += n_qty_packets

                else:
                    # initialize data structure and respective values if the ingress/egress point doesnt
                    # exist yet in the time bin
                    d_results_unique_traf_5min_agg_perpoint_current[id_point] = [set(), set(), 0, 0]

                    s_unique_ips_current = set(values_rmaster[0])
                    d_results_unique_traf_5min_agg_perpoint_current[id_point][0].update(s_unique_ips_current)

                    s_bgpprefixes_current = set(values_rmaster[2])
                    d_results_unique_traf_5min_agg_perpoint_current[id_point][1].update(s_bgpprefixes_current)

                    d_results_unique_traf_5min_agg_perpoint_current[id_point][2] = n_trafficvolume_bytes
                    d_results_unique_traf_5min_agg_perpoint_current[id_point][3] = n_qty_packets

                # control when to save aggregated data to file. E.g.: 1h, 60 min / 5 min files = 12
                if count_records_toagg % c_flowfiles_to_gen_record == 0:

                    # if the ingress/egress point exists in both time windows compute the differences
                    # (otherwise does not include it)
                    if (id_point in d_results_unique_traf_5min_agg_perpoint_current) and \
                            (id_point in d_results_unique_traf_5min_agg_perpoint_past):

                        l_activity_timebin_status[id_point] = do_compute_activity_churn_between_timebins(
                            d_results_unique_traf_5min_agg_perpoint_current[id_point][0],
                            d_results_unique_traf_5min_agg_perpoint_past[id_point][0],
                            d_results_unique_traf_5min_agg_perpoint_current[id_point][1],
                            d_results_unique_traf_5min_agg_perpoint_past[id_point][1],
                            1)

                        l_activity_timebin_status[id_point].append(d_results_unique_traf_5min_agg_perpoint_past[id_point][2] -
                                                                   d_results_unique_traf_5min_agg_perpoint_current[id_point][2])

                        l_activity_timebin_status[id_point].append(d_results_unique_traf_5min_agg_perpoint_past[id_point][3] -
                                                                   d_results_unique_traf_5min_agg_perpoint_current[id_point][3])

                        # Debug
                        logging.info("{} | {}, {} (count: {}) - Agg    -- IPs DOWN: {} | IPs UP: {} | BGP DOWN: {} | BGP UP: {} | TrafV: {} | Pckts: {}".format(k_id,
                                                                                                                                        k_timestamp_rmaster,
                                                                                                                                        id_point,
                                                                                                                                        count_records_toagg,
                                                                                                                                        l_activity_timebin_status[id_point][0],
                                                                                                                                        l_activity_timebin_status[id_point][1],
                                                                                                                                        l_activity_timebin_status[id_point][2],
                                                                                                                                        l_activity_timebin_status[id_point][3],
                                                                                                                                        fmtutil.rawnum_to_humannum(l_activity_timebin_status[id_point][4]),
                                                                                                                                        l_activity_timebin_status[id_point][5]))

                    else:
                        # Debug
                        logging.info(
                            "{} | {}, {} (count: {}) - not exist in both time windows compared, current and previous".format(
                                k_id, k_timestamp_rmaster, id_point, count_records_toagg))

                    # keep a record of time window data to compare in the next iteration
                    if id_point in d_results_unique_traf_5min_agg_perpoint_past:
                        d_results_unique_traf_5min_agg_perpoint_past[id_point] = deepcopy(d_results_unique_traf_5min_agg_perpoint_current[id_point])
                    else:
                        d_results_unique_traf_5min_agg_perpoint_past[id_point] = [set(), set(), 0, 0]
                        d_results_unique_traf_5min_agg_perpoint_past[id_point] = deepcopy(d_results_unique_traf_5min_agg_perpoint_current[id_point])

                    # reset current to build the new time window to compare with the latest one computed
                    d_results_unique_traf_5min_agg_perpoint_current.clear()

                    d_all_results_activity_churn_alltraf_5min.d[k_id][k_timestamp_rmaster] = deepcopy(l_activity_timebin_status)

    return d_result_unique_data_aggregated, d_all_results_activity_churn_alltraf_5min


def do_compute_metrics_traffic_per_ingress_egress(l_s_sorted_results, p_position_dict_result, op_to_process_categories):
    """
    Compute metrics per ingress and egress points.
    :param l_s_sorted_results:
    :param p_position_dict_result:
    :param op_to_process_categories:
    :return:
    """

    if op_to_process_categories == 1:
        d_all_results_unique_agg_alltraf_5min = DictResultsPerCategory(0)
        d_all_results_activity_churn_alltraf_5min = DictResultsPerCategory(0)
    else:
        d_all_results_unique_agg_alltraf_5min = DictResultsAllTraffic(0)
        d_all_results_activity_churn_alltraf_5min = DictResultsAllTraffic(0)

    for record in l_s_sorted_results:
        k_id_ts_class = record[0]
        v_dict_points = record[1]

        k_timestamp = k_id_ts_class[0]
        k_classlabel = k_id_ts_class[1]
        k_id = (k_classlabel, p_position_dict_result)

        ##############################################
        # compute spatio-temporal Utilization (STU)
        ##############################################
        d_info_point = dict()

        # for each ingress/egress point compute the unique values
        for k, v in v_dict_points.iteritems():
            count_unique_ips = len(v_dict_points[k][0])
            count_s_asns = len(v_dict_points[k][1])
            count_s_bgpprefixes = len(v_dict_points[k][2])
            count_s_countries = len(v_dict_points[k][3])

            n_trafficvolume_bytes = v_dict_points[k][4]
            n_qty_packets = v_dict_points[k][5]

            d_info_point[k] = [count_unique_ips, count_s_asns, count_s_bgpprefixes, count_s_countries, n_trafficvolume_bytes, n_qty_packets]

        d_all_results_unique_agg_alltraf_5min.d[k_id][k_timestamp] = d_info_point

    ################################################
    # compute activity/churn metric per i/e point
    ################################################
    print("compute activity/churn metric per i/e point.")

    l_activity_timebin_status = dict()

    # deal with (timestamp, class)
    for record_master in l_s_sorted_results:

        k_id_ts_class_rmaster = record_master[0]
        v_dict_points_rmaster = record_master[1]

        k_timestamp_rmaster = k_id_ts_class_rmaster[0]
        k_classlabel_rmaster = k_id_ts_class_rmaster[1]
        k_id = (k_classlabel_rmaster, p_position_dict_result)

        # for each (timestamp, class) process all the ingress/egress points
        # for each ingress/egress point compute the unique values
        for id_point, values_rmaster in v_dict_points_rmaster.iteritems():
            s_unique_ips_past = set(values_rmaster[0])
            s_bgpprefixes_past = set(values_rmaster[2])

            # used to compute the difference in activity metric
            n_trafficvolume_bytes_before = values_rmaster[4]
            n_qty_packets_before = values_rmaster[5]

            # do lookup to find the next 5-bin with value for each ingress/egress points
            for record_interal in l_s_sorted_results:
                k_id_ts_class_rinternal = record_interal[0]
                v_dict_points_rinternal = record_interal[1]

                k_timestamp_rinternal = k_id_ts_class_rinternal[0]

                # if they match the class + timestamp going forward + exists the i/e point in the new timestamp
                if (tutil.strf_to_date(k_timestamp_rinternal) > tutil.strf_to_date(k_timestamp_rmaster)) and \
                        (id_point in v_dict_points_rinternal):
                    s_unique_ips_present = set(v_dict_points_rinternal[id_point][0])
                    s_bgpprefixes_present = set(v_dict_points_rinternal[id_point][2])

                    n_trafficvolume_bytes = v_dict_points_rinternal[id_point][4]
                    n_qty_packets = v_dict_points_rinternal[id_point][5]

                    l_activity_timebin_status[id_point] = do_compute_activity_churn_between_timebins(
                        s_unique_ips_present,
                        s_unique_ips_past,
                        s_bgpprefixes_present,
                        s_bgpprefixes_past,
                        1)

                    # keep the difference of the volume (if value is positive the traffic before was higher,
                    # if negative the current traffic is the higher one)
                    l_activity_timebin_status[id_point].append(n_trafficvolume_bytes_before - n_trafficvolume_bytes)
                    l_activity_timebin_status[id_point].append(n_qty_packets_before - n_qty_packets)

                    d_all_results_activity_churn_alltraf_5min.d[k_id][k_timestamp_rinternal] = deepcopy(l_activity_timebin_status)

                    # once the next available timestamp was found break the operation and go to next timebin
                    break

    return d_all_results_unique_agg_alltraf_5min, d_all_results_activity_churn_alltraf_5min


def do_create_timebin(p_tbin_agg, d_all_results_wtimestamp_unique_alltraf_5min, p_position_dict_result,
                      p_results_filename, op_to_process_categories):
    """
    Execute the bin creation performing the aggregation level requested for both data structure formats supported.
    :param p_tbin_agg:
    :param d_all_results_wtimestamp_unique_alltraf_5min:
    :param p_position_dict_result:
    :param p_results_filename:
    :return:
    """

    const_lbl_fn_name_activity_metric = ".activity"

    if p_tbin_agg == '5min':

        # these are the dicts containing data from `src` and `dst` flow traffic information
        if p_position_dict_result in [0, 1]:
            print "Starts to compute 5min bin agg for: {}.".format("src" if p_position_dict_result == 0 else "dst")

            l_s_sorted_results = sorted(d_all_results_wtimestamp_unique_alltraf_5min.items(),key=lambda (k, v): (k[1], k[0]), reverse=False)

            # all traffic view
            if op_to_process_categories == 0:
                d_all_results_unique_agg_alltraf_5min, \
                d_all_results_activity_churn_alltraf_5min = do_compute_metrics_alltraffic(l_s_sorted_results,
                                                                                          p_position_dict_result,
                                                                                          op_to_process_categories)

                k_id = ('all', p_position_dict_result)

                # save results to log files
                save_results_tofile(d_all_results_unique_agg_alltraf_5min.d, base_tmp_dir,
                                    p_results_filename, k_id)
                save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir,
                                    p_results_filename, k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

                # clear memory
                l_s_sorted_results = list()
                del d_all_results_unique_agg_alltraf_5min
                del d_all_results_activity_churn_alltraf_5min

            # per category traffic view
            elif op_to_process_categories == 1:

                # the input dict has all categories together, we separate to process each one individually
                s_categories_to_process = set(x[1] for x in d_all_results_wtimestamp_unique_alltraf_5min.keys())

                # for each category
                for cat in s_categories_to_process:
                    l_records_category_to_process = list()

                    # ... create the list of record to be processed
                    for record in l_s_sorted_results:
                        k_id = record[0]
                        k_category_class = k_id[1]

                        if cat == k_category_class:
                            l_records_category_to_process.append(record)

                    d_all_results_unique_agg_alltraf_5min, \
                    d_all_results_activity_churn_alltraf_5min = do_compute_metrics_alltraffic(l_records_category_to_process,
                                                                                              p_position_dict_result,
                                                                                              op_to_process_categories)

                    k_id = (cat, p_position_dict_result)

                    # save results to log files
                    save_results_tofile(d_all_results_unique_agg_alltraf_5min.d, base_tmp_dir,
                                        p_results_filename, k_id)
                    save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir,
                                        p_results_filename, k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

                # clear memory
                del d_all_results_unique_agg_alltraf_5min
                del d_all_results_activity_churn_alltraf_5min

        # these are the dicts containing data per ingress/egress points
        if p_position_dict_result in [2, 3]:
            print "Starts to compute 5min bin agg for: {}.".format("ingress" if p_position_dict_result == 2 else "egress")

            """
            Resulting data structure being processed after sorting operation, list composed with set key and list values
            [(('2017-05-07 00:00:00', 'incone'), ( ('12345', [1, 26, 3, 40]),
                                                   ('9876',  [1, 20, 43, 4]),
                                                   ('4567',  [10, 2, 73, 4]) ),
             (('2017-05-07 00:05:00', 'incone'), [10, 11, 12]),
             (('2017-05-07 00:00:00', 'outofcone'), [4, 5, 6]),
             (('2017-05-07 00:05:00', 'outofcone'), [13, 15, 16]),
             (('2017-05-07 00:00:00', 'unverifiable'), [7, 8, 9]),
             (('2017-05-07 00:05:00', 'unverifiable'), [67, 34, 12])]
             """

            l_s_sorted_results = sorted(d_all_results_wtimestamp_unique_alltraf_5min.items(), key=lambda (k, v): (k[1], k[0]), reverse=False)

            # all traffic view
            if op_to_process_categories == 0:
                d_all_results_unique_agg_alltraf_5min, \
                d_all_results_activity_churn_alltraf_5min = do_compute_metrics_traffic_per_ingress_egress(l_s_sorted_results,
                                                                                                          p_position_dict_result,
                                                                                                          op_to_process_categories)

                k_id = ('all', p_position_dict_result)

                # save results to log files
                save_results_tofile(d_all_results_unique_agg_alltraf_5min.d, base_tmp_dir,
                                    p_results_filename, k_id)
                save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir,
                                    p_results_filename, k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

                # clear memory
                del d_all_results_unique_agg_alltraf_5min
                del d_all_results_activity_churn_alltraf_5min

            # per category traffic view
            elif op_to_process_categories == 1:

                # the input dict has all categories together, we separate to process each one individually
                s_categories_to_process = set(x[1] for x in d_all_results_wtimestamp_unique_alltraf_5min.keys())

                # for each category
                for cat in s_categories_to_process:
                    l_records_category_to_process = list()

                    # ... create the list of record to be processed
                    for record in l_s_sorted_results:
                        k_id = record[0]
                        k_category_class = k_id[1]

                        if cat == k_category_class:
                            l_records_category_to_process.append(record)

                    d_all_results_unique_agg_alltraf_5min, \
                    d_all_results_activity_churn_alltraf_5min = do_compute_metrics_traffic_per_ingress_egress(l_records_category_to_process,
                                                                                                              p_position_dict_result,
                                                                                                              op_to_process_categories)

                    k_id = (cat, p_position_dict_result)

                    # save results to log files
                    save_results_tofile(d_all_results_unique_agg_alltraf_5min.d, base_tmp_dir,
                                        p_results_filename, k_id)
                    save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir,
                                        p_results_filename, k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

    ##############################################
    # DATA AGGREGATION STARTS
    # if timebin in [15min, 30min, 1h, 1d, 1w]
    ##############################################
    if p_tbin_agg in l_timebins[1:]:
        print "Starts to compute data aggregation, time window: {}.".format(p_tbin_agg)

        # variable to control how to perfom the aggregation of data being processed via mod
        # 15min / 5 min files = 3
        if p_tbin_agg == l_timebins[1]:
            c_flowfiles_to_gen_record = l_timebins_agg_values[1]

        # 30min / 5 min files = 6
        elif p_tbin_agg == l_timebins[2]:
            c_flowfiles_to_gen_record = l_timebins_agg_values[2]

        # 1h - 60 min / 5 min files = 12
        elif p_tbin_agg == l_timebins[3]:
            c_flowfiles_to_gen_record = l_timebins_agg_values[3]

        # 1d - 24h * 12 h files = 288
        elif p_tbin_agg == l_timebins[4]:
            c_flowfiles_to_gen_record = l_timebins_agg_values[4]

        # 1w - 7d * 288 files = 2016
        elif p_tbin_agg == l_timebins[5]:
            c_flowfiles_to_gen_record = l_timebins_agg_values[5]

        #######################
        # these are the dicts containing data from `src` and `dst` flow traffic information
        #######################
        if p_position_dict_result in [0, 1]:
            print "Starts to compute data aggregation for: {}.".format("src" if p_position_dict_result == 0 else "dst")

            l_s_sorted_results = sorted(d_all_results_wtimestamp_unique_alltraf_5min.items(), key=lambda (k, v): (k[1], k[0]), reverse=False)

            # all traffic view
            if op_to_process_categories == 0:
                d_result_unique_data_aggregated, \
                d_all_results_activity_churn_alltraf_5min = do_compute_metrics_aggregation_alltraffic(l_s_sorted_results,
                                                                                                      p_position_dict_result,
                                                                                                      op_to_process_categories,
                                                                                                      c_flowfiles_to_gen_record)
                k_id = ('all', p_position_dict_result)

                # save results to log files
                save_results_tofile(d_result_unique_data_aggregated.d, base_tmp_dir, p_results_filename, k_id)
                save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir, p_results_filename,
                                    k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

                # clear memory
                del d_result_unique_data_aggregated
                del d_all_results_activity_churn_alltraf_5min

            # per category traffic view
            elif op_to_process_categories == 1:

                # the input dict has all categories together, we separate to process each one individually
                s_categories_to_process = set(x[1] for x in d_all_results_wtimestamp_unique_alltraf_5min.keys())

                # for each category
                for cat in s_categories_to_process:
                    l_records_category_to_process = list()

                    # ... create the list of record to be processed
                    for record in l_s_sorted_results:
                        k_id = record[0]
                        k_category_class = k_id[1]

                        if cat == k_category_class:
                            l_records_category_to_process.append(record)

                    d_result_unique_data_aggregated, \
                    d_all_results_activity_churn_alltraf_5min = do_compute_metrics_aggregation_alltraffic(l_records_category_to_process,
                                                                                                          p_position_dict_result,
                                                                                                          op_to_process_categories,
                                                                                                          c_flowfiles_to_gen_record)
                    k_id = (cat, p_position_dict_result)

                    # save results to log files
                    save_results_tofile(d_result_unique_data_aggregated.d, base_tmp_dir, p_results_filename, k_id)
                    save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir, p_results_filename,
                                        k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

                # clear memory
                del d_result_unique_data_aggregated
                del d_all_results_activity_churn_alltraf_5min

        #######################
        # these are the dicts containing data per ingress/egress points
        #######################
        if p_position_dict_result in [2, 3]:
            print "Starts to compute data aggregation for: {}.".format("ingress" if p_position_dict_result == 2 else "egress")

            count_max_categories = len(set(x[1] for x in d_all_results_wtimestamp_unique_alltraf_5min.keys()))
            l_s_sorted_results = sorted(d_all_results_wtimestamp_unique_alltraf_5min.items(), key=lambda (k, v): (k[1], k[0]), reverse=False)

            # all traffic view
            if op_to_process_categories == 0:
                d_result_unique_data_aggregated, \
                d_all_results_activity_churn_alltraf_5min = do_compute_metrics_aggregation_traffic_per_ingress_egress(l_s_sorted_results,
                                                                                                                      p_position_dict_result,
                                                                                                                      op_to_process_categories,
                                                                                                                      c_flowfiles_to_gen_record)
                k_id = ('all', p_position_dict_result)

                # save results to log files
                save_results_tofile(d_result_unique_data_aggregated.d, base_tmp_dir, p_results_filename, k_id)
                save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir, p_results_filename,
                                    k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

                # clear memory
                del d_result_unique_data_aggregated
                del d_all_results_activity_churn_alltraf_5min

            # per category traffic view
            elif op_to_process_categories == 1:

                # the input dict has all categories together, we separate to process each one individually
                s_categories_to_process = set(x[1] for x in d_all_results_wtimestamp_unique_alltraf_5min.keys())

                # for each category
                for cat in s_categories_to_process:
                    l_records_category_to_process = list()

                    # ... create the list of record to be processed
                    for record in l_s_sorted_results:
                        k_id = record[0]
                        k_category_class = k_id[1]

                        if cat == k_category_class:
                            l_records_category_to_process.append(record)

                    d_result_unique_data_aggregated, \
                    d_all_results_activity_churn_alltraf_5min = do_compute_metrics_aggregation_traffic_per_ingress_egress(l_records_category_to_process,
                                                                                                                          p_position_dict_result,
                                                                                                                          op_to_process_categories,
                                                                                                                          c_flowfiles_to_gen_record)

                    k_id = (cat, p_position_dict_result)

                    # save results to log files
                    save_results_tofile(d_result_unique_data_aggregated.d, base_tmp_dir, p_results_filename, k_id)
                    save_results_tofile(d_all_results_activity_churn_alltraf_5min.d, base_tmp_dir, p_results_filename,
                                        k_id, p_fn_addon=const_lbl_fn_name_activity_metric)

                # clear memory
                del d_result_unique_data_aggregated
                del d_all_results_activity_churn_alltraf_5min


def generate_timebins_file_sets(l_d_all_results_unique_5min, p_aggregate_level, op_to_process_categories):
    """
    Generate the set of timebins with distinct aggregation levels following the user input parameter choice.
    :param l_d_all_results_unique_5min:
    :param p_aggregate_level:
    :return:
    """

    results_filename_pattern = "{data_label}.traffic-flow.{timestamp}.tbin={lbl_timebin}.ip={ip_option}.ipv=4.ixp={ixplabel}"

    # the order of elements is directly associated with the order of dicts from the first param
    l_dict_results_order = ['src', 'dst', 'src', 'dst']
    l_labels_dict_results_order = ['overallbehavior', 'overallbehavior', 'ingressbehavior', 'egressbehavior']

    c_flowfiles_day = 288
    c_flowfiles_week = 2016
    c_flowfiles_month = 8640

    for d_results in l_d_all_results_unique_5min:

        if p_aggregate_level == 1:
            results_filename = results_filename_pattern.format(data_label=l_labels_dict_results_order[l_d_all_results_unique_5min.index(d_results)],
                                                               timestamp=parsed_args.time_window_op,
                                                               lbl_timebin=l_timebins[0],
                                                               ip_option=l_dict_results_order[l_d_all_results_unique_5min.index(d_results)],
                                                               ixplabel='RS-IX')

            do_create_timebin(l_timebins[0], d_results, l_d_all_results_unique_5min.index(d_results), results_filename, op_to_process_categories)

        # if requested to aggregate in different levels do it
        if p_aggregate_level > 1:

            # if level 2 (5min, 15min) it's required at least 1 full day
            if (p_aggregate_level == 2) and (len(d_results) >= c_flowfiles_day):
                l_timebins_to_process = l_timebins[:p_aggregate_level]

            # if level 3 (5min, 15min, 30min) it's required at least 1 full day
            elif (p_aggregate_level == 3) and (len(d_results) >= c_flowfiles_day):
                l_timebins_to_process = l_timebins[:p_aggregate_level]

            # if level 4 (5min, 15min, 30min, 1h) it's required at least 1 full day
            elif (p_aggregate_level == 4) and (len(d_results) >= c_flowfiles_day):
                l_timebins_to_process = l_timebins[:p_aggregate_level]

            # if level 5 (5min, 15min, 30min, 1h, 1d) it's required at least 1 full week
            elif (p_aggregate_level == 5) and (len(d_results) >= c_flowfiles_week):
                l_timebins_to_process = l_timebins[:p_aggregate_level]

            # if level 6 (5min, 15min, 30min, 1h, 1d, 1w) it's required at least 1 full month
            elif (p_aggregate_level == 6) and (len(d_results) >= c_flowfiles_month):
                l_timebins_to_process = l_timebins[:p_aggregate_level]

            # if level 7 (personalized aggregation) it's required at least 1 full day
            elif (p_aggregate_level == 7) and (len(d_results) >= c_flowfiles_day):
                l_timebins_to_process = l_timebins[:len(l_timebins)]

            else:
                print("ERROR: aggregation level requested incompatible with the period of the data being processed.\n"
                      "Revise your input parameters definition.")
                exit(1)

            for tbin in l_timebins_to_process:
                results_filename = results_filename_pattern.format(data_label=l_labels_dict_results_order[l_d_all_results_unique_5min.index(d_results)],
                                                                   timestamp=parsed_args.time_window_op,
                                                                   lbl_timebin=tbin,
                                                                   ip_option=l_dict_results_order[l_d_all_results_unique_5min.index(d_results)],
                                                                   ixplabel='RS-IX')

                do_create_timebin(tbin, d_results, l_d_all_results_unique_5min.index(d_results), results_filename, op_to_process_categories)


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Traffic classification taking Apache Avro '
                                                                   'as input files.')

    parser.add_argument('-tw', dest='time_window_op', required=True,
                        help="Time window to load files to process. Format: start-end, %Y%m%d%H%M-%Y%m%d%H%M")

    parser.add_argument('-ccid', dest='customercone_algoid', type=int, choices=[4, 8], required=True,
                        help="Options: "
                             "4 - IMC17 FullCone "
                             "8 - CoNEXT19 Prefix-Level Customer Cone.")

    parser.add_argument('-flowdir', dest='flows_dir_path', required=True,
                        help="Directory where are the flows to process")

    parser.add_argument('-tmpdir', dest='temp_path', required=True,
                        help="Temporary dir to save output files")

    parser.add_argument('-np', dest='number_concur_process',
                        help="Number of concurrent process to execute")

    parser.add_argument('-agg', dest='op_aggregate_level', type=int, choices=[1, 2, 3, 4, 5, 6, 7], required=True,
                        help="Aggregation level desired of flow processing data. "
                             "Options: "
                             "1 - 5 min; "
                             "2 - 15 min; "
                             "3 - 30 min; "
                             "4 - 1 hour; "
                             "5 - 1 day; "
                             "6 - 1 week; "
                             "7 - agg personalized.")

    parser.add_argument('-pagg', dest='personalized_op_agg_level', required=False,
                        help="Personalized aggregation level desired for flow data metrics."
                             "Syntax e.g.: '['5min','6h'];[1,72]' ")

    parser.add_argument('-pc', dest='to_process_categories', type=int, choices=[0, 1], required=True,
                        help="Process the categories flow traffic data files - incone, ouf-of-cone, unverifiable. "
                             "Options: 1 - yes or 0 - no (meaning that the whole traffic will be analyzed)")

    parser.add_argument('-cat', dest='set_of_categories_to_process', required=False,
                        help="Define the set of categories that must be processed to compute the metrics. "
                             " Syntax: '[incone, out-of-cone, unverifiable]' ")

    parser.add_argument('-sraw', dest='op_save_raw_dataresults_activity_churn', type=int, choices=[0, 1], required=True,
                        help='Indicate if should save the raw data computed during the '
                             'Activity/Churn metric computation.')

    parser.add_argument('-process_ingress_egress_data', dest='to_process_data_per_ingress_egress', type=int, choices=[0, 1], required=True,
                        help="Indicates if it is necessary to break down data per category "
                             "into a view per ingress and egress ASes."
                             "Options: 1 - yes or 0 - no")

    parser.add_argument('-log', dest='loglevel', required=True,
                        help="Set the log level (debug, info, warn, error, critical).")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    # set up of variables to generate flow file names
    if parsed_args.time_window_op:
        tw_start, tw_end = cmdutil.get_timewindow_to_process(parsed_args.time_window_op)

    # number of concurrent process (performance control)
    if parsed_args.number_concur_process is None:
        n_cores_to_use = None
    else:
        n_cores_to_use = int(parsed_args.number_concur_process)

    # Customer Cone method algorithm
    id_customer_cone_algo_dataset = parsed_args.customercone_algoid

    # Process data Ingress and Egress
    is_to_process_data_per_ingress_egress = parsed_args.to_process_data_per_ingress_egress

    # directory paths set up for the conversion process
    flowfiles_basedir = parsed_args.flows_dir_path
    base_tmp_dir = parsed_args.temp_path

    op_aggregate_level = parsed_args.op_aggregate_level
    op_loglevel = parsed_args.loglevel

    if parsed_args.set_of_categories_to_process:
        l_set_of_filters_traffic_categories = ast.literal_eval(parsed_args.set_of_categories_to_process)

    if op_aggregate_level < 7:
        l_timebins = ['5min', '15min', '30min', '1h', '1d', '1w']
        l_timebins_agg_values = [1, 3, 6, 12, 288, 2016]
        print "Starting aggregation: {}".format(op_aggregate_level)
    else:
        str_personalized_agg = parsed_args.personalized_op_agg_level.split(';')
        l_timebins = ast.literal_eval(str_personalized_agg[0])
        l_timebins_agg_values = ast.literal_eval(str_personalized_agg[1])
        print "Starting personalized aggregation: {}".format(l_timebins)

    # ------------------------------------------------------------------
    # logging parameters
    # ------------------------------------------------------------------
    fn_log = base_tmp_dir + 'output.log'
    numeric_level = getattr(logging, op_loglevel.upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % op_loglevel)

    logging.basicConfig(filename=fn_log, filemode='w', level=numeric_level)

    start = timer()
    # ------------------------------------------------------------------
    #  Metrics computation logic processes start
    # ------------------------------------------------------------------
    default_flowtraffic_datafile = ".avro"

    pattern_ipsrc =".ip=src."
    pattern_ipdst = ".ip=dst."
    pattern_ingress = ".point=ingress."
    pattern_egress = ".point=egress."

    print "---Creating list of files for processing (5-min flow files):"

    if parsed_args.to_process_categories:
        pattern_ip_alltraf_file_extension = '{def_ext}.idcc={id_cc_version}.class={lbl_class}.ip={ip_type}.ipv=4.svln=all.txt.gz'
        pattern_iepoint_alltraf_file_extension = '{def_ext}.idcc={id_cc_version}.class={lbl_class}.point={point_type}.ipv=4.svln=all.txt.gz'

        if not parsed_args.set_of_categories_to_process:
            l_pattern_file_extensions = [
                                         pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                  lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                                  ip_type='src',
                                                                                  id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                  lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                                  ip_type='src',
                                                                                  id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                  lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                                  ip_type='src',
                                                                                  id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                  lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                                  ip_type='dst',
                                                                                  id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                  lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                                  ip_type='dst',
                                                                                  id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                  lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                                  ip_type='dst',
                                                                                  id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                       lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                                       point_type='ingress',
                                                                                       id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                       lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                                       point_type='ingress',
                                                                                       id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                       lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                                       point_type='ingress',
                                                                                       id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                       lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                                       point_type='egress',
                                                                                       id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                       lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                                       point_type='egress',
                                                                                       id_cc_version=id_customer_cone_algo_dataset),
                                         pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                                       lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                                       point_type='egress',
                                                                                       id_cc_version=id_customer_cone_algo_dataset)
            ]

            l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                              flowfiles_basedir,
                                                                                              l_pattern_file_extensions)

        # if enabled to lookup to a specific class, prepare the list of files for only these categories
        # possibilities and indexing [incone, out-of-cone, unverifiable]
        elif parsed_args.set_of_categories_to_process:

            l_pattern_file_extensions = list()
            i_index = 0

            for lbl_category in l_set_of_filters_traffic_categories:
                #########
                # incone
                if lbl_category == 1 and i_index == 0:
                    print "Preparing to process IN-CONE traffic."

                    l_pattern_file_extensions.append(
                        pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                 lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                 ip_type='src',
                                                                 id_cc_version=id_customer_cone_algo_dataset)

                    )
                    l_pattern_file_extensions.append(
                        pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                 lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                 ip_type='dst',
                                                                 id_cc_version=id_customer_cone_algo_dataset)
                    )

                    if is_to_process_data_per_ingress_egress:
                        l_pattern_file_extensions.append(
                            pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                          lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                          point_type='ingress',
                                                                          id_cc_version=id_customer_cone_algo_dataset)
                        )
                        l_pattern_file_extensions.append(
                            pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                          lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE,
                                                                          point_type='egress',
                                                                          id_cc_version=id_customer_cone_algo_dataset)
                        )
                ##############
                # out-of-cone
                if lbl_category == 1 and i_index == 1:
                    print "Preparing to process OUT-OF-CONE traffic."

                    l_pattern_file_extensions.append(
                        pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                 lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                 ip_type='src',
                                                                 id_cc_version=id_customer_cone_algo_dataset)

                    )
                    l_pattern_file_extensions.append(
                        pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                 lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                 ip_type='dst',
                                                                 id_cc_version=id_customer_cone_algo_dataset)
                    )

                    if is_to_process_data_per_ingress_egress:
                        l_pattern_file_extensions.append(
                            pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                          lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                          point_type='ingress',
                                                                          id_cc_version=id_customer_cone_algo_dataset)
                        )
                        l_pattern_file_extensions.append(
                            pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                          lbl_class=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                                                                          point_type='egress',
                                                                          id_cc_version=id_customer_cone_algo_dataset)
                        )

                ##############
                # unverifiable
                if lbl_category == 1 and i_index == 2:
                    print "Preparing to process UNVERIFIABLE traffic."

                    l_pattern_file_extensions.append(
                        pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                 lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                 ip_type='src',
                                                                 id_cc_version=id_customer_cone_algo_dataset)

                    )
                    l_pattern_file_extensions.append(
                        pattern_ip_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                 lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                 ip_type='dst',
                                                                 id_cc_version=id_customer_cone_algo_dataset)
                    )

                    if is_to_process_data_per_ingress_egress:
                        l_pattern_file_extensions.append(
                            pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                          lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                          point_type='ingress',
                                                                          id_cc_version=id_customer_cone_algo_dataset)
                        )
                        l_pattern_file_extensions.append(
                            pattern_iepoint_alltraf_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                                          lbl_class=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS,
                                                                          point_type='egress',
                                                                          id_cc_version=id_customer_cone_algo_dataset)
                        )

                i_index += 1

            l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                              flowfiles_basedir,
                                                                                              l_pattern_file_extensions)

    else:
        pattern_ipsrc_alltraf_file_extension = '.avro.ip=src.ipv=4.svln=all.txt.gz'
        pattern_ipdst_alltraf_file_extension = '.avro.ip=dst.ipv=4.svln=all.txt.gz'
        pattern_ingress_alltraf_file_extension = '.avro.point=ingress.ipv=4.svln=all.txt.gz'
        pattern_egress_alltraf_file_extension = '.avro.point=egress.ipv=4.svln=all.txt.gz'

        l_pattern_file_extensions = [pattern_ipsrc_alltraf_file_extension,
                                     pattern_ipdst_alltraf_file_extension,
                                     pattern_ingress_alltraf_file_extension,
                                     pattern_egress_alltraf_file_extension]

        l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                          flowfiles_basedir,
                                                                                          l_pattern_file_extensions)

    print "---Started multiprocessing of traffic files, {} to be processed.".format(len(l_filenames_to_process))
    mp = mpPool.MultiprocessingPool(n_cores_to_use)
    results = mp.get_results_map_multiprocessing(do_iplevel_aggregation_analysis, l_filenames_to_process)

    print "---Started post-processing classification results. Aggregation level: {}".format(op_aggregate_level)
    d_all_results_unique_agg_ipsrc_alltraf_info, \
    d_all_results_unique_agg_ipdst_alltraf_info, \
    d_all_results_unique_agg_ingress_alltraf_info, \
    d_all_results_unique_agg_egress_alltraf_info = post_processing_aggregate_results(results, parsed_args.to_process_categories)

    if is_to_process_data_per_ingress_egress:
        l_d_all_results_unique_agg_5min_alltraf = [d_all_results_unique_agg_ipsrc_alltraf_info,
                                                   d_all_results_unique_agg_ipdst_alltraf_info]
    else:
        # Important: the order of the dictionaries inside this list has a direct impact on the final processing
        # to save to aggregate files - if the order change is fundamental to revise the methods that make use of it
        l_d_all_results_unique_agg_5min_alltraf = [d_all_results_unique_agg_ipsrc_alltraf_info,
                                                   d_all_results_unique_agg_ipdst_alltraf_info,
                                                   d_all_results_unique_agg_ingress_alltraf_info,
                                                   d_all_results_unique_agg_egress_alltraf_info]

    print "---Generating time bins and saving to files: ", tw_start, " to ", tw_end
    generate_timebins_file_sets(l_d_all_results_unique_agg_5min_alltraf, op_aggregate_level, parsed_args.to_process_categories)

    end = timer()
    print "---Total execution time: {} seconds".format(end - start)

    print "---Sending e-mail notification about the execution status:"
    notifutil.send_notification_end_of_execution(sys.argv, sys.argv[0], start, end)
