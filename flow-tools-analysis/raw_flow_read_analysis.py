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
import utils.as2org_dataset_utilities as as2orgutil
import utils.time_utilities as tutil
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
from timeit import default_timer as timer
import csv

"""
---------------------------------------ABOUT----------------------------------------
Code base: flow-tools-analysis/gen_data_input_flows_behavior_metrics.py
Process original traffic flow data, transforming and aggregating data to export 
in bins, allowing distinct analysis over network behaviors.
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
    if len(ip_prefix_fields) == 2:
        cidr_block = ip_prefix_fields[1]
        prefix_net = IPNetwork(ip_prefix)

        if int(cidr_block) < 24:
            subnets = list(prefix_net.subnet(ipv4_prefixlen_desired))
            return len(subnets)

        elif int(cidr_block) == 24:
            return 1

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


def update_log_ip_dict(flow_ip, origin_asn, asn_name, ip_prefix, country_code, flow_bytes, flow_packets,
                       asn_ingress_point, asn_ingress_point_name, asn_egress_point, asn_egress_point_name,
                       src_vlan_tag, d_ip_level_analysis):
    """
    Counts the unique IPAddresses, BGP prefixes, origin_asn for all the traffic that is seen.
    :param flow_ip:
    :param origin_asn:
    :param ip_prefix:
    :param d_ip_level_analysis:
    :return:
    """

    k = (flow_ip, origin_asn, asn_name, ip_prefix, country_code, asn_ingress_point, asn_ingress_point_name, asn_egress_point, asn_egress_point_name, src_vlan_tag)
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


def update_flowtuple_dict(ipsrc, ipdst, protocol, srcport, dstport, flow_bytes, flow_packets, d_tuplelevel_analysis):

    k = (ipsrc, ipdst, protocol, srcport, dstport)
    values = [1, flow_bytes, flow_packets]

    if k not in d_tuplelevel_analysis:
        d_tuplelevel_analysis[k] = values
    else:
        d_tuplelevel_analysis[k] = map(add, d_tuplelevel_analysis[k], values)

    return d_tuplelevel_analysis


def update_topdst_commun_target_dict(ipsrc, ipdst, member_ingress_asn, flow_bytes, flow_packets, d_topdst_target_analysis):
    """
    Control dict to keep the top IP DST stats, i.e., #uniq Src IP, #flows w/IP DST, traffic volume, #packets
    :param ipsrc:
    :param ipdst:
    :param flow_bytes:
    :param flow_packets:
    :param d_topdst_target_analysis:
    :return:
    """

    k = ipdst
    values = [1, flow_bytes, flow_packets]

    if k not in d_topdst_target_analysis:
        d_topdst_target_analysis[k] = [set(), set(), values]
        d_topdst_target_analysis[k][0].add(ipsrc)
        d_topdst_target_analysis[k][1].add(member_ingress_asn)
    else:
        d_topdst_target_analysis[k][0].add(ipsrc)
        d_topdst_target_analysis[k][1].add(member_ingress_asn)
        d_topdst_target_analysis[k][2] = map(add, d_topdst_target_analysis[k][2], values)

    return d_topdst_target_analysis


def update_top_dst_macadrr_commun_target_dict(ipsrc, dst_macaddr, dst_macaddr_asn, flow_bytes, flow_packets,
                                              d_top_dst_macaddr_target_analysis):
    """
    Control dict to keep the Top Destination Mac Addresses/IXP member ASNs.
    :param ipsrc:
    :param dst_macaddr:
    :param dst_macaddr_asn:
    :param flow_bytes:
    :param flow_packets:
    :param d_top_dst_macaddr_target_analysis:
    :return:
    """

    k = (dst_macaddr, dst_macaddr_asn)
    values = [1, flow_bytes, flow_packets]

    if k not in d_top_dst_macaddr_target_analysis:
        d_top_dst_macaddr_target_analysis[k] = [set(), values]
        d_top_dst_macaddr_target_analysis[k][0].add(ipsrc)
    else:
        d_top_dst_macaddr_target_analysis[k][0].add(ipsrc)
        d_top_dst_macaddr_target_analysis[k][1] = map(add, d_top_dst_macaddr_target_analysis[k][1], values)

    return d_top_dst_macaddr_target_analysis


def update_records_ports_dict(flow_protocol, flow_port, ipaddr, flow_bytes, flow_packets, d_flow_port_count):

    k = (flow_protocol, flow_port)
    values = [1, flow_bytes, flow_packets]

    if k not in d_flow_port_count:
        d_flow_port_count[k] = [set(), values]
        d_flow_port_count[k][0].add(ipaddr)
    else:
        d_flow_port_count[k][0].add(ipaddr)
        d_flow_port_count[k][1] = map(add, d_flow_port_count[k][1], values)

    return d_flow_port_count


def count_uniq_ip(l_d_flow_records, s_timestamp_label_key, d_filters={}):
    """
    Filter the traffic flow data and execute the processing analysis logic for network behavior metrics.
    """

    d_ipsrc_level_analysis = dict()   # more detailed flow analysis over the src ip
    d_ipsrc_ports_protocols = dict()  # get raw unique ports and protocols per src ip over all flow
    d_ipsrc_ports = dict()            # account for port number of flows generated for that port per src ip

    d_ipdst_level_analysis = dict()   # more detailed flow analysis over the dst ip
    d_ipdst_ports_protocols = dict()  # get raw unique ports and protocols per dst ip over all flow
    d_ipdst_ports = dict()            # account for port number of flows generated for that port per dst ip

    d_tuple_level_analysis = dict()

    d_top_dst_communication_target = dict()
    d_top_dst_macaddr_communication_target = dict()

    for flow in l_d_flow_records:
        if futil.matches_desired_set(flow, d_filters) and filter_toselect_flows(flow, s_timestamp_label_key):

            str_flow_sa = fputil.record_to_ip(flow['sa'])
            str_flow_da = fputil.record_to_ip(flow['da'])

            flow_bytes = fputil.record_to_numeric(flow['ibyt'])
            flow_packets = fputil.record_to_numeric(flow['ipkt'])

            flow_sp = fputil.record_to_numeric(flow['sp'])
            flow_dp = fputil.record_to_numeric(flow['dp'])
            str_flow_pr = fputil.proto_int_to_str(flow['pr'])

            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc']).replace(':', '').upper()
            flow_egress_dst_macaddr = fputil.record_to_mac(flow['odmc']).replace(':', '').upper()

            src_vlan_tag = fputil.record_to_numeric(flow['svln'])

            flow_ingress_asn = ['UNKNOWN']
            if flow_ingress_src_macaddr in d_mapping_macaddress_member_asn:
                flow_ingress_asn = d_mapping_macaddress_member_asn[flow_ingress_src_macaddr]

            flow_egress_asn = ['UNKNOWN']
            if flow_egress_dst_macaddr in d_mapping_macaddress_member_asn:
                flow_egress_asn = d_mapping_macaddress_member_asn[flow_egress_dst_macaddr]

            sa_origin_asn, sa_ip_prefix = do_prefix_lookup_forip(str_flow_sa)
            da_origin_asn, da_ip_prefix = do_prefix_lookup_forip(str_flow_da)

            flow_src_asn_name = as2orgutil.do_lookup_as2org(sa_origin_asn, d_mapping_as_data, d_mapping_org_data)
            flow_dst_asn_name = as2orgutil.do_lookup_as2org(da_origin_asn, d_mapping_as_data, d_mapping_org_data)

            flow_ingress_asn_name = as2orgutil.do_lookup_as2org(flow_ingress_asn[0], d_mapping_as_data, d_mapping_org_data)
            flow_egress_asn_name = as2orgutil.do_lookup_as2org(flow_egress_asn[0], d_mapping_as_data, d_mapping_org_data)

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
            # Tuple
            #######
            d_tuple_level_analysis = update_flowtuple_dict(str_flow_sa, str_flow_da, str_flow_pr, flow_sp, flow_dp,
                                                           flow_bytes,
                                                           flow_packets,
                                                           d_tuple_level_analysis)

            #####################
            # IPADDR DESTINATION
            #####################
            d_top_dst_communication_target = update_topdst_commun_target_dict(str_flow_sa, str_flow_da,
                                                                              flow_ingress_asn[0],
                                                                              flow_bytes,
                                                                              flow_packets,
                                                                              d_top_dst_communication_target)

            d_top_dst_macaddr_communication_target = update_top_dst_macadrr_commun_target_dict(str_flow_sa,
                                                                                               flow_egress_dst_macaddr,
                                                                                               flow_egress_asn[0],
                                                                                               flow_bytes,
                                                                                               flow_packets,
                                                                                               d_top_dst_macaddr_communication_target)

            # save data processed
            #######
            # SRC
            #######
            d_ipsrc_level_analysis = update_log_ip_dict(str_flow_sa,
                                                        sa_origin_asn,
                                                        flow_src_asn_name,
                                                        sa_ip_prefix,
                                                        sa_country_code,
                                                        flow_bytes,
                                                        flow_packets,
                                                        flow_ingress_asn[0],
                                                        flow_ingress_asn_name,
                                                        flow_egress_asn[0],
                                                        flow_egress_asn_name,
                                                        src_vlan_tag,
                                                        d_ipsrc_level_analysis)

            # save info about src ports and flow protocols
            d_ipsrc_ports_protocols = update_log_ip_ports_protocols_dict(str_flow_sa,
                                                                         flow_sp,
                                                                         str_flow_pr,
                                                                         d_ipsrc_ports_protocols)

            # account info about src ports
            d_ipsrc_ports = update_records_ports_dict(str_flow_pr, flow_sp, str_flow_sa,
                                                      flow_bytes, flow_packets, d_ipsrc_ports)

            #######
            # DST
            #######
            d_ipdst_level_analysis = update_log_ip_dict(str_flow_da,
                                                        da_origin_asn,
                                                        flow_dst_asn_name,
                                                        da_ip_prefix,
                                                        da_country_code,
                                                        flow_bytes,
                                                        flow_packets,
                                                        flow_ingress_asn[0],
                                                        flow_ingress_asn_name,
                                                        flow_egress_asn[0],
                                                        flow_egress_asn_name,
                                                        src_vlan_tag,
                                                        d_ipdst_level_analysis)

            # save info about dst ports and flow protocols
            d_ipdst_ports_protocols = update_log_ip_ports_protocols_dict(str_flow_da,
                                                                         flow_dp,
                                                                         str_flow_pr,
                                                                         d_ipdst_ports_protocols)
            # account info about dst ports
            d_ipdst_ports = update_records_ports_dict(str_flow_pr, flow_dp, str_flow_da,
                                                      flow_bytes, flow_packets, d_ipdst_ports)

    return d_ipsrc_level_analysis, d_ipdst_level_analysis, \
           d_ipsrc_ports_protocols, d_ipdst_ports_protocols, \
           d_tuple_level_analysis, d_top_dst_communication_target,\
           d_ipsrc_ports, d_ipdst_ports, d_top_dst_macaddr_communication_target


def do_iplevel_analysis(fn_input):
    """
    Execute analysis over the IP level information from the file.
    :param fn_input:
    :return:
    """
    fn_output_pattern_src_addr = "ip=src"
    fn_output_pattern_dst_addr = "ip=dst"

    try:
        reader = fputil.get_flowrecords_from_flowdata_file(fn_input)

        # timestamp built to filter traffic info that goes up (gained)
        # to filter the traffic that goes down (lost) is needed to check the set from the past, to do that add to calc
        # ' - datetime.timedelta(minutes=5) '
        dt_timestamp_label_key = fputil.extract_timestamp_from_flowfilepath(fn_input)
        s_timestamp_label_key = str(tutil.formated_date(tutil.date_to_ts(dt_timestamp_label_key)))

        print "Starting -- {}: {}".format(s_timestamp_label_key, fn_input)

        d_ipsrc_level_analysis, \
        d_ipdst_level_analysis, \
        d_ipsrc_ports_protocols, \
        d_ipdst_ports_protocols, \
        d_tuple_level_analysis, \
        d_top_dst_communication_target, \
        d_ipsrc_ports, d_ipdst_ports, \
        d_top_dst_macaddr_commun_target = count_uniq_ip(reader, s_timestamp_label_key, d_filters=d_filter_to_apply)

        if gen_intermediate_5min_files:
            # save data log for the whole traffic (src, dst + ports info)
            save_to_logfile(d_ipsrc_level_analysis, d_ipsrc_ports_protocols, fn_input, fn_output_pattern_src_addr,
                            filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset)
            save_to_logfile(d_ipdst_level_analysis, d_ipdst_ports_protocols, fn_input, fn_output_pattern_dst_addr,
                            filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset)

            # save data log for the top ip destinations
            save_tofile_topdst_data(d_top_dst_communication_target, fn_input, "", filter_ip_version, filter_svln,
                                    filter_protocol_flows, id_customer_cone_algo_dataset)

        d_ipsrc_level_analysis.clear()
        d_ipdst_level_analysis.clear()
        d_ipsrc_ports_protocols.clear()
        d_ipdst_ports_protocols.clear()
        d_tuple_level_analysis.clear()

        return [d_top_dst_communication_target, d_ipsrc_ports, d_ipdst_ports, d_top_dst_macaddr_commun_target]

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


def post_processing_aggregate_results(l_l_results):
    """
    Exec selected post-processing data after multiprocessing.
    :param l_l_results:
    :return:
    """

    d_output_topdst_targets_info = dict()
    d_output_src_ports_info = dict()
    d_output_dst_ports_info = dict()
    d_output_top_dst_macaddr_info = dict()

    for results_record in l_l_results:

        # start processing top dst for each 5-min file results and aggregate data
        l_d_top_dst_communication_target = results_record[0]

        for k_ipdst, l_setvalues in l_d_top_dst_communication_target.iteritems():

            if k_ipdst not in d_output_topdst_targets_info:
                d_output_topdst_targets_info[k_ipdst] = l_setvalues
            else:
                d_output_topdst_targets_info[k_ipdst][0] = d_output_topdst_targets_info[k_ipdst][0].union(l_setvalues[0])
                d_output_topdst_targets_info[k_ipdst][1] = d_output_topdst_targets_info[k_ipdst][1].union(l_setvalues[1])
                d_output_topdst_targets_info[k_ipdst][2] = map(add, d_output_topdst_targets_info[k_ipdst][2], l_setvalues[2])

        # src ports analysis data post-processing
        l_d_src_ports = results_record[1]
        for port_id, l_setvalues in l_d_src_ports.iteritems():

            if port_id not in d_output_src_ports_info:
                d_output_src_ports_info[port_id] = l_setvalues
            else:
                d_output_src_ports_info[port_id][0] = d_output_src_ports_info[port_id][0].union(l_setvalues[0])
                d_output_src_ports_info[port_id][1] = map(add, d_output_src_ports_info[port_id][1], l_setvalues[1])

        # dst ports analysis data post-processing
        l_d_dst_ports = results_record[2]
        for port_id, l_setvalues in l_d_dst_ports.iteritems():

            if port_id not in d_output_dst_ports_info:
                d_output_dst_ports_info[port_id] = l_setvalues
            else:
                d_output_dst_ports_info[port_id][0] = d_output_dst_ports_info[port_id][0].union(l_setvalues[0])
                d_output_dst_ports_info[port_id][1] = map(add, d_output_dst_ports_info[port_id][1], l_setvalues[1])

        # Mac Addresses Destionation analysis data post-processing
        l_d_top_macaddr_dst_data = results_record[3]
        for k_mac_asn_dst, l_setvalues in l_d_top_macaddr_dst_data.iteritems():

            if k_mac_asn_dst not in d_output_top_dst_macaddr_info:
                d_output_top_dst_macaddr_info[k_mac_asn_dst] = l_setvalues
            else:
                d_output_top_dst_macaddr_info[k_mac_asn_dst][0] = d_output_top_dst_macaddr_info[k_mac_asn_dst][0].union(l_setvalues[0])
                d_output_top_dst_macaddr_info[k_mac_asn_dst][1] = map(add, d_output_top_dst_macaddr_info[k_mac_asn_dst][1], l_setvalues[1])

    return [d_output_topdst_targets_info, d_output_src_ports_info, d_output_dst_ports_info, d_output_top_dst_macaddr_info]


def get_timestamp_from_flowfilename(fn_input):
    """
    Given a flow file name extract timestamp info.
    :param fn_input:
    :return:
    """

    flow_filename = path.basename(fn_input)
    if flow_filename:
        flow_filename_timestamp = flow_filename.split('.')[1]
        return flow_filename_timestamp
    else:
        print "Exception trying to get timestamp label from file."
        return None


def save_tofile_top_dst_macaddr_data(d_top_dst_macaddr_commun_target, fn_input, tw,
                                     filter_ip_version, filter_svln,
                                     filter_protocol_flows, id_customer_cone_algo_dataset):
    """
    Save macddr dst data information to file.
    [unique dst mac addresses; member ASN; qty unique ip sources; traffic volume gen; qty packets gen; qty flows where dst ipaddr appears]

    :param d_topdst_commun_target:
    :param fn_input:
    :param filter_ip_version:
    :param filter_svln:
    :return:
    """

    if fn_input != "":
        # get timestamp from filename
        flow_filename_timestamp = get_timestamp_from_flowfilename(fn_input)
    else:
        flow_filename_timestamp = tw

    fn_output_pattern = "{file_dest_dir}top-dst-macaddr-flowdata.{twindow}.cat={lbl_category}.ipv={ip_version}.svln={filter_svln}.pr={filter_protocol}.idcc={id_cc_version}.txt.gz"
    fn_output_name = fn_output_pattern.format(file_dest_dir=base_tmp_dir,
                                              twindow=flow_filename_timestamp,
                                              lbl_category=op_category_to_process,
                                              ip_version=filter_ip_version,
                                              filter_svln=filter_svln,
                                              filter_protocol=filter_protocol_flows,
                                              id_cc_version=id_customer_cone_algo_dataset)

    sorted_d_top_dst_macaddr_analysis = sorted(d_top_dst_macaddr_commun_target.items(), key=lambda (k, v): v[1][0], reverse=True)

    with gzip.open(fn_output_name, 'wb') as f:
        for record in sorted_d_top_dst_macaddr_analysis:
            row_formatted = "{dst_macaddr};{dst_mac_asn};{qty_srcs};{tvolume};{qty_packets};{qty_flows}".format(
                                                                                      dst_macaddr=record[0][0],
                                                                                      dst_mac_asn=record[0][1],
                                                                                      qty_srcs=len(record[1][0]),
                                                                                      tvolume=record[1][1][1],
                                                                                      qty_packets=record[1][1][2],
                                                                                      qty_flows=record[1][1][0])
            f.write(row_formatted + "\n")


def save_tofile_topdst_data(d_topdst_commun_target, fn_input, tw,
                            filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset):
    """
    Save dst data information to file.
    [unique dst ipaddresses; qty unique ip sources; traffic volume gen; qty packets gen; qty flows where dst ipaddr appears]

    :param d_topdst_commun_target:
    :param fn_input:
    :param filter_ip_version:
    :param filter_svln:
    :return:
    """

    if fn_input != "":
        # get timestamp from filename
        flow_filename_timestamp = get_timestamp_from_flowfilename(fn_input)
    else:
        flow_filename_timestamp = tw

    fn_output_pattern = "{file_dest_dir}topdst-flowdata.{twindow}.cat={lbl_category}.ipv={ip_version}.svln={filter_svln}.pr={filter_protocol}.idcc={id_cc_version}.txt.gz"
    fn_output_name = fn_output_pattern.format(file_dest_dir=base_tmp_dir,
                                              twindow=flow_filename_timestamp,
                                              lbl_category=op_category_to_process,
                                              ip_version=filter_ip_version,
                                              filter_svln=filter_svln,
                                              filter_protocol=filter_protocol_flows,
                                              id_cc_version=id_customer_cone_algo_dataset)

    sorted_d_topdst_analysis = sorted(d_topdst_commun_target.items(), key=lambda (k, v): v[2][0], reverse=True)

    with gzip.open(fn_output_name, 'wb') as f:
        for record in sorted_d_topdst_analysis:
            row_formatted = "{ipdst};{qty_srcs};{qty_ingress_asn};{tvolume};{qty_packets};{qty_flows};{set_of_ingress_asns}".format(
                                                                                      ipdst=record[0],
                                                                                      qty_srcs=len(record[1][0]),
                                                                                      qty_ingress_asn=len(record[1][1]),
                                                                                      tvolume=record[1][2][1],
                                                                                      qty_packets=record[1][2][2],
                                                                                      qty_flows=record[1][2][0],
                                                                                      set_of_ingress_asns=record[1][1]
            )
            f.write(row_formatted + "\n")


def save_tofile_ports_analysis_data(d_ports_analysis, fn_input, tw, s_ip_direction,
                                    filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset):

    if fn_input != "":
        # get timestamp from filename
        flow_filename_timestamp = get_timestamp_from_flowfilename(fn_input)
    else:
        flow_filename_timestamp = tw

    fn_output_pattern = "{file_dest_dir}ports-flowsanalysis.{twindow}.ip={ip_dir}.cat={lbl_category}.ipv={ip_version}.svln={filter_svln}.pr={filter_protocol}.idcc={id_cc_version}.txt.gz"
    fn_output_name = fn_output_pattern.format(file_dest_dir=base_tmp_dir,
                                              twindow=flow_filename_timestamp,
                                              ip_dir=s_ip_direction,
                                              lbl_category=op_category_to_process,
                                              ip_version=filter_ip_version,
                                              filter_svln=filter_svln,
                                              filter_protocol=filter_protocol_flows,
                                              id_cc_version=id_customer_cone_algo_dataset)

    sorted_d_ports_analysis = sorted(d_ports_analysis.items(), key=lambda (k, v): v[1][0], reverse=True)

    with gzip.open(fn_output_name, 'wb') as f:
        for record in sorted_d_ports_analysis:
            row_formatted = "{protocol};{port};{qty_ipaddr};{qty_flows};{tvolume};{qty_packets}".format(protocol=record[0][0],
                                                                   port=record[0][1],
                                                                   qty_ipaddr=len(record[1][0]),
                                                                   qty_flows=record[1][1][0],
                                                                   tvolume=record[1][1][1],
                                                                   qty_packets=record[1][1][2]
                                                                   )
            f.write(row_formatted + "\n")


def save_to_logfile(d_ip_level_analysis, d_ip_ports_protocols, fn_input, fn_label,
                    filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset):
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

    # get timestamp from filename
    flow_filename_timestamp = get_timestamp_from_flowfilename(fn_input)

    fn_output_pattern = "{file_dest_dir}flowdata.{twindow}.{file_label}.ipv={ip_version}.svln={filter_svln}.pr={filter_protocol}.idcc={id_cc_version}.txt.gz"
    fn_output_name = fn_output_pattern.format(file_dest_dir=base_tmp_dir,
                                              twindow=flow_filename_timestamp,
                                              file_label=fn_label,
                                              ip_version=filter_ip_version,
                                              filter_svln=filter_svln,
                                              filter_protocol=filter_protocol_flows,
                                              id_cc_version=id_customer_cone_algo_dataset)

    # order records by bytes volume desc and write dict result to log file
    sorted_d_ip_level_analysis = sorted(d_ip_level_analysis.items(), key=lambda (k, v): v[1], reverse=True)

    # Output print patterns
    print_header_row_pattern = '{:<13}|{:<10}|{:<50s}|{:<8}|{:<8}|{:<10}|{:<50}|{:<20}|{:<15}|{:<20}|{:<20}'
    print_row_pattern = '{ip:<16.16s}|{prefix:<18.18s}|{asn:<8.8s}|{as_name:<25.25s}|{ip_country:3.3s}|{vlan:<6.6s}|{asn_ingress_point:<8.8s}|{asn_ingress_point_name:<25.25s}|{asn_egress_point:<8.8s}|{asn_egress_point_name:<25.25s}|{ports:<15.15s}|{protocols:10.10s}|{vol_bytes:<20.20s}|{qty_packets:<15.15s}|{qty_flows:<10.10s}'

    with gzip.open(fn_output_name, 'wb') as f:

        '''
        Data structure ordered [ [set(),list()], 
                                 [], [], ... ]
            # k = (flow_ip, origin_asn, asn_name, ip_prefix, country_code, asn_ingress_point, asn_ingress_point_name, asn_egress_point, asn_egress_point_name, src_vlan_tag)
            # values = [1, flow_bytes, flow_packets]
        '''
        for record in sorted_d_ip_level_analysis:

            ipaddr = record[0][0]
            s_ports = d_ip_ports_protocols[ipaddr][0]
            s_protocols = d_ip_ports_protocols[ipaddr][1]

            row_formated = print_row_pattern.format(ip=record[0][0],
                                                    prefix=record[0][3],
                                                    asn=str(record[0][1]),
                                                    as_name=record[0][2],
                                                    ip_country=record[0][4],
                                                    vlan=str(record[0][9]),
                                                    asn_ingress_point=str(record[0][5]),
                                                    asn_ingress_point_name=record[0][6],
                                                    asn_egress_point=str(record[0][7]),
                                                    asn_egress_point_name=record[0][8],
                                                    ports=";".join(str(e) for e in s_ports),
                                                    protocols=";".join(str(e) for e in s_protocols),
                                                    vol_bytes=str(record[1][1]),
                                                    qty_packets=str(record[1][2]),
                                                    qty_flows=str(record[1][0])
                                                    )

            f.write(row_formated + "\n")
    f.close()


def load_iplist_to_filter_trafficdata(fn_path_iplist):
    """
    Receive as input a file with the list of IPs to filter to further analysis from traffic flow data.
    :param fn_path_iplist:
    :return:
    """
    d_ips = dict()

    print "List of IPs file: {}".format(fn_path_iplist)

    iplist_file = open(fn_path_iplist, "r")
    reader = csv.reader(iplist_file, delimiter=';')

    for line in reader:
        d_ips[line[0]] = set(ast.literal_eval(line[1]))

    print "List of IPs set size per timestamp:"
    sorted_d_ips = sorted(d_ips.items(), key=lambda (k, v): k)
    for record in sorted_d_ips:
        print "{}: {}".format(record[0], len(record[1]))

    return d_ips


def filter_toselect_flows(flow_record, s_timestamp_label_key):
    """
    Filter records from traffic flow to a subset of which are required further analysis.
    :param flow_record:
    :param s_timestamp_label_key:
    :return:
    """

    # traffic filter processing is enabled
    if fn_path_iplist_tofilter_analysis is not None:

        if parsed_args.traffic_filter_direction == 0:
            s_flow_ip = fputil.record_to_ip(flow_record['sa'])
        else:
            s_flow_ip = fputil.record_to_ip(flow_record['da'])

        if s_flow_ip in set(d_ipset_per_timenin[s_timestamp_label_key]):
            return True
        else:
            return False

    # if it's not enable to filter traffic to a subset, then always True
    else:
        return True


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
                             "Syntax: as string {'ip': 4, 'svlan': 'all'}")

    parser.add_argument('-cat', dest='op_category_to_process', type=int, choices=[0, 1, 2, 3, 4], required=True,
                        help="Define the category that must be processed and analyzed. "
                             " Syntax: '[0-bogon, 1-unrouted, 2-incone, 3-out-of-cone, 4-unverifiable]' ")

    parser.add_argument('-g5min', dest='gen_intermediate_5min_files', type=int, choices=[0, 1], required=True,
                        help="Indicate if should create intermediate 5min files "
                             "with data processed for further analysis.")

    parser.add_argument('-lips', dest='fpath_to_ips_data_analysis', required=False,
                        help="File path to IP addresses file to load, filter and create analysis view.")

    parser.add_argument('-fdir', dest='traffic_filter_direction', type=int, choices=[0, 1], required=False,
                        help="Define the direction src or dst which should be applied to filter "
                             "traffic using the file loaded. "
                             "Options: 0 - src"
                             "         1 - dst")

    parser.add_argument('-ccid', dest='customercone_algoid', type=int, choices=[4, 8], required=True,
                        help="Options: "
                             "4 - IMC17 FullCone "
                             "8 - CoNEXT19 Prefix-Level Customer Cone.")

    parser.add_argument('-as2org', dest='s_as2org_epoch_input', required=True,
                        help="Year id to define which CAIDA AS2ORG dataset to be loaded during processing.")

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

    if not parsed_args.op_category_to_process is None:
        op_category_to_process = l_categories[parsed_args.op_category_to_process]

    if parsed_args.gen_intermediate_5min_files:
        gen_intermediate_5min_files = True
    else:
        gen_intermediate_5min_files = False

    if parsed_args.fpath_to_ips_data_analysis:
        fn_path_iplist_tofilter_analysis = parsed_args.fpath_to_ips_data_analysis
    else:
        fn_path_iplist_tofilter_analysis = None

    # ------------------------------------------------------------------
    #   Analysis logic processes start
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
    d_mapping_macaddress_member_asn = ixp_member_util.build_dict_mapping_macaddress_members_asns(
        cons.DEFAULT_MACADDRESS_ASN_MAPPING)

    print "---Loading CAIDA as2org mapping data..."
    s_as2org_epoch_input = parsed_args.s_as2org_epoch_input
    # First lookup for ASN to get ORG_ID, then lookup at the ORG_DATA to get the name
    d_mapping_org_data, d_mapping_as_data = as2orgutil.build_dicts_as2org_caida_mapping(s_as2org_epoch_input)

    if fn_path_iplist_tofilter_analysis is not None:
        print "---Loading IPs to filter from traffic flow data..."
        d_ipset_per_timenin = load_iplist_to_filter_trafficdata(fn_path_iplist_tofilter_analysis)

    print "---Creating list of files for processing (5-min flow files):"
    # if user input choice is to process each file category generate input names to multiprocessing step
    default_flowtraffic_datafile = ".avro"
    pattern_file_extension = '{def_ext}.idcc={id_cc_version}.class={lbl_class}'

    l_pattern_file_extensions = [pattern_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                               id_cc_version=id_customer_cone_algo_dataset,
                                                               lbl_class=op_category_to_process)]

    l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                      flowfiles_basedir,
                                                                                      l_pattern_file_extensions)

    print "---Started multiprocessing traffic data..."
    mp = mpPool.MultiprocessingPool(n_cores_to_use)
    results = mp.get_results_map_multiprocessing(do_iplevel_analysis, l_filenames_to_process)

    print "---Started post-processing classification results"
    d_output_results_postprocessed = post_processing_aggregate_results(results)

    d_output_topdst_targets_info = d_output_results_postprocessed[0]
    save_tofile_topdst_data(d_output_topdst_targets_info, "", parsed_args.time_window_op,
                            filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset)

    d_output_src_ports_info = d_output_results_postprocessed[1]
    save_tofile_ports_analysis_data(d_output_src_ports_info, "", parsed_args.time_window_op, 'src',
                                    filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset)

    d_output_dst_ports_info = d_output_results_postprocessed[2]
    save_tofile_ports_analysis_data(d_output_dst_ports_info, "", parsed_args.time_window_op, 'dst',
                                    filter_ip_version, filter_svln, filter_protocol_flows, id_customer_cone_algo_dataset)

    d_output_top_dst_macaddr_targets_info = d_output_results_postprocessed[3]
    save_tofile_top_dst_macaddr_data(d_output_top_dst_macaddr_targets_info, "", parsed_args.time_window_op,
                                     filter_ip_version, filter_svln, filter_protocol_flows,
                                     id_customer_cone_algo_dataset)

    end = timer()
    print "---Total execution time: {} seconds".format(end - start)

    print "---Sending e-mail notification about the execution status:"
    notifutil.send_notification_end_of_execution(sys.argv, sys.argv[0], start, end)
