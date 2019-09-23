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
import utils.prefixes_utils_routeviews as putilrv
import argparse
import sys
import utils.cmdline_interface_utilities as cmdutil
import ast
import traceback
from operator import add
from timeit import default_timer as timer
from itertools import islice
import copy
import gzip
from json import dump
import pyasn

"""
---------------------------------------ABOUT----------------------------------------
Process original traffic flow data, cutting and aggregating data to export 
protocol traffic proprieties in bins for the different categories.
------------------------------------------------------------------------------------
"""


class PerInferredASNAnalysis(object):
    """
    Manage inferred ASN (through IP address) analysis accounting for each ASN and its [bytes, packets].
    """

    def __init__(self):
        self.d_asn_traffic = dict()

    def update_ip_asn_data(self, int_ipaddress, flow_bytes, flow_packets):
        """
        Account bytes, packets per unique ASN.
        :param port:
        :param int_ipaddress:
        :param flow_bytes:
        :param flow_packets:
        :return:
        """

        values = [flow_bytes, flow_packets]

        # extract ASN from IP
        str_flow_asn = fputil.record_to_ip(int_ipaddress)
        i_ip_asn, s_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(str_flow_asn)

        if i_ip_asn not in self.d_asn_traffic:
            self.d_asn_traffic[i_ip_asn] = values
        else:
            self.d_asn_traffic[i_ip_asn] = map(add, self.d_asn_traffic[i_ip_asn], values)

    def get_data(self):
        return self.d_asn_traffic


class PerPortIPAddressesAnalysis(object):
    """
    Manage L7 protocol analysis accounting each IP Addresses and its bytes, packets
    """

    def __init__(self):
        self.d_protocol = dict()

    def update_port_ip_data(self, port, int_ipaddress, flow_bytes, flow_packets):
        """
        Account bytes, packets per unique IP Addresses identified per Port.
        :param port:
        :param int_ipaddress:
        :param flow_bytes:
        :param flow_packets:
        :return:
        """

        values = [flow_bytes, flow_packets]

        if port not in self.d_protocol:
            self.d_protocol[port] = dict()
            self.d_protocol[port][int_ipaddress] = values
        else:
            if int_ipaddress not in self.d_protocol[port]:
                self.d_protocol[port][int_ipaddress] = values
            else:
                self.d_protocol[port][int_ipaddress] = map(add, self.d_protocol[port][int_ipaddress], values)

    def get_data(self):
        return self.d_protocol


class TopProtocolAnalysis(object):
    """
    Manage the protocol L7 analysis per 5min-bin.
    """

    def __init__(self):
        self.d_protocol_sum = dict()
        self.d_port_ips_sum = dict()

    def update_port_sum(self, port, bytes, packets):

        values = [bytes, packets]

        if port not in self.d_protocol_sum:
            self.d_protocol_sum[port] = values
        else:
            self.d_protocol_sum[port] = map(add, self.d_protocol_sum[port], values)

    def is_there_data_port_ips_sum(self):
        return len(self.d_port_ips_sum)

    def get_protocol_sum(self):
        return self.d_protocol_sum

    def get_protocol_sum_values_by_key(self, protocol):
        return self.d_protocol_sum[protocol]

    def get_sorted_protocol_sum(self, option):
        """
        Return d_protocol_sum order ports by bytes decreasing.
        :return:
        """
        if option == "BYTES":
            return sorted(self.d_protocol_sum.items(), key=lambda (k, v): v[0], reverse=True)
        elif option == "PACKETS":
            return sorted(self.d_protocol_sum.items(), key=lambda (k, v): v[1], reverse=True)

    def update_port_ips_sum(self, port, int_ipaddress):
        """
        Store per Port the unique IP Addresses identified.
        :param port:
        :param int_ipaddress:
        :return:
        """
        if port not in self.d_port_ips_sum:
            self.d_port_ips_sum[port] = set()
            self.d_port_ips_sum[port].add(int_ipaddress)
        else:
            self.d_port_ips_sum[port].add(int_ipaddress)

    def get_count_port_unique_ips(self):
        """
        Get a dict with k = port identification and v = count(unique IPs).
        :return:
        """
        tmp = dict()

        for k, v in self.d_port_ips_sum.items():
            tmp[k] = len(v)

        return tmp

    def get_port_unique_ips_utilized(self, port):
        """
        Get number of unique IPs utilized on flows which matched the specified port.
        :param port:
        :return:
        """
        return len(self.d_port_ips_sum[port])

    def get_port_ips_utilized(self, port):
        """
        Get list of IPs utilized on flows which matched the specified port.
        :param port:
        :return:
        """
        return self.d_port_ips_sum[port]

    def get_sorted_port_unique_ips_utilized(self):
        """
        Return d_port_ips_sum order ports by unique IPs count decreasing.
        :return:
        """
        return sorted(self.d_port_ips_sum.items(), key=lambda (k, v): len(v), reverse=True)

    def get_total_unique_ips_per_protocol(self):
        """
        Get the total of unique IPs to a given protocol/direction.
        :return:
        """
        total = set()

        for k, v in self.d_port_ips_sum.items():
            for ip in v:
                total.add(ip)

        return len(total)


class OverallProtocolAnalysis(object):
    """
    Manage the protocol L4 analysis per 5min-bin.
    """

    def __init__(self):

        self.tprops = {
            cons.BYTES_TOTAL: 0,
            cons.PACKETS_TOTAL: 0,

            cons.TCP_BYTES_TOTAL: 0,
            cons.TCP_FLAG_SYN_BYTES_TOTAL: 0,
            cons.TCP_FLAG_SYNACK_BYTES_TOTAL: 0,
            cons.TCP_FLAG_ACK_BYTES_TOTAL: 0,
            cons.TCP_FLAG_RESET_BYTES_TOTAL: 0,
            cons.TCP_FLAG_PUSH_BYTES_TOTAL: 0,
            cons.TCP_FLAG_FIN_BYTES_TOTAL: 0,
            cons.TCP_FLAG_UNUSUALL_BYTES_TOTAL: 0,
            cons.TCP_NO_FLAGS_BYTES_TOTAL: 0,

            cons.TCP_PACKETS_TOTAL: 0,
            cons.TCP_FLAG_SYN_PACKETS_TOTAL: 0,
            cons.TCP_FLAG_SYNACK_PACKETS_TOTAL: 0,
            cons.TCP_FLAG_ACK_PACKETS_TOTAL: 0,
            cons.TCP_FLAG_RESET_PACKETS_TOTAL: 0,
            cons.TCP_FLAG_PUSH_PACKETS_TOTAL: 0,
            cons.TCP_FLAG_FIN_PACKETS_TOTAL: 0,
            cons.TCP_FLAG_UNUSUALL_PACKETS_TOTAL: 0,
            cons.TCP_NO_FLAGS_PACKETS_TOTAL: 0,

            cons.UDP_BYTES_TOTAL: 0,
            cons.UDP_PACKETS_TOTAL: 0
        }

        self.bytes_total = 0
        self.packets_total = 0

        self.tcp_bytes_total = 0
        self.tcp_flag_syn_bytes_total = 0

        self.tcp_packets_total = 0
        self.tcp_flag_syn_packets_total = 0

        self.udp_bytes_total = 0
        self.udp_packets_total = 0

        self.d_tcp_unique_src_ips = dict()
        self.d_tcp_unique_dst_ips = dict()

        self.d_udp_unique_src_ips = dict()
        self.d_udp_unique_dst_ips = dict()

    def add_tprops(self, k_tpropriety, value):
        self.tprops[k_tpropriety] += value

    def get_tprop_value(self, k_tpropriety):
        return self.tprops[k_tpropriety]

    def add_src_ip_to_dict(self, l4_protocol, value):
        """
        Save int representation of src IP Address.
        :param value:
        :return:
        """
        if l4_protocol == "TCP":
            if value not in self.d_tcp_unique_src_ips:
                self.d_tcp_unique_src_ips[value] = 1
            else:
                self.d_tcp_unique_src_ips[value] += 1

        elif l4_protocol == "UDP":
            if value not in self.d_udp_unique_src_ips:
                self.d_udp_unique_src_ips[value] = 1
            else:
                self.d_udp_unique_src_ips[value] += 1

    def add_dst_ip_to_dict(self, l4_protocol, value):
        """
        Save int representation of dst IP Address.
        :param value:
        :return:
        """
        if l4_protocol == "TCP":
            if value not in self.d_tcp_unique_dst_ips:
                self.d_tcp_unique_dst_ips[value] = 1
            else:
                self.d_tcp_unique_dst_ips[value] += 1

        elif l4_protocol == "UDP":
            if value not in self.d_udp_unique_dst_ips:
                self.d_udp_unique_dst_ips[value] = 1
            else:
                self.d_udp_unique_dst_ips[value] += 1

    def get_count_unique_src_ips(self, option="ALL"):
        """
        Return to a 5-min bucket of traffic the total of unique IPs recorded during analysis.
        :param option: ALL (tcp + udp), only TCP or only UDP
        :return:
        """

        if option == "ALL":
            count_unique_ips = len(self.d_tcp_unique_src_ips) + len(self.d_udp_unique_src_ips)

        elif option == "TCP":
            count_unique_ips = len(self.d_tcp_unique_src_ips)

        elif option == "UDP":
            count_unique_ips = len(self.d_udp_unique_src_ips)

        return count_unique_ips

    def get_count_unique_dst_ips(self, option="ALL"):
        """
        Return to a 5-min bucket of traffic the total of unique IPs recorded during analysis.
        :param option: ALL (tcp + udp), only TCP or only UDP
        :return:
        """

        if option == "ALL":
            count_unique_ips = len(self.d_tcp_unique_dst_ips) + len(self.d_udp_unique_dst_ips)

        elif option == "TCP":
            count_unique_ips = len(self.d_tcp_unique_dst_ips)

        elif option == "UDP":
            count_unique_ips = len(self.d_udp_unique_dst_ips)

        return count_unique_ips


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


def query_ip2prefixasn_routeviewsdb(ip_address):
    """
    Perform a lookup on Routeviews database to get the prefix and ASN numbers.
    :param ip_address:
    :return:
    """
    try:
        prefix_lookup_result = f_global_asndb_routeviews.lookup(ip_address)
        origin_asn_lookup = prefix_lookup_result[0]
        ip_prefix_lookup = prefix_lookup_result[1]
    except:
        # if fail to lookup, then store raw ipaddress
        ip_prefix_lookup = ip_address
        origin_asn_lookup = "NOT-FOUND"

    return ip_prefix_lookup, origin_asn_lookup


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


def matches_desired_flows(flow_ipsrc_asn, flow_ipdst_asn, flow_ingress_asn_filter, flow, d_filters):
    """
    Execute default flow filtering method (IP version, VLAN, etc) and add extra filter parameters
    to specific zoom-in analysis.
    :param flow_ipsrc_asn, flow_ipdst_asn, flow_ingress_asn can be -1 assuming the method default filters only or
    a ASN int number if informed by the user.
    """

    # execute default traffic flow filters
    if futil.matches_desired_set(flow, d_filters):

        # then proceed with extra filters.
        # In this case checking the traffic generated specifically for a given SRC or DST ASN / or going to INGRESS-ASN.
        if (flow_ipsrc_asn == -1) and (flow_ipdst_asn == -1) and (flow_ingress_asn_filter == -1):
            return True

        # active filter: traffic going into a INGRESS-ASN only
        elif (flow_ingress_asn_filter > -1) and (flow_ipsrc_asn == -1) and (flow_ipdst_asn == -1):

            # lookup mac2asn -- get and transform mac address to same format as mac2as mapping data
            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc']).replace(':', '').upper()
            flow_ingress_asn = get_asn_via_macaddress(flow_ingress_src_macaddr)

            if flow_ingress_asn is 'UNKNOWN':
                return False
            elif flow_ingress_asn_filter == flow_ingress_asn:
                return True
            elif flow_ingress_asn_filter != flow_ingress_asn:
                return False

        # active filter: traffic going into a INGRESS-ASN to a specific IP-DST-ASN
        elif (flow_ingress_asn_filter > -1) and (flow_ipsrc_asn == -1) and (flow_ipdst_asn > -1):

            # lookup mac2asn -- get and transform mac address to same format as mac2as mapping data
            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc']).replace(':', '').upper()
            flow_ingress_asn = get_asn_via_macaddress(flow_ingress_src_macaddr)

            # lookup IP-DST-ASN
            str_flow_da = fputil.record_to_ip(flow['da'])
            i_dst_asn, s_dst_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(str_flow_da)

            # in case any lookup fails isnt a match
            if (flow_ingress_asn is 'UNKNOWN') or (i_dst_asn is None):
                return False
            # if INGRESS-AS and IP-DST-AS match = OK
            elif (flow_ingress_asn_filter == flow_ingress_asn) and (i_dst_asn == flow_ipdst_asn):
                return True
            else:
                return False

        # active filter: SRC-ASN only
        elif (flow_ipsrc_asn > -1) and (flow_ipdst_asn == -1):
            str_flow_sa = fputil.record_to_ip(flow['sa'])
            i_src_asn, s_src_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(str_flow_sa)

            # if IP to ASN is not successful None is return, then assume that flow does not match the filter
            if i_src_asn is None:
                return False
            # if IP to ASN succeed then do comparison to evaluate flow match
            elif int(i_src_asn) == int(flow_ipsrc_asn):
                return True
            # if they dont match, flow is skipped from the analyses
            elif int(i_src_asn) != int(flow_ipsrc_asn):
                return False

        # active filter: DST-ASN only
        elif (flow_ipsrc_asn == -1) and (flow_ipdst_asn > -1):
            str_flow_da = fputil.record_to_ip(flow['da'])
            i_dst_asn, s_dst_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(str_flow_da)

            # if IP to ASN is not successful None is return, then assume that flow does not match the filter
            if i_dst_asn is None:
                return False
            # if IP to ASN succeed then do comparison to evaluate flow match
            elif int(i_dst_asn) == int(flow_ipdst_asn):
                return True
            # if they dont match, flow is skipped from the analyses
            elif int(i_dst_asn) != int(flow_ipdst_asn):
                return False

        # active filter: SRC-ASN and DST-ASN
        elif (flow_ipsrc_asn > -1) and (flow_ipdst_asn > -1):
            str_flow_sa = fputil.record_to_ip(flow['sa'])
            i_src_asn, s_src_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(str_flow_sa)

            str_flow_da = fputil.record_to_ip(flow['da'])
            i_dst_asn, s_dst_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(str_flow_da)

            # if IP to ASN is not successful None is return, then assume that flow does not match the filter
            if (i_src_asn is None) or (i_dst_asn is None):
                return False
            # if IP to ASN succeed then do comparison to evaluate flow match
            elif (int(i_src_asn) == int(flow_ipsrc_asn)) and (int(i_dst_asn) == int(flow_ipdst_asn)):
                return True
            # if they dont match, flow is skipped from the analyses
            elif (int(i_src_asn) != int(flow_ipsrc_asn)) or (int(i_dst_asn) != int(flow_ipdst_asn)):
                return False


def do_update_protocols_diversity_traffic_props(d_protocols_diversity_traffic_props, protocol,
                                                flow_bytes, flow_packets):

    values = [flow_bytes, flow_packets]

    if protocol not in d_protocols_diversity_traffic_props:
        d_protocols_diversity_traffic_props[protocol] = values
    else:
        d_protocols_diversity_traffic_props[protocol] = map(add, d_protocols_diversity_traffic_props[protocol], values)

    return d_protocols_diversity_traffic_props


def summarize_traffic_profile(l_d_flow_records, op_traffic_flow_direction, s_timestamp_label_key, d_filters={}):
    """
    Filter the traffic flow data and execute the processing analysis logic for network behavior metrics.
    Observation: do not account for other L4 protocols like ICMP, GRE.
    """

    # traffic overview totals by Layer 4 - TCP and UDP
    o_overall_l4_protocol_analysis = OverallProtocolAnalysis()

    # traffic overview totals by Layer 7 - exclusively UDP-DST analysis (check for potential amplification attacks)
    o_overall_l7_upd_src_analysis = TopProtocolAnalysis()
    o_overall_l7_upd_dst_analysis = TopProtocolAnalysis()

    # traffic stats accounting by Layer 7 DST-ports, recording each IP and corresponding bytes,packets
    # UDP - exclusively: DNS, NTP, QUIC
    o_l7port_ip_stats_upd_src = PerPortIPAddressesAnalysis()
    o_l7port_ip_stats_upd_dst = PerPortIPAddressesAnalysis()

    # TCP - exclusively: HTTP, HTTPS, DNS, TELNET, SSH
    o_l7port_ip_stats_tcp_src = PerPortIPAddressesAnalysis()
    o_l7port_ip_stats_tcp_dst = PerPortIPAddressesAnalysis()

    d_overall_ingress_ases = dict()

    # account for the destination traffic of a given INGRESS ASN being filtered
    o_overall_dst_ases_of_giveningress = PerInferredASNAnalysis()

    # account for L4 protocols diversity
    d_protocols_diversity_traffic_props = dict()

    for flow in l_d_flow_records:
        # print "Flow:", str(flow)
        if matches_desired_flows(op_src_asn_to_filter, op_dst_asn_to_filter, op_ingress_asn_to_filter, flow, d_filters):

            # get srcIP and dstIP
            int_flow_sa = flow['sa']
            int_flow_da = flow['da']

            # get bytes and packets
            flow_bytes = fputil.record_to_numeric(flow['ibyt'])
            flow_packets = fputil.record_to_numeric(flow['ipkt'])

            # get ports and protocol
            flow_sp_l7 = fputil.record_to_numeric(flow['sp'])
            flow_dp_l7 = fputil.record_to_numeric(flow['dp'])
            i_flow_pr_l4 = flow['pr']
            str_flow_pr_l4 = fputil.proto_int_to_str(i_flow_pr_l4)

            # get FLAGS value (get the flag value if we have the field, otherwise set to empty to follow processing)
            flow_flag = fputil.flags_int_to_str(flow['flg']) if ('flg' in flow) else ''

            # account for traffic protocols diversity properties
            d_protocols_diversity_traffic_props = do_update_protocols_diversity_traffic_props(d_protocols_diversity_traffic_props, fputil.proto_int_to_str(i_flow_pr_l4), flow_bytes, flow_packets)

            # account for total bytes and packets per 5min bins
            o_overall_l4_protocol_analysis.add_tprops(cons.BYTES_TOTAL, flow_bytes)
            o_overall_l4_protocol_analysis.add_tprops(cons.PACKETS_TOTAL, flow_packets)

            # account for L4 protocols breakdown
            if str_flow_pr_l4 == "TCP":
                o_overall_l4_protocol_analysis.add_tprops(cons.TCP_BYTES_TOTAL, flow_bytes)
                o_overall_l4_protocol_analysis.add_tprops(cons.TCP_PACKETS_TOTAL, flow_packets)

                # if record contains unusuall flags, print the flags in hex as 0x.. number
                if ('0x' in flow_flag):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_UNUSUALL_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_UNUSUALL_PACKETS_TOTAL, flow_packets)

                # if flag == SYN
                if (flow_flag == '....S.'):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_SYN_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_SYN_PACKETS_TOTAL, flow_packets)

                # if flag == SYN-ACK
                if ('S' in flow_flag) and ('A' in flow_flag):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_SYNACK_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_SYNACK_PACKETS_TOTAL, flow_packets)

                # if flag = ACK
                if (flow_flag == '.A....'):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_ACK_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_ACK_PACKETS_TOTAL, flow_packets)

                # if flag == RST
                if ('R' in flow_flag):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_RESET_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_RESET_PACKETS_TOTAL, flow_packets)

                # if flag == PUSH
                if ('P' in flow_flag):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_PUSH_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_PUSH_PACKETS_TOTAL, flow_packets)

                # if flag == FIN
                if ('F' in flow_flag):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_FIN_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_FLAG_FIN_PACKETS_TOTAL, flow_packets)

                # NO FLAG SET
                if (flow_flag == '......'):
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_NO_FLAGS_BYTES_TOTAL, flow_bytes)
                    o_overall_l4_protocol_analysis.add_tprops(cons.TCP_NO_FLAGS_PACKETS_TOTAL, flow_packets)

                o_overall_l4_protocol_analysis.add_src_ip_to_dict(str_flow_pr_l4, int_flow_sa)
                o_overall_l4_protocol_analysis.add_dst_ip_to_dict(str_flow_pr_l4, int_flow_da)

                # Compute data to analyze possible TCP Flooding attacks (lock analyses to destination UDP ports)
                # for each flow keep the DST PORT, count how many unique SRC IPs and DST IPs
                # 1 = DST
                if (op_traffic_flow_direction == 1) and ((flow_dp_l7 == cons.d_proto_l7_str_int["HTTP"]) or
                        (flow_dp_l7 == cons.d_proto_l7_str_int["HTTPS/QUIC"]) or
                        (flow_dp_l7 == cons.d_proto_l7_str_int["DNS"]) or
                        (flow_dp_l7 == cons.d_proto_l7_str_int["SSH"]) or
                        (flow_dp_l7 == cons.d_proto_l7_str_int["TELNET"])):
                    o_l7port_ip_stats_tcp_src.update_port_ip_data(flow_dp_l7, int_flow_sa, flow_bytes, flow_packets)
                    o_l7port_ip_stats_tcp_dst.update_port_ip_data(flow_dp_l7, int_flow_da, flow_bytes, flow_packets)
                # 0 = SRC
                elif (op_traffic_flow_direction == 0) and ((flow_sp_l7 == cons.d_proto_l7_str_int["HTTP"]) or
                        (flow_sp_l7 == cons.d_proto_l7_str_int["HTTPS/QUIC"]) or
                        (flow_sp_l7 == cons.d_proto_l7_str_int["DNS"]) or
                        (flow_sp_l7 == cons.d_proto_l7_str_int["SSH"]) or
                        (flow_sp_l7 == cons.d_proto_l7_str_int["TELNET"])):
                    o_l7port_ip_stats_tcp_src.update_port_ip_data(flow_sp_l7, int_flow_sa, flow_bytes, flow_packets)
                    o_l7port_ip_stats_tcp_dst.update_port_ip_data(flow_sp_l7, int_flow_da, flow_bytes, flow_packets)

            if str_flow_pr_l4 == "UDP":
                o_overall_l4_protocol_analysis.add_tprops(cons.UDP_BYTES_TOTAL, flow_bytes)
                o_overall_l4_protocol_analysis.add_tprops(cons.UDP_PACKETS_TOTAL, flow_packets)
                o_overall_l4_protocol_analysis.add_src_ip_to_dict(str_flow_pr_l4, int_flow_sa)
                o_overall_l4_protocol_analysis.add_dst_ip_to_dict(str_flow_pr_l4, int_flow_da)

                # Compute data to analyze possible UDP Amplification attacks (lock analyses to destination UDP ports)
                # for each flow keep the DST PORT, count how many unique SRC IPs and DST IPs
                o_overall_l7_upd_dst_analysis.update_port_sum(flow_dp_l7, flow_bytes, flow_packets)

                # >SRC
                o_overall_l7_upd_src_analysis.update_port_ips_sum(flow_dp_l7, int_flow_sa)

                # >DST
                o_overall_l7_upd_dst_analysis.update_port_ips_sum(flow_dp_l7, int_flow_da)

                # 1 = DST
                if (op_traffic_flow_direction == 1) and ((flow_dp_l7 == cons.d_proto_l7_str_int["DNS"]) or
                   (flow_dp_l7 == cons.d_proto_l7_str_int["NTP"]) or
                   (flow_dp_l7 == cons.d_proto_l7_str_int["HTTPS/QUIC"]) or
                   (flow_dp_l7 == 1024)):
                    o_l7port_ip_stats_upd_src.update_port_ip_data(flow_dp_l7, int_flow_sa, flow_bytes, flow_packets)
                    o_l7port_ip_stats_upd_dst.update_port_ip_data(flow_dp_l7, int_flow_da, flow_bytes, flow_packets)
                # 0 = SRC
                elif (op_traffic_flow_direction == 0) and ((flow_sp_l7 == cons.d_proto_l7_str_int["DNS"]) or
                     (flow_sp_l7 == cons.d_proto_l7_str_int["NTP"]) or
                     (flow_sp_l7 == cons.d_proto_l7_str_int["HTTPS/QUIC"]) or
                     (flow_sp_l7 == 1024)):
                    o_l7port_ip_stats_upd_src.update_port_ip_data(flow_sp_l7, int_flow_sa, flow_bytes, flow_packets)
                    o_l7port_ip_stats_upd_dst.update_port_ip_data(flow_sp_l7, int_flow_da, flow_bytes, flow_packets)

            # ###### lookup mac2asn ######
            # get and transform mac address to same format as mac2as mapping data
            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc']).replace(':', '').upper()
            flow_ingress_asn = 'UNKNOWN'
            if flow_ingress_src_macaddr in d_mapping_macaddress_member_asn:
                flow_ingress_asn = d_mapping_macaddress_member_asn[flow_ingress_src_macaddr][0]

            values = [flow_bytes, flow_packets]
            if flow_ingress_asn not in d_overall_ingress_ases:
                d_overall_ingress_ases[flow_ingress_asn] = values
            else:
                d_overall_ingress_ases[flow_ingress_asn] = map(add, d_overall_ingress_ases[flow_ingress_asn], values)

            # if INGRESS-ASN filter enabled then account for the DST traffic of the given INGRESS ASN being filtered
            if op_ingress_asn_to_filter > -1:
                o_overall_dst_ases_of_giveningress.update_ip_asn_data(int_flow_da, flow_bytes, flow_packets)

            # SYSOUT ANALYSIS PURPOSE ONLY
            if op_enable_sysout_prints:
                flow_svln_id = fputil.record_to_numeric(flow['svln'])
                flow_egress_dst_macaddress = fputil.record_to_mac(flow['odmc']).replace(':', '').upper()
                flow_egress_asn = get_asn_via_macaddress(flow_egress_dst_macaddress)

                s_src_ip = fputil.record_to_ip(int_flow_sa)
                s_dst_ip = fputil.record_to_ip(int_flow_da)
                srcip_port = s_src_ip + ":" + str(flow_sp_l7)
                dstip_port = s_dst_ip + ":" + str(flow_dp_l7)

                srcip_prefix_lookup, src_asn_lookup = query_ip2prefixasn_routeviewsdb(s_src_ip)
                dstip_prefix_lookup, dst_asn_lookup = query_ip2prefixasn_routeviewsdb(s_dst_ip)

                print "{:<4} | SRC: {:<22} -{:<8} | DST: {:<22} -{:<8} | FLAG: {:6} | BYTES: {:<8} | PACKETS: {:<5} | INGRESS: {:<8};{:<2} | EGRESS: {:<8};{:<2} | SVLAN: {:<5}".format(
                    str_flow_pr_l4,
                    srcip_port,
                    src_asn_lookup,
                    dstip_port,
                    dst_asn_lookup,
                    flow_flag,
                    flow_bytes,
                    flow_packets,
                    flow_ingress_asn,
                    len(d_mapping_macaddress_member_asn[flow_ingress_src_macaddr]),
                    flow_egress_asn,
                    len(d_mapping_macaddress_member_asn[flow_egress_dst_macaddress]) if flow_egress_dst_macaddress in d_mapping_macaddress_member_asn else '0',
                    flow_svln_id)

    return [o_overall_l4_protocol_analysis,
            o_overall_l7_upd_src_analysis, o_overall_l7_upd_dst_analysis,
            d_overall_ingress_ases,
            o_l7port_ip_stats_upd_src,
            o_l7port_ip_stats_upd_dst,
            o_l7port_ip_stats_tcp_src,
            o_l7port_ip_stats_tcp_dst,
            o_overall_dst_ases_of_giveningress,
            d_protocols_diversity_traffic_props]


def do_traffic_overall_stats_analysis(fn_input):
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
        l_profile_bin_results = summarize_traffic_profile(reader,
                                                          op_traffic_flow_direction,
                                                          s_timestamp_label_key,
                                                          d_filters=d_filter_to_apply)

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


def summarize_traffic_mix(l_d_flow_records, d_filters={}):
    """
    Filter the traffic flow data and execute the processing analysis logic for network behavior metrics.
    """

    o_tcp_src_analysis = TopProtocolAnalysis()
    o_tcp_dst_analysis = TopProtocolAnalysis()

    o_upd_src_analysis = TopProtocolAnalysis()
    o_upd_dst_analysis = TopProtocolAnalysis()

    for flow in l_d_flow_records:
        # print "Flow:", str(flow)
        if matches_desired_flows(op_src_asn_to_filter, op_dst_asn_to_filter, op_ingress_asn_to_filter, flow, d_filters):

            # get srcIP and dstIP
            int_flow_sa = flow['sa']

            # get bytes and packets
            flow_bytes = fputil.record_to_numeric(flow['ibyt'])
            flow_packets = fputil.record_to_numeric(flow['ipkt'])

            # get ports and protocol
            flow_sp = fputil.record_to_numeric(flow['sp'])
            flow_dp = fputil.record_to_numeric(flow['dp'])
            str_flow_pr = fputil.proto_int_to_str(flow['pr'])

            # process and save traffic information per selected L7 protocols and group other using -1 port number
            if str_flow_pr == "TCP":
                if flow_sp in cons.d_proto_l7_int_str.keys():
                    o_tcp_src_analysis.update_port_sum(flow_sp, flow_bytes, flow_packets)
                    o_tcp_src_analysis.update_port_ips_sum(flow_sp, int_flow_sa)
                else:
                    o_tcp_src_analysis.update_port_sum(-1, flow_bytes, flow_packets)
                    o_tcp_src_analysis.update_port_ips_sum(-1, int_flow_sa)

                if flow_dp in cons.d_proto_l7_int_str.keys():
                    o_tcp_dst_analysis.update_port_sum(flow_dp, flow_bytes, flow_packets)
                else:
                    o_tcp_dst_analysis.update_port_sum(-1, flow_bytes, flow_packets)

            if str_flow_pr == "UDP":
                if flow_sp in cons.d_proto_l7_int_str.keys():
                    o_upd_src_analysis.update_port_sum(flow_sp, flow_bytes, flow_packets)
                    o_upd_src_analysis.update_port_ips_sum(flow_sp, int_flow_sa)
                else:
                    o_upd_src_analysis.update_port_sum(-1, flow_bytes, flow_packets)
                    o_upd_src_analysis.update_port_ips_sum(-1, int_flow_sa)

                if flow_dp in cons.d_proto_l7_int_str.keys():
                    o_upd_dst_analysis.update_port_sum(flow_dp, flow_bytes, flow_packets)
                else:
                    o_upd_dst_analysis.update_port_sum(-1, flow_bytes, flow_packets)

    return [o_tcp_src_analysis, o_tcp_dst_analysis,
            o_upd_src_analysis, o_upd_dst_analysis]


def do_traffic_mix_protocols_analysis(fn_input):
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

        l_profile_bin_results = summarize_traffic_mix(reader, d_filters=d_filter_to_apply)

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


def post_processing_overall_stats_5min_results(l_d_results):
    """
    Exec selected post-processing data after multiprocessing.
    :param l_d_results: with the following contents

            [ 0 - o_overall_l4_protocol_analysis,
              1 - o_overall_l7_upd_src_analysis,
              2 - o_overall_l7_upd_dst_analysis,
              3 - d_overall_ingress_ases,
              4 - o_l7port_ip_stats_upd_src,
              5 - o_l7port_ip_stats_upd_dst,
              6 - o_l7port_ip_stats_tcp_src,
              7 - o_l7port_ip_stats_tcp_dst,
              8 - o_overall_dst_ases_of_giveningress,
              9 - d_protocols_diversity_traffic_props]

    :return:
    """

    d_flows_overall_stats_results = dict()
    d_flows_overall_l7_results = dict()
    d_flows_overall_ingress_ases = dict()
    d_flows_overall_dst_ases_traffic_of_giveningress = dict()
    d_flows_overall_protocols_diversity_traffic_props = dict()

    d_flows_udp_src_port_agg = dict()
    d_flows_udp_dst_port_agg = dict()

    d_l7port_ip_udp_src_stats_agg = dict()
    d_l7port_ip_udp_dst_stats_agg = dict()

    d_l7port_ip_tcp_src_stats_agg = dict()
    d_l7port_ip_tcp_dst_stats_agg = dict()

    for dict_result in l_d_results:

        # for each timestamp dict there is a list of results to be read all in object format
        for k, v in dict_result.items():
            o_overall_l4_protocol_analysis = v[0]
            d_protocol_sum = v[2].get_protocol_sum()

            # > Global 5min bin totals
            d_5min_flows_overall_stats = post_processing_5min_totals(k, o_overall_l4_protocol_analysis)
            d_flows_overall_stats_results[k] = d_5min_flows_overall_stats

            # > sum protocols stats
            for k_protocol, v_stats_protocol in d_protocol_sum.items():

                values = v_stats_protocol

                # aggregate the unique UDP filtered by DST-port get SRC IPs found per Port
                if k_protocol not in d_flows_udp_src_port_agg:
                    d_flows_udp_src_port_agg[k_protocol] = set(v[1].get_port_ips_utilized(k_protocol))
                elif k_protocol in d_flows_udp_src_port_agg:
                    d_flows_udp_src_port_agg[k_protocol].update(set(v[1].get_port_ips_utilized(k_protocol)))

                # aggregate the unique UDP filtered by DST-port get DST IPs found per Port
                if k_protocol not in d_flows_udp_dst_port_agg:
                    d_flows_udp_dst_port_agg[k_protocol] = set(v[2].get_port_ips_utilized(k_protocol))
                elif k_protocol in d_flows_udp_src_port_agg:
                    d_flows_udp_dst_port_agg[k_protocol].update(set(v[2].get_port_ips_utilized(k_protocol)))

                # aggregate bytes and packets UDP by DST-port
                if k_protocol not in d_flows_overall_l7_results:
                    d_flows_overall_l7_results[k_protocol] = values
                else:
                    d_flows_overall_l7_results[k_protocol] = map(add, d_flows_overall_l7_results[k_protocol], values)

            # > create output with the timestamp and current {INGRESS-ASN: [bytes, packets], ...} to further analysis
            d_flows_overall_ingress_ases[k] = v[3]

            # > create aggregated output for Port/IPs stats (bytes, packets)
            # UDP SRC-IP
            d_l7port_ip_stats_upd_src = v[4].get_data()
            d_l7port_ip_udp_src_stats_agg = do_aggregate_5min_port_ip_data_into_total_forperiod(d_l7port_ip_stats_upd_src, d_l7port_ip_udp_src_stats_agg)

            # UDP DST-IP
            d_l7port_ip_stats_upd_dst = v[5].get_data()
            d_l7port_ip_udp_dst_stats_agg = do_aggregate_5min_port_ip_data_into_total_forperiod(d_l7port_ip_stats_upd_dst, d_l7port_ip_udp_dst_stats_agg)

            # TCP SRC-IP
            d_l7port_ip_stats_tcp_src = v[6].get_data()
            d_l7port_ip_tcp_src_stats_agg = do_aggregate_5min_port_ip_data_into_total_forperiod(d_l7port_ip_stats_tcp_src, d_l7port_ip_tcp_src_stats_agg)

            # TCP DST-IP
            d_l7port_ip_stats_tcp_dst = v[7].get_data()
            d_l7port_ip_tcp_dst_stats_agg = do_aggregate_5min_port_ip_data_into_total_forperiod(d_l7port_ip_stats_tcp_dst, d_l7port_ip_tcp_dst_stats_agg)

            # if INGRESS-ASN filter enabled then account for the DST traffic of the given INGRESS ASN being filtered
            d_flows_overall_dst_ases_traffic_of_giveningress[k] = v[8].get_data()

            # > create output with the timestamp and current
            # {'L4-PROTOCOL-NAME': [bytes, packets], ...} to further analysis
            d_flows_overall_protocols_diversity_traffic_props[k] = v[9]

    # at the end append the total unique IPs locate for each protocol port
    for k_protocol, v_l_stats in d_flows_overall_l7_results.items():
        d_flows_overall_l7_results[k_protocol].append(len(d_flows_udp_src_port_agg[k_protocol]))  # unique SRC IPs
        d_flows_overall_l7_results[k_protocol].append(len(d_flows_udp_dst_port_agg[k_protocol]))  # unique DST IPs

    return d_flows_overall_stats_results, d_flows_overall_l7_results, d_flows_overall_ingress_ases,\
           d_l7port_ip_udp_src_stats_agg, d_l7port_ip_udp_dst_stats_agg, \
           d_l7port_ip_tcp_src_stats_agg, d_l7port_ip_tcp_dst_stats_agg, \
           d_flows_overall_dst_ases_traffic_of_giveningress, \
           d_flows_overall_protocols_diversity_traffic_props


def do_aggregate_5min_port_ip_data_into_total_forperiod(d_l7port_ip_stats_l4_src, d_l7port_ip_l4_direction_stats_agg):
    """
    Take as input a dict with a pre-selected flow Ports, each with the respectives IPs
    that generated traffic [bytes, packets] and group data of each 5min bin.
    :param d_l7port_ip_stats_l4_src:
                                    {
                                      l7_port_id: {
                                                    IP: [bytes, packets],
                                                    IP: [bytes, packets],
                                                    ...
                                                   },
                                      ...
                                    }
    :return:
    """

    for k_port, v_d_ips_stats in d_l7port_ip_stats_l4_src.items():

        # if Port not in dict create an entry for aggregation of all IPs exchanging traffic on each port
        if k_port not in d_l7port_ip_l4_direction_stats_agg:
            d_l7port_ip_l4_direction_stats_agg[k_port] = v_d_ips_stats

        # if Port already in dict, add or update IP entry to that port with its totals(bytes, packets)
        else:
            # check for each Port the existing IPaddresses recorded
            for k_ipaddress, v_l_stats in v_d_ips_stats.items():
                # if IP does not exist for the Port in analysis add it
                if k_ipaddress not in d_l7port_ip_l4_direction_stats_agg[k_port]:
                    d_l7port_ip_l4_direction_stats_agg[k_port][k_ipaddress] = v_l_stats
                # else, if exists just update the record values
                else:
                    d_l7port_ip_l4_direction_stats_agg[k_port][k_ipaddress] = \
                        map(add, d_l7port_ip_l4_direction_stats_agg[k_port][k_ipaddress], v_l_stats)

    return d_l7port_ip_l4_direction_stats_agg


def post_processing_traffic_mix_analysis_results(l_d_results):
    """
    Exec selected post-processing data after multiprocessing.
    :param l_d_results: with the following contents

            [o_tcp_src_analysis, o_tcp_dst_analysis,
             o_upd_src_analysis, o_upd_dst_analysis]

    :return:
    """

    d_flows_traffic_mix_preselected_l7protocols_results = dict()

    for dict_result in l_d_results:

        # for each timestamp dict there is a list of results to be read all in object format
        for k, v in dict_result.items():
            o_tcp_src_analysis = v[0]
            o_tcp_dst_analysis = v[1]
            o_upd_src_analysis = v[2]
            o_upd_dst_analysis = v[3]

            # Top TCP/SRC
            l_l7protocols_tcp_src = post_processing_preselected_l7ports(o_tcp_src_analysis)

            # Top TCP/DST
            l_l7protocols_tcp_dst = post_processing_preselected_l7ports(o_tcp_dst_analysis)

            # Top UDP/SRC
            l_l7protocols_udp_src = post_processing_preselected_l7ports(o_upd_src_analysis)

            # Top UDP/DST
            l_l7protocols_udp_dst = post_processing_preselected_l7ports(o_upd_dst_analysis)

            d_flows_traffic_mix_preselected_l7protocols_results[k] = [{'TCP-SRC': l_l7protocols_tcp_src},
                                                                      {'TCP-DST': l_l7protocols_tcp_dst},
                                                                      {'UDP-SRC': l_l7protocols_udp_src},
                                                                      {'UDP-DST': l_l7protocols_udp_dst}]

    return d_flows_traffic_mix_preselected_l7protocols_results


def post_processing_5min_totals(timestamp, o_overall_protocol_analysis):
    """
    Sum and organize the commom values per 5-min bins.
    :param timestamp:
    :param o_overall_protocol_analysis:
    :return:
    """

    bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.BYTES_TOTAL)
    packets_total = o_overall_protocol_analysis.get_tprop_value(cons.PACKETS_TOTAL)
    qty_src_unique_ips = o_overall_protocol_analysis.get_count_unique_src_ips()
    qty_dst_unique_ips = o_overall_protocol_analysis.get_count_unique_dst_ips()

    tcp_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_BYTES_TOTAL)
    tcp_syn_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_SYN_BYTES_TOTAL)
    percentage_bytes_tcp = round(float(tcp_bytes_total * 100.0 / bytes_total), 5) if bytes_total > 0 else 0
    percentage_bytes_tcp_syn = round(float(tcp_syn_bytes_total * 100.0 / tcp_bytes_total), 5) if tcp_bytes_total > 0 else 0
    tcp_synack_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_SYNACK_BYTES_TOTAL)
    tcp_ack_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_ACK_BYTES_TOTAL)
    tcp_reset_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_RESET_BYTES_TOTAL)
    tcp_push_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_PUSH_BYTES_TOTAL)
    tcp_fin_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_FIN_BYTES_TOTAL)
    tcp_flags_unusuall_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_UNUSUALL_BYTES_TOTAL)
    tcp_no_flags_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_NO_FLAGS_BYTES_TOTAL)

    tcp_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_PACKETS_TOTAL)
    tcp_syn_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_SYN_PACKETS_TOTAL)
    percentage_packets_tcp = round(float(tcp_packets_total * 100.0 / packets_total), 5) if tcp_packets_total > 0 else 0
    percentage_packets_tcp_syn = round(float(tcp_syn_packets_total * 100.0 / tcp_packets_total), 5) if tcp_packets_total > 0 else 0
    tcp_synack_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_SYNACK_PACKETS_TOTAL)
    tcp_ack_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_ACK_PACKETS_TOTAL)
    tcp_reset_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_RESET_PACKETS_TOTAL)
    tcp_push_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_PUSH_PACKETS_TOTAL)
    tcp_fin_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_FIN_PACKETS_TOTAL)
    tcp_flags_unusuall_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_FLAG_UNUSUALL_PACKETS_TOTAL)
    tcp_no_flags_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.TCP_NO_FLAGS_PACKETS_TOTAL)

    tcp_qty_src_unique_ips = o_overall_protocol_analysis.get_count_unique_src_ips("TCP")
    percentage_src_ips_tcp = round(float(tcp_qty_src_unique_ips * 100.0 / qty_src_unique_ips), 5) if qty_src_unique_ips > 0 else 0

    udp_bytes_total = o_overall_protocol_analysis.get_tprop_value(cons.UDP_BYTES_TOTAL)
    percentage_bytes_udp = round(float(udp_bytes_total * 100.0 / bytes_total), 5) if bytes_total > 0 else 0
    udp_packets_total = o_overall_protocol_analysis.get_tprop_value(cons.UDP_PACKETS_TOTAL)
    percentage_packets_udp = round(float(udp_packets_total * 100.0 / packets_total), 5) if packets_total > 0 else 0
    udp_qty_src_unique_ips = o_overall_protocol_analysis.get_count_unique_src_ips("UDP")
    percentage_src_ips_udp = round(float(udp_qty_src_unique_ips * 100.0 / qty_src_unique_ips), 5) if qty_src_unique_ips > 0 else 0

    print "{} -- TCP: {:.3f}% bytes/{:.3f}% packets (SYN: {:.3f}% bytes/{:.3f}% packets), {} unique src IPs ({:.3f}%), UDP: {:.3f}% bytes/{:.3f}% packets, {} unique src IPs ({:.3f}%)".format(timestamp,
                                                                                              percentage_bytes_tcp,
                                                                                              percentage_packets_tcp,
                                                                                              percentage_bytes_tcp_syn,
                                                                                              percentage_packets_tcp_syn,
                                                                                              tcp_qty_src_unique_ips,
                                                                                              percentage_src_ips_tcp,
                                                                                              percentage_bytes_udp,
                                                                                              percentage_packets_udp,
                                                                                              udp_qty_src_unique_ips,
                                                                                              percentage_src_ips_udp)

    return [bytes_total, packets_total, qty_src_unique_ips, qty_dst_unique_ips,
            tcp_bytes_total, percentage_bytes_tcp, tcp_packets_total, percentage_packets_tcp, tcp_qty_src_unique_ips, percentage_src_ips_tcp,
            udp_bytes_total, percentage_bytes_udp, udp_packets_total, percentage_packets_udp, udp_qty_src_unique_ips, percentage_src_ips_udp,
            tcp_syn_bytes_total, tcp_syn_packets_total,
            tcp_synack_bytes_total, tcp_synack_packets_total,
            tcp_ack_bytes_total, tcp_ack_packets_total,
            tcp_reset_bytes_total, tcp_reset_packets_total,
            tcp_push_bytes_total, tcp_push_packets_total,
            tcp_fin_bytes_total, tcp_fin_packets_total,
            tcp_flags_unusuall_bytes_total, tcp_flags_unusuall_packets_total,
            tcp_no_flags_bytes_total, tcp_no_flags_packets_total
            ]


def post_processing_preselected_l7ports(o_topProtocolAnalysis):
    """
    Cut the port stats computed to a subset of specific L7 ports, per 5-min bin.
    :param o_topProtocolAnalysis:
    :return:
    """
    d_port_sum_bytes_packets = o_topProtocolAnalysis.get_protocol_sum()
    d_port_count_unique_src_ips = o_topProtocolAnalysis.get_count_port_unique_ips()

    for k, v in d_port_sum_bytes_packets.items():
        # add to list the information about unique src IPs seen
        if len(d_port_count_unique_src_ips) > 0:
            d_port_sum_bytes_packets[k].append(d_port_count_unique_src_ips[k])

    return d_port_sum_bytes_packets


def process_formatted_output_port_ips_udp_dst_analysis(d_l7port_ip_udp_dst_stats_agg, o_db_routeviews_ip_prefix,
                                                       results_filename, op_data_format, total_bins_in_interval):
    """
    Method to read and write formatted output for further analysis.
    :param d_l7port_ip_udp_dst_stats_agg:
    :return:
    """

    if op_data_format == "ASN":
        print_header_row_pattern = '{:<12}|{:<20}|{:<20}\n'
        print_row_pattern = '{asn_id:<12}|{packets_ps:<20,.0f}|{bytes_ps:<20,.0f}\n'

    # IP, PREFIX
    else:
        print_header_row_pattern = '{:<18}|{:<20}|{:<20}\n'
        print_row_pattern = '{asn_id:<18}|{packets_ps:<20,.0f}|{bytes_ps:<20,.0f}\n'

    with gzip.open(results_filename, 'wb') as f:

        for k_port, v_d_ips_stats in d_l7port_ip_udp_dst_stats_agg.items():

            f.write("#>> Port: {}\n".format(k_port))

            if op_data_format == "ASN":
                f.write(print_header_row_pattern.format("#ASN", "PACKETS/S(^)", "BYTES/S"))
            elif op_data_format == "PREFIX":
                f.write(print_header_row_pattern.format("#PREFIX", "PACKETS/S(^)", "BYTES/S"))
            elif op_data_format == "IP":
                f.write(print_header_row_pattern.format("#IP", "PACKETS/S(^)", "BYTES/S"))

            # reset the dict per Port
            d_port_asn_agg = dict()

            for k_ipaddress, l_ip_stats in v_d_ips_stats.items():

                s_ipaddress = fputil.record_to_ip(k_ipaddress)

                if op_data_format == "ASN":
                    i_asn, s_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(s_ipaddress)

                    if i_asn not in d_port_asn_agg:
                        d_port_asn_agg[i_asn] = l_ip_stats
                    else:
                        d_port_asn_agg[i_asn] = map(add, d_port_asn_agg[i_asn], l_ip_stats)

                elif op_data_format == "PREFIX":
                    i_asn, s_ip_prefix = o_db_routeviews_ip_prefix.do_prefix_lookup_forip(s_ipaddress)

                    if s_ip_prefix not in d_port_asn_agg:
                        d_port_asn_agg[s_ip_prefix] = l_ip_stats
                    else:
                        d_port_asn_agg[s_ip_prefix] = map(add, d_port_asn_agg[s_ip_prefix], l_ip_stats)

                elif op_data_format == "IP":
                    if s_ipaddress not in d_port_asn_agg:
                        d_port_asn_agg[s_ipaddress] = l_ip_stats
                    else:
                        d_port_asn_agg[s_ipaddress] = map(add, d_port_asn_agg[s_ipaddress], l_ip_stats)

            # after aggregation, order by packets and write results for each port
            l_d_port_asn_agg_sorted = sorted(d_port_asn_agg.items(), key=lambda (k, v): v[1], reverse=True)
            for record in l_d_port_asn_agg_sorted:
                k_asn = record[0]
                l_stats_bytes = round(float(record[1][0]/(total_bins_in_interval * 5 * 60)), 1)
                l_stats_packets = round(float(record[1][1]/(total_bins_in_interval * 5 * 60)), 1)
                f.write(print_row_pattern.format(asn_id=k_asn,
                                                 packets_ps=l_stats_packets,
                                                 bytes_ps=l_stats_bytes))
    f.close()


def post_processing_l7ports_top10_byvolume(o_topProtocolAnalysis):
    """
    Cut the protocol stats computed to a subset of the top X protocols order by bytes.
    :param o_topProtocolAnalysis:
    :return:
    """

    d_port_selected_data = dict()
    d_port_sum_bytes_packets_sorted = copy.deepcopy(o_topProtocolAnalysis.get_sorted_protocol_sum())

    for i, val in enumerate(islice(d_port_sum_bytes_packets_sorted, 10)):

        # protocol
        k = val[0]

        # bytes, packets
        values = val[1]

        # unique IPs
        if o_topProtocolAnalysis.is_there_data_port_ips_sum() > 0:
            values.append(o_topProtocolAnalysis.get_port_unique_ips_utilized(k))

        d_port_selected_data[k] = values

    return sorted(d_port_selected_data.items(), key=lambda (k, v): v[0], reverse=True)


def post_processing_l7ports_top10_by_uniqueIPs(o_topProtocolAnalysis):
    """
    Cut the protocol stats computed to a subset of the top X protocols order by #unique IPs.
    :param o_topProtocolAnalysis:
    :return:
    """

    d_port_selected_data = dict()
    for i, val in enumerate(islice(o_topProtocolAnalysis.get_sorted_port_unique_ips_utilized(), 10)):

        # protocol
        k = val[0]
        qty_unique_ips_protocol = len(val[1])

        # bytes, packets
        values = copy.deepcopy(o_topProtocolAnalysis.get_protocol_sum_values_by_key(k))
        values.append(qty_unique_ips_protocol)

        d_port_selected_data[k] = values

    return sorted(d_port_selected_data.items(), key=lambda (k, v): v[2], reverse=True)


def generate_output_fullpath_filename(s_label, s_file_extension, p_dest_filepath, s_lbl_ASN_filter_employed):
    """
    Generate filename fullpath to a new output file.
    :param s_label:
    :param s_file_extension:
    :param p_dest_filepath:
    :return:
    """
    results_filename_pattern = "{filebased_label}.{timestamp}.ipv={ip_version}.svln={filter_svln}.idcc={ccversion_id}.cat={category_id}{active_asn_filters}ixp={location_id}"
    results_filename = results_filename_pattern.format(filebased_label=s_label,
                                                       timestamp=parsed_args.time_window_op,
                                                       ip_version=filter_ip_version,
                                                       filter_svln=filter_svln,
                                                       ccversion_id=id_customer_cone_algo_dataset,
                                                       category_id=op_category_to_process,
                                                       active_asn_filters=s_lbl_ASN_filter_employed,
                                                       location_id="RS-IX")

    fn_output_flow_info_pattern = "{file_dest_dir}{file_name}.{file_extension}.gz"
    fn_output_flow_info = fn_output_flow_info_pattern.format(file_dest_dir=p_dest_filepath,
                                                             file_name=results_filename,
                                                             file_extension=s_file_extension)

    return fn_output_flow_info


def save_results_to_jsonfile(l_d_post_results, fn_fullpath):
    """
    Save data to a json file.
    :param p_dest_filepath:
    :param p_file_name:
    :param p_location_id:
    :return:
    """

    # write dict result with flow traffic info to a json file
    with gzip.open(fn_fullpath, 'wb') as f:
        dump(l_d_post_results, f, sort_keys=True)
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

    parser.add_argument('-cat', dest='op_category_to_process', type=int, choices=[0, 1, 2, 3, 4], required=True,
                        help="Define the category that must be processed and analyzed. "
                             " Syntax: '[0-bogon, 1-unassigned, 2-incone, 3-out-of-cone, 4-unverifiable]' ")

    parser.add_argument('-ccid', dest='customercone_algoid', type=int, choices=[4, 8], required=True,
                        help="Options: "
                             "4 - IMC17 FullCone "
                             "8 - Prefix-Level Customer Cone.")

    parser.add_argument('-tfdir', dest='op_traffic_flow_direction', type=int, choices=[0, 1], required=True,
                        help="Options: "
                             "0 - filter applied to SRC port (usually replies, client/server architecture)"
                             "1 - filter applied to DST port (usually requests, client/server architecture)")

    parser.add_argument('-fipsrcasn', dest='op_src_asn_to_filter', type=int, default=-1,
                        help="Options: "
                             " -1 = in case we don't filter SRC-IP converted to SRC-ASN."
                             " SRC-AS number = filter applied to SRC-IP which is converted to SRC-ASN.")

    parser.add_argument('-fipdstasn', dest='op_dst_asn_to_filter', type=int, default=-1,
                        help="Options: "
                             " -1 = in case we don't filter DST-IP converted to DST-ASN."
                             " DST-AS number = filter applied to DST-IP which is converted to DST-ASN.")

    parser.add_argument('-fingressasn', dest='op_ingress_asn_to_filter', type=int, default=-1,
                        help="Options: "
                             " -1 = in case we don't filter INGRESS AS."
                             " INGRESS AS number = filter applied to INGRESS AS (converted based on MAC2AS).")

    parser.add_argument('-sysout', dest='op_enable_sysout_prints', type=int, default=0,
                        help="Options: "
                             " 0 = in case we don't want to see sysout prints."
                             " 1 = if we want to see sysout prints to eval data.")

    parser.add_argument('-execanalysis', dest='op_which_analysis_to_run', required=True,
                        help="Syntax: choose which analyses must be executed " 
                             "          '[ traffic-directions-properties-per-L4protocols, "
                             "           L7protocols-analysis-usage ]' "
                             "e.g.: '[0, 1]' ")

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

    # Filter to apply on traffic flow direction (i.e., lookup over SRC or DST port)
    if parsed_args.op_traffic_flow_direction:
        op_traffic_flow_direction = 1  # DST
    else:
        op_traffic_flow_direction = 0  # SRC

    # Set value to SRC-ASN and/or DST-ASN filters
    op_src_asn_to_filter = parsed_args.op_src_asn_to_filter
    op_dst_asn_to_filter = parsed_args.op_dst_asn_to_filter
    print "Input system param: SRC-ASN filter value set = {}".format(op_src_asn_to_filter)
    print "Input system param: DST-ASN filter value set = {}".format(op_dst_asn_to_filter)

    # Set value to INGRESS-ASN filter
    op_ingress_asn_to_filter = parsed_args.op_ingress_asn_to_filter
    print "Input system param: INGRESS-ASN filter value set = {}".format(op_ingress_asn_to_filter)

    # set format of output data writing based on input parameter
    if (op_src_asn_to_filter == -1) and (op_dst_asn_to_filter == -1):
        op_data_format = "ASN"
    else:
        op_data_format = "IP"

    # set param to add to filename indicating the employed filters to analyse the data.
    if (op_src_asn_to_filter == -1) and (op_dst_asn_to_filter == -1) and (op_ingress_asn_to_filter == -1):
        s_label_ASN_filter_employed = ".SRC-ASN=all.DST-ASN=all.INGRESS-AS=all."
    else:
        lbl_src_asn = op_src_asn_to_filter if op_src_asn_to_filter > -1 else 'all'
        lbl_dst_asn = op_dst_asn_to_filter if op_dst_asn_to_filter > -1 else 'all'
        lbl_ingress_asn = op_ingress_asn_to_filter if op_ingress_asn_to_filter > -1 else 'all'

        s_label_ASN_filter_employed = ".SRC-ASN={}.DST-ASN={}.INGRESS-AS={}.".format(lbl_src_asn, lbl_dst_asn, lbl_ingress_asn)

    # list of categories raw files generated after the traffic classification process
    l_categories = [cons.CATEGORY_LABEL_BOGON_CLASS, cons.CATEGORY_LABEL_UNASSIGNED_CLASS,
                    cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE, cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE,
                    cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS]

    if not parsed_args.op_category_to_process is None:
        op_category_to_process = l_categories[parsed_args.op_category_to_process]


    print "---Loading Routeviews ip2prefix-asn database file..."
    f_global_asndb_routeviews = load_database_ip2prefixasn_routeviews_by_timewindow(tw_start)

    print "---Loading mac2asn mapping data..."
    d_mapping_macaddress_member_asn = ixp_member_util.build_dict_mapping_macaddress_members_asns(
        cons.DEFAULT_MACADDRESS_ASN_MAPPING)

    o_db_routeviews_ip_prefix = putilrv.PrefixUtilsRouteViews(tw_start)

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
    pattern_file_extension = '{def_ext}.idcc={id_cc_version}.class={lbl_class}'

    l_pattern_file_extensions = [pattern_file_extension.format(def_ext=default_flowtraffic_datafile,
                                                               id_cc_version=id_customer_cone_algo_dataset,
                                                               lbl_class=op_category_to_process)]

    l_filenames_to_process = cmdutil.generate_filenames_to_process_bysetof_extensions(tw_start, tw_end,
                                                                                      flowfiles_basedir,
                                                                                      l_pattern_file_extensions)

    # ----- START: TRAFFIC ANALYSIS PER DIRECTION AND L4-PROTOCOL (UDP-SRC/DST and TCP-SRC/DST)
    if l_which_analysis_to_run[0] == 1:
        print "---Started multiprocessing traffic data -- Overall traffic category analysis..."
        mp = mpPool.MultiprocessingPool(n_cores_to_use)
        results = mp.get_results_map_multiprocessing(do_traffic_overall_stats_analysis, l_filenames_to_process)

        print "---Started post-processing: Overall traffic category analysis..."

        l_d_flows_overall_stats_results, \
        d_flows_overall_l7_results,\
        d_flows_overall_ingress_ases, \
        d_l7port_ip_udp_src_stats_agg, d_l7port_ip_udp_dst_stats_agg,\
        d_l7port_ip_tcp_src_stats_agg, d_l7port_ip_tcp_dst_stats_agg, \
        d_flows_overall_dst_ases_traffic_of_giveningress, \
        d_flows_overall_protocols_diversity_traffic_props = post_processing_overall_stats_5min_results(results)

        print "- Generate output files"

        # FLOWS OVERALL STATS
        results_filename = generate_output_fullpath_filename("flows-overall-stats", "json", base_tmp_dir, s_label_ASN_filter_employed)
        save_results_to_jsonfile(l_d_flows_overall_stats_results, results_filename)

        # FLOWS L7-PORTS -- UDP-DST -- STATS OVERALL
        results_filename = generate_output_fullpath_filename("UDP-flows-L7-DST-ports-overall-stats", "json", base_tmp_dir, s_label_ASN_filter_employed)
        save_results_to_jsonfile(d_flows_overall_l7_results, results_filename)

        # INGRESS ASes OVERALL STATS - the ASes allowing the traffic to go through the IXP infrastructure
        results_filename = generate_output_fullpath_filename("flows-ingressASNs-stats", "json", base_tmp_dir, s_label_ASN_filter_employed)
        save_results_to_jsonfile(d_flows_overall_ingress_ases, results_filename)

        # FLOWS L4-PROTOCOLS -- STATS OVERALL
        results_filename = generate_output_fullpath_filename("flows-L4-protocols-presence-overall-stats", "json", base_tmp_dir, s_label_ASN_filter_employed)
        save_results_to_jsonfile(d_flows_overall_protocols_diversity_traffic_props, results_filename)

        # INGRESS AS FILTER ENABLED - DST-ASes OVERALL STATS - the DST ASes where the traffic is going to
        if op_ingress_asn_to_filter > -1:
            results_filename = generate_output_fullpath_filename("traffic-stats-per-dst-ases-of-given-ingressas", "json", base_tmp_dir, s_label_ASN_filter_employed)
            save_results_to_jsonfile(d_flows_overall_dst_ases_traffic_of_giveningress, results_filename)

        # FLOWS L7-PORTS -- UDP-DST per PORT/IP -- TIME-WINDOW AGGREGATED
        print "#UDP ports analysis: SRC IPs view"
        if op_traffic_flow_direction:  # 1 = DST
            results_filename = generate_output_fullpath_filename("UDP-flows-L7-DST-ports-SRC-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        else:  # 0 = SRC
            results_filename = generate_output_fullpath_filename("UDP-flows-L7-SRC-ports-SRC-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        process_formatted_output_port_ips_udp_dst_analysis(d_l7port_ip_udp_src_stats_agg,
                                                           o_db_routeviews_ip_prefix,
                                                           results_filename,
                                                           op_data_format,
                                                           len(l_filenames_to_process))

        print "#UDP ports analysis: DST IPs view"
        if op_traffic_flow_direction:  # 1 = DST
            results_filename = generate_output_fullpath_filename("UDP-flows-L7-DST-ports-DST-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        else:  # 0 = SRC
            results_filename = generate_output_fullpath_filename("UDP-flows-L7-SRC-ports-DST-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        process_formatted_output_port_ips_udp_dst_analysis(d_l7port_ip_udp_dst_stats_agg,
                                                           o_db_routeviews_ip_prefix,
                                                           results_filename,
                                                           op_data_format,
                                                           len(l_filenames_to_process))

        # FLOWS L7-PORTS -- TCP-DST per PORT/IP -- TIME-WINDOW AGGREGATED
        print "#TCP ports analysis: SRC IPs view"
        if op_traffic_flow_direction:  # 1 = DST
            results_filename = generate_output_fullpath_filename("TCP-flows-L7-DST-ports-SRC-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        else:  # 0 = SRC
            results_filename = generate_output_fullpath_filename("TCP-flows-L7-SRC-ports-SRC-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        process_formatted_output_port_ips_udp_dst_analysis(d_l7port_ip_tcp_src_stats_agg,
                                                           o_db_routeviews_ip_prefix,
                                                           results_filename,
                                                           op_data_format,
                                                           len(l_filenames_to_process))

        print "#TCP ports analysis: DST IPs view"
        if op_traffic_flow_direction:  # 1 = DST
            results_filename = generate_output_fullpath_filename("TCP-flows-L7-DST-ports-DST-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        else:  # 0 = SRC
            results_filename = generate_output_fullpath_filename("TCP-flows-L7-SRC-ports-DST-ASN-agg", "txt", base_tmp_dir, s_label_ASN_filter_employed)
        process_formatted_output_port_ips_udp_dst_analysis(d_l7port_ip_tcp_dst_stats_agg,
                                                           o_db_routeviews_ip_prefix,
                                                           results_filename,
                                                           op_data_format,
                                                           len(l_filenames_to_process))

    # ----- START: TRAFFIC MIX LAYER-7 PROTOCOL ANALYSIS
    if l_which_analysis_to_run[1] == 1:
        print "---Started multiprocessing traffic data -- Traffic Mix category analysis..."
        mp = mpPool.MultiprocessingPool(n_cores_to_use)
        results = mp.get_results_map_multiprocessing(do_traffic_mix_protocols_analysis, l_filenames_to_process)

        print "---Started post-processing: Traffic Mix category analysis..."
        l_d_flows_traffic_mix_preselected_l7protocols_results = post_processing_traffic_mix_analysis_results(results)

        # FLOWS TRAFFIC MIX -- pre-selected L7 protocols
        results_filename = generate_output_fullpath_filename("flows-traffic-mix-L7selected", "json", base_tmp_dir, s_label_ASN_filter_employed)
        save_results_to_jsonfile(l_d_flows_traffic_mix_preselected_l7protocols_results, results_filename)

    end = timer()
    print "---Total execution time: {} seconds".format(end - start)

    print "---Sending e-mail notification about the execution status:"
    notifutil.send_notification_end_of_execution(sys.argv, sys.argv[0], start, end)
