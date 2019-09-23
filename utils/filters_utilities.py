#!/usr/bin/env python
# -*- coding: utf-8 -*-

from netaddr import IPAddress, AddrFormatError
import utils.fileparsing_utilities as fputil
import utils.prefixes_utilities as putil


class FlowFilters(object):
    def __init__(self, d_flow_record, d_filters):
        self.d_flow_record = d_flow_record
        self.d_filters = d_filters

    def flow_filter_ip(self):
        # ip protocol version filters
        if self.d_filters['ip'] == 1:
            any_ip = True
        else:
            any_ip = False

        if any_ip:
            return True
        else:
            if self.d_filters['ip'] in [4, 6]:
                if valid_ip(self.d_flow_record, self.d_filters['ip']):
                    return True
                else:
                    return False

    def flow_filter_svln(self):
        # vlan tag filter
        if valid_svln(self.d_flow_record, self.d_filters['svln']):
            return True

    def flow_filter_dmac(self):
        # destination mac filter
        flow_egress_dst_macaddr = fputil.record_to_mac(self.d_flow_record['odmc']).replace(':', '').upper()
        if flow_egress_dst_macaddr == self.d_filters['dmac']:
            return True
        else:
            return False

    def flow_filter_pr(self):
        # protocol filter
        if type(self.d_filters['pr']) is tuple:
            i_flow_pr = self.d_flow_record['pr']

            if i_flow_pr in self.d_filters['pr']:
                return True
            else:
                return False

        else:
            str_flow_pr = fputil.proto_int_to_str(self.d_flow_record['pr'])
            if str_flow_pr == self.d_filters['pr']:
                return True
            else:
                return False


def valid_ip(d_flow_record, ip_type):
    """
    Filter flow record by IP protocol version.
    :param d_flow_record: flow record
    :param ip_type: IP protocol version, 4 or 6
    :return: True if the SA field matches on flow record, False if doesnt match.
    """
    try:
        ip = IPAddress(fputil.record_to_ip(d_flow_record['sa']))

        if ip.version is not None:
            if ip_type == 4 and ip.version == 4:
                return True
            elif ip_type == 6 and ip.version == 6:
                return True
            else:
                # is an invalid IP version!
                return False

    except AddrFormatError:
        return False


def valid_svln(d_flow_record, vlan_tag):
    """
    Filter flow record by SVLN tag.
    :param d_flow_record: flow record.
    :param vlan_tag: source vlan tag value.
    :return: True if the SVLN field matches on flow record, False if doesnt match.
    """
    try:
        # if positive filter only the flow with this vlan tag
        if vlan_tag > 0:
            if fputil.record_to_numeric(d_flow_record['svln']) == vlan_tag:
                return True
            else:
                return False

        # if negative filter all the flow that is different from this vlan tag (*-1 remove signal)
        elif vlan_tag < 0:
            if fputil.record_to_numeric(d_flow_record['svln']) != (vlan_tag * -1):
                return True
            else:
                return False

    except Exception as e:
        print e
        return False


def matches_desired_set(d_flow_record, d_filters):
    """
    Apply a filter to the flow being processed.
    :param d_flow_record:
    :param d_filters:
    :return:
    """

    # check if there are filters applied
    if len(d_filters) == 0:
        return False

    flow_filters = FlowFilters(d_flow_record, d_filters)
    matched_flow = False

    for field_filter in d_filters:
        # apply the filtering to each field requested in the parameters
        matched_flow = getattr(flow_filters, "flow_filter_" + field_filter)()
        if not matched_flow:
            break

    return matched_flow


def matches_desired_flows_by_discarding_prefixes_traffic(l_flow_ipsrc_prefix, flow, d_filters):
    """
    Extend default flows filter method to handle specific analysis over traffic flow data.

    :param l_flow_ipsrc_prefix: list of prefixes for which the traffic should be discarded from analysis.
    """

    # execute default traffic flow filters
    if matches_desired_set(flow, d_filters):

        # then proceed with extra filters.
        # In this case filter out the traffic generated specifically for a given SRC.
        if len(l_flow_ipsrc_prefix) == 0:
            return True

        # active filter: do not consider a given SRC-prefix traffic
        elif len(l_flow_ipsrc_prefix) > 0:
            str_flow_sa = fputil.record_to_ip(flow['sa'])

            # create radix tree
            ipv4_prefixes24_finder = putil.gen_radixtree_from_list(l_flow_ipsrc_prefix)
            status_search, str_ip_prefix = putil.ipaddress_is_in_prefixes(str_flow_sa, ipv4_prefixes24_finder)

            # if IP match Prefix, flow is skipped from the analysis (we discard the traffic)
            if status_search:
                return False
            # if IP does not match the Prefix then do comparison to evaluate flow
            else:
                return True
