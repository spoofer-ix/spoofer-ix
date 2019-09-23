#!/usr/bin/env python
# -*- coding: utf-8 -*-

import utils.fileparsing_utilities as fputil
import utils.filters_utilities as futil
import utils.prefixes_utilities as putil
import utils.constants as cons
from operator import add
import utils.avrofile_manipulation_utilities as famutil
import utils.ixp_members_mappings_utilities as ixp_member_util

DEFAULT_FLOW_SIGNATURE = cons.DEFAULT_FLOW_SIGNATURE
DEFAULT_STATS = cons.DEFAULT_STATS
DEFAULT_FIELDS = cons.DEFAULT_FIELDS


class DictUnverifiableTrafficBreakdown(object):
    """
    Data structure class to account for the unverifiable category breakdown data.
    """

    def __init__(self):

        self.l_d_subcats = {
            cons.UNKNOWN_INGRESS_MACADDRESS_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_IXP_ASES_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_CF_ASES_ID_CLASS: [0, 0],
            cons.UNKNOWN_EGRESS_MACADDRESS_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_P2C_INGRESS_EGRESS_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_P2C_DIR_TRAFFIC_VALIDIN_PROVIDERCONE_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_P2C_DIR_TRAFFIC_NOTVALIDIN_PROVIDERCONE_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_ROUTER_IP_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_TRANSPORT_PROVIDER_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_BOGON_VLAN_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_UNASSIGNED_VLAN_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_REMOTE_PEERING_ID_CLASS: [0, 0],
            cons.UNVERIFIABLE_SIBLING_TO_SIBLING_ID_CLASS: [0, 0]
        }

    def update_unverifiable_breakdown_dict(self, key, values):

        self.l_d_subcats[key] = map(add, self.l_d_subcats[key], values)

    def get_breakdown_list_dict_results(self):
        return self.l_d_subcats


class ListDictASRelationships(object):
    """
    Data structure class to record the inferred and no-inferred AS-relationships.
    """

    def __init__(self):
        self.l_d_asrels = [
            {}, # NO-INFERRED AS-RELS
            {}  # ASRELS-INFERRED
        ]

    def add_noinferred_entry(self, ingress_asn, egress_asn, svln_id):
        k1 = ''.join(map(str, ingress_asn)) if len(ingress_asn) == 1 else ';'.join(map(str, ingress_asn))
        k2 = ''.join(map(str, egress_asn)) if len(egress_asn) == 1 else ';'.join(map(str, egress_asn))
        k = (k1, k2, svln_id)

        if k not in self.l_d_asrels[0]:
            self.l_d_asrels[0][k] = 1
        else:
            self.l_d_asrels[0][k] += 1

    def add_inferred_entry(self, ingress_asn, egress_asn, svln_id):
        k1 = ''.join(map(str, ingress_asn)) if len(ingress_asn) == 1 else ';'.join(map(str, ingress_asn))
        k2 = ''.join(map(str, egress_asn)) if len(egress_asn) == 1 else ';'.join(map(str, egress_asn))
        k = (k1, k2, svln_id)

        if k not in self.l_d_asrels[1]:
            self.l_d_asrels[1][k] = 1
        else:
            self.l_d_asrels[1][k] += 1

    def get_listdict_asrelationship_inference_analysis(self):
        return self.l_d_asrels


def str_flow_record(d_flow_record, l_keys = DEFAULT_FIELDS):
    record = fputil.get_single_avro_record(d_flow_record, l_keys)
    return fputil.to_csv(record)


def none_to_zero(value):
    if value is None:
        return 0
    else:
        return value


def build_signature(d_flow_record, l_mask):
    sign = "".join([str(d_flow_record[k]) for k in l_mask])
    return sign


def update_aggregated(d_aggregated_flows, d_flow_record, l_mask=DEFAULT_FLOW_SIGNATURE, l_stats=DEFAULT_STATS):
    """
    Adds a flow or updates its counters to the list of different flows.

    This aggregation process follows closely the one applied in NFDUMP.

    As in NFDUMP, for every flow record, it first hashes "relevant fields" and checks whether it is a new flow or an
    old one.

    Next, we:
    1) Add new flows to a global flow record
    or
    2) Update 'old' flows "statistics"

    :param d_aggregated_flows: global dictionary used to aggregate flows and record statistics
    :param d_flow_record: all information regarding a flow in dictionary format
    :param l_mask: set of fields used to describe a flow
    :param l_stats: list of statistics to collect
    :return:
    """
    sign = build_signature(d_flow_record, l_mask)

    if sign not in d_aggregated_flows:
        for k in d_flow_record:
            if k in ["ts", "te", "ibyt", "obyt", "ipkt", "opkt", "flg"]:
                d_flow_record[k] = none_to_zero(d_flow_record[k])

        d_aggregated_flows[sign] = d_flow_record
        if "fl" in l_stats:
            d_aggregated_flows[sign]["fl"] = 1
    else:
        for k in ["ibyt", "obyt", "ipkt", "opkt"]:
            if k in l_stats:
                d_aggregated_flows[sign][k] += none_to_zero(d_flow_record[k])

        if "ts" in l_stats:
            d_aggregated_flows[sign]["ts"] = min(d_aggregated_flows[sign]["ts"], none_to_zero(d_flow_record["ts"]))

        if "te" in l_stats:
            d_aggregated_flows[sign]["te"] = max(d_aggregated_flows[sign]["te"], none_to_zero(d_flow_record["te"]))

        if "td" in l_stats:
            if "ts" not in l_stats or "te" not in l_stats:
                ts_in_l = "ts" in l_stats
                te_in_l = "te" in l_stats
                raise ValueError("Expected valid values for ts and te when calculating td." +
                                 "\nStatus:" +
                                 "\nis ts in collected statistics? " + str(ts_in_l) +
                                 "\nis te in collected statistics? " + str(te_in_l))
            else:
                d_aggregated_flows[sign]["td"] = d_aggregated_flows[sign]["te"] - d_aggregated_flows[sign]["ts"]

        if "fl" in l_stats:
            d_aggregated_flows[sign]["fl"] += 1

        if "flg" in l_stats:
            d_aggregated_flows[sign]["flg"] |= none_to_zero(d_flow_record["flg"])

        if "bps" in l_stats:
            if "td" not in l_stats or "ibyt" not in l_stats:
                td_in_l = "td" in l_stats
                ibyt_in_l = "ibyt" not in l_stats
                raise ValueError("Expected valid values for td and ibyt when calculating bps." +
                                 "\nStatus:" +
                                 "\nis td in collected statistics? " + str(td_in_l) +
                                 "\nis ibyt in collected statistics? " + str(ibyt_in_l))
            else:
                duration = d_aggregated_flows[sign]["td"]
                num_bytes = d_aggregated_flows[sign]["ibyt"]
                if duration > 0:
                    d_aggregated_flows[sign]["bps"] = (num_bytes << 3) / duration
                else:
                    d_aggregated_flows[sign]["bps"] = 0

        if "pps" in l_stats:
            if "td" not in l_stats or "ipkt" not in l_stats:
                td_in_l = "td" in l_stats
                ipkt_in_l = "ipkt" not in l_stats
                raise ValueError("Expected valid values for td and ipkt when calculating pps." +
                                 "\nStatus:" +
                                 "\nis td in collected statistics? " + str(td_in_l) +
                                 "\nis ipkt in collected statistics? " + str(ipkt_in_l))
            else:
                duration = d_aggregated_flows[sign]["td"]
                num_pkts = d_aggregated_flows[sign]["ipkt"]
                if duration > 0:
                    d_aggregated_flows[sign]["pps"] = num_pkts / duration
                else:
                    d_aggregated_flows[sign]["pps"] = 0

        if "bpp" in l_stats:
            if "ibyt" not in l_stats or "ipkt" not in l_stats:
                ibyt_in_l = "ibyt" in l_stats
                ipkt_in_l = "ipkt" not in l_stats
                raise ValueError("Expected valid values for ibyt and ipkt when calculating bpp." +
                                 "\nStatus:" +
                                 "\nis ibyt in collected statistics? " + str(ibyt_in_l) +
                                 "\nis ipkt in collected statistics? " + str(ipkt_in_l))
            else:
                num_bytes = d_aggregated_flows[sign]["ibyt"]
                num_pkts = d_aggregated_flows[sign]["ipkt"]
                if num_pkts > 0:
                    d_aggregated_flows[sign]["bpp"] = num_bytes / num_pkts
                else:
                    d_aggregated_flows[sign]["bpp"] = 0

    return d_aggregated_flows


def aggregate(l_csv_flow_records, d_aggregated_flows={}, l_mask=DEFAULT_FLOW_SIGNATURE,
              l_stats=DEFAULT_STATS, d_filters={}):
    for flow in l_csv_flow_records:
        if futil.matches_desired_set(flow, d_filters):
            update_aggregated(d_aggregated_flows, flow, l_mask)

    return d_aggregated_flows


def get_asn_via_macaddress(flow_asn_macaddr, d_mapping_macaddress_member_asn):
    """
    Lookup mac2asn -- get and transform mac address to same format as mac2as mapping data
    :param flow_asn_macaddr:
    :return:
    """

    flow_mac2asn = 'UNKNOWN'
    if flow_asn_macaddr in d_mapping_macaddress_member_asn:
        flow_mac2asn = d_mapping_macaddress_member_asn[flow_asn_macaddr][0]

    return flow_mac2asn


def aggregate_classify_illegitimate_full(l_d_flow_records, bogon_prefixes_finder, unrouted_prefixes_finder,
                                         d_map_macadd_member_asn,
                                         d_mac2asn_alldata,
                                         d_global_members_customercone_prefix_finder,
                                         d_global_members_customercone_ppdcases_finder,
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
                                         d_aggregated_flows={},
                                         l_mask=[cons.LABEL_BOGON_ID_CLASS, cons.LABEL_UNASSIGNED_ID_CLASS,
                                                 cons.LABEL_AS_SPECIFIC_ID_CLASS, cons.LABEL_UNVERIFIABLE_ID_CLASS],
                                         l_stats=DEFAULT_STATS,
                                         d_filters={}):

    d_prefixes_matchs = dict()
    d_count_unknown_macadd = dict()

    if log_inferred_asrel:
        l_d_record_status_inferred_asrel = ListDictASRelationships()
    else:
        l_d_record_status_inferred_asrel = False

    if log_p2c_flow_matches:
        l_d_record_status_p2c_asrels_matches = ListDictASRelationships()
    else:
        l_d_record_status_p2c_asrels_matches = False

    d_breakdown_unverifiable_traffic = DictUnverifiableTrafficBreakdown()

    # [p2c_incone_bytes, p2c_incone_pkts, p2c_outofcone_bytes, p2c_outofcone_pkts]
    l_p2c_flow_validation_stats = [0, 0, 0, 0]

    # ground truth data information defined in accord with the IXP infrastructure management operators
    set_of_nonbilateral_vlans_to_check = (10, 20, 99)

    dt_flow_timestamp_fields = fputil.extract_timestamp_from_flowfilepath(fn_input)

    if gen_intermediate_flowfiles_bycategories:
        fn_pattern_output_category_traffic_file = "{fn_path}.idcc={id_cc_version}.class={label_category}"

        fn_bogon_traffic = fn_pattern_output_category_traffic_file.format(fn_path=fn_input, id_cc_version=id_customer_cone_algo_dataset, label_category=cons.CATEGORY_LABEL_BOGON_CLASS)
        fn_bogon_traffic_file = famutil.create_new_empty_avro_file(fn_bogon_traffic, avro_schema=cons.DEFAULT_AVRO_SHRINK_NFCAP_FLOWS_SCHEMA_FILEPATH)

        fn_unassigned_traffic = fn_pattern_output_category_traffic_file.format(fn_path=fn_input, id_cc_version=id_customer_cone_algo_dataset, label_category=cons.CATEGORY_LABEL_UNASSIGNED_CLASS)
        fn_unassigned_traffic_file = famutil.create_new_empty_avro_file(fn_unassigned_traffic, avro_schema=cons.DEFAULT_AVRO_SHRINK_NFCAP_FLOWS_SCHEMA_FILEPATH)

        fn_outofcone_traffic = fn_pattern_output_category_traffic_file.format(fn_path=fn_input, id_cc_version=id_customer_cone_algo_dataset, label_category=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_OUTOFCONE)
        fn_outofcone_traffic_file = famutil.create_new_empty_avro_file(fn_outofcone_traffic, avro_schema=cons.DEFAULT_AVRO_SHRINK_NFCAP_FLOWS_SCHEMA_FILEPATH)

        fn_incone_traffic = fn_pattern_output_category_traffic_file.format(fn_path=fn_input, id_cc_version=id_customer_cone_algo_dataset, label_category=cons.CATEGORY_LABEL_AS_SPECIFIC_CLASS_INCONE)
        fn_incone_traffic_file = famutil.create_new_empty_avro_file(fn_incone_traffic, avro_schema=cons.DEFAULT_AVRO_SHRINK_NFCAP_FLOWS_SCHEMA_FILEPATH)

        fn_unverifiable_traffic = fn_pattern_output_category_traffic_file.format(fn_path=fn_input, id_cc_version=id_customer_cone_algo_dataset, label_category=cons.CATEGORY_LABEL_UNVERIFIABLE_CLASS)
        fn_unverifiable_traffic_file = famutil.create_new_empty_avro_file(fn_unverifiable_traffic, avro_schema=cons.DEFAULT_AVRO_SHRINK_NFCAP_FLOWS_SCHEMA_FILEPATH)

    for flow in l_d_flow_records:
        if futil.matches_desired_set(flow, d_filters):
            flow_sa = fputil.record_to_ip(flow['sa'])
            flow_da = fputil.record_to_ip(flow['da'])
            flow_ingress_src_macaddr = fputil.record_to_mac(flow['ismc'])
            flow_egress_dst_macaddr = fputil.record_to_mac(flow['odmc'])
            flow_bytes = fputil.record_to_numeric(flow['ibyt'])
            flow_pkts = fputil.record_to_numeric(flow['ipkt'])
            flow_svln_id = fputil.record_to_numeric(flow['svln'])

            values = [1, flow_bytes, flow_pkts]

            flow[cons.LABEL_UNVERIFIABLE_ID_CLASS] = False
            flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] = False
            flow[cons.LABEL_UNASSIGNED_ID_CLASS] = False
            flow[cons.LABEL_BOGON_ID_CLASS] = False

            flow[cons.LABEL_BOGON_ID_CLASS], ip_prefix = putil.ipaddress_is_in_prefixes(flow_sa, bogon_prefixes_finder)

            if global_set_of_filters_unverifiable_traffic[5] and flow[cons.LABEL_BOGON_ID_CLASS] and (flow_svln_id not in (10, 20)):
                flow[cons.LABEL_UNVERIFIABLE_ID_CLASS] = True
                flow[cons.LABEL_BOGON_ID_CLASS] = False

                d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_BOGON_VLAN_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_BOGON_VLAN_ID_CLASS, [flow_bytes, flow_pkts])

                if gen_intermediate_flowfiles_bycategories:
                    famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_unverifiable_traffic_file)

            elif flow[cons.LABEL_BOGON_ID_CLASS] and not flow[cons.LABEL_UNVERIFIABLE_ID_CLASS]:
                k = (cons.BOGON_ID_CLASS, ip_prefix, flow_ingress_src_macaddr)
                d_prefixes_matchs = update_records_log_dict_classification(k, values, ip_prefix, d_prefixes_matchs)

                if gen_intermediate_flowfiles_bycategories:
                    famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_bogon_traffic_file)

            if (not flow[cons.LABEL_UNVERIFIABLE_ID_CLASS]) and (not flow[cons.LABEL_BOGON_ID_CLASS]):
                flow[cons.LABEL_UNASSIGNED_ID_CLASS], ip_prefix = putil.ipaddress_is_in_prefixes(flow_sa, unrouted_prefixes_finder)

                if global_set_of_filters_unverifiable_traffic[5] and flow[cons.LABEL_UNASSIGNED_ID_CLASS] and (flow_svln_id not in (10, 20)):
                    flow[cons.LABEL_UNVERIFIABLE_ID_CLASS] = True
                    flow[cons.LABEL_UNASSIGNED_ID_CLASS] = False

                    d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_UNASSIGNED_VLAN_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                    d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_UNASSIGNED_VLAN_ID_CLASS, [flow_bytes, flow_pkts])

                    if gen_intermediate_flowfiles_bycategories:
                        famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_unverifiable_traffic_file)

                elif flow[cons.LABEL_UNASSIGNED_ID_CLASS] and not flow[cons.LABEL_UNVERIFIABLE_ID_CLASS]:
                    k = (cons.UNASSIGNED_ID_CLASS, ip_prefix, flow_ingress_src_macaddr)
                    d_prefixes_matchs = update_records_log_dict_classification(k, values, ip_prefix, d_prefixes_matchs)

                    if gen_intermediate_flowfiles_bycategories:
                        famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_unassigned_traffic_file)

            if (not flow[cons.LABEL_UNVERIFIABLE_ID_CLASS]) and (not flow[cons.LABEL_BOGON_ID_CLASS]) and (not flow[cons.LABEL_UNASSIGNED_ID_CLASS]) and (not flow[cons.LABEL_AS_SPECIFIC_ID_CLASS]):
                flow_ingress_macaddress = flow_ingress_src_macaddr.replace(':', '').upper()
                flow_egress_macaddress = flow_egress_dst_macaddr.replace(':', '').upper()

                isflow_classifiable, d_prefixes_matchs, d_count_unknown_macadd, \
                d_breakdown_unverifiable_traffic, l_d_record_status_inferred_asrel, i_reason_id = \
                    isolate_traffic_unclassifiable_from_customer_cone(dt_flow_timestamp_fields, id_customer_cone_algo_dataset,
                        flow_ingress_macaddress, flow_sa, flow_da, flow_bytes, flow_pkts, flow_svln_id,
                        d_global_ixps_cfs_known, global_ixp_lan_prefixes_finder, d_global_cdns_known, d_global_sibling_ases_mapixp,
                        global_router_prefixes_finder, d_prefixes_matchs, f_global_asndb_routeviews,
                        d_global_members_customercone_ppdcases_finder,
                        flow_egress_macaddress, d_map_macadd_member_asn, d_count_unknown_macadd,
                        d_breakdown_unverifiable_traffic,
                        l_d_record_status_inferred_asrel,
                        global_set_of_filters_unverifiable_traffic,
                        log_inferred_asrel
                    )

                if isflow_classifiable:
                    flow[cons.LABEL_UNVERIFIABLE_ID_CLASS] = False
                    flow_ingress_asn = d_map_macadd_member_asn[flow_ingress_macaddress]

                    if id_customer_cone_algo_dataset == cons.ID_CUSTOMERCONE_PLCC_CONEXT2019:
                        flow_egress_asn = d_map_macadd_member_asn[flow_egress_macaddress]

                        count_presence_ingress = ixp_member_util.query_member_presence_in_multiple_locations(d_mac2asn_alldata,
                                                                                    flow_ingress_macaddress,
                                                                                    flow_ingress_asn[0])

                        count_presence_egress = ixp_member_util.query_member_presence_in_multiple_locations(d_mac2asn_alldata,
                                                                                    flow_egress_macaddress,
                                                                                    flow_egress_asn[0])

                    if len(flow_ingress_asn) == 1:
                        rtree_prefixes_finder = d_global_members_customercone_prefix_finder[flow_ingress_asn[0]]
                        flow[cons.LABEL_AS_SPECIFIC_ID_CLASS], ip_address = putil.ipaddress_is_in_customercone_prefixes(flow_sa, rtree_prefixes_finder)
                    elif len(flow_ingress_asn) > 1:
                        del flow[cons.LABEL_AS_SPECIFIC_ID_CLASS]
                        d_temp_results = dict()
                        for origin_asn in flow_ingress_asn:
                            rtree_prefixes_finder = d_global_members_customercone_prefix_finder[origin_asn]
                            result_cone_lookup, ip_address = putil.ipaddress_is_in_customercone_prefixes(flow_sa, rtree_prefixes_finder)
                            d_temp_results[origin_asn] = [result_cone_lookup, ip_address]

                        for k, v in d_temp_results.items():
                            if v[0] == False:
                                flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] = False
                                ip_address = None
                                break

                        if cons.LABEL_AS_SPECIFIC_ID_CLASS not in flow:
                            flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] = True
                            ip_address = ip_address

                    if global_set_of_filters_unverifiable_traffic[5] and \
                            (flow[cons.LABEL_AS_SPECIFIC_ID_CLASS]) and (flow_svln_id not in set_of_nonbilateral_vlans_to_check):
                        flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] = False

                    if global_set_of_filters_unverifiable_traffic[6] and (flow[cons.LABEL_AS_SPECIFIC_ID_CLASS]) and (count_presence_ingress > 1 or count_presence_egress > 1):
                        flow[cons.LABEL_UNVERIFIABLE_ID_CLASS] = True
                        flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] = False

                    if flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] and not flow[cons.LABEL_UNVERIFIABLE_ID_CLASS]:
                        if gen_intermediate_flowfiles_bycategories:
                            famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_outofcone_traffic_file)

                        try:
                            prefix_lookup_result = f_global_asndb_routeviews.lookup(ip_address)
                            origin_asn_lookup = prefix_lookup_result[0]
                            ip_prefix_lookup = prefix_lookup_result[1]
                        except:
                            ip_prefix_lookup = ip_address
                            origin_asn_lookup = None

                        k = (cons.AS_SPECIFIC_ID_CLASS_OUT_OF_CONE, ip_prefix_lookup, origin_asn_lookup, flow_ingress_src_macaddr)
                        d_prefixes_matchs = update_records_log_dict_classification(k, values, ip_prefix_lookup, d_prefixes_matchs)

                    elif not flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] and not flow[cons.LABEL_UNVERIFIABLE_ID_CLASS]:
                        k = cons.AS_SPECIFIC_ID_CLASS_IN_CONE
                        if k not in d_prefixes_matchs and (ip_prefix is None):
                            d_prefixes_matchs[k] = values
                        elif ip_prefix is None:
                            d_prefixes_matchs[k] = map(add, d_prefixes_matchs[k], values)

                        if gen_intermediate_flowfiles_bycategories:
                            famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_incone_traffic_file)

                    elif not flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] and flow[cons.LABEL_UNVERIFIABLE_ID_CLASS]:
                        d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_TRANSPORT_PROVIDER_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                        d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_TRANSPORT_PROVIDER_ID_CLASS, [flow_bytes, flow_pkts])
                        i_reason_id = cons.UNVERIFIABLE_TRANSPORT_PROVIDER_ID_CLASS

                        if gen_intermediate_flowfiles_bycategories:
                            flow['tag'] = i_reason_id
                            famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_unverifiable_traffic_file)

                else:
                    flow[cons.LABEL_UNVERIFIABLE_ID_CLASS] = True
                    flow[cons.LABEL_AS_SPECIFIC_ID_CLASS] = False

                    if i_reason_id == cons.UNVERIFIABLE_P2C_INGRESS_EGRESS_ID_CLASS:

                        flow_ingress_asn = d_map_macadd_member_asn[flow_ingress_macaddress]
                        flow_egress_asn = d_map_macadd_member_asn[flow_egress_macaddress]

                        rtree_prefixes_finder = d_global_members_customercone_prefix_finder[flow_ingress_asn[0]]
                        validation_result, ip_address = putil.ipaddress_is_in_customercone_prefixes(flow_sa, rtree_prefixes_finder)

                        if validation_result:
                            d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_P2C_DIR_TRAFFIC_VALIDIN_PROVIDERCONE_ID_CLASS, [flow_bytes, flow_pkts])
                            i_reason_id = cons.UNVERIFIABLE_P2C_DIR_TRAFFIC_VALIDIN_PROVIDERCONE_ID_CLASS

                            if log_p2c_flow_matches:
                                l_p2c_flow_validation_stats = map(add, l_p2c_flow_validation_stats, [flow_bytes, flow_pkts, 0, 0])
                                l_d_record_status_p2c_asrels_matches.add_inferred_entry(flow_ingress_asn, flow_egress_asn, 0)

                        else:
                            d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_P2C_DIR_TRAFFIC_NOTVALIDIN_PROVIDERCONE_ID_CLASS, [flow_bytes, flow_pkts])
                            i_reason_id = cons.UNVERIFIABLE_P2C_DIR_TRAFFIC_NOTVALIDIN_PROVIDERCONE_ID_CLASS

                            if log_p2c_flow_matches:
                                l_p2c_flow_validation_stats = map(add, l_p2c_flow_validation_stats, [0, 0, flow_bytes, flow_pkts])
                                l_d_record_status_p2c_asrels_matches.add_noinferred_entry(flow_ingress_asn, flow_egress_asn, 0)

                    if gen_intermediate_flowfiles_bycategories:
                        flow['tag'] = i_reason_id
                        famutil.save_rawtraffic_categories_records_to_avrofiles(flow, fn_unverifiable_traffic_file)

            d_aggregated_flows = update_aggregated(d_aggregated_flows, flow, l_mask, l_stats)

    if gen_intermediate_flowfiles_bycategories:
        famutil.close_writing_avrofile(fn_bogon_traffic_file)
        famutil.close_writing_avrofile(fn_unassigned_traffic_file)
        famutil.close_writing_avrofile(fn_outofcone_traffic_file)
        famutil.close_writing_avrofile(fn_incone_traffic_file)
        famutil.close_writing_avrofile(fn_unverifiable_traffic_file)

    return d_aggregated_flows, d_prefixes_matchs, d_count_unknown_macadd, \
           d_breakdown_unverifiable_traffic, l_d_record_status_inferred_asrel, \
           l_p2c_flow_validation_stats, l_d_record_status_p2c_asrels_matches


def isolate_traffic_unclassifiable_from_customer_cone(dt_flow_timestamp_fields,
                                                      id_customer_cone_algo_dataset, flow_ingress_macaddress,
                                                      flow_sa, flow_da, flow_bytes, flow_pkts, flow_svln_id,
                                                      d_global_ixps_cfs_known, global_ixp_lan_prefixes_finder,
                                                      d_global_cdns_known, d_global_sibling_ases_mapixp,
                                                      global_router_prefixes_finder, d_prefixes_matchs,
                                                      f_global_asndb_routeviews,
                                                      d_global_members_customercone_ppdcases_finder,
                                                      flow_egress_macaddress, d_map_macadd_member_asn,
                                                      d_count_unknown_macadd, d_breakdown_unverifiable_traffic,
                                                      l_d_record_status_inferred_asrel,
                                                      global_set_of_filters_unverifiable_traffic, log_inferred_asrel):

    """
    Apply all the rules that defines the unverifiable traffic and create log records for these flows.
    """

    isflow_classifiable = True
    i_reason_id = 0

    if isflow_classifiable and global_set_of_filters_unverifiable_traffic[0]:

        flow_sa_origin_asn = ipaddress_to_asn_lookup(f_global_asndb_routeviews, flow_sa)

        if flow_sa_origin_asn in d_global_ixps_cfs_known:
            if d_global_ixps_cfs_known[flow_sa_origin_asn][1] == "CF":
                d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_CF_ASES_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_CF_ASES_ID_CLASS, [flow_bytes, flow_pkts])
                isflow_classifiable = False
                i_reason_id = cons.UNVERIFIABLE_CF_ASES_ID_CLASS

    if isflow_classifiable and global_set_of_filters_unverifiable_traffic[1]:
        result_flow_sa, ip_prefix = putil.ipaddress_is_in_prefixes(flow_sa, global_ixp_lan_prefixes_finder)
        result_flow_da, ip_prefix = putil.ipaddress_is_in_prefixes(flow_da, global_ixp_lan_prefixes_finder)

        if result_flow_sa or result_flow_da:
            d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_IXP_ASES_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
            d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_IXP_ASES_ID_CLASS, [flow_bytes, flow_pkts])
            isflow_classifiable = False
            i_reason_id = cons.UNVERIFIABLE_IXP_ASES_ID_CLASS

    if flow_ingress_macaddress in d_map_macadd_member_asn:
        flow_ingress_asn = d_map_macadd_member_asn[flow_ingress_macaddress]

        if isflow_classifiable and \
                (global_set_of_filters_unverifiable_traffic[0] or global_set_of_filters_unverifiable_traffic[1]):

            if len(flow_ingress_asn) == 1:
                if flow_ingress_asn[0] in d_global_ixps_cfs_known:

                    if (d_global_ixps_cfs_known[flow_ingress_asn[0]][1] == "CF") and global_set_of_filters_unverifiable_traffic[0]:
                        d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_CF_ASES_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                        d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_CF_ASES_ID_CLASS, [flow_bytes, flow_pkts])
                        isflow_classifiable = False
                        i_reason_id = cons.UNVERIFIABLE_CF_ASES_ID_CLASS

                    elif (d_global_ixps_cfs_known[flow_ingress_asn[0]][1] == "IXP") and global_set_of_filters_unverifiable_traffic[1]:
                        d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_IXP_ASES_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                        d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_IXP_ASES_ID_CLASS, [flow_bytes, flow_pkts])
                        isflow_classifiable = False
                        i_reason_id = cons.UNVERIFIABLE_IXP_ASES_ID_CLASS

            elif len(flow_ingress_asn) > 1:
                for origin_asn in flow_ingress_asn:
                    if origin_asn in d_global_ixps_cfs_known:

                        if (d_global_ixps_cfs_known[origin_asn][1] == "CF") and global_set_of_filters_unverifiable_traffic[0]:
                            d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_CF_ASES_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                            d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_CF_ASES_ID_CLASS, [flow_bytes, flow_pkts])
                            isflow_classifiable = False
                            i_reason_id = cons.UNVERIFIABLE_CF_ASES_ID_CLASS
                            break

                        elif (d_global_ixps_cfs_known[origin_asn][1] == "IXP") and global_set_of_filters_unverifiable_traffic[1]:
                            d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_IXP_ASES_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                            d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_IXP_ASES_ID_CLASS, [flow_bytes, flow_pkts])
                            isflow_classifiable = False
                            i_reason_id = cons.UNVERIFIABLE_IXP_ASES_ID_CLASS
                            break

        if isflow_classifiable and global_set_of_filters_unverifiable_traffic[2]:

            if flow_egress_macaddress in d_map_macadd_member_asn:
                flow_egress_asn = d_map_macadd_member_asn[flow_egress_macaddress]

                if global_set_of_filters_unverifiable_traffic[7]:
                    exist_inferred_sibling_to_sibling = exist_inferred_asrel_sibling_to_sibling(flow_ingress_asn,
                                                                                                flow_egress_asn,
                                                                                                d_global_sibling_ases_mapixp)
                else:
                    exist_inferred_sibling_to_sibling = False

                if not exist_inferred_sibling_to_sibling:
                    exist_inferred_asrel_dir_p2c = exists_inferred_relationship(flow_ingress_asn,
                                                                                flow_egress_asn,
                                                                                d_global_members_customercone_ppdcases_finder)

                    exist_inferred_asrel_dir_c2p = exists_inferred_relationship(flow_egress_asn,
                                                                                flow_ingress_asn,
                                                                                d_global_members_customercone_ppdcases_finder)

                    if not exist_inferred_asrel_dir_c2p and not exist_inferred_asrel_dir_p2c:
                        isflow_classifiable = True

                        if log_inferred_asrel:
                            l_d_record_status_inferred_asrel.add_noinferred_entry(flow_ingress_asn, flow_egress_asn, flow_svln_id)

                    elif exist_inferred_asrel_dir_p2c and not exist_inferred_asrel_dir_c2p:

                        if log_inferred_asrel:
                            l_d_record_status_inferred_asrel.add_inferred_entry(flow_ingress_asn, flow_egress_asn, flow_svln_id)

                        if id_customer_cone_algo_dataset == cons.ID_CUSTOMERCONE_PLCC_CONEXT2019:
                            d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_P2C_INGRESS_EGRESS_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                            d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_P2C_INGRESS_EGRESS_ID_CLASS, [flow_bytes, flow_pkts])
                            isflow_classifiable = False
                            i_reason_id = cons.UNVERIFIABLE_P2C_INGRESS_EGRESS_ID_CLASS

                    elif exist_inferred_asrel_dir_c2p:
                        isflow_classifiable = True

                        if log_inferred_asrel:
                            l_d_record_status_inferred_asrel.add_inferred_entry(flow_ingress_asn, flow_egress_asn, flow_svln_id)

                else:
                    d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_SIBLING_TO_SIBLING_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                    d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_SIBLING_TO_SIBLING_ID_CLASS, [flow_bytes, flow_pkts])
                    isflow_classifiable = False
                    i_reason_id = cons.UNVERIFIABLE_SIBLING_TO_SIBLING_ID_CLASS
            else:
                k = (flow_egress_macaddress, flow_svln_id, 'e')
                values = [1, flow_bytes, flow_pkts]
                if flow_egress_macaddress not in d_count_unknown_macadd:
                    d_count_unknown_macadd[k] = values
                else:
                    d_count_unknown_macadd[k] = map(add, d_count_unknown_macadd[k], values)

                if flow_svln_id in cons.SET_OF_VLANS_RELATED_TO_REMOTE_PEERING[dt_flow_timestamp_fields.year]:
                    d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_REMOTE_PEERING_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                    d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_REMOTE_PEERING_ID_CLASS, [flow_bytes, flow_pkts])
                    i_reason_id = cons.UNVERIFIABLE_REMOTE_PEERING_ID_CLASS
                else:
                    d_prefixes_matchs = update_records_log_dict(cons.UNKNOWN_EGRESS_MACADDRESS_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
                    d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNKNOWN_EGRESS_MACADDRESS_ID_CLASS, [flow_bytes, flow_pkts])
                    i_reason_id = cons.UNKNOWN_EGRESS_MACADDRESS_ID_CLASS

                isflow_classifiable = False
    else:
        k = (flow_ingress_macaddress, flow_svln_id, 'i')
        values = [1, flow_bytes, flow_pkts]
        if flow_ingress_macaddress not in d_count_unknown_macadd:
            d_count_unknown_macadd[k] = values
        else:
            d_count_unknown_macadd[k] = map(add, d_count_unknown_macadd[k], values)

        d_prefixes_matchs = update_records_log_dict(cons.UNKNOWN_INGRESS_MACADDRESS_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
        d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNKNOWN_INGRESS_MACADDRESS_ID_CLASS, [flow_bytes, flow_pkts])
        isflow_classifiable = False
        i_reason_id = cons.UNKNOWN_INGRESS_MACADDRESS_ID_CLASS

    if isflow_classifiable and global_set_of_filters_unverifiable_traffic[3]:
        result, ip_prefix = putil.ipaddress_is_in_prefixes(flow_sa, global_router_prefixes_finder)
        if result:
            d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_ROUTER_IP_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
            d_breakdown_unverifiable_traffic.update_unverifiable_breakdown_dict(cons.UNVERIFIABLE_ROUTER_IP_ID_CLASS, [flow_bytes, flow_pkts])
            isflow_classifiable = False
            i_reason_id = cons.UNVERIFIABLE_ROUTER_IP_ID_CLASS

    if isflow_classifiable and global_set_of_filters_unverifiable_traffic[4]:
        flow_sa_origin_asn = ipaddress_to_asn_lookup(f_global_asndb_routeviews, flow_sa)

        if flow_sa_origin_asn in d_global_cdns_known:
            d_prefixes_matchs = update_records_log_dict(cons.UNVERIFIABLE_CDN_ASES_ID_CLASS, d_prefixes_matchs, flow_bytes, flow_pkts)
            isflow_classifiable = False
            i_reason_id = cons.UNVERIFIABLE_CDN_ASES_ID_CLASS

    return isflow_classifiable, d_prefixes_matchs, d_count_unknown_macadd, \
           d_breakdown_unverifiable_traffic, l_d_record_status_inferred_asrel, i_reason_id


def update_records_log_dict_classification(k_id_class, l_values, p_ip_prefix, d_prefixes_matchs):
    """
    Update log record entries for a given key, aggregating values when the key already exist.
    """

    if (k_id_class not in d_prefixes_matchs) and (p_ip_prefix is not None):
        d_prefixes_matchs[k_id_class] = l_values
    elif p_ip_prefix is not None:
        d_prefixes_matchs[k_id_class] = map(add, d_prefixes_matchs[k_id_class], l_values)

    return d_prefixes_matchs


def update_records_log_dict(k_id_class, d_prefixes_matchs, flow_bytes, flow_pkts):
    """
    Record log entries for a given id_class key, computes flow_bytes and flow_pkts.
    """

    k = k_id_class
    if k not in d_prefixes_matchs:
        d_prefixes_matchs[k] = [1, flow_bytes, flow_pkts]
    else:
        d_prefixes_matchs[k] = map(add, d_prefixes_matchs[k], [1, flow_bytes, flow_pkts])

    return d_prefixes_matchs


def ipaddress_to_asn_lookup(f_global_asndb_routeviews, flow_sa):
    """
    Execute lookup AS number for IPs via route
    """

    try:
        prefix_lookup_result = f_global_asndb_routeviews.lookup(flow_sa)
        flow_sa_origin_asn = prefix_lookup_result[0]
    except:
        flow_sa_origin_asn = None

    return flow_sa_origin_asn


def exists_inferred_relationship(flow_ingress_asn, flow_egress_asn, d_global_members_customercone_ppdcases_finder):
    """
    Checks the existence of AS-Relationship in the inferences dataset from (AS-Rel algorithm).
    """

    exist_inferred_asrel = False
    ingress_asn_info = flow_ingress_asn
    egress_asn_info = flow_egress_asn

    if len(flow_ingress_asn) == 1:
        set_ingress_ases_customer_cone = d_global_members_customercone_ppdcases_finder[flow_ingress_asn[0]]

        if len(flow_egress_asn) == 1:
            # check if the egress ASN is part of the Ingress ASN Customer Cone
            if flow_egress_asn[0] in set_ingress_ases_customer_cone:
                exist_inferred_asrel = True
                ingress_asn_info = flow_ingress_asn[0]
                egress_asn_info = flow_egress_asn[0]

        elif len(flow_egress_asn) > 1:
            for egress_asn in flow_egress_asn:
                # check if the egress ASN is part of the Ingress ASN Customer Cone
                if egress_asn in set_ingress_ases_customer_cone:
                    exist_inferred_asrel = True
                    ingress_asn_info = flow_ingress_asn[0]
                    egress_asn_info = egress_asn
                    break

    elif len(flow_ingress_asn) > 1:
        for ingress_asn in flow_ingress_asn:
            if exist_inferred_asrel:
                break
            if len(flow_egress_asn) == 1:
                if flow_egress_asn[0] in d_global_members_customercone_ppdcases_finder[ingress_asn]:
                    exist_inferred_asrel = True
                    ingress_asn_info = ingress_asn
                    egress_asn_info = flow_egress_asn[0]
                    break

            elif len(flow_egress_asn) > 1:
                for egress_asn in flow_egress_asn:
                    if egress_asn in d_global_members_customercone_ppdcases_finder[ingress_asn]:
                        exist_inferred_asrel = True
                        ingress_asn_info = ingress_asn
                        egress_asn_info = egress_asn
                        break

    return exist_inferred_asrel


def exist_inferred_asrel_sibling_to_sibling(flow_ingress_asn, flow_egress_asn, d_global_sibling_ases_mapixp):

    exist_inferred_asrel = False

    f_ingress_asn = flow_ingress_asn[0]
    f_egress_asn = flow_egress_asn[0]

    if (f_ingress_asn in d_global_sibling_ases_mapixp) and (f_egress_asn in d_global_sibling_ases_mapixp):
        if d_global_sibling_ases_mapixp[f_ingress_asn][1] == d_global_sibling_ases_mapixp[f_egress_asn][1]:
            exist_inferred_asrel = True

    return exist_inferred_asrel
