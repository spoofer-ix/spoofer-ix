#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '../..')))
import utils.constants as cons
import utils.as2org_dataset_utilities as as2orgutil
import utils.ixp_members_mappings_utilities as ixp_member_util
import argparse
import sys
import bz2
import gzip
import jsonlines
import aggregate6 as prefixagg
import utils.multiprocessing_poll as mpPool
import ast
from copy import deepcopy


def build_dict_mapping_known_sibling_ases_crafted():
    """
    Build the mapping dict cache to sibling ASNs.
    :return:
    """

    fn_mapping_input_jsonl = cons.DEFAULT_BRAZIL_SIBLING_ASES_MAPPING

    d_sibling_ases = dict()
    with jsonlines.open(fn_mapping_input_jsonl) as reader:
        for obj in reader:
            asn = int(obj['asn'])
            asname = obj['asname']
            org_id = obj['org_id']

            if asn not in d_sibling_ases:
                d_sibling_ases[asn] = [asname, org_id]

    return d_sibling_ases


def extract_ixp_members_including_manual_siblings_ases_customercone(p_macaddress_file, p_customercone_datafile):
    """
    Extract the Customer Cone data relevant only to the members of a given IXP. Also extract sets of ASes
    belonging to the same organization using the manual mapping data ".jsonl" and add a full mesh of links between all
    ASes within each set.
    :param p_macaddress_file:
    :param p_customercone_datafile:
    :return:
    """

    d_mapping_sibling_ases_org_data = build_dict_mapping_known_sibling_ases_crafted()

    if not i_op_deactivate_slice_members:
        d_uniq_member_asns = ixp_member_util.load_members_ixp(p_macaddress_file)

    d_alldata_customer_cone = dict()
    with bz2.BZ2File(p_customercone_datafile, "r") as fin:
        for line in fin:
            if not line.startswith("#"):
                lf = line.strip().split(" ")
                if len(lf) >= 2:
                    asn_key = int(lf[0])
                    data_cone = lf[1:]

                    s_cone_ases = set()
                    for asn in data_cone:
                        s_cone_ases.add(int(asn))

                    d_alldata_customer_cone[asn_key] = s_cone_ases

                    if not i_op_deactivate_slice_members:
                        if asn_key in d_uniq_member_asns:
                            d_uniq_member_asns[asn_key] = s_cone_ases

    if i_op_deactivate_slice_members:
        d_uniq_member_asns = deepcopy(d_alldata_customer_cone)

    for k_ixp_member_asn, v_cone_aslevel_ixp_member in d_uniq_member_asns.iteritems():
        for k_cone_asn, v_cone_ases in d_alldata_customer_cone.iteritems():
            if k_cone_asn in d_mapping_sibling_ases_org_data:

                if (k_ixp_member_asn in d_mapping_sibling_ases_org_data) and (len(v_cone_aslevel_ixp_member) > 0):

                    if (d_mapping_sibling_ases_org_data[k_ixp_member_asn][1] == d_mapping_sibling_ases_org_data[k_cone_asn][1]) and (k_ixp_member_asn != k_cone_asn):
                        d_uniq_member_asns[k_ixp_member_asn].update(d_alldata_customer_cone[k_cone_asn])

    if i_op_deactivate_slice_members == 0:
        d_uniq_member_asns_final = deepcopy(d_uniq_member_asns)
        for k_ixp_member_asn, v_cone_aslevel_ixp_member in d_uniq_member_asns.iteritems():
            for customer_asn in v_cone_aslevel_ixp_member:
                if customer_asn in d_mapping_sibling_ases_org_data:
                    if customer_asn in d_uniq_member_asns:
                        d_uniq_member_asns_final[k_ixp_member_asn].update(d_uniq_member_asns[customer_asn])
                    elif (customer_asn not in d_uniq_member_asns) and (customer_asn in d_alldata_customer_cone):
                        d_uniq_member_asns_final[k_ixp_member_asn].update(d_alldata_customer_cone[customer_asn])
    else:
        d_uniq_member_asns_final = deepcopy(d_uniq_member_asns)

    return d_uniq_member_asns_final


def extract_ixp_members_asns_multiorg_customercone(p_macaddress_file, p_customercone_datafile):
    """
    Extract the Customer Cone data relevant only to the members of a given IXP. Also extract sets of ASes
    belonging to the same organization, and add a full mesh of links between all ASes within each set.
    :param p_macaddress_file:
    :param p_customercone_datafile:
    :param p_output_dir:
    :return:
    """

    d_mapping_org_data, d_mapping_as_data = as2orgutil.build_dicts_as2org_caida_mapping(s_as2org_epoch_input)

    if not i_op_deactivate_slice_members:
        d_uniq_member_asns = ixp_member_util.load_members_ixp(p_macaddress_file)

    d_alldata_customer_cone = dict()
    with bz2.BZ2File(p_customercone_datafile, "r") as fin:
        for line in fin:
            if not line.startswith("#"):
                lf = line.strip().split(" ")
                if len(lf) >= 2:
                    asn_key = int(lf[0])
                    data_cone = lf[1:]

                    s_cone_ases = set()
                    for asn in data_cone:
                        s_cone_ases.add(int(asn))

                    d_alldata_customer_cone[asn_key] = s_cone_ases

                    if not i_op_deactivate_slice_members:
                        if asn_key in d_uniq_member_asns:
                            d_uniq_member_asns[asn_key] = s_cone_ases

    if i_op_deactivate_slice_members:
        d_uniq_member_asns = deepcopy(d_alldata_customer_cone)

    for k_ixp_member_asn, v_cone_aslevel_ixp_member in d_uniq_member_asns.iteritems():
        for k_cone_asn, v_cone_ases in d_alldata_customer_cone.iteritems():

            if k_cone_asn in d_mapping_as_data:
                if (k_ixp_member_asn in d_mapping_as_data) and (len(v_cone_aslevel_ixp_member) > 0):

                    if (d_mapping_as_data[k_ixp_member_asn] == d_mapping_as_data[k_cone_asn]) and (k_ixp_member_asn != k_cone_asn):
                        d_uniq_member_asns[k_ixp_member_asn].update(d_alldata_customer_cone[k_cone_asn])

    return d_uniq_member_asns


def extract_ixp_members_asns_customercone(p_macaddress_file, p_customercone_datafile):
    """
    Extract the Customer Cone data relevant only to the members of a given IXP.
    :param p_macaddress_file:
    :param p_customercone_datafile:
    :param p_output_dir:
    :return:
    """

    d_uniq_member_asns = ixp_member_util.load_members_ixp(p_macaddress_file)

    print "Customer Cone dataset: {}".format(p_customercone_datafile)

    if p_customercone_datafile.lower().endswith('.txt'):
        fin = open(p_customercone_datafile)

    elif p_customercone_datafile.lower().endswith('.gz'):
        fin = gzip.open(p_customercone_datafile, "rb")

    elif p_customercone_datafile.lower().endswith('.bz2'): # full cone datasets
        fin = bz2.BZ2File(p_customercone_datafile, "r")

    for line in fin:
        if not line.startswith("#"):
            lf = line.strip().split(" ")
            if len(lf) >= 2:
                asn = int(lf[0])
                data_cone = lf[1:]

                # save all the records
                if asn in d_uniq_member_asns:
                    d_uniq_member_asns[asn] = data_cone

    return d_uniq_member_asns


def save_tofile_cones_subset_ixp_members(p_d_uniq_member_asns, p_customercone_datafile, p_output_dir, p_id_ixp, op_multi_organization_cc):
    """
    Save subset result of cones definition for a given set of members from an IXP.
    :param p_d_uniq_member_asns:
    :param p_customercone_datafile:
    :param p_output_dir:
    :param p_id_ixp:
    :return:
    """

    customercone_data_filename = path.basename(p_customercone_datafile)
    id_ixp = p_id_ixp

    if op_multi_organization_cc == 3:
        fn_output_pattern = "{out_dir}{out_filename}_subset={id_ixp}.txt.bz2"
    else:
        fn_output_pattern = "{out_dir}{out_filename}_multi-asn-org_subset={id_ixp}.txt.bz2"

    # Create the output files
    fn_output = fn_output_pattern.format(out_dir=p_output_dir, out_filename=customercone_data_filename, id_ixp=id_ixp)
    output_file_asn_customercone = bz2.BZ2File(fn_output, 'w')

    for asn_key, customercone in p_d_uniq_member_asns.items():
        # check if we have data, otherwise the record is not written (will be empty anyway)
        if len(customercone) > 0:
            output_file_asn_customercone.write(str(asn_key) + "".join(" %s" % str(data) for data in customercone) + "\n")

    output_file_asn_customercone.close()


def do_prefixes_merge(s_cone_asn_prefixes):
    """
    Receive a prefix cone definition to be merged and execute it.
    Return: cone prefix definition merged.
    """
    d_cone_def_merged = dict()
    id_asn_cone = s_cone_asn_prefixes[0]
    l_prefixes = s_cone_asn_prefixes[1]

    d_cone_def_merged[id_asn_cone] = prefixagg.aggregate(l_prefixes)

    return d_cone_def_merged


def post_processing_aggregate_results(l_d_classification_results):
    """
    Post processing results obtained from multi-processing cones prefixes.
    """

    d_ases_cones_prefixes_merged = dict()

    # prepare three dictionaries as output
    for dict_result in l_d_classification_results:
        for k, v in dict_result.iteritems():
            d_ases_cones_prefixes_merged[k] = v

    return d_ases_cones_prefixes_merged


def validate_generated_subdataset(p_d_uniq_member_asns):
    """
    Execute a simple validation over the subset data generated to guarantee that the data is valid, i.e., that we have
    the needed information to next steps.
    :param p_d_uniq_member_asns:
    :return:
    """
    print "List of ASN not found during cone processing data:"
    validation_status = True
    for asn_key, customercone in p_d_uniq_member_asns.iteritems():
        if len(customercone) == 0:
            print str(asn_key)
            validation_status = False

    if validation_status:
        print "Cone subset data validation: APPROVED!"
    else:
        print "Cone subset data validation: FAILED, it's good to check the input Mac2ASN mapping, there as some ASNs" \
              " that are not present in the CONE dataset used at the moment!"


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Create the Customer Cone data files for the IXP '
                                                                   'Members only.')

    parser.add_argument('-odir', dest='output_dir', required=True,
                        help="Dir to save output files")

    parser.add_argument('-macf', dest='macaddress_file', required=False,
                        help="Full path to MacAddress Mapping file DB (*.JSON)")

    parser.add_argument('-ccf', dest='customer_cone_file', required=True,
                        help="Full path to Customer Cone file to extract data")

    parser.add_argument('-mo', dest='create_multiorganization', required=True, type=int, choices=[1, 2, 3],
                        help="Build Multi-Organization Customer Cone options:"
                             "0 - disabled, i.e., do not create it;"
                             "1 - create using only the CAIDA AS2ORG inferred mapping data via WHOIS;"
                             "2 - create using only the additional mapping file created by hand (generated via individual cases analyses).")

    parser.add_argument('-as2org', dest='s_as2org_epoch_input', required=False,
                        help="Year id to define which CAIDA AS2ORG dataset to be loaded during processing.")

    parser.add_argument('-lixp', dest='label_ixp', required=False,
                        help="Label id to identify the IXP on the output files")

    parser.add_argument('-agg_prefixes', dest='aggregate_prefixes', required=True, type=int, choices=[0, 1],
                        help="Merge/aggregate list of prefixes of each cone")

    parser.add_argument('-deactivate_slice_members', dest='op_deactivate_slice_members', required=False, type=int, choices=[0, 1], default=0,
                        help="Indicates when to slice the cone and extract only the member ASes to optimize "
                             "load process in memory to future processes."
                             "Syntax: "
                             "0 - perform slice of ASes extracting only members of the IXP;"
                             "1 - do not perform slice of ASes and consider all ASes in the Cone to process.")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    # directory paths set up for the conversion process
    path_output_dir = parsed_args.output_dir

    # location of mac address mapping MACADDRESS vs ASN
    if parsed_args.macaddress_file:
        path_macaddress_file = parsed_args.macaddress_file
    else:
        path_macaddress_file = cons.DEFAULT_MACADDRESS_ASN_MAPPING

    customer_cone_datafile_path = parsed_args.customer_cone_file
    multi_organization_cc = parsed_args.create_multiorganization
    merge_prefixes_to_small_set = parsed_args.aggregate_prefixes
    i_op_deactivate_slice_members = parsed_args.op_deactivate_slice_members
    s_as2org_epoch_input = parsed_args.s_as2org_epoch_input

    # multi-org cone computation processing
    if multi_organization_cc in (1, 2):

        if multi_organization_cc == 1:
            d_uniq_member_asns = extract_ixp_members_asns_multiorg_customercone(path_macaddress_file,
                                                                                customer_cone_datafile_path)
        if multi_organization_cc == 2:
            d_uniq_member_asns = extract_ixp_members_including_manual_siblings_ases_customercone(path_macaddress_file,
                                                                                                 customer_cone_datafile_path)

        validate_generated_subdataset(d_uniq_member_asns)

    # default cone slice, prefixes aggregation if requested and no extra computation
    if multi_organization_cc == 3:
        d_uniq_member_asns = extract_ixp_members_asns_customercone(path_macaddress_file, customer_cone_datafile_path)
        validate_generated_subdataset(d_uniq_member_asns)

    # if enabled to merge prefixes, execute it now
    if not merge_prefixes_to_small_set:
        print "---Save cone data to file ..."
        save_tofile_cones_subset_ixp_members(d_uniq_member_asns,
                                             customer_cone_datafile_path,
                                             path_output_dir,
                                             parsed_args.label_ixp,
                                             multi_organization_cc)

    elif merge_prefixes_to_small_set:
        print "---Started multiprocessing cones prefixes..."
        mp = mpPool.MultiprocessingPool(max_concurrent_jobs=None)
        results = mp.get_results_imap_multiprocessing(do_prefixes_merge, d_uniq_member_asns.items())

        print "---Started post-processing cones ..."
        d_ases_cones_prefixes_merged = post_processing_aggregate_results(results)

        print "---Save cone data to file ..."
        save_tofile_cones_subset_ixp_members(d_ases_cones_prefixes_merged,
                                             customer_cone_datafile_path,
                                             path_output_dir,
                                             parsed_args.label_ixp,
                                             multi_organization_cc)
