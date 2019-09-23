#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '../..')))
import utils.constants as cons
import utils.ixp_members_mappings_utilities as ixp_member_util
import argparse
import sys
import gzip
from netaddr import IPNetwork, IPAddress
import utils.as2org_dataset_utilities as as2orgutil
import aggregate6 as prefixagg
import multiprocessing as mp
import copy


def extract_ixp_members_asns_multiorg_fullcone(p_macaddress_file, p_ases_fullcone_datafile):
    """
    Extract the Full Cone data relevant only to the members of a given IXP. Also extract sets of ASes
    belonging to the same organization, and add a full mesh of links between all ASes within each set.
    :param p_macaddress_file:
    :param p_customercone_datafile:
    :param p_output_dir:
    :return:
    """

    d_mapping_org_data, d_mapping_as_data = as2orgutil.build_dicts_as2org_caida_mapping(s_as2org_epoch_input)

    if i_op_create_multiorganization != 2:
        d_uniq_member_asns = ixp_member_util.load_members_ixp(p_macaddress_file)

    d_alldata_uniq_asns_fullcone = dict()
    with gzip.open(p_ases_fullcone_datafile, "r") as fin:
        for line in fin:
            lf = line.strip().split(" ")
            if len(lf) >= 2:
                asn_key = int(lf[0])
                data_cone = lf[1:]

                s_cone_ases = set()
                for asn in data_cone:
                    s_cone_ases.add(int(asn))

                d_alldata_uniq_asns_fullcone[asn_key] = s_cone_ases

                if i_op_create_multiorganization != 2:
                    # save only the data that belongs to the IXP members
                    if asn_key in d_uniq_member_asns:
                        d_uniq_member_asns[asn_key] = s_cone_ases

    if i_op_create_multiorganization == 2 and is_to_build_fullprefixfile:
        d_uniq_member_asns = copy.deepcopy(d_alldata_uniq_asns_fullcone)

    print "Start AS-level merge cones operations... cone total ASes: {} -- members cone: {}".format(len(d_alldata_uniq_asns_fullcone),
                                                                                                    len(d_uniq_member_asns))
    # For each IXP member
    for k_ixp_member_asn, v_cone_aslevel_ixp_member in d_uniq_member_asns.iteritems():

        # Loop over all Full Cone dataset looking for ASN that
        # belong to the same ORG (and then join the Full Cones)
        for k_cone_asn, v_cone_ases in d_alldata_uniq_asns_fullcone.iteritems():

            # check if the ASN from Full Cone file exists in the AS2ORG file
            # (there is some cases that the ASN at the Full Cone file is there but its not allocated
            # cases of BGP poisoning (since Full Cone its build using RV and RIPE public BGP feeds)
            if k_cone_asn in d_mapping_as_data:

                if (k_ixp_member_asn in d_mapping_as_data) and (len(v_cone_aslevel_ixp_member) > 0):

                    # if both ases belong to the same org_id, then add to cone
                    if (d_mapping_as_data[k_ixp_member_asn] == d_mapping_as_data[k_cone_asn]) and (k_ixp_member_asn != k_cone_asn):
                        d_uniq_member_asns[k_ixp_member_asn].update(d_alldata_uniq_asns_fullcone[k_cone_asn])

    return d_uniq_member_asns


def build_prefix_fullcone(p_ases_fullcone_datafile, d_uniq_asns_fullcone, p_fullcone_prefixes_datafile, p_output_dir):
    """
    Build the full prefix Full Cone combining the "raw_cones" w/ the "prefixes" output.
    ##### WARNING: IT REQUIRES A LOT OF MEMORY TO BUILD THE RAW FULL CONE PREFIXES FILE. ######
    :param p_fullcone_datafile:
    :param p_output_dir:
    :return:
    """

    fullcone_data_filename = path.basename(p_ases_fullcone_datafile)
    fn_output_prefixes_pattern = "{out_dir}{out_filename}-prefixes.gz"

    if i_op_create_multiorganization == 2 and is_to_build_fullprefixfile:
        fn_output_prefixes_pattern = "{out_dir}{out_filename}_Prefixes-INTERNET-COMPLETEVIEW-wAS2ORG.txt.gz"

    d_uniq_asns_prefixes = dict()
    # reads the prefixes file, store all values in dict
    with gzip.open(p_fullcone_prefixes_datafile, "r") as fin:
        for line in fin:
            k_asn, prefixlist = line.strip().split(": ")
            k_asn = int(k_asn)

            d_uniq_asns_prefixes[k_asn] = list()
            for p in prefixlist.split(','):
                prefix = IPNetwork(p)
                d_uniq_asns_prefixes[k_asn].append([prefix.value, prefix.prefixlen])

    # build dict with k_asn and set of prefixes
    d_fullcone_ixpmembers_prefixes = dict()

    # #### Create the output files #####
    # FULL CONE PREFIXES FILE
    fn_output = fn_output_prefixes_pattern.format(out_dir=p_output_dir, out_filename=fullcone_data_filename)
    output_file_prefixes_fullcone = gzip.open(fn_output, 'wb')

    str_asn_prefix = "{ipaddress}/{prefixlen}"
    for asn_key, ases_fullcone in d_uniq_asns_fullcone.items():

        for asn_in_fc in ases_fullcone:

            if asn_key not in d_fullcone_ixpmembers_prefixes:
                d_fullcone_ixpmembers_prefixes[asn_key] = set()

                # for each ASN belonging to the FullCone check the prefixes and add to the resulting set
                if asn_in_fc in d_uniq_asns_prefixes:
                    for asn_prefix in d_uniq_asns_prefixes[asn_in_fc]:
                        prefix = str_asn_prefix.format(ipaddress=str(IPAddress(asn_prefix[0])),
                                                       prefixlen=str(asn_prefix[1]))
                        d_fullcone_ixpmembers_prefixes[asn_key].add(prefix)
            else:
                # for each ASN belonging to the FullCone check the prefixes and add to the resulting set
                if asn_in_fc in d_uniq_asns_prefixes:
                    for asn_prefix in d_uniq_asns_prefixes[asn_in_fc]:
                        prefix = str_asn_prefix.format(ipaddress=str(IPAddress(asn_prefix[0])),
                                                       prefixlen=str(asn_prefix[1]))
                        d_fullcone_ixpmembers_prefixes[asn_key].add(prefix)

        # write as soon the results is read to free memory
        if asn_key in d_fullcone_ixpmembers_prefixes:
            output_file_prefixes_fullcone.write(str(asn_key) + "".join(" %s" % str(data) for data in d_fullcone_ixpmembers_prefixes[asn_key]) + "\n")

            # after writing free memory
            d_fullcone_ixpmembers_prefixes[asn_key].clear()
            del d_fullcone_ixpmembers_prefixes[asn_key]

    output_file_prefixes_fullcone.close()

    return d_fullcone_ixpmembers_prefixes


def extract_ixp_members_asns_fullcone(p_macaddress_file, p_fullcone_rawases_datafile, p_fullcone_prefixes_datafile):
    """
    Extract the Full Cone data relevant only to the members of a given IXP.
    :param p_macaddress_file:
    :param p_fullcone_rawases_datafile:
    :param p_output_dir:
    :return:
    """

    d_uniq_member_asns = ixp_member_util.load_members_ixp(p_macaddress_file)

    # reads the ASes file definition
    with gzip.open(p_fullcone_rawases_datafile, "r") as fin:
        for line in fin:
            lf = line.strip().split(" ")
            if len(lf) >= 2:
                asn = int(lf[0])
                data_cone = lf[1:]

                # save all the records
                if asn in d_uniq_member_asns:
                    d_uniq_member_asns[asn] = data_cone

    d_uniq_asns_prefixes = dict()
    # reads the prefixes file, store all values in dict
    with gzip.open(p_fullcone_prefixes_datafile, "r") as fin:
        for line in fin:
            k_asn, prefixlist = line.strip().split(": ")
            k_asn = int(k_asn)

            d_uniq_asns_prefixes[k_asn] = prefixlist

    # build dict with k_asn and set of prefixes
    d_fullcone_ixpmembers_prefixes = dict()

    # for each IXP member
    for asn_key, ases_fullcone in d_uniq_member_asns.items():
        # check the ASNs that belong to the FullCone
        for asn_fc in ases_fullcone:
            asn_fc = int(asn_fc)

            if asn_key not in d_fullcone_ixpmembers_prefixes:
                d_fullcone_ixpmembers_prefixes[asn_key] = set()

                # first check if the fullcone dataset has an entry for the ASN with prefix information to get it
                if asn_fc in d_uniq_asns_prefixes:
                    # for each ASN belonging to the FullCone check the prefixes and add to the resulting set
                    for asn_prefix in d_uniq_asns_prefixes[asn_fc].split(','):
                        d_fullcone_ixpmembers_prefixes[asn_key].add(asn_prefix)
            else:
                # for each ASN belonging to the FullCone check the prefixes and add to the resulting set
                if asn_fc in d_uniq_asns_prefixes:
                    for asn_prefix in d_uniq_asns_prefixes[asn_fc].split(','):
                        d_fullcone_ixpmembers_prefixes[asn_key].add(asn_prefix)
                else:
                    print "ASN: {} does not exist in Prefixes file from FullCone.".format(str(asn_fc))

    return d_uniq_member_asns, d_fullcone_ixpmembers_prefixes


def save_tofile_cones_subset_ixp_members(p_d_uniq_member_asns, p_fullcone_datafile, p_output_dir, p_id_ixp, op_multi_organization_cc):
    """
    Save subset result of cones definition for a given set of members from an IXP.
    :param p_d_uniq_member_asns:
    :param p_fullcone_datafile:
    :param p_output_dir:
    :param p_id_ixp:
    :return:
    """

    fullcone_data_filename = path.basename(p_fullcone_datafile)
    id_ixp = p_id_ixp

    if op_multi_organization_cc == 0:
        fn_output_pattern = "{out_dir}{out_filename}_subset={id_ixp}.txt.gz"

    elif op_multi_organization_cc == 1:
        fn_output_pattern = "{out_dir}{out_filename}_multi-asn-org_subset={id_ixp}.txt.gz"

    elif op_multi_organization_cc == 2:
        fn_output_pattern = "{out_dir}{out_filename}_ASes-INTERNET-COMPLETEVIEW-wAS2ORG.txt.gz"

    # Create the output files
    fn_output = fn_output_pattern.format(out_dir=p_output_dir, out_filename=fullcone_data_filename, id_ixp=id_ixp)

    print ">>> Output file created: {}".format(fn_output)

    output_file_asn_fullcone = gzip.open(fn_output, 'w')

    for asn_key, fullcone in p_d_uniq_member_asns.items():
        # check if we have data, otherwise the record is not written (will be empty anyway)
        if len(fullcone) > 0:
            output_file_asn_fullcone.write(str(asn_key) + "".join(" %s" % str(data) for data in fullcone) + "\n")

    output_file_asn_fullcone.close()


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


def create_pool_prefixes_merge(d_uniq_member_asns, max_concurrent_jobs):
    """
    Manage the merge of multiple list of prefixes asynchronously in parallel.
    """
    # Create a pool of workers equaling cores on the machine
    pool = mp.Pool(processes=max_concurrent_jobs, maxtasksperchild=1)
    result = pool.imap(do_prefixes_merge, d_uniq_member_asns.items(), chunksize=1)

    # Close the pool
    pool.close()

    # Combine the results of the workers
    pool.join()

    return result


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

    validation_status = True
    for asn_key, customercone in p_d_uniq_member_asns.iteritems():
        if len(customercone) == 0:
            print "ASN: {} - not found during cone processing data.".format(asn_key)
            validation_status = False

    if validation_status:
        print "Cone subset data validation: APPROVED!"
    else:
        print "Cone subset data validation: FAILED, some ASNs from the Mac2ASN mapping don't appear in cone dataset!"


# ----------------------------------------------------------------------------------
#                              DEFAULT CONFIGURATION
# ----------------------------------------------------------------------------------
N_JOBS = mp.cpu_count() - 1  # definition of how many cpus will be in use for the task

if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Create the Full Cone data files for the IXP '
                                                                   'Members only.')

    parser.add_argument('-odir', dest='output_dir', required=True,
                        help="Dir to save output files")

    parser.add_argument('-np', dest='number_concur_process',
                        help="Number of concurrent process to execute")

    parser.add_argument('-macf', dest='macaddress_file', required=False,
                        help="Full path to MacAddress Mapping file DB (*.JSON)")

    parser.add_argument('-ccf', dest='fullcone_ases_file', required=True,
                        help="Full path to Full Cone ASes file to extract data")

    parser.add_argument('-prefixes', dest='fullcone_prefixes_file', required=False,
                        help="Prefixes file generated by Full-cone code")

    parser.add_argument('-buildprefixfile', dest='is_to_build_fullprefixfile', required=False, type=int, choices=[0, 1],
                        help="Enable to build from the Full Cone the full prefix cone dataset.")

    parser.add_argument('-mo', dest='create_multiorganization', required=False, type=int, choices=[0, 1, 2],
                        help="Use as2org file to build Multi-Organization ASes Full Cone."
                             " 0 - disable additional processing to add Siblings via CAIDA AS2ORG and slice the subset "
                             "     of ASes to IXP members indicated by the participants list;"
                             " 1 - add Siblings via CAIDA AS2ORG and slice the subset of ASes to IXP members "
                             "     indicated by the participants list;"
                             " 2 - add Siblings via CAIDA AS2ORG without any slicing of members, i.e., "
                             "     the whole Internet ASes.")

    parser.add_argument('-as2org', dest='s_as2org_epoch_input', required=False,
                        help="Year id to define which CAIDA AS2ORG dataset to be loaded during processing.")

    parser.add_argument('-lixp', dest='label_ixp', required=False, type=str,
                        help="Label id to identify the IXP on the output files")

    parser.add_argument('-c', dest='merge_prefixes', required=True, type=int, choices=[0, 1],
                        help="Merge/aggregate list of prefixes of each cone")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    # directory paths set up for the conversion process
    path_output_dir = parsed_args.output_dir

    # number of concurrent process (performance control)
    if parsed_args.number_concur_process:
        n_cores_to_use = int(parsed_args.number_concur_process)
    else:
        n_cores_to_use = int(N_JOBS)

    # location of mac address mapping MACADDRESS to ASN
    if parsed_args.macaddress_file:
        path_macaddress_file = parsed_args.macaddress_file
    else:
        path_macaddress_file = cons.DEFAULT_MACADDRESS_ASN_MAPPING

    fullcone_ases_datafile_path = parsed_args.fullcone_ases_file
    fullcone_prefixesfile_path = parsed_args.fullcone_prefixes_file
    merge_prefixes_to_small_set = parsed_args.merge_prefixes
    is_to_build_fullprefixfile = parsed_args.is_to_build_fullprefixfile
    i_op_create_multiorganization = parsed_args.create_multiorganization
    s_as2org_epoch_input = parsed_args.s_as2org_epoch_input

    # build the Fullcones with MULTI ORG VIA CAIDA AS2ORG --
    # but without any slicing of members, i.e., the whole Internet
    if i_op_create_multiorganization == 2 and is_to_build_fullprefixfile:
        print "Multi-org started - via CAIDA AS2ORG -- but without any slicing of members, i.e., the whole Internet!"

        d_uniq_member_asns = extract_ixp_members_asns_multiorg_fullcone(path_macaddress_file,
                                                                        fullcone_ases_datafile_path)

        d_fullcone_ixpmembers_prefixes = build_prefix_fullcone(fullcone_ases_datafile_path,
                                                               d_uniq_member_asns,
                                                               fullcone_prefixesfile_path,
                                                               path_output_dir)

    # MULTI ORG VIA CAIDA AS2ORG -- sliced with only the subset of IXP members indicated by the participants list param
    if i_op_create_multiorganization == 1:
        print "Multi-org started - via CAIDA AS2ORG -- sliced with only the subset of IXP members indicated by the participants list"

        d_uniq_member_asns = extract_ixp_members_asns_multiorg_fullcone(path_macaddress_file,
                                                                        fullcone_ases_datafile_path)

        d_fullcone_ixpmembers_prefixes = build_prefix_fullcone(fullcone_ases_datafile_path,
                                                               d_uniq_member_asns,
                                                               fullcone_prefixesfile_path,
                                                               path_output_dir)

        validate_generated_subdataset(d_uniq_member_asns)

    # NO ADDITIONAL TRANSFORMATION WITH AS2ORG
    elif i_op_create_multiorganization == 0:

        d_uniq_member_asns, d_fullcone_ixpmembers_prefixes = extract_ixp_members_asns_fullcone(path_macaddress_file,
                                                                                               fullcone_ases_datafile_path,
                                                                                               fullcone_prefixesfile_path)
        validate_generated_subdataset(d_uniq_member_asns)

    # if enabled to merge prefixes, execute it now otherwise just save the data
    print "---Save ASes cone data to file ..."
    save_tofile_cones_subset_ixp_members(d_uniq_member_asns,
                                         fullcone_ases_datafile_path,
                                         path_output_dir,
                                         parsed_args.label_ixp,
                                         parsed_args.create_multiorganization)

    if (merge_prefixes_to_small_set == 1) and (not is_to_build_fullprefixfile):

        print "---Started multiprocessing cones prefixes... number of ASes in cone: {}".format(len(d_fullcone_ixpmembers_prefixes))
        result = create_pool_prefixes_merge(d_fullcone_ixpmembers_prefixes, n_cores_to_use)
        d_ases_cones_prefixes_merged = post_processing_aggregate_results(result)

        print "---Save fullcone prefixes file multiprocessed..."
        save_tofile_cones_subset_ixp_members(d_ases_cones_prefixes_merged,
                                             fullcone_prefixesfile_path,
                                             path_output_dir,
                                             parsed_args.label_ixp,
                                             i_op_create_multiorganization)

