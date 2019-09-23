#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '../..')))

import sys
import argparse
import bz2
import gzip
import time
from json import dump
from netaddr import IPNetwork
import mmap

"""
---------------------------------------ABOUT----------------------------------------
Given two cones definitions execute a diff operation between the two and check its
differences for all ASes in the Internet captured by their inferences.
------------------------------------------------------------------------------------
"""


def do_compute_address_space_per_asn(p_l_prefixes, d_global_prefix_address_pace_size):
    """
    Requires already aggregated prefixes as input.
    """

    size_address_space = 0
    for prefix in p_l_prefixes:

        if prefix in d_global_prefix_address_pace_size:
            size_address_space += d_global_prefix_address_pace_size[prefix]
        else:
            ip = IPNetwork(prefix)
            size_address_space += ip.size
            d_global_prefix_address_pace_size[prefix] = ip.size

    return size_address_space


def save_internetwide_proportion_results_to_file(d_ixp_results, p_outdir, p_s_current_analysis):
    """
    Save results in json format.
    :param d_ixp_results:
    :param p_outdir:
    :return:
    """

    timestr = time.strftime("%Y%m%d-%H%M%S")
    results_filename_pattern = "{output_dir}/proportion-internetwide.ppdc={current_analysis}.{timestamp}.json.gz"
    results_filename = results_filename_pattern.format(current_analysis=p_s_current_analysis, timestamp=timestr, output_dir=p_outdir)

    with gzip.open(results_filename, 'wb') as f:
        dump(d_ixp_results, f)
    f.close()


def build_dict_asn_fileentry_position(f_data_mmap_prefix_cone):
    """
    Build dict of ASN and its current position entry at dataset file disk.
    :param f_data_mmap_prefix_cone:
    :return:
    """

    d_asn_fileposition = dict()

    while True:
        pos_file = f_data_mmap_prefix_cone.tell()
        line = f_data_mmap_prefix_cone.readline()
        if line == '':
            break

        line_cone = line.strip().split(" ")

        if len(line_cone) >= 2:
            k_asn = int(line_cone[0])
            d_asn_fileposition[k_asn] = pos_file

    return d_asn_fileposition


def do_compute_proportion_prefixes_cone_size_internetwide(d_ases_internet,
                                                          p_cc_prefixes_dataset,
                                                          p_fullcone_prefixes_dataset, d_global_prefix_address_pace_size):
    """
    Compute the total address space proportion between the cones definitions.
    :return:
    """

    d_members_proportion_prefixes_cones = dict()

    d_prefix_cc = open(p_cc_prefixes_dataset, "r")
    data_prefix_cc = mmap.mmap(d_prefix_cc.fileno(), 0, prot=mmap.PROT_READ)

    d_cc_asn_fileposition = build_dict_asn_fileentry_position(data_prefix_cc)

    d_prefix_fullc = open(p_fullcone_prefixes_dataset, 'r')
    data_prefix_fullc = mmap.mmap(d_prefix_fullc.fileno(), 0, prot=mmap.PROT_READ)

    d_fullcone_asn_fileposition = build_dict_asn_fileentry_position(data_prefix_fullc)

    print("#ASN;CDF_PROP;ADDRSPACE_SIZE_CCI;ADDRSPACE_SIZE_FC;PREFIXES_COUNT_CCI;PREFIXES_COUNT_FC;COUNT_DIFF_PREFIXES")
    # compute CDF traffic bytes
    for asn in d_ases_internet.iterkeys():

        # check if we have data available from the member ASN
        if (asn in d_cc_asn_fileposition) and (asn in d_fullcone_asn_fileposition):

            # go to exact position at disk file and readline to get prefixes to memory -- PLCC
            data_prefix_cc.seek(d_cc_asn_fileposition[asn])
            line_prefixes_cc = data_prefix_cc.readline()
            cone_as_cc = line_prefixes_cc.strip().split(" ")[1:]

            # go to exact position at disk file and readline to get prefixes to memory -- FULL CONE
            d_prefix_fullc.seek(d_fullcone_asn_fileposition[asn])
            line_prefixes_fullcone = d_prefix_fullc.readline()
            cone_as_fullcone = line_prefixes_fullcone.strip().split(" ")[1:]

            # compute address space size CC
            size_addr_space_cc_prefixes = do_compute_address_space_per_asn(cone_as_cc, d_global_prefix_address_pace_size)

            # compute address space size FC
            size_addr_space_fullcone_prefixes = do_compute_address_space_per_asn(cone_as_fullcone, d_global_prefix_address_pace_size)

            cdf_prop_actual_record = float(size_addr_space_cc_prefixes) / float(size_addr_space_fullcone_prefixes)
            d_members_proportion_prefixes_cones[asn] = cdf_prop_actual_record

            # check to guarantee the correct order of differences computation
            if len(cone_as_fullcone) >= len(cone_as_cc):
                howmany_prefixes_fullcone_hasmore = set(cone_as_fullcone).difference(set(cone_as_cc))
                print("{};{};{};{};{};{};{}").format(asn,
                                               cdf_prop_actual_record,
                                               size_addr_space_cc_prefixes,
                                               size_addr_space_fullcone_prefixes,
                                               len(cone_as_cc),
                                               len(cone_as_fullcone),
                                               len(howmany_prefixes_fullcone_hasmore))

            # if PPLC has more prefixes
            else:
                howmany_prefixes_cci_hasmore = set(cone_as_cc).difference(set(cone_as_fullcone))
                print("{};{};{};{};{};{};{}").format(asn,
                                               cdf_prop_actual_record,
                                               size_addr_space_cc_prefixes,
                                               size_addr_space_fullcone_prefixes,
                                               len(cone_as_cc),
                                               len(cone_as_fullcone),
                                               len(howmany_prefixes_cci_hasmore))

        else:
            if (asn in d_cc_asn_fileposition) and not (asn in d_fullcone_asn_fileposition):
                print("# {} _not_present_in_PLCC_only_in_FC".format(asn))
            elif (asn in d_fullcone_asn_fileposition) and not (asn in d_cc_asn_fileposition):
                print("# {} _not_present_in_FC_only_in_PLCC".format(asn))

    return d_members_proportion_prefixes_cones


def build_dict_asns_fullcone_rawcones(path_to_file):
    """
    Build a dict with the key being the ASN value empty.
    """

    if path_to_file.lower().endswith('.gz'):  # full cone datasets
        f = gzip.open(path_to_file, 'rb')
    elif path_to_file.lower().endswith('.bz2'): # full cone datasets
        f = bz2.BZ2File(path_to_file, "r")

    d_as_cone_finder = dict()
    for line in f:
        lf = line.strip().split(" ")
        if len(lf) >= 2:
            k_asn = int(lf[0])

        # create a set of ASNs to each member
        if k_asn not in d_as_cone_finder:
            d_as_cone_finder[int(k_asn)] = None

    return d_as_cone_finder


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Compute cones diff between inferences '
                                                                   'implementation - FC vs PLCC.')

    parser.add_argument('-paths', dest='input_cc_paths_file', required=False,
                        help="File input w/ CC paths dataset.")

    parser.add_argument('-internetwide', dest='param_compute_diff_internetwide',
                        type=int, choices=[0, 1], required=True, default=1,
                        help="Set to:"
                             " 1 - to compute the difference to all ASNs in the AS-Level Customer Cone."
                             " 0 - to do nothing here.")

    parser.add_argument('-fc-asescone', dest='f_fc_asescone_dataset_file', required=True,
                        help="Path to file Full Cone ASes cone definition.")

    parser.add_argument('-fc-prefixescone', dest='f_fc_prefixescone_dataset_file', required=True,
                        help="Path to file Full Cone Prefixes cone definition.")

    parser.add_argument('-plcc-prefixescone', dest='f_plcc_prefixescone_dataset_file', required=True,
                        help="Path to file of PLCC cone definition.")

    parser.add_argument("-d", dest="dest_dir", type=str, required=False,
                        help="destination of the output files.")

    parser.add_argument("-eval", dest="eval_what_dataset", type=int, choices=[0, 1], required=True,
                        help="Options: "
                             "0: ppdc-ases"
                             "1: ppdc-prefixes")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    s_current_analysis = ""
    label_ases_analysis = "ases"
    label_prefixes_analysis = "prefixes"
    if parsed_args.eval_what_dataset == 0:
        s_current_analysis = label_ases_analysis
    elif parsed_args.eval_what_dataset == 1:
        s_current_analysis = label_prefixes_analysis

    # for each new prefix seen store the total number of existing /24 subnets.
    d_global_prefix_to_24subnets_count = dict()

    # if we compute for all ASes start here
    if parsed_args.param_compute_diff_internetwide == 1:

        ases_level_fc_file = parsed_args.f_fc_asescone_dataset_file

        print "Loading ASNs to memory: {}".format(ases_level_fc_file)
        d_ases_fc = build_dict_asns_fullcone_rawcones(ases_level_fc_file)
        print "Loading ASNs done, size: {}".format(str(len(d_ases_fc.keys())))

        prefix_level_cc_file = parsed_args.f_plcc_prefixescone_dataset_file
        prefix_level_fc_file = parsed_args.f_fc_prefixescone_dataset_file

        global d_global_prefix_address_pace_size
        d_global_prefix_address_pace_size = dict()

        print("Computing diff...")
        # ## COMPUTE PREFIXES PROPORTION
        d_internetwide_proportion_prefixes_cones = do_compute_proportion_prefixes_cone_size_internetwide(d_ases_fc,
                                                                                                         prefix_level_cc_file,
                                                                                                         prefix_level_fc_file,
                                                                                                         d_global_prefix_address_pace_size)

        print("Saving Internet-wide ASes processing results...")
        save_internetwide_proportion_results_to_file(d_internetwide_proportion_prefixes_cones,
                                                     parsed_args.dest_dir,
                                                     s_current_analysis)
