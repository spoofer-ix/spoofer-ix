#!/usr/bin/env python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '../..')))
import argparse
import sys
import aggregate6 as prefixagg
import multiprocessing as mp
from itertools import islice
import time

"""
Computes the aggregated prefix-level cone definition dataset.
Format: ASN prefix/size prefix/size prefix/size ...
"""


def do_prefixes_merge(chunk_line):
    """
    Receive a prefix cone definition to be merged and execute it.
    Return: cone prefix definition merged.
    """

    d_cone_def_merged = dict()

    l_striped_line = chunk_line.strip().split(" ")
    id_asn_cone = l_striped_line[0]
    l_prefixes = l_striped_line[1:]

    d_cone_def_merged[id_asn_cone] = prefixagg.aggregate(l_prefixes)

    return d_cone_def_merged


def create_pool_prefixes_merge(chunk_lines, max_concurrent_jobs):
    """
    Manage the merge of multiple list of prefixes asynchronously in parallel.
    """
    # Create a pool of workers equaling cores on the machine
    pool = mp.Pool(processes=max_concurrent_jobs, maxtasksperchild=1)
    result = pool.imap(do_prefixes_merge, chunk_lines, chunksize=1)

    # Close the pool
    pool.close()

    # Combine the results of the workers
    pool.join()

    return result


def post_processing_aggregate_results(l_d_classification_results, fobj_prefixes_output):
    """
    Post processing results obtained from multi-processing cones prefixes.
    """

    # prepare three dictionaries as output
    for dict_result in l_d_classification_results:
        for k, v in dict_result.iteritems():

            if len(v) > 0:
                fobj_prefixes_output.write(str(k) + "".join(" %s" % str(data) for data in v) + "\n")


# ----------------------------------------------------------------------------------
#                              DEFAULT CONFIGURATION
# ----------------------------------------------------------------------------------
N_JOBS = mp.cpu_count() - 1  # definition of how many cpus will be in use for the task

if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Create the prefix-level Cone dataset aggregated.')

    parser.add_argument('-odir', dest='output_dir', required=True,
                        help="Dir to save output files")

    parser.add_argument('-np', dest='number_concur_process',
                        help="Number of concurrent process to execute")

    parser.add_argument('-prefixes', dest='cone_prefixes_file', required=False,
                        help="Original prefix-level cone file")

    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    # directory paths set up for the conversion process
    path_output_dir = parsed_args.output_dir
    p_prefix_file = parsed_args.cone_prefixes_file

    # number of concurrent process (performance control)
    if parsed_args.number_concur_process:
        n_cores_to_use = int(parsed_args.number_concur_process)
    else:
        n_cores_to_use = int(N_JOBS)

    fn_output_prefixes_pattern = "{out_dir}prefixes_aggregated.txt"

    # #### Create the output files #####
    fn_output = fn_output_prefixes_pattern.format(out_dir=path_output_dir)
    fobj_prefixes_output = open(fn_output, 'w')

    print "---Started multiprocessing cones prefixes..."

    prefix_cone_fileobj = open(p_prefix_file, 'r')

    number_lines_read = n_cores_to_use * 25
    chunk = list(islice(prefix_cone_fileobj, number_lines_read))
    while chunk:
        t0 = time.time()

        results = create_pool_prefixes_merge(chunk, n_cores_to_use)
        post_processing_aggregate_results(results, fobj_prefixes_output)
        chunk = list(islice(prefix_cone_fileobj, number_lines_read))

        t1 = time.time()
        total = t1-t0

        print "Time: {}".format(total)

    fobj_prefixes_output.close()

    print ">>> Finished multiprocessing cones prefixes!"
