#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import gzip
import multiprocessing as mp
import shlex
from subprocess import Popen, CalledProcessError
import shutil
import os
import sys
import tempfile as tf

"""
---------------------------------------ABOUT----------------------------------------
Wrapper to NFDUMP deal with *.gz flow capture files.
------------------------------------------------------------------------------------
"""

# ----------------------------------------------------------------------------------
#                              DEFAULT CONFIGURATION
# ----------------------------------------------------------------------------------
global TEMP_OUTPUT_DEST_DIR
global BASE_OUTPUT_DEST_DIR
N_JOBS = mp.cpu_count() - 1  # definition of how many cpus will be in use for the task


def do_extract(list_of_filenames):
    """
    Manage the extraction of multiple files in parallel.
    :param list_of_filenames:
    :return:
    """
    # Create a pool of workers equaling cores on the machine
    pool = mp.Pool(N_JOBS)
    pool.imap(uncompress, list_of_filenames, chunksize=1)

    # Close the pool
    pool.close()

    # Combine the results of the workers
    pool.join()

    return


def uncompress(path):
    """
    Execute unzip and save the file to temp dir.
    :param path:
    :return:
    """
    global TEMP_OUTPUT_DEST_DIR
    flow_filename = os.path.basename(path)
    with gzip.open(path, 'rb') as src, open(TEMP_OUTPUT_DEST_DIR+"/"+flow_filename.rstrip('.gz'), 'wb') as dest:
        shutil.copyfileobj(src, dest)


if __name__ == '__main__':
    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Wrapper NFDUMP to be able to receive *.gz files as input.')
    parser.add_argument('-tmpdir', dest='temp_path', help="Temporary dir to extract files")

    exgroup_aggregation_format = parser.add_mutually_exclusive_group()
    exgroup_aggregation_format.add_argument('-a', dest='aggregate', action='store_true', help="Aggregate netflow data "
                                                                                              "at connection level by "
                                                                         "taking the 5-tuple protocol, srcip, dstip, "
                                                                         "srcport and dstport")
    exgroup_aggregation_format.add_argument('-ap', dest='aggregate_person', help="Set a personalized aggregation level"
                                                                                 "using by default the 5-tuple "
                                                                                 "protocol, srcip, dstip, srcport and "
                                                                                 "dstport adding the extra fields "
                                                                                 "indicated by parameter")
    exgroup_output_format = parser.add_mutually_exclusive_group()
    exgroup_output_format.add_argument('-o', dest='output_format', help="Selects the output format to print flows")
    exgroup_output_format.add_argument('--of', dest='output_format_file', help="Selects the output format to print "
                                                                               "flows from formatfile")
    parser.add_argument('-f', dest='filters_format_file', help="Reads the filter syntax from filterfile")
    exgroup_input_format = parser.add_mutually_exclusive_group(required=True)
    exgroup_input_format.add_argument('-R', '--file-list', dest='set_files', nargs='*', help="the nfcapd file(s) mask")
    exgroup_input_format.add_argument('-r', '--file', dest='uniq_file', help="the nfcapd file name")
    parser.add_argument('-saver', dest='full_filepath_save_results', help="Save the results of a nfcap reading to an"
                                                                          "ouput file.")

    # parse parameters
    parsed_args = parser.parse_args()

    # if distinct temp path used, otherwise use default
    if parsed_args.temp_path:
        BASE_OUTPUT_DEST_DIR = parsed_args.temp_path
        TEMP_OUTPUT_DEST_DIR = tf.mkdtemp(dir=BASE_OUTPUT_DEST_DIR)
    else:
        BASE_OUTPUT_DEST_DIR = "/Users/lucasmuller/temp/"
        TEMP_OUTPUT_DEST_DIR = tf.mkdtemp(dir=BASE_OUTPUT_DEST_DIR)

    # start building command line
    nfdump_args = 'nfdump '
    if parsed_args.set_files:  # only works for a continuous set of files
        filenames = parsed_args.set_files
        do_extract(filenames)

        files = []
        for file in parsed_args.set_files:
            flow_filename = os.path.basename(file)
            files += [TEMP_OUTPUT_DEST_DIR + "/" + flow_filename.rstrip('.gz')]

        sorted_files = sorted(files)
        first_file = sorted_files[0]
        last_file = os.path.basename(sorted_files[-1])
        nfdump_args += '-R ' + first_file + ':' + last_file + ' -q'

    if parsed_args.uniq_file:  # only for one file
        f = [parsed_args.uniq_file]
        do_extract(f)
        flow_filename = os.path.basename(f[0])
        flow_file = TEMP_OUTPUT_DEST_DIR + "/" + flow_filename.rstrip('.gz')
        nfdump_args += '-r ' + flow_file + ' -q'

    if parsed_args.aggregate:
        nfdump_args += ' -a '

    if parsed_args.aggregate_person:
        nfdump_args += ' -A ' + parsed_args.aggregate_person

    if parsed_args.output_format:
        nfdump_args += ' -o ' + parsed_args.output_format

    if parsed_args.output_format_file:
        of_file = open(parsed_args.output_format_file, "r")
        output_format = of_file.readline()
        of_file.close()
        nfdump_args += ' -o ' + output_format

    if parsed_args.filters_format_file:
        nfdump_args += ' -f ' + parsed_args.filters_format_file

    # if requested to save the reading to an external file
    if parsed_args.full_filepath_save_results:
        with open(parsed_args.full_filepath_save_results, 'w') as out:
            try:
                args = shlex.split(nfdump_args)
                process = Popen(args, stdout=out)
                process.wait()

                out.flush()
                out.close()
            except CalledProcessError as e:
                print e.output
            except KeyboardInterrupt:
                # Allow ^C to interrupt from any thread.
                sys.stdout.write('user interrupt\n')
    else:
        # Execute NFDUMP OS call
        os.system(nfdump_args)

    # Delete the temporary folder and files at the end
    shutil.rmtree(TEMP_OUTPUT_DEST_DIR)
