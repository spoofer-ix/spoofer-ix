#!/usr/bin/python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import argparse
import sys
import os
import multiprocessing as mp
import shlex
from subprocess import Popen, CalledProcessError
from numpy import arange, random
import tempfile as tf
import shutil
import utils.constants as cons
import utils.cmdline_interface_utilities as cmdutil
import logging
import utils.notification_utilities as notifutil
from timeit import default_timer as timer

"""
---------------------------------------ABOUT----------------------------------------
Wrapper to convert NFDUMP *.gz flow capture files to Apache AVRO format.
Depends on the following other scripts:
    * flows-wrapper.py  --> this one needs NFDUMP software already installed.
    * serialize_csv_toavro.py
------------------------------------------------------------------------------------
"""


def do_conversion(list_of_commands, max_concurrent_jobs):
    """
    Manage the conversion of multiple files asynchronously in parallel.
    :param list_of_commands:
    :param max_concurrent_jobs:
    :return:
    """
    # Create a pool of workers equaling cores on the machine
    pool = mp.Pool(processes=max_concurrent_jobs)

    try:
        l_pids = pool.imap(do_execute_conversion_call, list_of_commands, chunksize=1)
    except KeyboardInterrupt:
        # Allow ^C to interrupt from any thread.
        sys.stdout.write('\033[0m')
        sys.stdout.write('user interrupt\n')

    # Close the pool
    pool.close()

    # Combine the results of the workers
    pool.join()

    return l_pids


def do_execute_conversion_call(cmd_call):
    """
    Make the call to execute the bash command.
    :param cmd_call:
    :return:
    """
    try:
        args = shlex.split(cmd_call)
        process = Popen(args)
        process.wait()

        return process.pid

    except CalledProcessError as e:
        print e.output
    except KeyboardInterrupt:
        # Allow ^C to interrupt from any thread.
        sys.stdout.write('\033[0m')
        sys.stdout.write('user interrupt\n')


def do_move_files(src, dest, file_extension):
    """
    Move a list of files from a given source to a destination.
    :param src:
    :param dest:
    :return:
    """
    for file in os.listdir(src):
        if file.endswith(file_extension):
            try:
                shutil.move(src+file, dest)
            except shutil.Error as e:
                print('Error: %s' % e)
            except IOError as e:
                print('Error: %s' % e.strerror)


def check_pid(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False  # is not running
    else:
        return True  # is running


# ----------------------------------------------------------------------------------
#                              DEFAULT CONFIGURATION
# ----------------------------------------------------------------------------------
N_JOBS = mp.cpu_count() - 1  # definition of how many cpus will be in use for the task
DEFAULT_FLOWS_WRAPPER_SCRIPT_PATH = "python flow-tools-analysis/flows-wrapper.py"
DEFAULT_SERIALIZE_CSV_TOAVRO_SCRIPT_PATH = "python flow-conversion/serialize_csv_toavro.py"

DEFAULT_CMD_FLOW_WRAPPER = DEFAULT_FLOWS_WRAPPER_SCRIPT_PATH + " -r {flowfiles_dir}{flow_file}.gz -o csv -tmpdir {processing_temp_dir} -saver {conversion_output_dir}{out_filename}.csv"
DEFAULT_CMD_SERIALIZE_TOAVRO = DEFAULT_SERIALIZE_CSV_TOAVRO_SCRIPT_PATH + " {conversion_output_dir}{input_csv_file}.csv {conversion_output_dir}{output_avro_file}.avro -s {schema}"

if __name__ == '__main__':
    """
    Build cli parameter parser.
    """

    parser = argparse.ArgumentParser(prog=sys.argv[0], description='Wrapper to convert NFDUMP nfcap *.gz files to '
                                                                   'Apache Avro.')
    parser.add_argument('-tw', dest='time_window_op', required=True,
                        help="Time window to load files to process. Format: start-end, %Y%m%d%H%M-%Y%m%d%H%M")

    parser.add_argument('-flowdir', dest='flows_dir_path', required=True,
                        help="Directory where are located the flows to convert")

    parser.add_argument('-tmpdir', dest='temp_path', required=True,
                        help="Temporary directory to store the files that have been converted")

    parser.add_argument('-s', dest='schema_file_name',
                        help="Path and schema file name to process .avro files")

    parser.add_argument('-np', dest='number_concur_process',
                        help="Number of concurrent process to execute")

    parser.add_argument('-nodel', dest='is_to_delete_files',
                        help="By default delete intermediate CSV files, if not desired set this parameter to 0")

    parser.add_argument('-w', dest='steps_to_exec', type=int, choices=[1, 2, 3], required=True,
                        help="Conversion : 1 - .csv; "
                        "2 - .avro; "
                        "3 - .csv and .avro")

    parser.add_argument('-log', dest='loglevel', required=True,
                        help="Set the log level (debug, info, warn, error, critical).")

    start = timer()
    # ------------------------------------------------------------------
    # parse parameters
    # ------------------------------------------------------------------
    parsed_args = parser.parse_args()

    # set up of variables to generate flow file names
    if parsed_args.time_window_op:
        tw_start, tw_end = cmdutil.get_timewindow_to_process(parsed_args.time_window_op)

    # avro schema filepath
    if parsed_args.schema_file_name:
        fn_schema = parsed_args.schema_file_name
    else:
        fn_schema = cons.DEFAULT_AVRO_NFCAP_FLOWS_SCHEMA_FILEPATH

    # number of concurrent process (performance control)
    if parsed_args.number_concur_process:
        n_cores_to_use = int(parsed_args.number_concur_process)
    else:
        n_cores_to_use = int(N_JOBS)

    # directory paths set up for the conversion process
    flowfiles_basedir = parsed_args.flows_dir_path
    base_tmp_dir = parsed_args.temp_path
    temp_dir = tf.mkdtemp(dir=base_tmp_dir) + "/"

    op_loglevel = parsed_args.loglevel

    # ------------------------------------------------------------------
    # logging parameters
    # ------------------------------------------------------------------
    fn_log = base_tmp_dir + 'conversion_wrapper_nfpcap_to_avro.log'
    numeric_level = getattr(logging, op_loglevel.upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % op_loglevel)

    logging.basicConfig(filename=fn_log, filemode='w', level=numeric_level)

    # ------------------------------------------------------------------
    # initiate the new list of commands to execute
    # ------------------------------------------------------------------
    commands = list()

    # ------------------------------------------------------------------
    # bash call commands definition
    # ------------------------------------------------------------------
    cmd_flowwrapper = DEFAULT_CMD_FLOW_WRAPPER
    cmd_serialize_toavro = DEFAULT_CMD_SERIALIZE_TOAVRO

    # ------------------------------------------------------------------
    #   validate what will be executed
    # ------------------------------------------------------------------
    l_filenames_to_process = cmdutil.generate_flow_filenames_to_process(tw_start, tw_end, "", "")

    # Only convert NFCAP to CSV
    if parsed_args.steps_to_exec == 1:

        for fn_flowfile in l_filenames_to_process:
            cmd = cmd_flowwrapper.format(flowfiles_dir=flowfiles_basedir, flow_file=fn_flowfile,
                                         processing_temp_dir=temp_dir,
                                         conversion_output_dir=temp_dir, out_filename=fn_flowfile)
            commands.append(cmd)
        # execute conversion
        do_conversion(commands, n_cores_to_use)

    # Only convert CSV to AVRO
    if parsed_args.steps_to_exec == 2:

        for fn_flowfile in l_filenames_to_process:
            cmd = cmd_serialize_toavro.format(input_csv_file=fn_flowfile, output_avro_file=fn_flowfile,
                                              conversion_output_dir=base_tmp_dir, schema=fn_schema)
            commands.append(cmd)
        # execute conversion
        do_conversion(commands, n_cores_to_use)

    # All conversion enabled, first NFCAP to CSV and second convert CSV to AVRO
    if parsed_args.steps_to_exec == 3:

        for fn_flowfile in l_filenames_to_process:
            cmd = cmd_flowwrapper.format(flowfiles_dir=flowfiles_basedir, flow_file=fn_flowfile,
                                         processing_temp_dir=temp_dir,
                                         conversion_output_dir=temp_dir, out_filename=fn_flowfile)
            commands.append(cmd)
        # execute conversion
        print "--- [1] Started nfpcap > csv conversion: "
        logging.info("Commands to execute: \n {}".format(commands))

        n_cores_to_use = int(N_JOBS)
        resulting_pids = do_conversion(commands, n_cores_to_use)

        print "--- [2] Started csv > avro conversion: "
        # start new list of commands to execute
        commands = list()

        random.shuffle(l_filenames_to_process)
        for fn_flowfile in l_filenames_to_process:
            cmd = cmd_serialize_toavro.format(input_csv_file=fn_flowfile, output_avro_file=fn_flowfile,
                                              conversion_output_dir=temp_dir, schema=fn_schema)
            commands.append(cmd)

        # execute conversion (memory control limiting the use of cores at the same time)
        n_cores_to_use = int(parsed_args.number_concur_process)
        do_conversion(commands, n_cores_to_use)

    # ------------------------------------------------------------------
    # cleaning temporary files generated and moving results to final directories
    # ------------------------------------------------------------------
    # move *.avro files to destination
    do_move_files(temp_dir, base_tmp_dir, cons.DEFAULT_AVRO_FILE_EXTENSION)
    if parsed_args.is_to_delete_files is None:
        # delete the temporary folder and *csv files at the end
        shutil.rmtree(temp_dir)

    end = timer()
    print "---Sending e-mail notification about the execution status:"
    notifutil.send_notification_end_of_execution(sys.argv, sys.argv[0], start, end)
