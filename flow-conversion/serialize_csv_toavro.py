#!/usr/bin/python
# -*- coding: utf-8 -*-
from os import sys, path
sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))

import utils.constants as cons
import utils.avrofile_manipulation_utilities as famutil
import utils.fileparsing_utilities as fputil
import csv
import argparse
import os


def main(argv):
    parser = argparse.ArgumentParser(prog=argv[0], description="Reads a CSV file containing flow records and outputs "
                                                               "in AVRO format.")
    parser.add_argument(dest="input_file_name", help="CSV file input without header/statistics")
    parser.add_argument(dest="output_file_name", help="AVRO filepath and output name")
    parser.add_argument("-s", dest="schema_file_name")

    # get values from arguments
    parsed_args = parser.parse_args()
    fn_input = parsed_args.input_file_name
    fn_output = parsed_args.output_file_name

    if parsed_args.schema_file_name:
        fn_schema = parsed_args.schema_file_name
    else:
        fn_schema = cons.DEFAULT_AVRO_NFCAP_FLOWS_SCHEMA_FILEPATH

    # prepare records to new format
    list_flow_records_to_write = []
    with open(fn_input, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')

        # read each line and transform it
        for flow_row in reader:
            flow_serialized = fputil.create_flow_record_from_csv(flow_row)
            list_flow_records_to_write.append(flow_serialized)

    # write records to avro file output
    famutil.save_records_to_avrofile(list_flow_records_to_write, fn_output, fn_schema)

    sys.stdout.write('File created: ' + fn_output + '\n')

    # delete the temporary *csv file at the end at each round of conversion (storage constraints)
    if os.path.exists(fn_input):
        os.remove(fn_input)


if __name__ == '__main__':
    main(sys.argv)

