#!/usr/bin/env python
# -*- coding: utf-8 -*-

import utils.constants as cons
import avro.schema
from avro.datafile import DataFileReader
from avro.io import DatumReader

from avro.datafile import DataFileWriter
from avro.io import DatumWriter


def save_records_to_avrofile(flows_towrite, fn_output, avro_schema=cons.DEFAULT_AVRO_NFCAP_FLOWS_SCHEMA_FILEPATH):
    """
    Write to an AVRO file a given a dictionary or a list of dicts containing flow records.
    :param flows_towrite: dict or list of flow records.
    :param fn_output: .avro output filepath and name.
    :param avro_schema: schema to write the records to an .avro file.
    :return: none
    """
    # load schema
    schema = avro.schema.parse(open(avro_schema, "rb").read())

    # create object writer
    writer = DataFileWriter(open(fn_output, "wb"), DatumWriter(), schema, codec="deflate")

    # write records to avro file output
    if type(flows_towrite) is dict:
        for k, v in flows_towrite.items():
            writer.append(v)
        writer.close()

    if type(flows_towrite) is list:
        for record in flows_towrite:
            writer.append(record)
        writer.close()


def create_new_empty_avro_file(fn_output, avro_schema=cons.DEFAULT_AVRO_NFCAP_FLOWS_SCHEMA_FILEPATH):
    """
    Create an AVRO empty file to write content on-the-fly.
    :param fn_output: file name
    :param avro_schema: avro .AVSC model
    :return: writer object
    """
    # load schema
    schema = avro.schema.parse(open(avro_schema, "rb").read())

    # create object writer
    writer = DataFileWriter(open(fn_output, "wb"), DatumWriter(), schema, codec="deflate")

    return writer


def save_rawtraffic_categories_records_to_avrofiles(flow_record_towrite, fn_avrowriter_obj):
    """
    Add content to an AVRO file.
    :param flow_record_towrite:
    :param fn_avrowriter_obj:
    :return:
    """
    try:
        if not str(flow_record_towrite):
            print "trying to save empty flow record during multiprocessing"

        fn_avrowriter_obj.append(flow_record_towrite)

    except Exception as e:
        print('Caught exception in writing avro file: {}').format(flow_record_towrite)
        # This prints the type, value, and stack trace of the
        # current exception being handled.
        raise e


def close_writing_avrofile(fn_avrowriter_obj):
    """
    Close AVRO file when finish writing operations.
    :param fn_avrowriter_obj:
    :return:
    """
    fn_avrowriter_obj.close()


def open_avrofile(fn_input):
    """
    Return an the data file reader to a given AVRO file.
    *note that to open an .avro file is not necessary to inform the schema because it's embedded in the file*
    :param fn_input:
    :return: record reader object
    """
    return DataFileReader(open(fn_input, "rb"), DatumReader())
