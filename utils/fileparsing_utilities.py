#!/usr/bin/env python
# -*- coding: utf-8 -*-

import utils.constants as cons
import utils.conversion_utilities as cutil
import utils.time_utilities as tutil
from avro.datafile import DataFileReader
from avro.io import DatumReader
from netaddr import IPAddress, EUI
import csv
from os import path
import datetime
import zlib

# Constants
DEFAULT_FIELDS = cons.DEFAULT_FIELDS


# ====================================================
# sanitization and conversion 1: loading and printing
# ====================================================
def ts_to_datetime(ts):
    if ts is None:
        ts = 0

    return tutil.formated_date(ts)


def record_to_numeric(num):
    """
    Check if the field has a value other then zero.
    :param str_field_to_check:
    :return:
    """
    if num is None:
        return 0
    else:
        return num


def proto_int_to_str(int_proto):
    if int_proto in cons.d_proto_int_str:
        return cons.d_proto_int_str[int_proto]
    else:
        return str(int_proto)


def flags_int_to_str(flags):
    if flags == None:
        return "......"
    else:
        try:
            if flags > 63:
                return str(hex(flags))
            else:
                str_flags = ''
                for symb in 'UAPRSF':
                    if flags & 32:
                        str_flags += symb
                    else:
                        str_flags += '.'
                    flags <<= 1
                return str_flags
        except TypeError:
            return str(flags)  # This is probably encoded as a string, so just return it


def ip_bytes_to_str(ip_bytes):
    if len(ip_bytes) == 4:
        ip_str = cutil.record_to_ipv4(ip_bytes)
    else:
        ip_str = cutil.record_to_ipv6(ip_bytes)

    return ip_str


def record_to_ip(ipaddress):
    if ipaddress is None:
        return "0.0.0.0"
    else:
        return ip_bytes_to_str(ipaddress)


def record_to_mac(macaddress):
    if macaddress is None:
        return "00:00:00:00:00:00"
    else:
        return cutil.record_to_mac(macaddress)


# ====================================================
# loading data to process and printing
# ====================================================
def get_flowrecords_from_flowdata_file(filename_path_input):
    """
    Create a Python generator to read the csv/txt/avro file returning the records to processing.
    *Important: when considering CSV/TXT files remember to use files without header/statistics as input files*
    :param filename_path_input: exported csv/txt/avro flow input file from the original nfpcap file via NFDUMP
    :return: generator to records from file
    """
    if filename_path_input.lower().endswith(('.csv', '.txt')):
        with open(filename_path_input) as csvfile:
            reader = csv.reader(csvfile)
            for line in reader:
                yield create_flow_record_from_csv(line)

    # >> default extension Apache AVRO <<
    else:
        # prepare to read binary
        flowsrecords_reader = DataFileReader(open(filename_path_input, "rb"), DatumReader())
        try:
            for flow in flowsrecords_reader:
                yield flow
        except zlib.error as ze:
            print ze.message
            pass
        except IOError as io:
            print io.message


def get_single_avro_record(flow_record, l_fields_to_process=DEFAULT_FIELDS):
    """
    Reads a single flow record in dictionary format and outputs as a list. The output
    list will contain the entries specified in l_entry_to_process argument, in the same
    order as listed by this argument.

    :param flow_record:
    :param l_entry_to_process:
    :return:
    """

    l_record = []

    for k in l_fields_to_process:
        if k in ["ts", "te", "tr"]:
            l_record += [ts_to_datetime(flow_record[k])]
        elif k in ["td"]:
            l_record += [round(float(record_to_numeric(flow_record[k])), 3)]
        elif k in ["sa", "da", "nh", "nhb", "ra"]:
            l_record += [record_to_ip(flow_record[k])]
        elif k in ["pr"]:
            l_record += [proto_int_to_str(flow_record[k])]
        elif k in ["flg"]:
            l_record += [flags_int_to_str(flow_record[k])]
        elif k in ["ismc", "odmc", "idmc", "osmc"]:
            l_record += [record_to_mac(flow_record[k])]
        else:
            l_record += [record_to_numeric(flow_record[k])]

    return l_record


def load_avro_flow_records(flowsrecords_reader, l_fields_to_process=DEFAULT_FIELDS):
    """
    Reads flow records and outputs as a list of flow records. Each flow record will
    contain the entries specified in l_entry_to_process argument, in the same order
    as listed by this argument.

    :param flowsrecords_reader:
    :param l_entry_to_process:
    :return:
    """

    l_flow_records = []
    for flow in flowsrecords_reader:
        l_flow_records += [get_single_avro_record(flow, l_fields_to_process)]

    return l_flow_records


def to_csv(l_fields):
    return ",".join([str(f) for f in l_fields])


def print_single_record(l_fields):
    print to_csv(l_fields)


def print_flow_records(l_flowrecords):
    for l_fields in l_flowrecords:
        print_single_record(l_fields)


def dump_avro_flow_records(flowsrecords_reader, l_fields_to_process=DEFAULT_FIELDS):
    """
    Reads flow records and output to the screen. The output will follow that specified
    in l_entry_to_process argument, in the same order as listed by this argument.

    :param flowsrecords_reader:
    :param l_entry_to_process:
    :return:
    """

    l_flow_records = []
    for flow in flowsrecords_reader:
        record = get_single_avro_record(flow, l_fields_to_process)
        print_single_record(record)
        l_flow_records += [record]

    return l_flow_records


# ====================================================
# sanitization and convertion 2: creating files
# ====================================================
def datetime_to_ts(str_datetime):
    """
    Transform datetime representation to unix epoch.
    :return:
    """
    if '1969-12-31' in str_datetime:
        # ignore default values
        return None
    else:
        # convert to timestamp
        if '.' in str_datetime:  # check whether it has milliseconds or not
            dt = tutil.strff_to_date(str_datetime)
        else:
            dt = tutil.strf_to_date(str_datetime)
        ts = tutil.date_to_ts(dt)
        return ts


def numeric_to_record(n_field):
    """
    Check if the field has a value other then zero.
    :param str_field_to_check:
    :return:
    """
    if n_field == 0:
        return None
    else:
        return n_field


def ip_str_to_bytes(ip_str):
    """
    Check the respective IP address version 4 or 6 then do the appropriate conversion call.
    :param ip_str:
    :return:
    """
    ip = IPAddress(ip_str)
    if ip.version == 4:
        ip_converted_byte = cutil.ipv4_to_record(ip)
    else:
        ip_converted_byte = cutil.ipv6_to_record(ip)

    return ip_converted_byte


def proto_str_to_int(str_proto):
    if str_proto in cons.d_proto_str_int:
        return cons.d_proto_str_int[str_proto]
    else:
        return None


def flags_str_to_int(str_flags):
    """
    Check if there is some value in flags field
    :param flags_str:
    :return:
    """
    if str_flags == "......":
        return None
    else:
        try:
            i_flags = int(str_flags, 16)
            return i_flags
        except ValueError:
            i_flags = 0
            idx = 32
            for symb in str_flags:
                if symb in 'UAPRSF':
                    i_flags += idx
                idx >>= 1
            return i_flags


def ip_to_record(ipaddress):
    """
    Check for a valid ip address.
    :param ipaddress:
    :return:
    """
    if ipaddress == "0.0.0.0":
        return None
    else:
        return ip_str_to_bytes(ipaddress)


def mac_to_record(macaddress):
    """
    Check for a valid mac address.
    :param macaddress:
    :return:
    """
    if macaddress == "00:00:00:00:00:00":
        return None
    else:
        return cutil.mac_to_record(EUI(macaddress))


def create_flow_record_from_csv(flow_fields, l_fields_to_process=DEFAULT_FIELDS):
    """
    Transform the received flow record in CSV format into a more compact version to save.
    The output dictionary will contain the entries specified in l_entry_to_process argument.
    :param flow_line:
    :param l_entry_to_process:
    :return:
    """

    d_flow_record = {}
    for k in l_fields_to_process:
        try:
            field = flow_fields[cons.d_flow_key_to_idx[k]]
        except IndexError:
            print "flow_fields: ", flow_fields, " field: ", k, " index field: ", cons.d_flow_key_to_idx[k]

        if k in ["ts", "te", "tr"]:
            d_flow_record[k] = datetime_to_ts(field)

        elif k in ["td"]:
            field = round(float(field), 3)
            d_flow_record[k] = numeric_to_record(field)

        elif k in ["sa", "da"]:
            d_flow_record[k] = ip_str_to_bytes(field)

        elif k in ["pr"]:
            d_flow_record[k] = proto_str_to_int(field)

        elif k in ["flg"]:
            d_flow_record[k] = flags_str_to_int(field)

        elif k in ["sp", "dp", "fwd", "stos", "ipkt", "opkt", "in", "out", "sas", "das", "smk", "dmk", "dtos", "dir",
                   "svln", "dvln"]:
            d_flow_record[k] = numeric_to_record(int(field))

        elif k in ["ibyt", "obyt"]:
            d_flow_record[k] = numeric_to_record(long(field))

        elif k in ["nh", "nhb", "ra"]:
            d_flow_record[k] = ip_to_record(field)

        elif k in ["ismc", "odmc", "idmc", "osmc"]:
            d_flow_record[k] = mac_to_record(field)

    return d_flow_record


def extract_timestamp_from_flowfilepath(flow_filepath):
    """
    Extract from flow file path the date/time information.
    :param fp_flowfile:
    :return: datetime object parsed from a string
    """
    flow_filename = path.basename(flow_filepath)

    if flow_filename:
        flow_filename_timestamp = flow_filename.split('.')[1]
        return datetime.datetime.strptime(flow_filename_timestamp, "%Y%m%d%H%M")
    else:
        return None
