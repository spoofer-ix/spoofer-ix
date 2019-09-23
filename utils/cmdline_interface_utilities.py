#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta


def get_timewindow_to_process(p_interval):
    """
    Extract from user input timestamp objects to use on files execution preparation.
    :param p_interval: arg string input from the user to set processing data time window.
    :return:
    """

    if "-" in p_interval:
        tw = p_interval.split('-')
        ts_start = tw[0]
        ts_end = tw[1]

        # eg. 201705250000-201705311645
        if len(ts_start) == 12 and len(ts_end) == 12:
            ts_start = datetime.strptime(ts_start, "%Y%m%d%H%M")
            ts_end = datetime.strptime(ts_end, "%Y%m%d%H%M")
            return ts_start, ts_end

        else:
            print("Invalid time window format! One of the dates doesnt have 12 digits (%Y%m%d%H%M).")
            exit(1)
    else:
        print("Invalid time window format! Missing - character.")
        exit(1)


def generate_flow_filenames_to_process(p_tw_start, p_tw_end, p_flowfiles_dir, p_flowfiles_extension):
    """
    Generate the list of flow filenames to the conversion processing.
    :return:
    """
    file_to_read_str = "{flowfiles_dir}nfcapd.{timestamp}{file_extension}"
    l_filenames = []

    dates_generated = [p_tw_start + timedelta(seconds=x) for x in range(0, int((p_tw_end - p_tw_start).total_seconds()) + 300, 300)]

    for ts in dates_generated:
        fr = file_to_read_str.format(flowfiles_dir=p_flowfiles_dir, timestamp=ts.strftime("%Y%m%d%H%M"), file_extension=p_flowfiles_extension)
        l_filenames.append(fr)

    return l_filenames


def generate_filenames_to_process_bysetof_extensions(p_tw_start, p_tw_end, p_flowfiles_dir, l_flowfiles_extension):
    """
    Generate a list of filenames based on timestamp records to the conversion processing.
    :return:
    """
    file_to_read_str = "{flowfiles_dir}nfcapd.{timestamp}{file_extension}"
    l_filenames = []

    dates_generated = [p_tw_start + timedelta(seconds=x) for x in range(0, int((p_tw_end - p_tw_start).total_seconds()) + 300, 300)]

    for op_extension in l_flowfiles_extension:
        for ts in dates_generated:
            fr = file_to_read_str.format(flowfiles_dir=p_flowfiles_dir, timestamp=ts.strftime("%Y%m%d%H%M"), file_extension=op_extension)
            l_filenames.append(fr)

    return l_filenames
