#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime


def time_in_range(start, end, x):
    """
    Return true if x is in the range [start, end]
    """
    if start <= end:
        return start <= x <= end
    else:
        return start <= x or x <= end


def formated_date(timestamp):
    return datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")


def full_formated_date(timestamp):
    return datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S.%f")


def short_formated_date(timestamp):
    return datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d")


def time_now():
    return int(datetime.datetime.utcnow().strftime("%s"))


def ts_to_date(ts):
    return datetime.datetime.fromtimestamp(int(ts))


def date_to_ts(dt):
    return int(dt.strftime("%s"))


def ymd_to_date(year, month, day):
    return datetime.datetime(year, month, day)


def strf_to_date(str_formated_date):
    return datetime.datetime.strptime(str_formated_date, '%Y-%m-%d %H:%M:%S')


def strff_to_date(str_formated_date):
    return datetime.datetime.strptime(str_formated_date, '%Y-%m-%d %H:%M:%S.%f')


def strsf_to_date(str_short_formated_date):
    return datetime.datetime.strptime(str_short_formated_date, '%Y-%m-%d')


def epoch():
    return ymd_to_date(1970, 1, 1)


EPOCH = epoch()
