#!/usr/bin/env python
# -*- coding: utf-8 -*-


def rawnum_to_humannum(n_num):
    un = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']  # should not go past 'PB'

    f_num = n_num * 1.0
    n_div = 0

    while f_num > 1000:
        f_num /= 1024.0
        n_div += 1

    s_num = str("%.2f" % f_num) + un[n_div]

    return s_num
