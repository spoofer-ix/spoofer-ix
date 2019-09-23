#!/usr/bin/env python
# -*- coding: utf-8 -*-

import utils.constants as cons
import pyasn


class PrefixUtilsRouteViews(object):

    def __init__(self, p_tw_start):
        """
        Load the IPAddress to Prefix/ASN lookup database from Routeviews.
        """
        self.s_start_time = p_tw_start

        str_key = str(self.s_start_time.year) + str(self.s_start_time.month)

        if str_key in cons.DICT_OF_ROUTEVIEWS_IP2PREFIX_DATABASES:
            path_to_file = cons.DICT_OF_ROUTEVIEWS_IP2PREFIX_DATABASES[str_key]
        else:
            print "> ERROR: fail to load Routeviews ip2prefixasn database file."
            path_to_file = ""

        self.ip_prefix_db_routeviews = pyasn.pyasn(path_to_file)

    def do_prefix_lookup_forip(self, str_ip_address):
        """
        For a given ip address execute a lookup on routeviews db to get the prefix and asn information.
        :param str_ip_address:
        :return:
        """

        try:
            prefix_lookup_result = self.ip_prefix_db_routeviews.lookup(str_ip_address)
            origin_asn = prefix_lookup_result[0]
            ip_prefix = prefix_lookup_result[1]
            return origin_asn, ip_prefix

        except:
            print "Routeviews DB lookup failed! Double check if the file is ok."
            return None, None
