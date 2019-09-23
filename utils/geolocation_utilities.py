#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import pyipmeta
except ImportError:
    pass

import geoip2.database  # geoip2 official API - github.com/maxmind/GeoIP2-python
import utils.constants as cons


def get_country_maxmind_geoip_from_prefix(str_ip_prefix, geoipdb_reader):
    """
    Geo locate IP Prefix using Maxmind Geoip2 Lite.
    :param str_ip_prefix:
    :param path_to_geodb:
    :return:
    """

    # Queries MaxMindDB - "country" corresponds to the database in use
    match = None
    country_code = None
    
    try:
        # Get only IP
        ip = str_ip_prefix.split('/')[0]
        match = geoipdb_reader.country(ip)

    except geoip2.errors.AddressNotFoundError:
        print "AddressNotFoundError: {}".format(str_ip_prefix)

    if match:
        country_code = match.country.iso_code
        # country_name = match.country.name

    return country_code


def load_netacq_edge_geodb_by_timewindow(p_tw_start):
    """
    Load the netacq edge lookup database for a given time window.
    :param p_tw_start:
    :return:
    """

    str_key = str(p_tw_start.year) + str(p_tw_start.month)
    i_geodb_id = 0

    if str_key in cons.DICT_DEFAULT_PATH_TO_NETACQEDGE_DATABASE:

        if module_exists("pyipmeta"):
            print ">INFO[utils/geolocation_utilities.py]: load netacq-edge geodb."
            ipm = pyipmeta.IpMeta(provider="netacq-edge",
                                  provider_config="-b {} -l {}".format(cons.DICT_DEFAULT_PATH_TO_NETACQEDGE_DATABASE[str_key][0],
                                                                       cons.DICT_DEFAULT_PATH_TO_NETACQEDGE_DATABASE[str_key][1]))
            i_geodb_id = 1
        # fallback to Maxmind GeoIP2
        else:
            print ">INFO[utils/geolocation_utilities.py]: load Maxmind Geolite2 geodb."
            # Creates a Reader object, use the same object across multiple requests
            ipm = geoip2.database.Reader(cons.DEFAULT_PATH_TO_GEOLITE2_DATABASE[str_key])
            i_geodb_id = 2

    else:
        print ">ERROR[utils/geolocation_utilities.py]: fail to load geolocation database file."
        exit(1)

    return ipm, i_geodb_id


def get_country_netacq_edge_from_ip(str_ip, ipmeta_query_obj, i_geodb_id):

    # netacq_edge db query
    if i_geodb_id == 1:
        result = ipmeta_query_obj.lookup(str_ip)
        str_country = None

        if result[0]['country_code'] != '??':
            str_country = result[0]['country_code']

    # Maxmind GeoIP2 query
    if i_geodb_id == 2:
        str_country = get_country_maxmind_geoip_from_prefix(str_ip, ipmeta_query_obj)

    return str_country


def module_exists(module_name):
    try:
        __import__(module_name)
    except ImportError:
        return False
    else:
        return True
