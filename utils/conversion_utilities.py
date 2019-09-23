#!/usr/bin/python
# -*- coding: utf-8 -*-

from netaddr import IPAddress, EUI, mac_unix_expanded


def intVLen_to_abytes(num, lenght):
    l_bytes = []
    for idx in range(lenght):
        l_bytes += [0]
        l_bytes[idx] = 0xFF & num
        num >>= 8
    a_bytes = bytearray(l_bytes)
    return a_bytes


def abytes_to_intVLen(a_bytes, lenght):
    num = 0
    for idx in range(lenght):
        num += a_bytes[idx] << idx * 8
    return num


def int48_to_bytes(num):
    a_bytes = intVLen_to_abytes(num, 6)  # 48bits = 6 bytes
    return bytes(a_bytes)


def bytes_to_int48(bytes):
    num = abytes_to_intVLen(bytearray(bytes), 6)  # 48bits = 6 bytes
    return num


def int32_to_bytes(num):
    a_bytes = intVLen_to_abytes(num, 4)  # 32bits = 4 bytes
    return bytes(a_bytes)


def bytes_to_int32(bytes):
    num = abytes_to_intVLen(bytearray(bytes), 4)  # 32bits = 4 bytes
    return num


def int128_to_bytes(num):
    a_bytes = intVLen_to_abytes(num, 16)  # 128bits = 16 bytes
    return bytes(a_bytes)


def bytes_to_int128(bytes):
    num = abytes_to_intVLen(bytearray(bytes), 16)  # 128bits = 16 bytes
    return num


def mac_to_record(obj_mac_address):
    """

    :param obj_ip_address: EUI object created with netaddr lib
    :return:
    """
    return int48_to_bytes(int(obj_mac_address))


def record_to_mac(bytes_mac_address):
    return str(EUI(bytes_to_int48(bytes_mac_address), dialect=mac_unix_expanded))


def ipv4_to_record(obj_ip_address):
    """

    :param obj_ip_address: IPAddress object created with netaddr lib
    :return:
    """
    return int32_to_bytes(int(obj_ip_address))


def record_to_ipv4(bytes_ip_address):
    return str(IPAddress(bytes_to_int32(bytes_ip_address)))


def ipv6_to_record(obj_ip_address):
    """

    :param obj_ip_address: IPAddress object created with netaddr lib
    :return:
    """
    return int128_to_bytes(int(obj_ip_address))


def record_to_ipv6(bytes_ip_address):
    return str(IPAddress(bytes_to_int128(bytes_ip_address)))

