#!/usr/bin/env python

import argparse
import json
import gzip
import re

"""
Receives as input 'json.gz' files containing switches configuration 
extracted data, parse and create auxiliary mapping files to other systems.
"""


def get_params():

    parser = argparse.ArgumentParser(prog='Parse data from switches and create mappings.')

    parser.add_argument('-s',
            help='<path to file> containing information about switches (IP, manufacturer, colocation)',
            dest='fp_info_switches',
            nargs='*',
            default=[])

    parser.add_argument('-i',
            help='<filename> containing cmds executed in the set of switches',
            dest='fp_info_commands',
            nargs='*',
            default=[])

    parser.add_argument('-tmpdir',
            help='Temporary dir to save output files',
            dest='temp_path',
            nargs='*',
            default=[])

    args = parser.parse_args()

    return args


def create_mac2asn_mapping_file(args):
    """
    Create mac2asn mapping file.
    Requires switches configuration output from two command line queries.
    :param args:
    :return:
    """

    l_cmds_required_to_mapping_processing = ["show ports no",
                                             "show configuration fdb",
                                             "sh configuration | i display-string"]
    d_mac2asn_output = dict()

    # list of IP addresses
    print("Filepath of SW: {}".format(args.fp_info_switches))
    try:
        with open(args.fp_info_switches[0], 'r') as fd:
            l_info_switches = fd.read().strip().splitlines()
    except:
        pass

    # list of cmds executed in each switch
    print("Filepath of CMD: {}".format(args.fp_info_commands))
    try:
        with open(args.fp_info_commands[0], 'r') as fd:
            l_cmds_executed = fd.readlines()
    except:
        pass

    # for each device and each command process output files
    for ipaddr in l_info_switches:
        ipaddr_device = ipaddr.split('=')[0]
        s_device_manufacturer = ipaddr.split('=')[1]
        s_device_colocation_facility = ipaddr.split('=')[2]
        s_ipx_id_label = ipaddr.split('=')[3]

        print("ip: {} | s_device_manufacturer: {} | s_device_colocation_facility: {} |  s_ipx_id_label: {}".format(ipaddr_device, s_device_manufacturer, s_device_colocation_facility, s_ipx_id_label))

        # load data from all commands to then process and create the mapping data
        for cmd in l_cmds_executed:
            cli_cmd = cmd.rstrip()
            # pattern of output files from switches
            fn_output_info_pattern = "{file_dest_dir}{file_name}.ip={ip}.manufacturer={manufacturer}.command={data_command}.json.gz"
            fn_output_device_config_info = fn_output_info_pattern.format(file_dest_dir=args.temp_path[0],
                                                                         file_name="device-config",
                                                                         ip=ipaddr_device,
                                                                         manufacturer=s_device_manufacturer,
                                                                         data_command=cli_cmd)

            print("Loading file: {}".format(fn_output_device_config_info))

            # 1st command required
            if cli_cmd == l_cmds_required_to_mapping_processing[0]:
                o_info_ports_zip = gzip.open(fn_output_device_config_info, 'rb')
                l_d_info_ports_parsed = json.load(o_info_ports_zip)

            # 2nd command required
            if cli_cmd == l_cmds_required_to_mapping_processing[1]:
                o_fdb_config_zip = gzip.open(fn_output_device_config_info, 'rb')
                l_d_fdb_config_parsed = json.load(o_fdb_config_zip)

            # 3rd command required
            if cli_cmd == l_cmds_required_to_mapping_processing[2]:
                o_fdb_config_portsnames_zip = gzip.open(fn_output_device_config_info, 'rb')
                l_d_config_portsnames_parsed = json.load(o_fdb_config_portsnames_zip)

        # else:
        # with the data loaded, process it and save mapping data
        for record_port_entry in l_d_info_ports_parsed:
            for fdb_entry in l_d_fdb_config_parsed:

                if record_port_entry['port_number'] == fdb_entry['port_number']:

                    # search in the third config output file the matching full display string
                    for config_portnames_entry in l_d_config_portsnames_parsed:
                        if fdb_entry['port_number'] == config_portnames_entry['port_number']:
                            s_port_displaystring = config_portnames_entry['display_port_string']
                            break

                    # extract macaddr
                    k_macaddress = fdb_entry['macaddress'].replace(':', '').upper()

                    # extract display string
                    try:
                        i_asn_related_to_macaddr = int(re.findall(r"[(AS](\d+)[)]", s_port_displaystring)[0])

                    except Exception:
                        print "Failed to parse i_asn_related_to_macaddr: {} - {}".format(k_macaddress, s_port_displaystring)
                        i_asn_related_to_macaddr = s_port_displaystring

                    if k_macaddress not in d_mac2asn_output:
                        d_mac2asn_output[k_macaddress] = [i_asn_related_to_macaddr,
                                                          s_device_colocation_facility,
                                                          s_ipx_id_label]

    # sysout mapping processing
    for k_macaddr, v_data in d_mac2asn_output.iteritems():
        print "{}={}={}={}".format(k_macaddr, v_data[0], v_data[1], v_data[2])

    print(len(d_mac2asn_output))


# ##################################################################
# MAIN APPLICATION
# ##################################################################
if __name__ == '__main__':

    """
    Build cli parameter parser.
    """
    args = get_params()

    create_mac2asn_mapping_file(args)
