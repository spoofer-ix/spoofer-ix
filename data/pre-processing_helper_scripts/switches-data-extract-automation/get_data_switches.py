#!/usr/bin/env python

import argparse
import json
import gzip
import getpass
import socket
try:
    import readline
except:
    pass
from netmiko import ConnectHandler

# The command line expects a number of arguments
#    usage: get_data_switches.py [-h] [-d] [-u USERNAME] [-p PASSWORD]
#                                [-i [IPADDRESS [IPADDRESS ...]]] [-c] [-s]
#                                [cli [cli ...]]
#
#    optional arguments:
#      -h, --help            show this help message and exit
#      -u USERNAME           Login username for the remote system
#      -p PASSWORD           Login password for the remote system
#      -i [IPADDRESS [IPADDRESS ...]]
#                            IP address(s) of remote systems or <filename>
#                            containing IP addresses
#
#    CLI command options:
#      -c                    Remote CLI command
#      cli                   CLI command
#
# Examples:
# ---------
# Let get_data_switches.py prompt for information
#       - get_data_switches.py will prompt for
#           action - cli or script
#           username
#           password
#           ipaddress(es)
#           cli command or script name/args, depending on action selected
#
# Provide a list of IP addresses and a single CLI command
#   get_data_switches.py -u myname -p mypassword -i 10.10.10.1 10.10.10.2 -c show ports no
#
# Provide a file with IP addresses, interactively prompt for CLI commands
#   get_data_switches.py -u myname -p mypassword -i ipaddrlist.txt -c
#
# Provide a file with IP addresses and a file containing CLI commands
#   get_data_switches.py -u myname -p mypassword -i ipaddrlist.txt -c cmd_list.txt
#

def remote_cli(args):
    """
    Establish connection with remote device accordingly with manufacturer requirements.
    :param args:
    :return:
    """

    # ExtremeNetworks and Cisco IOS base connection strings
    extreme_sw = {'device_type': 'extreme', 'ip': '', 'username': '', 'password': ''}
    cisco_ios_sw = {'device_type': 'cisco_ios', 'ip': '', 'username': '', 'password': ''}

    # join the command line args into a cmdlist of one entry
    cmd = ' '.join(args.cli)

    # is it a filename that contains a list of CLI commands?
    try:
        with open(args.cli[0], 'r') as fd:
            # the first arg was a filename
            # join the file lines into a ';' separated string of commands
            #cmd = ';'.join(fd.read().strip().splitlines())
            cmd = fd.readlines()
    except:
        pass

    for ipaddr in args.ipaddress:
        ipaddr_device = ipaddr.split('=')[0]
        s_device_manufacturer = ipaddr.split('=')[1]

        print '\n', '=' * 80
        print 'IP:{} - manufacturer: {}'.format(ipaddr_device, s_device_manufacturer)
        print '*' * 80

        try:
            # Use the netmiko to send CLI commands to an IP address
            username = args.username
            password = args.password

            net_connect = ''

            # check the device manufacturer associated with the IP then set and load its connection string
            if s_device_manufacturer == "extreme":
                extreme_sw['ip'] = ipaddr_device
                extreme_sw['username'] = username
                extreme_sw['password'] = password
                net_connect = ConnectHandler(**extreme_sw)

            if s_device_manufacturer == "cisco_ios":
                cisco_ios_sw['ip'] = ipaddr_device
                cisco_ios_sw['username'] = username
                cisco_ios_sw['password'] = password
                net_connect = ConnectHandler(**cisco_ios_sw)

            # if requested more commands, call one command at time
            if len(cmd) > 1:
                for s_cmd in cmd:
                    s_cmd = s_cmd.strip()
                    print "executing -> {}".format(s_cmd)

                    output = net_connect.send_command(s_cmd, use_textfsm=True)
                    save_output_to_json_file(output, ipaddr_device, s_device_manufacturer, s_cmd, args)

            # if just one command
            else:
                print "executing -> {}".format(cmd)
                output = net_connect.send_command(cmd, use_textfsm=True)
                save_output_to_json_file(output, ipaddr_device, s_device_manufacturer, cmd, args)

            # print(output)

        except Exception as msg:
            print "Failed execution due to: {}".format(msg)
            continue


def save_output_to_json_file(d_output, ipaddr_device, s_device_manufacturer, cmd, args):
    """
    Save dict output from device cli cmd executed.
    :param d_output:
    :param ipaddr_device:
    :param s_device_manufacturer:
    :param cmd:
    :param args:
    :return:
    """

    fn_output_info_pattern = "{file_dest_dir}{file_name}.ip={ip}.manufacturer={manufacturer}.command={data_command}.json.gz"
    fn_output_device_config_info = fn_output_info_pattern.format(file_dest_dir=args.temp_path[0],
                                                                 file_name="device-config",
                                                                 ip=ipaddr_device,
                                                                 manufacturer=s_device_manufacturer,
                                                                 data_command=cmd)

    print("Output file: {}".format(fn_output_device_config_info))

    try:

        # write dict result with flow traffic info to a json file
        with gzip.open(fn_output_device_config_info, 'wb') as f:
            json.dump(d_output, f)
        f.close()

    except Exception as msg:
        print "Failed to save output file: {}".format(msg)


def prompt_for_cli(args):
    # start a CLI prompt loop for the user to enter EXOS commands
    while True:
        # prompt the user for an EXOS command
        args.cli = raw_input('Enter EXOS cli or filename: ')
        if args.cli in ['q','quit','exit']:
            break
        if len(args.cli.strip()) == 0:
            print '\tEXOS command or q, quit or exit to discontinue'
            continue

        # split CLI to make it look like a command line arg
        args.cli = args.cli.split()
        remote_cli(args)


# ##################################################################
# MAIN APPLICATION
# ##################################################################
def get_params():

    parser = argparse.ArgumentParser(prog = 'Connect to switches via SSH, run commands, extract data.')

    parser.add_argument('-u',
            dest='username',
            help='Login username for the remote system')

    parser.add_argument('-p',
            dest='password',
            help='Login password for the remote system',
            default='')

    parser.add_argument('-i',
            help='IP address(s) of remote systems or <filename> containing IP addresses',
            dest='ipaddress',
            nargs='*',
            default=[])

    parser.add_argument('-tmpdir',
            help='Temporary dir to save output files',
            dest='temp_path',
            nargs='*',
            default=[''])

    cli_group = parser.add_argument_group('CLI command options')
    cli_group.add_argument('-c',
            help='Remote CLI command',
            dest='is_cli',
            action='store_true',
            default=False)
    cli_group.add_argument('cli',
            help='CLI command',
            nargs='*',
            default=[])

    args = parser.parse_args()

    # username/password not provided on the command line, ask
    if args.username is None:
        # prompt for username
        args.username = raw_input('Enter remote system username: ')
        # also get password
        args.password = getpass.getpass('Remote system password: ')

        # prompt for username
        args.temp_path = raw_input('Enter output files destination: ')
        args.temp_path = [args.temp_path]

    while not args.ipaddress:
        # no IP address(es) or file name was provided on the command line, ask
        while True:
            # prompt for ip address of the remote system
            input_ipaddress = raw_input('Enter remote system IP address(es) or filename: ')
            input_ipaddress = input_ipaddress.strip()
            input_ipaddress = input_ipaddress.replace(',',' ')
            args.ipaddress = input_ipaddress.split()
            if len(args.ipaddress):
                break

    # args.ipaddress is either a list of IP addresses or a file name
    if len(args.ipaddress) == 1:
        try:
            with open(args.ipaddress[0], 'r') as fd:
                # the first arg was a filename
                # read the contents into args.ipaddress
                args.ipaddress = fd.read().strip().splitlines()
        except:
            pass

    # args.ipaddress is now a list of IP addresses
    # check to see if the addresses are in the correct format
    for ipaddr in args.ipaddress:
        ipaddr_device = ipaddr.split('=')[0]
        for addr_type in [socket.AF_INET, socket.AF_INET6]:
            try:
                socket.inet_pton(addr_type, ipaddr_device)
                break
            except Exception as e:
                pass
        else:
            print ipaddr_device, 'is not a filename or IP address'
            args.ipaddress.remove(ipaddr)

    # the command line didn't tell us what to do. Let's ask
    if args.is_cli is False:
        while True:
            # prompt for ip address of the remote system
            method_type = raw_input("Enter either 'cli' or 'script': ")
            method_type = method_type.strip()
            if method_type.startswith('c'):
                args.is_cli = True
                break
            if method_type.startswith('s'):
                args.is_script = True
                break
            print 'Unrecognized input:', method_type

    return args


def main():
    args = get_params()

    if args.is_cli is True:
        # if command line cli option, check if we have need to prompt
        if args.cli:
            # command line args are available
            remote_cli(args)
        else:
            # ask user for CLI command
            prompt_for_cli(args)
    else:
        print 'Unknown script error'


if __name__ == '__main__':

    """
    Build cli parameter parser.
    """

try:
    main()
except KeyboardInterrupt:
    pass
