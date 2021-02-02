# 
#  Python script using OME API to create a Network
#
# _author_ = Martin Flint <Martin.Flint@Dell.com> and Trevor Squillario <Trevor.Squillario@Dell.com>
#
# Copyright (c) 2021 Dell EMC Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
#### Synopsis
Script to export identity pools to CSV file

#### Description
Will export to a CSV file called IdentityPools.csv in the current directory by default.

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_identitypool.py --ip <xx> --user <username> --password <pwd> --outfile "/tmp/temp.csv"`
"""

import sys
import time
import argparse
from argparse import RawTextHelpFormatter
import traceback
import codecs
import binascii
import json
import requests
import urllib3
from datetime import datetime
import os
from os import path
import csv
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

session_auth_token = {}

def get_session(ip_address, user_name, password):
    session_url = 'https://%s/api/SessionService/Sessions' % ip_address
    base_uri = 'https://%s' % ip_address
    headers = {'content-type': 'application/json'}
    user_details = {'UserName': user_name, 'Password': password,
                    'SessionType': 'API'}
    session_info = requests.post(session_url, verify=False,
                                 data=json.dumps(user_details),
                                 headers=headers)
    if session_info.status_code == 201:
        session_info_token = session_info.headers['X-Auth-Token']
        session_info_data = session_info.json()
        session_auth_token = {'token': session_info_token,
                              'id': session_info_data['Id']}
    return session_auth_token


def delete_session(ip_address, headers, id):
    session_url = "https://%s/api/SessionService/Sessions('%s')" \
        % (ip_address, id)
    session_info = requests.delete(session_url, verify=False,
                                   headers=headers)
    if session_info.status_code == 204:
        return True
    else: 
        print ("Unable to delete session %s" % id)
        return False

def base64_to_mac_conversion(base64):
    """
    Convert base64 string to ascii. OME stores mac as base64.
    
    Args:
        base64: base64 encoded string

    Returns: ASCII MAC Address string
    """
    try:
        if base64:
            b64_mac_address = codecs.encode(codecs.decode(bytes(base64, 'utf-8'), 'base64'), 'hex')
            address = codecs.decode(b64_mac_address, 'utf-8').rstrip()
            return ':'.join(address[i:i+2] for i in range(0,len(address),2))
    except binascii.Error:
        print ('Decoding of MAC address {0} from base64 failed'.format(mac_address))

def get_indentity_pools(base_uri, headers, out_file):
    """
    Get identity pools and export them to CSV
    
    Args:
        base_uri: API URL
        headers: Authentication headers
        out_file: Output file

    Returns: None
    """
    network_url = base_uri + '/api/IdentityPoolService/IdentityPools'
    network_response = requests.get(network_url, headers=headers,
                                    verify=False)
    if network_response.status_code == 200 \
        or network_response.status_code == 201:
        network_data = network_response.json()
        network_data = network_data['value']

        headings = [
            'ID',
            'Name',
            'EthernetSettings IdentityCount',
            'EthernetSettings StartingMacAddress',
            'IscsiSettings IdentityCount',
            'IscsiSettings StartingMacAddress',
            'IscsiSettings InitiatorConfig IqnPrefix',
            'IscsiSettings InitiatorIpPoolSettings IpRange',
            'IscsiSettings InitiatorIpPoolSettings SubnetMask',
            'IscsiSettings InitiatorIpPoolSettings Gateway',
            'IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer',
            'IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer',
            'FcoeSettings IdentityCount',
            'FcoeSettings StartingMacAddress',
            'FcSettings Wwnn IdentityCount',
            'FcSettings Wwnn StartingAddress',
            'FcSettings Wwpn IdentityCount',
            'FcSettings Wwpn StartingAddress'
            ]
        if network_data:
            print ('Exporting Identity Pools')
            csvfile = open(out_file, 'w', newline='')
            print ("Opened file called %s to dump id pool(s)" % out_file)
            writer = csv.DictWriter(csvfile, fieldnames=headings)
            writer.writeheader()

            for i in network_data:
                print ('Id: %s, Name: %s' % (i['Id'], i['Name']))
                pool_name = i['Name']
                pool_id = i['Id']
                if i['EthernetSettings'] is not None:
                    print ('EthernetSettings for %s' % pool_name)
                    enet_IdentityCount = i['EthernetSettings']['Mac'
                            ]['IdentityCount']
                    print ('IdentityCount: %s' % enet_IdentityCount)
                    enet_StartingMacAddress = base64_to_mac_conversion(i['EthernetSettings']['Mac']['StartingMacAddress'])
                    print ('StartingMacAddress: %s' \
                        % i['EthernetSettings']['Mac'
                            ]['StartingMacAddress'])
                else:
                    print ('No EthernetSettings settings for %s' \
                        % pool_name)
                    enet_IdentityCount = ''
                    enet_StartingMacAddress = ''

                if i['IscsiSettings'] is not None:
                    print ('IscsiSettings for %s' % pool_name)
                    iscsi_IdentityCount = i['IscsiSettings']['Mac'
                            ]['IdentityCount']
                    print ('IdentityCount: %s' % iscsi_IdentityCount)
                    iscsi_StartingMacAddress = base64_to_mac_conversion(i['IscsiSettings']['Mac']['StartingMacAddress'])
                    print ('StartingMacAddress: %s' \
                        % iscsi_StartingMacAddress)
                    if i['IscsiSettings']['InitiatorConfig'] \
                        is not None:
                        iscsi_InitiatorConfig_IqnPrefix = \
                            i['IscsiSettings']['InitiatorConfig'
                                ]['IqnPrefix']
                        print ('IscsiSettings InitiatorConfig IqnPrefix: %s' \
                            % iscsi_InitiatorConfig_IqnPrefix)
                    else:
                        print ('No IscsiSettings InitiatorConfig for %s' \
                            % pool_name)
                        iscsi_InitiatorConfig_IqnPrefix = ''

                    if i['IscsiSettings']['InitiatorIpPoolSettings'] \
                        is not None:
                        iscsi_InitiatorIpPoolSettings_IpRange = \
                            i['IscsiSettings']['InitiatorIpPoolSettings'
                                ]['IpRange']
                        print ('IscsiSettings InitiatorIpPoolSettings IpRange: %s' \
                            % iscsi_InitiatorIpPoolSettings_IpRange)
                        iscsi_InitiatorIpPoolSettings_SubnetMask = \
                            i['IscsiSettings']['InitiatorIpPoolSettings'
                                ]['SubnetMask']
                        print ('IscsiSettings InitiatorIpPoolSettings SubnetMask: %s' \
                            % iscsi_InitiatorIpPoolSettings_SubnetMask)
                        iscsi_InitiatorIpPoolSettings_Gateway = \
                            i['IscsiSettings']['InitiatorIpPoolSettings'
                                ]['Gateway']
                        print ('IscsiSettings InitiatorIpPoolSettings Gateway: %s' \
                            % iscsi_InitiatorIpPoolSettings_Gateway)
                        iscsi_InitiatorIpPoolSettings_PrimaryDnsServer = \
                            i['IscsiSettings']['InitiatorIpPoolSettings'
                                ]['PrimaryDnsServer']
                        print ('IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer: %s' \
                            % iscsi_InitiatorIpPoolSettings_PrimaryDnsServer)
                        iscsi_InitiatorIpPoolSettings_SecondaryDnsServer = \
                            i['IscsiSettings']['InitiatorIpPoolSettings'
                                ]['SecondaryDnsServer']
                        print ('IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer: %s' \
                            % iscsi_InitiatorIpPoolSettings_SecondaryDnsServer)
                    else:
                        print ('No IscsiSettings InitiatorIpPoolSettings for %s' \
                            % pool_name)
                        iscsi_InitiatorIpPoolSettings_SecondaryDnsServer = \
                            ''
                        iscsi_InitiatorIpPoolSettings_PrimaryDnsServer = \
                            ''
                        iscsi_InitiatorIpPoolSettings_Gateway = ''
                        iscsi_InitiatorIpPoolSettings_SubnetMask = ''
                        iscsi_InitiatorIpPoolSettings_IpRange = ''
                else:

                    print ('No iscsi settings for %s' % pool_name)
                    iscsi_InitiatorIpPoolSettings_SecondaryDnsServer = \
                        ''
                    iscsi_InitiatorIpPoolSettings_PrimaryDnsServer = ''
                    iscsi_InitiatorIpPoolSettings_Gateway = ''
                    iscsi_InitiatorIpPoolSettings_SubnetMask = ''
                    iscsi_InitiatorIpPoolSettings_IpRange = ''
                    iscsi_InitiatorConfig_IqnPrefix = ''
                    iscsi_IdentityCount = ''
                    iscsi_StartingMacAddress = ''

                if i['FcoeSettings'] is not None:
                    print ('FcoeSettings for %s' % i['Name'])
                    fcoe_IdentityCount = i['FcoeSettings']['Mac'
                            ]['IdentityCount']
                    print ('IdentityCount: %s' % fcoe_IdentityCount)
                    fcoe_StartingMacAddress = base64_to_mac_conversion(i['FcoeSettings']['Mac']['StartingMacAddress'])
                    print ('StartingMacAddress: %s' \
                        % fcoe_StartingMacAddress)
                else:
                    print ('No FcoeSettings for %s' % pool_name)
                    fcoe_StartingMacAddress = ''
                    fcoe_IdentityCount = ''

                if i['FcSettings'] is not None:
                    print ('FcSettings for %s' % i['Name'])
                    fc_Wwnn_IdentityCount = i['FcSettings']['Wwnn'
                            ]['IdentityCount']
                    print ('IdentityCount: %s' % fc_Wwnn_IdentityCount)
                    fc_Wwnn_StartingAddress = base64_to_mac_conversion(i['FcSettings']['Wwnn']['StartingAddress'])
                    print ('StartingAddress: %s' \
                        % fc_Wwnn_StartingAddress)
                    fc_Wwpn_IdentityCount = i['FcSettings']['Wwpn'
                            ]['IdentityCount']
                    print ('IdentityCount: %s' % fc_Wwpn_IdentityCount)
                    fc_Wwpn_StartingAddress = base64_to_mac_conversion(i['FcSettings']['Wwpn']['StartingAddress'])
                    print ('StartingAddress: %s' \
                        % fc_Wwpn_StartingAddress)
                else:
                    print ('No FcSettings for %s' % pool_name)
                    fc_Wwnn_IdentityCount = ''
                    fc_Wwnn_StartingAddress = ''
                    fc_Wwpn_IdentityCount = ''
                    fc_Wwpn_StartingAddress = ''

                writer.writerow({
                    'ID': pool_id,
                    'Name': pool_name,
                    'EthernetSettings IdentityCount': enet_IdentityCount,
                    'EthernetSettings StartingMacAddress': enet_StartingMacAddress,
                    'IscsiSettings IdentityCount': iscsi_IdentityCount,
                    'IscsiSettings StartingMacAddress': iscsi_StartingMacAddress,
                    'IscsiSettings InitiatorConfig IqnPrefix': iscsi_InitiatorConfig_IqnPrefix,
                    'IscsiSettings InitiatorIpPoolSettings IpRange': iscsi_InitiatorIpPoolSettings_IpRange,
                    'IscsiSettings InitiatorIpPoolSettings SubnetMask': iscsi_InitiatorIpPoolSettings_SubnetMask,
                    'IscsiSettings InitiatorIpPoolSettings Gateway': iscsi_InitiatorIpPoolSettings_Gateway,
                    'IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer': iscsi_InitiatorIpPoolSettings_PrimaryDnsServer,
                    'IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer': iscsi_InitiatorIpPoolSettings_SecondaryDnsServer,
                    'FcoeSettings IdentityCount': fcoe_IdentityCount,
                    'FcoeSettings StartingMacAddress': fcoe_StartingMacAddress,
                    'FcSettings Wwnn IdentityCount': fc_Wwnn_IdentityCount,
                    'FcSettings Wwnn StartingAddress': fc_Wwnn_StartingAddress,
                    'FcSettings Wwpn IdentityCount': fc_Wwpn_IdentityCount,
                    'FcSettings Wwpn StartingAddress': fc_Wwpn_StartingAddress,
                    })
            csvfile.close()
        else:
            print ('No id pools found')
    else:
        print ('Unable to retrieve list from %s' % network_url)


# MAIN

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
            formatter_class=RawTextHelpFormatter)
    PARSER.add_argument('--ip', '-i', required=True,
                        help='OME Appliance IP')
    PARSER.add_argument('--user', '-u', required=False,
                        help='Username for OME Appliance',
                        default='admin')
    PARSER.add_argument('--password', '-p', required=True,
                        help='Password for OME Appliance')
    PARSER.add_argument("--out-file", "-f", required=False, default="IdentityPools.csv",
                        help="Path to CSV file")
    ARGS = PARSER.parse_args()
    base_uri = 'https://%s' %(ARGS.ip)
    auth_token = get_session(ARGS.ip, ARGS.user, ARGS.password)
    headers = {'content-type': 'application/json'}
    if auth_token.get('token') != None:
        headers['X-Auth-Token'] = auth_token['token']
    else:
        print("Unable to create a session with appliance %s" % (base_uri))
        quit()

    try:
        get_indentity_pools(base_uri, headers, ARGS.out_file)
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])