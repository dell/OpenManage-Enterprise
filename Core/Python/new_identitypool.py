#!/usr/bin/python
# -*- coding: utf-8 -*-
#  Python script using OME API to create a Network
#
# _author_ = Martin Flint <Martin.Flint@Dell.com>
# _version_ = 0.1
#
# Copyright (c) 2018 Dell EMC Corporation
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
Script to create identity pool in OpenManage Enterprise

#### Description
This script uses the OME REST API to create identity pools
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

*Must include header row with at least the rows in the example below
*Use get_identitypool.py to export CSV file
Example:
Name,EthernetSettings IdentityCount,EthernetSettings StartingMacAddress,IscsiSettings IdentityCount,IscsiSettings StartingMacAddress,IscsiSettings InitiatorConfig IqnPrefix,IscsiSettings InitiatorIpPoolSettings IpRange,IscsiSettings InitiatorIpPoolSettings SubnetMask,IscsiSettings InitiatorIpPoolSettings Gateway,IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer,IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer,FcoeSettings IdentityCount,FcoeSettings StartingMacAddress,FcSettings Wwnn IdentityCount,FcSettings Wwnn StartingAddress,FcSettings Wwpn IdentityCount,FcSettings Wwpn StartingAddress
TestPool01,30,04:00:00:00:01:00,30,04:00:00:00:02:00,iqn01,192.168.1.100/24,,,,,30,04:00:00:00:03:00,30,20:00:04:00:00:00:04:00,30,20:01:04:00:00:00:04:00

#### Example
`python .\new_identitypool.py --ip "mx7000-chassis.example.com" --user admin --password 'password' --in-file "C:\Temp\IdentityPools_New.csv"`
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

def mac_to_base64_conversion(mac_address):
    try:
        if mac_address:
            allowed_mac_separators = [':', '-', '.']
            for sep in allowed_mac_separators:
                if sep in mac_address:
                    b64_mac_address = codecs.encode(codecs.decode(
                        mac_address.replace(sep, ''), 'hex'), 'base64')
                    address = codecs.decode(b64_mac_address, 'utf-8').rstrip()
                    return address
    except binascii.Error:
        print ('Encoding of MAC address {0} to base64 failed'.format(mac_address))

def create_id_pool(
    base_uri,
    headers,
    Name,
    EthernetSettings_IdentityCount,
    EthernetSettings_StartingMacAddress,
    IscsiSettings_IdentityCount,
    IscsiSettings_StartingMacAddress,
    IscsiSettings_InitiatorConfig_IqnPrefix,
    IscsiSettings_InitiatorIpPoolSettings_IpRange,
    IscsiSettings_InitiatorIpPoolSettings_SubnetMask,
    IscsiSettings_InitiatorIpPoolSettings_Gateway,
    IscsiSettings_InitiatorIpPoolSettings_PrimaryDnsServer,
    IscsiSettings_InitiatorIpPoolSettings_SecondaryDnsServer,
    FcoeSettings_IdentityCount,
    FcoeSettings_StartingMacAddress,
    FcSettings_Wwnn_IdentityCount,
    FcSettings_Wwnn_StartingAddress,
    FcSettings_Wwpn_IdentityCount,
    FcSettings_Wwpn_StartingAddress,
    ):

    network_payload = {
        'Name': Name,
        'EthernetSettings': {'Mac': {'IdentityCount': '',
                             'StartingMacAddress': EthernetSettings_StartingMacAddress}},
        'IscsiSettings': {'Mac': {'IdentityCount': '',
                          'StartingMacAddress': IscsiSettings_StartingMacAddress},
                          'InitiatorConfig': {'IqnPrefix': ''},
                          'InitiatorIpPoolSettings': {
            'IpRange': IscsiSettings_InitiatorIpPoolSettings_IpRange,
            'SubnetMask': IscsiSettings_InitiatorIpPoolSettings_SubnetMask,
            'Gateway': IscsiSettings_InitiatorIpPoolSettings_Gateway,
            'PrimaryDnsServer': IscsiSettings_InitiatorIpPoolSettings_PrimaryDnsServer,
            'SecondaryDnsServer': IscsiSettings_InitiatorIpPoolSettings_SecondaryDnsServer,
            }},
        'FcoeSettings': {'Mac': {'IdentityCount': '',
                         'StartingMacAddress': FcoeSettings_StartingMacAddress}},
        'FcSettings': {'Wwnn': {'IdentityCount': '',
                       'StartingAddress': FcSettings_Wwnn_StartingAddress},
                       'Wwpn': {'IdentityCount': '',
                       'StartingAddress': FcSettings_Wwpn_StartingAddress}},
        }

    if IscsiSettings_InitiatorConfig_IqnPrefix != '':
        network_payload['IscsiSettings']['InitiatorConfig']['IqnPrefix'
                ] = IscsiSettings_InitiatorConfig_IqnPrefix
    else:
        network_payload['IscsiSettings']['InitiatorConfig']['IqnPrefix'
                ] = ''

    if EthernetSettings_IdentityCount != '':
        network_payload['EthernetSettings']['Mac']['IdentityCount'] = \
            int(EthernetSettings_IdentityCount)
    else:
        network_payload['EthernetSettings']['Mac']['IdentityCount'] = \
            int(0)

    if IscsiSettings_IdentityCount != '':
        network_payload['IscsiSettings']['Mac']['IdentityCount'] = \
            int(IscsiSettings_IdentityCount)
    else:
        network_payload['IscsiSettings']['Mac']['IdentityCount'] = \
            int(0)

    if FcoeSettings_IdentityCount != '':
        network_payload['FcoeSettings']['Mac']['IdentityCount'] = \
            int(FcoeSettings_IdentityCount)
    else:
        network_payload['FcoeSettings']['Mac']['IdentityCount'] = int(0)

    if FcSettings_Wwnn_IdentityCount != '':
        network_payload['FcSettings']['Wwnn']['IdentityCount'] = \
            int(FcSettings_Wwnn_IdentityCount)
    else:
        network_payload['FcSettings']['Wwnn']['IdentityCount'] = int(0)

    if FcSettings_Wwpn_IdentityCount != '':
        network_payload['FcSettings']['Wwpn']['IdentityCount'] = \
            int(FcSettings_Wwpn_IdentityCount)
    else:
        network_payload['FcSettings']['Wwpn']['IdentityCount'] = int(0)

    id_pool_id = None
    if IscsiSettings_IdentityCount != '' \
        and (IscsiSettings_InitiatorConfig_IqnPrefix == ''
             or IscsiSettings_InitiatorIpPoolSettings_IpRange == ''):
        print ('Skipping creation of ID pool %s' % Name)
        print ('When the iSCSI Initiator configuration is enabled, the IQN prefix and IP Range must be non-empty')
        id_pool_id = 'skip'
        exit()

    network_url = base_uri \
        + '/api/IdentityPoolService/IdentityPools'
    network_response = requests.post(network_url, headers=headers,
            verify=False, data=json.dumps(network_payload))

    # print ("network_response = %s" % (network_response))

    if network_response.status_code == 201 \
        or network_response.status_code == 200:
        network_data = network_response.json()
        id_pool_id = network_data['Id']
    elif network_response.status_code == 400 \
        or network_response.status_code == 500:
        print ('Failed ID pool creation... ')
        print ('Network Payload:')
        print (network_payload)
        print ('')
        print ('json dump...')
        print (json.dumps(network_response.json(), indent=4, sort_keys=False))

    return id_pool_id


def put_indentity_pool(base_uri, headers, outfile):

    if path.exists(outfile):
        with open(outfile) as f:
            records = csv.DictReader(f)
            for row in records:
                try:

                    pool_id = create_id_pool(
                        base_uri,
                        headers,
                        row['Name'],
                        row['EthernetSettings IdentityCount'],
                        mac_to_base64_conversion(row['EthernetSettings StartingMacAddress']),
                        row['IscsiSettings IdentityCount'],
                        mac_to_base64_conversion(row['IscsiSettings StartingMacAddress']),
                        row['IscsiSettings InitiatorConfig IqnPrefix'],
                        row['IscsiSettings InitiatorIpPoolSettings IpRange'
                            ],
                        row['IscsiSettings InitiatorIpPoolSettings SubnetMask'
                            ],
                        row['IscsiSettings InitiatorIpPoolSettings Gateway'
                            ],
                        row['IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer'
                            ],
                        row['IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer'
                            ],
                        row['FcoeSettings IdentityCount'],
                        mac_to_base64_conversion(row['FcoeSettings StartingMacAddress']),
                        row['FcSettings Wwnn IdentityCount'],
                        mac_to_base64_conversion(row['FcSettings Wwnn StartingAddress']),
                        row['FcSettings Wwpn IdentityCount'],
                        mac_to_base64_conversion(row['FcSettings Wwpn StartingAddress']),
                        )

                    if pool_id == None:
                        print ('ERROR: Unable to create Pool %s' \
                            % row['Name'])
                    elif pool_id == 'skip':
                        print ('Pool creation for %s skipped...' \
                            % row['Name'])
                        print ('')
                    else:
                        print ('Created new ID pool %s, ID = %s' \
                            % (row['Name'], pool_id))
                except KeyError:
                    print ('Unexpected error:', sys.exc_info())
                    print ('KeyError: Missing or improperly named columns.')
        f.close()



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
    PARSER.add_argument('--in-file', '-f', required=False,
                        help="""Path to CSV file
*Must include header row with at least the rows in the example below
*Use get_identitypool.py to export CSV file
Example:
Name,EthernetSettings IdentityCount,EthernetSettings StartingMacAddress,IscsiSettings IdentityCount,IscsiSettings StartingMacAddress,IscsiSettings InitiatorConfig IqnPrefix,IscsiSettings InitiatorIpPoolSettings IpRange,IscsiSettings InitiatorIpPoolSettings SubnetMask,IscsiSettings InitiatorIpPoolSettings Gateway,IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer,IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer,FcoeSettings IdentityCount,FcoeSettings StartingMacAddress,FcSettings Wwnn IdentityCount,FcSettings Wwnn StartingAddress,FcSettings Wwpn IdentityCount,FcSettings Wwpn StartingAddress
TestPool01,30,04:00:00:00:01:00,30,04:00:00:00:02:00,iqn01,192.168.1.100/24,,,,,30,04:00:00:00:03:00,30,20:00:04:00:00:00:04:00,30,20:01:04:00:00:00:04:00""")
    
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
        if ARGS.in_file:
            put_indentity_pool(base_uri, headers, ARGS.in_file)
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])


			
