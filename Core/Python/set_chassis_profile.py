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

import sys
import time
import argparse
from argparse import RawTextHelpFormatter
import traceback
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


def load_profile(
    base_uri,
    headers,
    shareType,
    shareAddress,
    shareName,
    userName,
    password,
    import_file,
    ):

    network_payload = {
        'Id': 0,
        'JobName': 'Import Profile',
        'JobDescription': 'Import Chassis profile',
        'NextRun': None,
        'LastRun': '2020-06-10 12:33:19.053',
        'StartTime': None,
        'EndTime': None,
        'Schedule': 'startnow',
        'State': 'Enabled',
        'CreatedBy': 'root',
        'UpdatedBy': None,
        'Visible': bool('True'),
        'Editable': bool('True'),
        'Builtin': bool('False'),
        'UserGenerated': bool('True'),
        'Targets': [],
        'Params': [
            {'Key': 'shareType', 'Value': shareType},
            {'Key': 'profile_option', 'Value': 'import'},
            {'Key': 'import_file', 'Value': import_file},
            {'Key': 'password', 'Value': password},
            {'Key': 'userName', 'Value': userName},
            {'Key': 'shareName', 'Value': shareName},
            {'Key': 'shareAddress', 'Value': shareAddress},
            ],
        'LastRunStatus': {'@odata.type': '#JobService.JobStatus',
                          'Id': 2060, 'Name': 'Completed'},
        'JobType': {
            '@odata.type': '#JobService.JobType',
            'Id': 22,
            'Name': 'ChassisProfile_Task',
            'Internal': bool('False'),
            },
        'JobStatus': {'@odata.type': '#JobService.JobStatus',
                      'Id': 2080, 'Name': 'New'},
        }

    network_url = base_uri + '/api/JobService/Jobs'
    network_response = requests.post(network_url, headers=headers, verify=False, data=json.dumps(network_payload))
    if network_response.status_code == 201 \
        or network_response.status_code == 200:
        network_data = network_response.json()
        print ('Imported profile to %s:%s/%s' % (shareAddress, shareName,
                import_file))
    elif network_response.status_code == 400 \
        or network_response.status_code == 500:
        print ('Failed to import profile... ')
        print (json.dumps(network_response.json(), indent=4,
                         sort_keys=False))

# MAIN

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
            formatter_class=RawTextHelpFormatter, prefix_chars='--')
    PARSER.add_argument('--ip', '-i', required=True,
                        help='OME Appliance IP')
    PARSER.add_argument('--user', '-u', required=False,
                        help='Username for OME Appliance',
                        default='admin')
    PARSER.add_argument('--password', '-p', required=True,
                        help='Password for OME Appliance')
    PARSER.add_argument("--share-type", required=True,
                        help="Type of share (NFS, CIFS)",
                        choices=['NFS', 'CIFS'])
    PARSER.add_argument("--share-ipaddress", required=True,
                        help="IP Address of share server")
    PARSER.add_argument("--share-path", required=True,
                        help="Path of share to import chassis profile from")
    PARSER.add_argument("--share-user", required=False,
                        help="Username for CIFS share")
    PARSER.add_argument("--share-password", required=False,
                        help="Password for CIFS share")
    PARSER.add_argument("--in-file", "-f", required=True,
                        help="File to import")
    
    ARGS = PARSER.parse_args()
    if ARGS.share_type == 'CIFS' and (ARGS.share_user is None or ARGS.share_password is None):
        PARSER.error("CIFS share requires --share-user and --share-password")

    base_uri = 'https://%s' %(ARGS.ip)
    auth_token = get_session(ARGS.ip, ARGS.user, ARGS.password)
    headers = {'content-type': 'application/json'}
    if auth_token.get('token') != None:
        headers['X-Auth-Token'] = auth_token['token']
    else:
        print("Unable to create a session with appliance %s" % (base_uri))
        quit()

    try:
        load_profile(
            base_uri,
            headers,
            ARGS.share_type,
            ARGS.share_ipaddress,
            ARGS.share_path,
            ARGS.share_user,
            ARGS.share_password,
            ARGS.in_file,
            )
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])
