#
#  Python script using OME API to create a Network
#
# _author_ = Greg Bowersock <Greg.Bowersock@Dell.com> and Trevor Squillario <Trevor.Squillario@Dell.com>
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
SYNOPSIS:
   Script to save all networks to a csv file
DESCRIPTION:
   This script exercises the OME REST API to save a copy of the 
   defined VLANS to a csv file.
   
   For authentication X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.
EXAMPLE:
   python get_network.py --ip <xx> --user <username> --password <pwd> --out_file <exported csv file>
"""
import sys
import argparse
from argparse import RawTextHelpFormatter
import traceback
import json
import requests
import urllib3
import os
from os import path
import csv
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

session_auth_token = {}

def get_session(ip_address, user_name, password):
    session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
    base_uri = 'https://%s' %(ip_address)
    headers = {'content-type': 'application/json'}
    user_details = {'UserName': user_name,
                    'Password': password,
                    'SessionType': 'API'}
    session_info = requests.post(session_url, verify=False,
                                    data=json.dumps(user_details),
                                    headers=headers)
    if session_info.status_code == 201:
        session_info_token = session_info.headers['X-Auth-Token']
        session_info_data = session_info.json()
        session_auth_token = {
            "token": session_info_token,
            "id": session_info_data['Id']
        }
    return session_auth_token

def delete_session(ip_address, headers, id):
    session_url = "https://%s/api/SessionService/Sessions('%s')" % (ip_address, id)
    session_info = requests.delete(session_url, verify=False, headers=headers)
    if session_info.status_code == 204:
        return True
    else: 
        print ("Unable to delete session %s" % id)
        return False

def get_networktypes(base_uri, headers):
    # Display Network Types
    networktype_url = base_uri + '/api/NetworkConfigurationService/NetworkTypes'
    networktype_response = requests.get(networktype_url, headers=headers, verify=False)
    if networktype_response.status_code == 200 or networktype_response.status_code == 201:
        networktype_data = networktype_response.json()
        networktype_data = networktype_data['value']
        for i in networktype_data:
            print("Id: %s, Name: %s, Description: %s" %(i["Id"], i["Name"], i["Description"]))
    else:
        print("Unable to retrieve list from %s" % (networktype_url))

def get_networks(base_uri, headers, out_file):
    # Display Network Types
    network_url = base_uri + '/api/NetworkConfigurationService/Networks'
    network_response = requests.get(network_url, headers=headers, verify=False)
    if network_response.status_code == 200 or network_response.status_code == 201:
        network_data = network_response.json()
        network_data = network_data['value']
        f = open(out_file, "w")
        f.write("ID,Name,Description,VlanMaximum,VlanMinimum,NetworkType\n")
        for i in network_data:
            print("Id: %s, Name: %s, Description: %s, VLAN Min: %s, VLAN Max: %s, Type: %s, Created By: %s" %(i["Id"], i["Name"], i["Description"], i["VlanMinimum"], i["VlanMaximum"], i["Type"], i["CreatedBy"]))
            f.write("%s,%s,%s,%s,%s,%s\n" %(i["Id"],i["Name"], i["Description"], i["VlanMaximum"], i["VlanMinimum"], i["Type"]))
        f.close()
    else:
        print("Unable to retrieve list from %s" % (network_url))

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--list-networktypes", "-lt", required=False, action='store_true',
                        help="List available Network Types")
    PARSER.add_argument("--out-file", "-f", required=False, default="Networks.csv",
                        help="""Path to CSV file
*Must include header row with at least the rows in the example below
*NetworkType must be an integer value. Use --list-networktypes
*For a single VLAN set VlanMinimum=VlanMaximum
Example:
Name,Description,VlanMaximum,VlanMinimum,NetworkType
VLAN 800,Description for VLAN 800,800,800,1""")
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
        if ARGS.list_networktypes:
            get_networktypes(base_uri, headers)
        else:
            get_networks(base_uri, headers, ARGS.out_file)
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])
