#
#  Python script using OME API to create a Network
#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
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
   Script to create a new network with VLAN

DESCRIPTION:
   This script exercises the OME REST API to create a new network
   A network consists of a Minimum and Maximum VLAN ID to create a range
   Set Minimum and Maximum to the same value to a single VLAN
   
   For authentication X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python create_network.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group"
"""
import sys
import argparse
from argparse import RawTextHelpFormatter
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
    if session_info.status_code == 201:
        return True
    else: 
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

def get_networks(base_uri, headers):
    # Display Network Types
    network_url = base_uri + '/api/NetworkConfigurationService/Networks'
    network_response = requests.get(network_url, headers=headers, verify=False)
    if network_response.status_code == 200 or network_response.status_code == 201:
        network_data = network_response.json()
        network_data = network_data['value']
        for i in network_data:
            print("Id: %s, Name: %s, Description: %s, VLAN Min: %s, VLAN Max: %s, Created By: %s" %(i["Id"], i["Name"], i["Description"], i["VlanMinimum"], i["VlanMaximum"], i["CreatedBy"]))
    else:
        print("Unable to retrieve list from %s" % (network_url))

def create_network(base_uri, headers, name, description, vlan_minimum, vlan_maximum, network_type):
    try:
        # Create Network
        network_payload = {
            "Name": name,
            "Description": description,
            "VlanMinimum": int(vlan_maximum),
            "VlanMaximum": int(vlan_minimum),
            "Type": int(network_type)
        }
        create_url = base_uri + '/api/NetworkConfigurationService/Networks'
        create_resp = requests.post(create_url, headers=headers,
                                    verify=False,
                                    data=json.dumps(network_payload))
        if create_resp.status_code == 201:
            print ("New network created %s" %(name))
        elif create_resp.status_code == 400:
            print ("Failed creation... ")
            print (json.dumps(create_resp.json(), indent=4,
                                sort_keys=False))
    except(ValueError):
        print ("Failed creation... ")
        print ("Value error:", sys.exc_info())
        pass

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--list-networks", "-ln", required=False, action='store_true',
                        help="List existing Networks")
    PARSER.add_argument("--list-networktypes", "-lt", required=False, action='store_true',
                        help="List available Network Types")
    PARSER.add_argument("--in-file", "-f", required=False,
                        help="""Path to CSV file
*Must include header row with at least the rows in the example below
*NetworkType must be an integer value. Use --list-networktypes
*For a single VLAN set VlanMinimum=VlanMaximum
Example:
Name,Description,VlanMaximum,VlanMinimum,NetworkType
VLAN 800,Description for VLAN 800,800,800,1""")
    ARGS = PARSER.parse_args()

    try:
        base_uri = 'https://%s' %(ARGS.ip)
        headers = {'content-type': 'application/json'}

        # Get auth token for session
        auth_token = get_session(ARGS.ip, ARGS.user, ARGS.password)
        if auth_token != None:
            headers['X-Auth-Token'] = auth_token['token']

            if ARGS.list_networks:
                get_networks(base_uri, headers)

            if ARGS.list_networktypes:
                get_networktypes(base_uri, headers)

            if ARGS.in_file != None and path.exists(ARGS.in_file):
                with open(ARGS.in_file) as f:
                    records = csv.DictReader(f)
                    for row in records:
                        print "Creating network from data: %s" %(row)
                        try:
                            create_network(base_uri, headers, row["Name"], row["Description"], row["VlanMinimum"], row["VlanMaximum"], row["NetworkType"])
                        except(KeyError):
                            print ("Unexpected error:", sys.exc_info())
                            print ("KeyError: Missing or improperly named columns. File must contain the following headers Name,Description,VlanMaximum,VlanMinimum,NetworkType")
    except:
        print ("Unexpected error:", sys.exc_info())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])