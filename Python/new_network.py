#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
#
# Copyright (c) 2022 Dell EMC Corporation
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
Script to create a new network with VLAN

#### Description
This script uses the OME REST API to create a new network
A network consists of a Minimum and Maximum VLAN ID to create a range
Set Minimum and Maximum to the same value to a single VLAN

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

*Must include header row with at least the rows in the example below
*NetworkType must be an integer value. Use get_network.py --list-networktypes
*For a single VLAN set VlanMinimum=VlanMaximum
For example:
Name,Description,VlanMaximum,VlanMinimum,NetworkType
VLAN 800,Description for VLAN 800,800,800,1

#### Example
`python new_network.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group"`
"""

import argparse
import csv
import json
import sys
import traceback
from argparse import RawTextHelpFormatter
from getpass import getpass
from os import path

import requests
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session_auth_token = {}


def get_session(ip_address, user_name, password):
    session_url = 'https://%s/api/SessionService/Sessions' % ip_address
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
    else:
        return None


def delete_session(ip_address, headers, id):
    session_url = "https://%s/api/SessionService/Sessions('%s')" % (ip_address, id)
    session_info = requests.delete(session_url, verify=False, headers=headers)
    if session_info.status_code == 204:
        return True
    else:
        print("Unable to delete session %s" % id)
        return False


def create_network(base_uri, headers, name, description, vlan_minimum, vlan_maximum, network_type):
    """
    Create network (VLAN)
    
    Args:
        base_uri: API URL
        headers: Authentication headers
        name: Name of network
        description: Description of network
        vlan_minimum: Min VLAN #
        vlan_maximum: Max VLAN #
        network_type: QOS Type
    
    Returns: None
    """
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
            print("New network created %s" % name)
        elif create_resp.status_code == 400:
            print("Failed creation... ")
            print(json.dumps(create_resp.json(), indent=4,
                             sort_keys=False))
    except Exception as e:
        print(traceback.format_exc())


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--name", "-n", required=False,
                        help="Name of VLAN")
    parser.add_argument("--description", "-d", required=False,
                        help="Description of VLAN")
    parser.add_argument("--vlan-minimum", "-vmin", required=False,
                        help="Minimum VLAN (Integer)")
    parser.add_argument("--vlan-maximum", "-vmax", required=False,
                        help="Maximum VLAN (Integer)")
    parser.add_argument("--vlan-type", "-vt", required=False,
                        help="Type of VLAN (Integer) Use get_network.py --list-networktypes")
    parser.add_argument("--in-file", "-f", required=False,
                        help="""Path to CSV file
*Must include header row with at least the rows in the example below
*NetworkType must be an integer value. Use get_network.py --list-networktypes
*For a single VLAN set VlanMinimum=VlanMaximum
#### Python Example
Name,Description,VlanMaximum,VlanMinimum,NetworkType
VLAN 800,Description for VLAN 800,800,800,1""")
    args = parser.parse_args()
    base_uri = 'https://%s' % args.ip

    if not args.password:
        if not sys.stdin.isatty():
            # notify user that they have a bad terminal
            # perhaps if os.name == 'nt': , prompt them to use winpty?
            print("Your terminal is not compatible with Python's getpass module. You will need to provide the"
                  " --password argument instead. See https://stackoverflow.com/a/58277159/4427375")
            sys.exit(0)
        else:
            password = getpass()
    else:
        password = args.password

    auth_token = get_session(args.ip, args.user, password)
    headers = {'content-type': 'application/json'}
    if auth_token.get('token') is not None:
        headers['X-Auth-Token'] = auth_token['token']
    else:
        print("Unable to create a session with appliance %s" % base_uri)
        quit()

    try:
        if args.name is not None and args.vlan_minimum is not None and args.vlan_maximum is not None and \
                args.vlan_type is not None:
            create_network(base_uri, headers, args.name, args.description, args.vlan_minimum, args.vlan_maximum,
                           args.vlan_type)
        elif args.in_file is not None and path.exists(args.in_file):
            with open(args.in_file) as f:
                records = csv.DictReader(f)
                for row in records:
                    print("Creating network from data: %s" % row)
                    try:
                        create_network(base_uri, headers, row["Name"], row["Description"], row["VlanMinimum"],
                                       row["VlanMaximum"], row["NetworkType"])
                    except KeyError:
                        print("Unexpected error:", sys.exc_info())
                        print("KeyError: Missing or improperly named columns. File must contain the following "
                              "headers Name,Description,VlanMaximum,VlanMinimum,NetworkType")
    except Exception as e:
        print(traceback.format_exc())
    finally:
        # TODO - auth_token['id] could be undefined in the event of a failure. This should be updated
        delete_session(args.ip, headers, auth_token['id'])
