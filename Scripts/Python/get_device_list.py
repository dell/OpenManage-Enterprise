#
#  Python script using OME API to get device list.
#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
# _version_ = 0.1
#
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
   Script to get the list of devices managed by OM Enterprise

DESCRIPTION:
   This script exercises the OME REST API to get a list of devices
   currently being managed by that instance. For authentication X-Auth
   is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_device_list.py --ip <xx> --user <username> --password <pwd>
"""

import sys
import argparse
from argparse import RawTextHelpFormatter
import json
import requests
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_device_list(ip_address, user_name, password):
    """ Authenticate with OME and enumerate devices """
    try:
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        base_uri = 'https://%s' %(ip_address)
        device_url = base_uri + '/api/DeviceService/Devices'
        next_link_url = None
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            device_response = requests.get(device_url, headers=headers, verify=False)
            if device_response.status_code == 200:
                json_data = device_response.json()
                device_count = json_data['@odata.count']
                if device_count > 0:
                    if '@odata.nextLink' in json_data:
                        next_link_url = base_uri + json_data['@odata.nextLink']
                    while next_link_url:
                        next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                        if next_link_response.status_code == 200:
                            next_link_json_data = next_link_response.json()
                            json_data['value'] += next_link_json_data['value']
                            if '@odata.nextLink' in next_link_json_data:
                                next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                            else:
                                next_link_url = None
                        else:
                            print("Unable to retrieve device list from nextLink %s" % (next_link_url))
                    print("*** Device List ***")
                    print(json.dumps(json_data, indent=4, sort_keys=True))
                else:
                    print("No devices managed by %s" % (ip_address))
            else:
                print("Unable to retrieve device list from %s" % (ip_address))
        else:
            print("Unable to create a session with appliance %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=True,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    ARGS = PARSER.parse_args()
    get_device_list(ARGS.ip, ARGS.user, ARGS.password)
