#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
#
# Copyright (c) 2020 Dell EMC Corporation
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
Script to get the details of groups managed by OM Enterprise

#### Description
This script uses the OME REST API to get a group and the
device details for all devices in that group. For authentication
X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_group_details.py --ip <xx> --user <username> --password <pwd>
--groupinfo "All Devices"`
"""
import argparse
import json
from argparse import RawTextHelpFormatter
from getpass import getpass

import requests
import urllib3


def get_group_details(ip_address, user_name, password, group_info):
    """ List out group details based on id/name/description """
    try:
        base_uri = 'https://%s' % ip_address
        session_url = base_uri + '/api/SessionService/Sessions'
        group_url = base_uri + '/api/GroupService/Groups'
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
            response = requests.get(group_url, headers=headers, verify=False)
            if response.status_code == 200:
                group_list = response.json()
                group_count = group_list['@odata.count']
                if group_count > 0:
                    found_group = False
                    if '@odata.nextLink' in group_list:
                        next_link_url = base_uri + group_list['@odata.nextLink']
                    while next_link_url:
                        next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                        if next_link_response.status_code == 200:
                            next_link_json_data = next_link_response.json()
                            group_list['value'] += next_link_json_data['value']
                            if '@odata.nextLink' in next_link_json_data:
                                next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                            else:
                                next_link_url = None
                        else:
                            print("Unable to get full group list ... ")
                            next_link_url = None
                    for group in group_list['value']:
                        if ((str(group['Id']).lower() == group_info.lower()) or
                                str(group['Name']).lower() == group_info.lower() or
                                str(group['Description']).lower() ==
                                group_info.lower()):
                            found_group = True
                            print("*** Group Details ***")
                            print(json.dumps(group, indent=4, sort_keys=True))
                            dev_url = group_url + "(" + str(group['Id']) + ")/Devices"
                            dev_response = requests.get(dev_url,
                                                        headers=headers,
                                                        verify=False)
                            if dev_response.status_code == 200:
                                device_list = dev_response.json()
                                device_count = device_list['@odata.count']
                                if device_count > 0:
                                    if '@odata.nextLink' in device_list:
                                        next_link_url = base_uri + device_list['@odata.nextLink']
                                    while next_link_url:
                                        next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                                        if next_link_response.status_code == 200:
                                            next_link_json_data = next_link_response.json()
                                            device_list['value'] += next_link_json_data['value']
                                            if '@odata.nextLink' in next_link_json_data:
                                                next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                                            else:
                                                next_link_url = None
                                        else:
                                            print("Unable to get full device list ... ")
                                            next_link_url = None

                                print("\n*** Group Device Details ***")
                                print(json.dumps(device_list, indent=4,
                                                 sort_keys=True))
                            else:
                                print("Unable to get devices for (%s)" % group_info)
                            break
                    if not found_group:
                        print("No group matching (%s) found" % group_info)
                else:
                    print("No group data retrieved from %s" % ip_address)
            else:
                print("Unable to retrieve group list from %s" % ip_address)
        else:
            print("Unable to create a session with appliance %s" % ip_address)
    except Exception as error:
        print("Unexpected error:", str(error))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=True,
                        help="Username for OME Appliance",
                        default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--groupinfo", "-g", required=True,
                        help="Group id/Name/Description - case insensitive")
    args = parser.parse_args()
    if not args.password:
        args.password = getpass()

    get_group_details(args.ip, args.user, args.password, str(args.groupinfo))
