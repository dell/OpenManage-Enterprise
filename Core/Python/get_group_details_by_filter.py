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
This script uses OData filters for extracting information

#### Description
This script uses the OME REST API to get a group and the
device details for all devices in that group. For authentication
X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_group_details_by_filter.py --ip <xx> --user <username> --password <pwd>
    --filterby Name --field "All Devices"`
"""
import argparse
import json
from argparse import RawTextHelpFormatter
from getpass import getpass

import requests
import urllib3


def get_group_details(ip_address, user_name, password, filter_by, field):
    """ Get Group Details using OData filters """
    try:
        base_uri = 'https://%s' % ip_address
        sess_url = base_uri + '/api/SessionService/Sessions'
        base_grp = base_uri + "/api/GroupService/Groups"
        grp_url = base_grp + "?$filter=%s eq '%s'" % (filter_by, field)
        next_link_url = None
        headers = {'content-type': 'application/json'}

        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        sess_info = requests.post(sess_url, verify=False,
                                  data=json.dumps(user_details),
                                  headers=headers)
        if sess_info.status_code == 201:
            headers['X-Auth-Token'] = sess_info.headers['X-Auth-Token']
            response = requests.get(grp_url, headers=headers, verify=False)
            if response.status_code == 200:
                json_data = response.json()
                if json_data['@odata.count'] > 0:
                    print("*** Group Details ***")
                    print(json.dumps(json_data, indent=4, sort_keys=True))
                    # Technically there should be only one result in the filter
                    group_id = json_data['value'][0]['Id']
                    print("\n*** Group Device Details ***")
                    dev_url = base_grp + "(" + str(group_id) + ")/Devices"
                    dev_resp = requests.get(dev_url, headers=headers,
                                            verify=False)
                    if dev_resp.status_code == 200:
                        print(json.dumps(dev_resp.json(), indent=4,
                                         sort_keys=True))
                        device_list = dev_resp.json()
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
                    else:
                        print("Unable to retrieve devices for group (%s) from %s" % (field, ip_address))
                else:
                    print("No group matching field (%s) retrieved from %s" % (field, ip_address))
            else:
                print("No group data retrieved from %s" % ip_address)
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
    parser.add_argument("--filterby", "-fby", required=True,
                        choices=('Name', 'Description'),
                        help="filter by group name or description")
    parser.add_argument("--field", "-f", required=True,
                        help="Field to filter by (group name or description)")
    args = parser.parse_args()
    if not args.password:
        args.password = getpass()

    get_group_details(args.ip, args.user, args.password,
                      str(args.filterby), str(args.field))
