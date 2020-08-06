#
#  Python script using OME API to create a new static group
#
# _author_ = Grant Curell <grant_curell@dell.com>
# _version_ = 0.1
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
SYNOPSIS:
   Add a host to a static group

DESCRIPTION:
   This script exercises the OME REST API to create a new static
   group. The user is responsible for adding devices to the
   group once the group has been successfully created.
   For authentication X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python create_static_group.py --ip <xx> --user <username>
        --password <pwd> --groupname "Random Test Group" --devicename "cmc1"
"""

import json
import sys
import argparse
from argparse import RawTextHelpFormatter
import urllib3
import requests


def add_device_to_static_group(ome_ip_address, ome_username, ome_password, group_name):
    """ Authenticate with OME and enumerate groups """
    try:
        session_url = 'https://%s/api/SessionService/Sessions' % ome_ip_address
        group_url = "https://%s/api/GroupService/Actions/GroupService.AddMemberDevices" % ome_ip_address
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': ome_username,
                        'Password': ome_password,
                        'SessionType': 'API'}

        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            response = requests.get(group_url, headers=headers, verify=False)
            if response.status_code == 200:
                json_data = response.json()
                if json_data['@odata.count'] > 0:
                    # Technically there should be only one result in the filter
                    group_id = json_data['value'][0]['Id']
                    group_payload = {"GroupModel": {
                        "Name": group_name,
                        "Description": "",
                        "MembershipTypeId": 12,
                        "ParentId": int(group_id)}
                    }
                    create_url = 'https://%s/api/GroupService/Actions/GroupService.CreateGroup' % (ome_ip_address)
                    create_resp = requests.post(create_url, headers=headers,
                                                verify=False,
                                                data=json.dumps(group_payload))
                    if create_resp.status_code == 200:
                        print("New group created : ID =", create_resp.text)
                    elif create_resp.status_code == 400:
                        print("Failed group creation ...See error info below")
                        print(json.dumps(create_resp.json(), indent=4,
                                         sort_keys=False))
            else:
                print("Unable to retrieve group list from %s" % ome_ip_address)
        else:
            print("Unable to create a session with appliance %s" % ome_ip_address)
    except Exception as e:
        print("Unexpected error:", str(e))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=True,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--groupname", "-g", required=True,
                        help="A valid name for the group")
    ARGS = PARSER.parse_args()
    add_device_to_static_group(ARGS.ome_ip_address, ARGS.user, ARGS.password, ARGS.groupname)
