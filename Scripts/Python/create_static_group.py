#
#  Python script using OME API to create a new static group
#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
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
   Script to create a new static group

DESCRIPTION:
   This script exercises the OME REST API to create a new static
   group. The user is responsible for adding devices to the
   group once the group has been successfully created.
   For authentication X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python create_static_group.py --ip <xx> --user <username>
        --password <pwd> --groupname "Random Test Group"
"""
import json
import sys
import argparse
from argparse import RawTextHelpFormatter
import urllib3
import requests
from utils import authenticate_with_ome


def create_static_group(ip_address, sessionheaders, group_name):
    """ Authenticate with OME and enumerate groups """
    group_url = "https://%s/api/GroupService/Groups?$filter=Name eq 'Static Groups'" % (ip_address)
    response = requests.get(group_url, headers=sessionheaders, verify=False)
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
            create_url = 'https://%s/api/GroupService/Actions/GroupService.CreateGroup' % (ip_address)
            create_resp = requests.post(create_url, headers=headers,
                                        verify=False,
                                        data=json.dumps(group_payload))
            if create_resp.status_code == 200:
                print("New group created : ID =", create_resp.text)
                return create_resp.text
            elif create_resp.status_code == 400:
                print("Failed group creation ...See error info below")
                print(json.dumps(create_resp.json(), indent=4,
                                 sort_keys=False))
                return None
    else:
        print("Unable to retrieve group list from %s" % (ip_address))
        return None


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
    try:
        auth_success, headers = authenticate_with_ome(ARGS.ip, ARGS.user, ARGS.password)
        if auth_success:
            create_static_group(ARGS.ip, headers, ARGS.groupname)
    except:
        print("Unexpected error:", sys.exc_info()[0])
