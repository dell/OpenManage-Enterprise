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
Script to create a new static group

#### Description
This script uses the OME REST API to create a new static
group. The user is responsible for adding devices to the
group once the group has been successfully created.
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python new_static_group.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group"`
"""
import argparse
import json
import sys
from argparse import RawTextHelpFormatter
from getpass import getpass

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
    sys.exit(0)


def authenticate(ome_ip_address: str, ome_username: str, ome_password: str) -> dict:
    """
    Authenticates with OME and creates a session

    Args:
        ome_ip_address: IP address of the OME server
        ome_username:  Username for OME
        ome_password: OME password

    Returns: A dictionary of HTTP headers

    Raises:
        Exception: A generic exception in the event of a failure to connect.
    """

    authenticated_headers = {'content-type': 'application/json'}
    session_url = 'https://%s/api/SessionService/Sessions' % ome_ip_address
    user_details = {'UserName': ome_username,
                    'Password': ome_password,
                    'SessionType': 'API'}
    session_info = requests.post(session_url, verify=False,
                                 data=json.dumps(user_details),
                                 headers=authenticated_headers)

    if session_info.status_code == 201:
        authenticated_headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        return authenticated_headers

    print("There was a problem authenticating with OME. Are you sure you have the right username, password, "
          "and IP?")
    raise Exception("There was a problem authenticating with OME. Are you sure you have the right username, "
                    "password, and IP?")


def create_static_group(authenticated_headers: dict, ome_ip_address: str, group_name: str) -> int:
    """
    Authenticate with OME and enumerate groups

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        group_name: The name of the group which you would like to create

    Returns: Returns an integer containing the ID of the group or -1 if the group creation failed
    """
    try:
        group_url = "https://%s/api/GroupService/Groups?$filter=Name eq 'Static Groups'" % ome_ip_address

        response = requests.get(group_url, headers=authenticated_headers, verify=False)
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
                create_url = 'https://%s/api/GroupService/Actions/GroupService.CreateGroup' % ome_ip_address
                create_resp = requests.post(create_url, headers=authenticated_headers,
                                            verify=False,
                                            data=json.dumps(group_payload))
                if create_resp.status_code == 200:
                    print("New group created : ID =", create_resp.text)
                    return int(create_resp.text)
                elif create_resp.status_code == 400:
                    print("Failed group creation ...See error info below")
                    print(json.dumps(create_resp.json(), indent=4,
                                     sort_keys=False))
                    return -1
        print("Unable to retrieve group list from %s" % ome_ip_address)
        return -1
    except Exception as error:
        print("Unexpected error:", str(error))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--groupname", "-g", required=True,
                        help="A valid name for the group")
    args = parser.parse_args()
    if not args.password:
        args.password = getpass()

    try:
        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        create_static_group(headers, args.ip, args.groupname)

    except Exception as error:
        print("Unexpected error:", str(error))
