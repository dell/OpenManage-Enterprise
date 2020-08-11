#
#  Python script using OME API to get list of groups
#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
# _version_ = 0.2
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
   Script to get the list of groups managed by OM Enterprise

DESCRIPTION:
   This script exercises the OME REST API to get a list of groups
   currently being managed by that instance. For authentication X-Auth
   is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_group_list.py --ip <xx> --user <username> --password <pwd>
"""
import json
import argparse
from argparse import RawTextHelpFormatter
import urllib3
import requests
import pprint


def get_group_list(ome_ip_address, user_name, password):
    """ Authenticate with OME and enumerate groups """
    try:
        session_url = 'https://%s/api/SessionService/Sessions' % ome_ip_address
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        group_data = None
        next_link_url = 'https://%s/api/GroupService/Groups' % ome_ip_address

        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']

            while next_link_url is not None:
                group_response = requests.get(next_link_url, headers=headers, verify=False)
                next_link_url = None

                if group_response.status_code == 200:
                    data = group_response.json()
                    if data['@odata.count'] <= 0:
                        print("No subgroups of static groups found on OME server: " + ome_ip_address)
                        return 0
                    if '@odata.nextLink' in data:
                        next_link_url = "https://%s" + data['@odata.nextLink']
                    if group_data is None:
                        group_data = data["value"]
                    else:
                        group_data += data["value"]
                else:
                    print("Unable to retrieve group list from %s" % ome_ip_address)
                    exit(1)

        pprint.pprint(group_data)

    except Exception as e:
        print("Encountered an error: " + str(e))
        exit(1)


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    ARGS = PARSER.parse_args()
    get_group_list(ARGS.ip, ARGS.user, ARGS.password)
