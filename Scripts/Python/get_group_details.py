#
#  Python script using OME API to get group details
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
   Script to get the details of groups managed by OM Enterprise

DESCRIPTION:
   This script exercises the OME REST API to get a group and the
   device details for all devices in that group. For authentication
   X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_group_details.py --ip <xx> --user <username> --password <pwd>
    --groupinfo "All Devices"
"""
import json
import sys
import argparse
from argparse import RawTextHelpFormatter
import urllib3
import requests


def get_group_details(ip_address, user_name, password, group_info):
    """ List out group details based on id/name/description """
    try:
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        group_url = 'https://%s/api/GroupService/Groups' % (ip_address)
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
                if group_list['@odata.count'] > 0:
                    found_group = False
                    for group in group_list['value']:
                        if ((str(group['Id']).lower() == group_info.lower()) or
                                str(group['Name']).lower() == group_info.lower() or
                                str(group['Description']).lower() ==
                                group_info.lower()):
                            found_group = True
                            print "*** Group Details ***"
                            print json.dumps(group, indent=4, sort_keys=True)
                            dev_url = group_url + "(" + str(group['Id']) + ")/Devices"
                            dev_response = requests.get(dev_url,
                                                        headers=headers,
                                                        verify=False)
                            if dev_response.status_code == 200:
                                print "\n*** Group Device Details ***"
                                print json.dumps(dev_response.json(), indent=4,
                                                 sort_keys=True)
                            else:
                                print "Unable to get devices for (%s)" % (group_info)
                            break
                    if not found_group:
                        print "No group matching (%s) found" % (group_info)
                else:
                    print "No group data retrieved from %s" % (ip_address)
            else:
                print "Unable to retrieve group list from %s" % (ip_address)
        else:
            print "Unable to create a session with appliance %s" % (ip_address)
    except:
        print "Unexpected error:", sys.exc_info()


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=True,
                        help="Username for OME Appliance",
                        default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--groupinfo", "-g", required=True,
                        help="Group id/Name/Description - case insensitive")
    ARGS = PARSER.parse_args()
    get_group_details(ARGS.ip, ARGS.user, ARGS.password, str(ARGS.groupinfo))
