#
#  Python script using OME API to get alerts for a group.
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
   Script to get the list of alerts for a group in OME

DESCRIPTION:
    This script exercises the OME REST API to get a list
    of alerts for the given group. For authentication X-Auth
    is used over Basic Authentication.
    Note that the credentials entered are not stored to disk.

EXAMPLE:
     python get_alerts_by_group.py --ip <ip addr> --user admin
         --password <password> --filterby Name
         --field "Dell iDRAC Servers"

"""
import sys
import argparse
from argparse import RawTextHelpFormatter
import json
import requests
import urllib3


def get_alerts_by_group(ip_address, user_name, password, filter_by, field):
    """ Get alerts by group using OData filter """
    try:
        base_uri = 'https://%s' %(ip_address)
        session_url = base_uri + "/api/SessionService/Sessions"
        base_grp = base_uri + "/api/GroupService/Groups"
        alert_svc = base_uri + "/api/AlertService/Alerts"
        grp_url = base_grp + "?$filter=%s eq '%s'" % (filter_by, field)
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
            response = requests.get(grp_url, headers=headers, verify=False)
            if response.status_code == 200:
                json_data = response.json()
                if json_data['@odata.count'] > 0:
                    # Technically there should be only one result in the filter
                    group_id = json_data['value'][0]['Id']
                    alert_url = alert_svc + "?$filter=AlertDeviceGroup eq %s" % (group_id)
                    alert_resp = requests.get(alert_url, headers=headers,
                                              verify=False)
                    if alert_resp.status_code == 200:
                        alert_Info = alert_resp.json()
                        total_alerts = alert_Info['@odata.count']
                        if total_alerts>0:
                            if '@odata.nextLink' in alert_Info:
                                next_link_url = base_uri + alert_Info['@odata.nextLink']
                            while next_link_url:
                                next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                                if next_link_response.status_code == 200:
                                    next_link_json_data = next_link_response.json()
                                    alert_Info['value'] += next_link_json_data['value']
                                    if '@odata.nextLink' in next_link_json_data:
                                        next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                                    else:
                                        next_link_url = None
                                else:
                                    print ("Unable to get full set of alerts ... ")
                                    next_link_url = None
                        print ("\n*** Alerts for group (%s) ***" % (field))
                        print (json.dumps(alert_Info, indent=4, sort_keys=True))
                    else:
                        print ("Unable to retrieve alerts for group (%s) from %s" % (field, ip_address))
                else:
                    print ("No group matching field (%s) retrieved from %s" % (field, ip_address))
            else:
                print ("No group data retrieved from %s" % (ip_address))
        else:
            print ("Unable to create a session with appliance %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u",
                        required=True, help="Username for OME Appliance",
                        default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--filterby", "-fby", required=True,
                        choices=('Name', 'Description'),
                        help="filter by group name or description")
    PARSER.add_argument("--field", "-f", required=True,
                        help="Field to filter by (a valid group name or desc)")
    ARGS = PARSER.parse_args()
    get_alerts_by_group(ARGS.ip, ARGS.user, ARGS.password,
                        ARGS.filterby, str(ARGS.field))
