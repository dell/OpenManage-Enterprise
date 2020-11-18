#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
#
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
Script to get the alerts for a device given the name or
asset tag of the device

#### Description
This script exercises the OME REST API to get a list of alerts for
a specific device given the name or the asset tag of the device
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_alerts_by_device.py --ip <xx> --user <username>
    --password <pwd> --filterby Name --field "idrac-abcdef"`
"""
import argparse
import json
from argparse import RawTextHelpFormatter

import requests
import urllib3


def get_alerts_by_device(ip_address, user_name, password, filter_by, field):
    """ Get alerts from OME filtered by name or asset tag """
    filter_map = {'Name': 'AlertDeviceName', 'DeviceIdentifier': 'AlertDeviceIdentifier'}
    try:
        base_uri = 'https://%s' % ip_address
        session_url = base_uri + "/api/SessionService/Sessions"
        alert_svc = "https://%s/api/AlertService/Alerts?$filter=%s eq '%s'" % (ip_address, filter_map[filter_by], field)
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
            response = requests.get(alert_svc, headers=headers, verify=False)
            if response.status_code == 200:
                json_data = response.json()
                total_alert = json_data['@odata.count']
                if total_alert > 0:
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
                            print("Unable to get full set of alerts ... ")
                            next_link_url = None
                    # Technically there should be only one result in the filter
                    print("\n*** Alerts for device (%s) ***" % field)
                    print(json.dumps(json_data, indent=4, sort_keys=True))
                else:
                    print("No alerts for device (%s) from %s" % (field, ip_address))
            else:
                print("No alert data retrieved from %s" % ip_address)
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
    parser.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    parser.add_argument("--filterby", "-fby", required=True,
                        choices=('Name', 'DeviceIdentifier'),
                        help="Filter by device identifier or name")
    parser.add_argument("--field", "-f", required=True,
                        help="Field to filter by (a valid device identifier or name)")
    args = parser.parse_args()
    get_alerts_by_device(args.ip, args.user, args.password,
                         args.filterby, str(args.field))
