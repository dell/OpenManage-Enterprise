#
#  Python script using OME API to get alerts for a device.
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
    Script to get the alerts for a device given the name or
    asset tag of the device

DESCRIPTION:
    This script exercises the OME REST API to get a list of alerts for
    a specific device given the name or the asset tag of the device
    Note that the credentials entered are not stored to disk.

EXAMPLE:
    python get_alerts_by_device.py --ip <xx> --user <username>
        --password <pwd> --filterby Name --field "idrac-abcdef"

"""
import sys
import argparse
from argparse import RawTextHelpFormatter
import json
import urllib3
import requests


def get_alerts_by_device(ip_address, user_name, password, filter_by, field):
    """ Get alerts from OME filtered by name or asset tag """
    filter_map = {'Name': 'AlertDeviceName', 'DeviceIdentifier': 'AlertDeviceIdentifier'}
    try:
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        alert_svc = "https://%s/api/AlertService/Alerts?$filter=%s eq '%s'" % (ip_address, filter_map[filter_by], field)
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
                    current_alert_count = len(json_data['value'])
                    if total_alert>current_repo_count:
                            delta = total_alert-current_alert_count
                            remaining_alert_url =alert_svc+"& $Skip=%s&$top=%s"%(current_alert_count,delta)
                            remaining_alert_resp = requests.get(remaining_alert_url, headers=headers, verify=False)
                            if remaining_alert_resp.status_code ==200:
                                remaining_alert_data = remaining_alert_resp.json()
                                for value in remaining_alert_data["value"]:
                                    json_data["value"].append(value)
                            else:
                                print ("Unable to get full set of alerts ... ")
                    # Technically there should be only one result in the filter
                    print ("\n*** Alerts for device (%s) ***" % (field))
                    print (json.dumps(json_data, indent=4, sort_keys=True))
                else:
                    print ("No alerts for device (%s) from %s" % (field, ip_address))
            else:
                print ("No alert data retrieved from %s" % (ip_address))
        else:
            print ("Unable to create a session with appliance %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])


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
    PARSER.add_argument("--filterby", "-fby", required=True,
                        choices=('Name', 'DeviceIdentifier'),
                        help="Filter by device identifier or name")
    PARSER.add_argument("--field", "-f", required=True,
                        help="Field to filter by (a valid device identifier or name)")
    ARGS = PARSER.parse_args()
    get_alerts_by_device(ARGS.ip, ARGS.user, ARGS.password,
                         ARGS.filterby, str(ARGS.field))
