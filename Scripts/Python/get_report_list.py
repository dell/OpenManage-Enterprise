#
#  Python script using OME API to get list of reports
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
   Script to get the list of reports defined in OM Enterprise

DESCRIPTION:
   This script exercises the OME REST API to get a list of reports
   currently defined in that instance. For authentication X-Auth
   is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_report_list.py --ip <xx> --user <username> --password <pwd>
"""
import sys
import argparse
from argparse import RawTextHelpFormatter
import json
import requests
import urllib3


def get_report_list(ip_address, user_name, password):
    """ Authenticate with OME and enumerate reports """
    try:
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        report_svc = 'https://%s/api/ReportService/ReportDefs' % (ip_address)
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            report_response = requests.get(report_svc, headers=headers, verify=False)
            if report_response.status_code == 200:
                report_info = report_response.json() 
                total_reports = report_info['@odata.count']
                if total_reports > 0:
                    current_repo_count = len(report_info['value'])
                    if total_reports > current_repo_count:
                        delta = total_reports - current_repo_count
                        remaining_report_url = report_svc +"?$skip=%s&$top=%s"%(current_repo_count, delta)
                        remaining_report_resp = requests.get(remaining_report_url, headers=headers, verify =False)
                        if remaining_report_resp.status_code == 200:
                            remaining_report_data = remaining_report_resp.json()
                            for value in remaining_report_data["value"]:
                                report_info["value"].append(value)
                        else:
                            print ("Unable to get full set of reports ... ")    
                    print ("*** List of pre-defined reports ***")
                    print (json.dumps(report_info, indent=4, sort_keys=True))
                else:
                    print ("No pre-defined reports found on %s" % (ip_address))
            else:
                print ("Unable to retrieve reports from %s" % (ip_address))
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
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    ARGS = PARSER.parse_args()
    get_report_list(ARGS.ip, ARGS.user, ARGS.password)
