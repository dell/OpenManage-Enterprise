#
#  Python script using OpenManage Enterprise API to get Power Manager specific Device and Group Reports (Pre-Canned & Custom) in OpenManage Enterprise.
#
# _author_ = Mahendran P <Mahendran_P@Dell.com>
# _version_ = 0.1
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
SYNOPSIS:
   Script to get the list of Power Manager Specific Device and Group Reports (Pre-Canned & Custom) in OpenManage Enterprise

DESCRIPTION:
   This script exercises the OpenManage Enterprise REST API to get the list of Power Manager Device and Group Reports
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_power_manager_reports.py --ip <xx> --username <username> --password <pwd>
   
    Output:
    
        =====================================
            Power Manager Device Reports
        =====================================

        REPORT_ID  REPORT_NAME                                          IS_PRE-CANNED_OR_CUSTOM?  LAST_EDITED_BY  LAST_RUN_BY  LAST_RUN_DURATION  LAST_RUN_DATE

        10287      DeviceWSnNotWS                                       Custom                    None            admin        0.78               2020-03-18 09:49:14.739
        2000       Power Manager: Metric Thresholds Report for Device  Pre-Canned                None            admin        3.68               2020-03-18 08:03:34.282
        2002       Power Manager: Power and Thermal Report of Device   Pre-Canned                None            admin        5.39               2020-03-18 08:04:14.099


        =====================================
            Power Manager Group Reports
        =====================================

        REPORT_ID  REPORT_NAME                                               IS_PRE-CANNED_OR_CUSTOM?  LAST_EDITED_BY  LAST_RUN_BY  LAST_RUN_DURATION  LAST_RUN_DATE

        10281      GroupThermal                                              Custom                    None            admin        3.56               2020-03-18 08:02:12.003
        2001       Power Manager: Metric Thresholds Report for Group        Pre-Canned                None            None         None               None

"""

#Import the modules required for this script
import sys
import argparse
from argparse import RawTextHelpFormatter
import json
import requests
import urllib3
from columnar import columnar
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#Report Type dictonary to display the output for better reading
report_type_dictionary = {
    True:"Pre-Canned",
    False:"Custom"}


def get_power_manager_reports(ip_address, user_name, password):
    """ Authenticate with OpenManage Enterprise, enumerate power manager device & group reports"""
    try:
        
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}

        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Define the report URL for Device & Group separately
        device_reports_url = "https://%s/api/ReportService/ReportDefs?$filter=contains(Category,'Power Manager Devices')" % (ip_address)
        group_reports_url = "https://%s/api/ReportService/ReportDefs?$filter=contains(Category,'Power Manager Groups')" % (ip_address)
        
        # Defining OUTPUT format
        output_column_headers = ['Report_ID', 'Report_Name', 'Is_Pre-Canned_or_Custom?', 'Last_Edited_By', 'Last_Run_By', 'Last_Run_Duration', 'Last_Run_Date']
        device_output_column_data = []
        group_output_column_data = []
        
        # Create the session with OpenManage Enterprise
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        
        #If session doesn't create, message the user with error
        if session_info.status_code != 201 & session_info.status_code != 200:
            
            session_json_data = session_info.json()
            if 'error' in session_json_data:
                error_content = session_json_data['error']
                if '@Message.ExtendedInfo' not in error_content:
                    print("Unable to create a session with  %s" % (ip_address))
                else:
                    extended_error_content = error_content['@Message.ExtendedInfo']
                    print("Unable to create a session with  %s. See below ExtendedInfo for more information" % (ip_address))
                    print(extended_error_content[0]['Message'])
            else:
                print("Unable to create a session with  %s. Please try again later" % (ip_address))
        else:
        
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            
            #Get Device Report API call with OpenManage Enterprise
            device_reports_response = requests.get(device_reports_url, headers=headers, verify=False)
            device_reports_json_data = device_reports_response.json()
            
            #If Reports API doesn't respond or failed, message the user with error
            if device_reports_response.status_code != 201 & device_reports_response.status_code != 200:
                if 'error' in device_reports_json_data:
                    error_content = device_reports_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager Device Reports from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager Device Reports from %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager Device Reports from %s" % (ip_address))
            else:
                device_reports_count = device_reports_json_data['@odata.count']
                
                #If the Device Reports count is 0, then error out immediately
                if device_reports_count <= 0:
                    print("No Power Manager Device Reports found in %s" % (ip_address))
                else:
                    device_reports_content = json.loads(device_reports_response.content)
                    
                    if device_reports_content:
                        # For every elements in the Power Manager Device Reports response, store the details in the table
                        for device_reports_elem in device_reports_content["value"]:
                            
                            device_reports_data = [device_reports_elem["Id"], device_reports_elem["Name"], report_type_dictionary[bool(device_reports_elem["IsBuiltIn"])], device_reports_elem["LastEditedBy"], device_reports_elem["LastRunBy"], device_reports_elem["LastRunDuration"], device_reports_elem["LastRunDate"]]
                            device_output_column_data.append(device_reports_data)
                            
                        table = columnar(device_output_column_data, output_column_headers, no_borders=True)
                        print("\n   =====================================")
                        print("      Power Manager Device Reports ")
                        print("   =====================================")
                        print(table)
                    else:
                        print("No Power Manager Device Reports found in %s" % (ip_address))
            
            #Get Group Report API call with OpenManage Enterprise
            group_reports_response = requests.get(group_reports_url, headers=headers, verify=False)
            group_reports_json_data = group_reports_response.json()
            
            #If Group Reports API doesn't respond or failed, message the user with error
            if group_reports_response.status_code != 201 & group_reports_response.status_code != 200:
                if 'error' in group_reports_json_data:
                    error_content = group_reports_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager Group Reports from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager Group Reports from %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager Group Reports from %s" % (ip_address))
            else:
                group_reports_count = group_reports_json_data['@odata.count']
                
                #If the group reports count is 0, then error out immediately
                if group_reports_count <= 0:
                    print("No Power Manager Group Reports found in %s" % (ip_address))
                else:
                    group_reports_content = json.loads(group_reports_response.content)
                    
                    if group_reports_content:
                        # For every elements in the Power Manager Group Reports response, store the details in the table
                        for group_reports_elem in group_reports_content["value"]:
                            
                            group_reports_data = [group_reports_elem["Id"], group_reports_elem["Name"], report_type_dictionary[bool(group_reports_elem["IsBuiltIn"])], group_reports_elem["LastEditedBy"], group_reports_elem["LastRunBy"], group_reports_elem["LastRunDuration"], group_reports_elem["LastRunDate"]]
                            group_output_column_data.append(group_reports_data)
                        
                        table = columnar(group_output_column_data, output_column_headers, no_borders=True)
                        print("\n   =====================================")
                        print("      Power Manager Group Reports ")
                        print("   =====================================")
                        print(table)
                    else:
                        print("No Power Manager Group Reports found in %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OpenManage Enterprise ", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise ")
    ARGS = PARSER.parse_args()
    
    get_power_manager_reports(ARGS.ip, ARGS.username, ARGS.password)
