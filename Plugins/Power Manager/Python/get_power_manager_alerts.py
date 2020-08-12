#
#  Python script using OpenManage Enterprise API to get Power Manager specific Alerts in OpenManage Enterprise.
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
   Script to get the list of Power Manager Specific Alerts in OpenManage Enterprise

DESCRIPTION:
   This script exercises the OpenManage Enterprise REST API to get the list of Power Manager specific alerts
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_power_manager_alerts.py --ip <xx> --username <username> --password <pwd>
   
    Output:

        =======================================
            Power Manager - Metrics - Alerts
        =======================================

        SEVERITY  SOURCE_NAME      TIME                     CATEGORY       SUB_CATEGORY  MESSAGE_ID  MESSAGE

        Warning   linux-0j8n       2020-03-20 16:31:20.484  System Health  Metrics       CMET0004    POWER on Group_R740s has exceeded its threshold.
        Critical  linux-0j8n       2020-03-20 16:16:21.252  System Health  Metrics       CMET0008    TEMPERATURE on Group_R740s has exceeded its lower threshold.

        ========================================================
            Power Manager - Power Configuration - Alerts
        ========================================================

        SEVERITY  SOURCE_NAME      TIME                     CATEGORY       SUB_CATEGORY         MESSAGE_ID  MESSAGE

        Normal    linux-0j8n       2020-01-23 13:30:00.399  System Health  Power Configuration  CPWR0014    Violation of power policy Policy_on_R740s on group Group_R740s got rectified.
        Critical  linux-0j8n       2020-01-23 12:30:00.417  System Health  Power Configuration  CPWR0013    Power policy Policy_on_R740s on group Group_R740s got violated.

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


def get_power_manager_alerts(ip_address, user_name, password):
    """ Authenticate with OpenManage Enterprise, enumerate power manager alerts"""
    try:
        
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        
        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Define the power manager alerts URL
        alerts_metrics_url = "https://%s/api/AlertService/Alerts?$top=10000000&$filter=contains(SubCategoryName,'Metrics')" % (ip_address)
        alerts_power_config_url = "https://%s/api/AlertService/Alerts?$top=10000000&$filter=contains(SubCategoryName,'Power Configuration')" % (ip_address)
        
        # Defining OUTPUT format    
        output_column_headers = ['Severity', 'Source_Name', 'Time', 'Category', 'Sub_Category', 'Message_ID', 'Message']
        alerts_metrics_output_column_data = []
        alerts_power_config_output_column_data = []
        
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
            
            #Get Metrics Alerts API call with OpenManage Enterprise
            alerts_metrics_response = requests.get(alerts_metrics_url, headers=headers, verify=False)
            alerts_metrics_json_data = alerts_metrics_response.json()
            
            #If Metrics Alerts API doesn't respond or failed, message the user with error
            if alerts_metrics_response.status_code != 201 & alerts_metrics_response.status_code != 200:
                if 'error' in alerts_metrics_json_data:
                    error_content = alerts_metrics_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager Metrics Alerts from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager Metrics Alerts from %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager Metrics Alerts from %s" % (ip_address))
            else:
                
                alerts_metrics_count = alerts_metrics_json_data['@odata.count']
                
                #If the Metrics Alerts count is 0, then error out immediately
                if alerts_metrics_count <= 0:
                    print("No Power Manager Metric Alerts found in %s" % (ip_address))
                else:
                    alerts_metrics_content = json.loads(alerts_metrics_response.content)
                    
                    if alerts_metrics_content:
                        # For every elements in the Power Manager Metrics Alerts response, store the details in the table
                        for alerts_metrics_elem in alerts_metrics_content["value"]:
                            
                            alerts_metrics_data = [alerts_metrics_elem["SeverityName"], alerts_metrics_elem["AlertDeviceName"], alerts_metrics_elem["TimeStamp"], alerts_metrics_elem["CategoryName"], alerts_metrics_elem["SubCategoryName"], alerts_metrics_elem["AlertMessageId"], alerts_metrics_elem["Message"]]
                            alerts_metrics_output_column_data.append(alerts_metrics_data)
                            
                        table = columnar(alerts_metrics_output_column_data, output_column_headers, no_borders=True)
                        print("\n   =======================================")
                        print("      Power Manager - Metrics - Alerts ")
                        print("   =======================================")
                        print(table)
                    else:
                        print("No Power Manager Metric Alerts found in %s" % (ip_address))
            
            #Get Power Configuration Alerts API call with OpenManage Enterprise
            alerts_power_config_response = requests.get(alerts_power_config_url, headers=headers, verify=False)
            alerts_power_config_json_data = alerts_power_config_response.json()
            
            #If Group Reports API doesn't respond or failed, message the user with error
            if alerts_power_config_response.status_code != 201 & alerts_power_config_response.status_code != 200:
                if 'error' in alerts_power_config_json_data:
                    error_content = alerts_power_config_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager - Power Configuration Alerts from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager - Power Configuration Alerts from %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager - Power Configuration Alerts from %s" % (ip_address))
            else:
            
                alerts_power_config_count = alerts_power_config_json_data['@odata.count']
                
                #If the Power Configuration Alerts count is 0, then error out immediately
                if alerts_power_config_count <= 0:
                    print("No Power Manager - Power Configuration Alerts found in %s" % (ip_address))
                else:
                    alerts_power_config_content = json.loads(alerts_power_config_response.content)
                    
                    if alerts_power_config_content:
                        # For every elements in the Power Manager - Power Configuration Alerts response, store the details in the table
                        for alerts_power_config_elem in alerts_power_config_content["value"]:
                            
                            alerts_power_config_data = [alerts_power_config_elem["SeverityName"], alerts_power_config_elem["AlertDeviceName"], alerts_power_config_elem["TimeStamp"], alerts_power_config_elem["CategoryName"], alerts_power_config_elem["SubCategoryName"], alerts_power_config_elem["AlertMessageId"], alerts_power_config_elem["Message"]]
                            alerts_power_config_output_column_data.append(alerts_power_config_data)
                        
                        table = columnar(alerts_power_config_output_column_data, output_column_headers, no_borders=True)
                        print("\n   ========================================================")
                        print("      Power Manager - Power Configuration - Alerts ")
                        print("   ========================================================")
                        print(table)
                    else:
                        print("No Power Manager - Power Configuration Alerts found in %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OpenManage Enterprise ", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise ")
    ARGS = PARSER.parse_args()
    
    get_power_manager_alerts(ARGS.ip, ARGS.username, ARGS.password)
