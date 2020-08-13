#
#  Python script using OpenManage Enterprise API to get Power Manager top power & temperature offenders in OpenManage Enterprise.
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
   Script to get the list of top power and temperature offenders (Device or Group which violated the respective threshold)

DESCRIPTION:
   This script exercises the OpenManage Enterprise REST API to get the list of top power and temperature offenders (Device or Group which violated the respective threshold)
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_power_manager_top_offenders.py --ip <xx> --username <username> --password <pwd>
   
    Output:
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

#Entity Type dictionary to display the output for better reading
entity_type_dictionary = {
    1:"Device",
    2:"Group"}

#Threshold Type dictionary to display the output for better reading
threshold_type_dictionary = {
    3:"Power",
    7:"Temperature"}

#Violation State dictionary to display the output for better reading
violation_state_dictionary = {
    1:"Unknown",
    2:"Normal",
    3:"Warning",
    4:"Critical"}

def get_power_manager_top_offenders(ip_address, user_name, password):
    """ Authenticate with OpenManage Enterprise, enumerate top power and temperature offenders"""
    try:
        
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        
        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Define the top offenders URL
        top_offenders_url = "https://%s/api/MetricService/TopOffenders" % (ip_address)
        
        # Defining OUTPUT format    
        output_column_headers = ['Entity_Id', 'Entity_Name', 'Entity_Type', 'Threshold_Type', 'Total_Violations', 'Violation_State']
        top_offenders_output_column_data = []
        
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
            
            #Get Top offenders API call with OpenManage Enterprise
            top_offenders_response = requests.get(top_offenders_url, headers=headers, verify=False)
            top_offenders_json_data = top_offenders_response.json()
            
            #If Top offenders API doesn't respond or failed, message the user with error
            if top_offenders_response.status_code != 201 & top_offenders_response.status_code != 200:
                if 'error' in top_offenders_json_data:
                    error_content = top_offenders_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager - Top Power & Termperature threshold offenders from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager - Top Power & Termperature threshold offenders from %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager - Top Power & Termperature threshold offenders from %s" % (ip_address))
            else:
                
                top_offenders_count = top_offenders_json_data['@odata.count']
                
                #If the Metrics Alerts count is 0, then error out immediately
                if top_offenders_count <= 0:
                    print("No Power Manager Top Power & Termperature threshold offenders found in %s" % (ip_address))
                else:
                    top_offenders_content = json.loads(top_offenders_response.content)
                    
                    if top_offenders_content:
                        # For every elements in the top offenders response, store the details in the table
                        for top_offenders_elem in top_offenders_content["value"]:
                            
                            top_offenders_data = [top_offenders_elem["EntityId"], top_offenders_elem["EntityName"], entity_type_dictionary[int(top_offenders_elem["EntityType"])], threshold_type_dictionary[int(top_offenders_elem["ThresholdType"])], top_offenders_elem["TotalViolations"], violation_state_dictionary[int(top_offenders_elem["ViolationState"])]]
                            top_offenders_output_column_data.append(top_offenders_data)
                            
                        table = columnar(top_offenders_output_column_data, output_column_headers, no_borders=True)
                        print("\n   ======================================================================")
                        print("      Power Manager - Top Offenders of Power & Temperature threshold ")
                        print("   ======================================================================")
                        print(table)
                    else:
                        print("No Power Manager Top Power & Termperature threshold offenders found in %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OpenManage Enterprise ", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise ")
    ARGS = PARSER.parse_args()
    
    get_power_manager_top_offenders(ARGS.ip, ARGS.username, ARGS.password)
