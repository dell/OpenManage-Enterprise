#
#  Python script using Power Manager API to get Power Manager Polcies.
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
   Script to get Power Manager policies created for either Devices/Groups with optional filters

DESCRIPTION:
   This script exercises the Power Manager REST API to get different Power Manager Polcies created on devices or groups.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_power_manager_policies.py --ip <xx> --username <username> --password <pwd> --filterBy <filter_name> --filterValue <filter_value>
   
    Output:
    
        ==================================
            Power Manager Policies
        ==================================

        POLICY_ID  POLICY_NAME                       POLICY_TYPE            POLICY_ENABLED  POLICY_EXECUTION_STATE  IS_POLICY_ON_GROUP/DEVICE?  GROUP/DEVICE_ASSIGNED_TO  CREATED_TIME

        9          Temperature Triggered for groups  TEMPERATURE-TRIGGERED  True            NOSTATE                 Group                       G1_PMP1.0                 2020-03-22 13:00:30.520681
        6          Policy3                           STATIC                 True            NOSTATE                 Device                      47XGH32                   2020-03-18 11:17:44.340717
        5          Policy2                           STATIC                 True            SUCCESS                 Device                      47XGH32                   2020-03-18 11:09:29.710303
        4          Policy1                           STATIC                 True            SUCCESS                 Device                      47XGH32                   2020-03-18 11:02:20.585298
    
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

#Policy Type dictonary to display the output for better reading
policy_type_dictionary = {
    1:"STATIC",
    2:"TEMPERATURE-TRIGGERED"}

#Policy Execution State dictonary to display the output for better reading
policy_execution_state_dictionary = {
    1:"NOSTATE",
    2:"EXECUTING",
    3:"SUCCESS",
    4:"PARTIAL_SUCCESS",
    5:"FAILED"}

#IsAssociatedToGroup dictonary to display the output for better reading
IsAssociatedToGroup_dictionary = {
    "True":"Group",
    "False":"Device"}

def get_power_manager_policies(ip_address, user_name, password, filterBY, filterValue):
    """ Authenticate with OpenManage Enterprise, get power manager policies"""
    try:
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        
        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Define the Policy URL basis the filter existance & type
        if filterBY and filterValue:
            if filterBY  in ('Enabled','Type'):
                policies_url = "https://%s/api/PowerService/Policies?$filter=%s eq %s" % (ip_address,filterBY,filterValue)
            else:
                policies_url = "https://%s/api/PowerService/Policies?$filter=contains(%s,'%s')" % (ip_address,filterBY,filterValue)
        else:
            policies_url = "https://%s/api/PowerService/Policies" % (ip_address)
        
        
        # Defining OUTPUT format
        output_column_headers = ['Policy_ID', 'Policy_Name', 'Policy_Type', 'Policy_Enabled', "Policy_Execution_State", "Is_Policy_on_Group/Device?", "Group/Device_Assigned_To", "Created_Time"]
        output_column_data = []
        
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
            
            #Get Power Manager Policies API call with OpenManage Enterprise
            policies_response = requests.get(policies_url, headers=headers, verify=False)
            policies_json_data = policies_response.json()
            
            #If policies API doesn't respond or failed, message the user with error
            if policies_response.status_code != 201 & policies_response.status_code != 200:
                if 'error' in policies_json_data:
                    error_content = policies_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager policies from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager policies from %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager policies from %s" % (ip_address))
            else:
                policies_count = policies_json_data['@odata.count']
                
                #If the policies count is 0, then error out immediately
                if policies_count <= 0:
                    print("No Power Manager Policies created in %s" % (ip_address))
                else:
                    policies_content = json.loads(policies_response.content)
                    
                    if policies_content:
                        # For every elements in the policies response, store the details in the table
                        for policies_elem in policies_content["value"]:
                            policies_data = [policies_elem["PolicyId"], policies_elem["Name"], policy_type_dictionary[int(policies_elem["Type"])], policies_elem["Enabled"], policy_execution_state_dictionary[int(policies_elem["ExecutionState"])], IsAssociatedToGroup_dictionary[str(policies_elem["IsAssociatedToGroup"])], policies_elem["AssignedTo"], policies_elem["CreatedTime"]]
                            output_column_data.append(policies_data)
                        
                        table = columnar(output_column_data, output_column_headers, no_borders=True)
                        print("\n   ==================================")
                        print("      Power Manager Policies ")
                        print("   ==================================")
                        print(table)
                    else:
                        print("No Power Manager Policies created in %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP <- Mandatory")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OpenManage Enterprise  <- Optional; default = admin", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise  <- Mandatory")
    PARSER.add_argument("--filterBy", "-b", required=False, help=''' Applicable Filters are:
        Name - Name of the policy
        Enabled - Policy Enabled state
        AssignedTo - Device service tag or Group Name
        Type - Policy Type
    ''', default=None)
    PARSER.add_argument("--filterValue", "-v", required=False, help='''  Input value for filtersBy:
        Name - Sting Value
        Enabled - true or false
        AssignedTo - String Value
        Type - 1-Static; 2-Temperature-Triggered
    ''', default=None)

    ARGS = PARSER.parse_args()
    
    get_power_manager_policies(ARGS.ip, ARGS.username, ARGS.password, ARGS.filterBy, ARGS.filterValue)