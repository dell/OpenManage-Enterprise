#
#  Python script using Power Manager API to get or set Power Manager - Settings.
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
   Script to get or set Power Manager Settings applied on OpenManage Enterprise 

DESCRIPTION:
   This script exercises the Power Manager REST API to get & set Power Manager Settings.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_set_power_manager_settings.py --ip <xx> --username <username> --password <pwd>

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

#Temperature Display Unit dictionary to display the output for better reading
temp_disp_unit_dictionary = {
    1:"Celsius",
    2:"Fahrenheit"}

#Power Display Unit dictionary to display the output for better reading
power_disp_unit_dictionary = {
    1:"Watt",
    2:"BTU/Hr"}

#Metric Interval dictionary to display the output for better reading
metric_interval_dictionary = {
    15:"15 minutes",
    30:"30 minutes",
    60:"60 minutes"}

#Built-in Report Interval dictionary to display the output for better reading
report_interval_dictionary = {
    1:"1 Day",
    7:"7 Days",
    15:"15 Days",
    30:"30 Days",
    90:"90 Days",
    180:"180 Days",
    365:"365 Days"}

#Built-in Report Time Granularity dictionary to display the output for better reading
report_granularity_dictionary = {
    1:"1 Hour",
    2:"1 Day"}

#Top Energy Consumers dictionary to display the output for better reading
top_energy_interval_dictionary = {
    4:"1 Day",
    5:"1 Week",
    6:"2 Weeks",
    7:"1 Month",
    8:"3 Months",
    9:"6 Months",
    10:"1 Year"}

#Delete Metric Data dictionary to display the output for better reading
delete_metric_data_dictionary = {
    1:"Delete data",
    2:"Keep data"}
    
#Reset WSMAN Power Metric dictionary to display the output for better reading
reset_metric_dictionary = {
    1:"Enabled",
    2:"Disable"}
    
#Power Manager Settings dictionary's dictionary to display the output for better reading
settings_dictionary = {
    (1 or 1.0):temp_disp_unit_dictionary,
    (2 or 2.0):power_disp_unit_dictionary,
    (3 or 3.0):metric_interval_dictionary,
    (5 or 5.0):report_interval_dictionary,
    (6 or 6.0):report_granularity_dictionary,
    (7 or 7.0):top_energy_interval_dictionary,
    (8 or 8.0):delete_metric_data_dictionary,
    (9 or 9.0):reset_metric_dictionary,
    (51 or 51.0):"Any number of days between 30 to 365"}

def get_power_manager_settings(ip_address, user_name, password):
    """ Authenticate with OpenManage Enterprise, get power manager settings"""
    try:
        # Defining Session URL & headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        
        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
                        
        # Define OUTPUT header & data format
        output_column_headers = ['Setting_ID', 'Name', 'Default_Value', 'Current_Value', 'Setting_Value_Enum']
        output_column_data = []
        
        # Defining Power Manager settings URL
        settings_url = "https://%s/api/PowerService/Settings" % (ip_address)
            
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
            return 0
        
        else:
        
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            
            #Get Power Manager settings API call with OpenManage Enterprise
            settings_response = requests.get(settings_url, headers=headers, verify=False)
            settings_json_data = settings_response.json()
            
            #If settings API doesn't respond or failed, message the user with error
            if settings_response.status_code != 201 & settings_response.status_code != 200:
                if 'error' in settings_json_data:
                    error_content = settings_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager settings from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager settings from %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager settings from %s" % (ip_address))
                return 0
            else:
                settings_content = json.loads(settings_response.content)
                
                if settings_content:
                    # For every elements in the Settings response, store the details in the table
                    for settings_elem in settings_content["value"]:
                        
                        data_dictionary = settings_dictionary[int(settings_elem["Id"])]
                                            
                        settings_data = [settings_elem["Id"], settings_elem["Name"], settings_elem["DefaultValue"], settings_elem["Value"], data_dictionary]
                        output_column_data.append(settings_data)
                        
                    table = columnar(output_column_data, output_column_headers, no_borders=True)
                    print("\n   ==========================================")
                    print("      Power Manager Settings ")
                    print("   ==========================================")
                    print(table)
                    return 1
                else:
                    print("No Power Manager settings from %s" % (ip_address))
                    return 0
    except:
        print ("Unexpected error:", sys.exc_info()[0])
        return 0

def set_power_manager_settings(ip_address, user_name, password, settings_id, settings_value):
    """ Authenticate with OpenManage Enterprise, set power manager settings"""
    try:
        
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        
        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Defining Power Manager settings URL
        settings_url = "https://%s/api/PowerService/Actions/PowerService.UpdateSettings" % (ip_address)
        
        # Payload for posting settings API
        settings_payload = {"Settings":[{ "Id": int(settings_id), "Value": int(settings_value)}]}
        
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
            
            #Set Power Manager settings API call with OpenManage Enterprise
            settings_response = requests.post(settings_url, data=json.dumps(settings_payload), headers=headers, verify=False)
            settings_json_data = settings_response.json()
            
            #If settings API doesn't respond or failed, message the user with error
            if settings_response.status_code != 201 & settings_response.status_code != 200:
                if 'error' in settings_json_data:
                    error_content = settings_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to set Power Manager Setting on %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to set Power Manager Setting on %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to set Power Manager Setting on %s" % (ip_address))
            else:
                print("Successfully applied Power Manger Setting on %s" % (ip_address))
    except:
        print ("Unexpected error:", sys.exc_info()[0])
        return 0

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP <- Mandatory")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OpenManage Enterprise  <- Optional; default = admin", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise  <- Mandatory")

    ARGS = PARSER.parse_args()
    
    return_value = get_power_manager_settings(ARGS.ip, ARGS.username, ARGS.password)
    
    # Only if get_power_manager_settings returns success, the proceed to do set.
    if return_value == 1:
        get_inputs = input("Do you want to change any Power Manager settings (Y/N) : ")
        
        #Until user says No to change the settings
        while get_inputs in ('Y','y',''):
            
            #Get the respective settings enumeration dictionary basis user input i.e. setting ID.
            setting_id_input = input("Please enter Setting_ID : ")
            
            #Define the type basis the input given either in int or float. Error out if otherwise & continue
            if "." in setting_id_input:
                setting_id_input = float(setting_id_input)
            elif setting_id_input.isdigit():
                setting_id_input = int(setting_id_input)
            else:
                print("\n   !!! ERROR :: Wrong Setting's ID Entered !!! \n  Please provide proper setting's ID & try again\n")
                continue
            
            #if the setting ID provided doesn't exist, then error out & continue
            if settings_dictionary.get(setting_id_input) == None:
                print("\n   !!! ERROR :: Wrong Setting's ID Entered !!! \n  Please provide proper setting's ID & try again\n")
                continue
            else:
                define_dictionary = settings_dictionary[setting_id_input]
            
            #Display the supported values basis the user setting input for easy user choice of setting the value
            print("Supported key values: \n ")
            if setting_id_input != 51 or setting_id_input != 51.0:
                for key, value in define_dictionary.items():
                    print(" ",key, ' : ' ,value)
            else:
                print(define_dictionary)
            
            #Get the user input for setting value
            settings_value_inputs = input("\nPlease enter Setting_Value : ")
            
            #if the setting value provided is not an integer and doesn't exist in the dictionary, then error out & continue
            if not settings_value_inputs.isdigit():
                print("\n   !!! ERROR :: Wrong Setting's Value Entered !!! \n  Please provide proper setting's value & try again\n")
                continue
            else:
                settings_value_inputs = int(settings_value_inputs)
                if define_dictionary.get(settings_value_inputs) == None:
                    print("\n   !!! ERROR :: Wrong Setting's Value Entered !!! \n  Please provide proper setting's value & try again\n")
                    continue
            
            set_power_manager_settings(ARGS.ip, ARGS.username, ARGS.password, setting_id_input, settings_value_inputs)
            
            get_inputs = input("\nDo you want to change any other Power Manager settings (Y/N) : ")