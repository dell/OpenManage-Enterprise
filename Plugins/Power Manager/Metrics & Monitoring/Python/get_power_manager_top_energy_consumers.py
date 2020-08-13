#
#  Python script using OpenManage Enterprise API to get top 5 energy consuming Server/Chassis/Group being monitored by Power Manager.
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
   Script to get the list of top 5 energy consuming (KWH) Server/Chassis/Group being monitored by Power Manager

DESCRIPTION:
   This script exercises the OpenManage Enterprise REST API to get the list of top 5 energy consuming Server/Chassis/Group (in KWH) being monitored by Power Manager
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_power_manager_top_energy_consumers.py --ip <xx> --username <username> --password <pwd>
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

#Top energy consumer dictionary to display the output for better reading
top_energy_consumer_dictionary = {
    1:"Server",
    2:"Chassis",
    3:"Group"}

#Duration dictionary to display the output for better reading
duration_dictionary = {
    4:"1 Day",
    5:"1 Week",
    6:"2 Weeks",
    7:"1 Month",
    8:"3 Months",
    9:"6 Months",
    10:"1 Year"}

def entity_type_definition(ent_input):

    entity_switch = {
        'Group':(1,1000),
        'Server':(0,1000),
        'Chassis':(0,2000)
    }
    
    return entity_switch.get(ent_input,"Empty")

def get_power_manager_top_energy_consumers(ip_address, user_name, password, entity, duration):
    """ Authenticate with OpenManage Enterprise, enumerate top energy consumers"""
    try:
        
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Define the power manager top energy consumer URL
        top_energy_consumer_url = "https://%s/api/MetricService/TopEnergyConsumption" % (ip_address)
        
        #Get entity & device type basis user input
        entity_type, device_type = entity_type_definition(entity)
        
        # Define Payload for posting top energy consumer API
        top_energy_consumer_payload = {
            "PluginId": "2F6D05BE-EE4B-4B0E-B873-C8D2F64A4625",
            "Top": 5,
            "EntityType": entity_type,
            "DeviceType": device_type,
            "Duration": duration}
        
        # Defining OUTPUT format    
        output_column_headers = ['Id', 'Name', 'Value (in KWH)']
        top_energy_consumer_output_column_data = []
        
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
            
            #Get top energy consumer API call with OpenManage Enterprise
            top_energy_consumer_response = requests.post(top_energy_consumer_url, data=json.dumps(top_energy_consumer_payload), headers=headers, verify=False)
            top_energy_consumer_json_data = top_energy_consumer_response.json()
            
            #If Top energy consumer API doesn't respond or failed, message the user with error
            if top_energy_consumer_response.status_code != 201 & top_energy_consumer_response.status_code != 200:
                if 'error' in top_energy_consumer_json_data:
                    error_content = top_energy_consumer_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager - top energy consuming %s in %s" % (entity,ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager - top energy consuming %s in %s. See below ExtendedInfo for more information" % (entity,ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager - top energy consuming %s in %s" % (entity,ip_address))
            else:
            
                top_energy_consumer_content = json.loads(top_energy_consumer_response.content)
                
                if 'Value' not in top_energy_consumer_content:
                    print("No Power Manager - top energy consuming %s in %s" % (entity,ip_address))
                else:
                    # For every elements in the Power Manager Metrics Alerts response, store the details in the table
                    for top_energy_consumer_elem in top_energy_consumer_content["Value"]:
                        
                        top_energy_consumer_data = [top_energy_consumer_elem["Id"], top_energy_consumer_elem["Name"], top_energy_consumer_elem["Value"]]
                        top_energy_consumer_output_column_data.append(top_energy_consumer_data)
                        
                    table = columnar(top_energy_consumer_output_column_data, output_column_headers, no_borders=True)
                    print("\n   =====================================================")
                    print("      Power Manager - Top energy consuming %s " % (entity))
                    print("   =====================================================")
                    print(table)
    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OpenManage Enterprise ", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise ")
    ARGS = PARSER.parse_args()
    
    get_inputs = 'Y'
    
    #Until user says NO to get top energy consumers
    while get_inputs in ('Y','y',''):
        
        #Get the top energy consumers choice
        entity_inputs = input("Enter the choice of Top Energy Consumer - 1 - Server / 2 - Chassis / 3 - Group : ")
        
        if not entity_inputs.isdigit():
            print("\n *** ERROR: Wrong Value Entered!!! Please enter proper value for Top Energy Consumer\n")
            continue
        else:
            entity_inputs = top_energy_consumer_dictionary.get(int(entity_inputs))
            if entity_inputs == None:
                print("\n *** ERROR: Wrong Value Entered!!! Please enter proper value for Top Energy Consumer\n")
                continue
            
        print("Supported durations: \n ")
        for key, value in duration_dictionary.items():
            print(" ",key, ' : ' ,value)
            
        #Get the input from user for duration value
        duration_inputs = input("\nPlease enter duration value : ")
            
        if not duration_inputs.isdigit():
            print("\n *** ERROR: Wrong Value Entered!!! Please enter proper value for Top Energy Consumer\n")
            continue
        else:
            dict_data_duration_inputs = duration_dictionary.get(int(duration_inputs))
            if dict_data_duration_inputs == None:
                print("\n *** ERROR: Wrong Value Entered!!! Please enter proper value for Top Energy Consumer\n")
                continue
        
        get_power_manager_top_energy_consumers(ARGS.ip, ARGS.username, ARGS.password, entity_inputs, int(duration_inputs))
        
        get_inputs = input("\nDo you want to continue getting other top energy consumer (Y/N) : ")