#
#  Python script using Power Manager API to get device or groups being monitored by Power Manager.
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
   Script to get devices or groups being monitored by Power Manager.

DESCRIPTION:
   This script exercises the Power Manager REST API to get devices or groups that being monitored by Power Manager.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_power_manager_monitoring_list.py --ip <xx> --username <username> --password <pwd>
   
    Output:

        ==============================================
            Devices being Monitored by Power Manager
        ==============================================

        DEVICE_ID  DEVICE_NAME              SERVICETAG  MODEL            IS_PART_OF_GROUP?  IS_POWER_POLICY_CAPABLE?

        10103      WINDOWS2012.BLR.net      XXXXXXX     PowerEdge R640   True               False
        10104      WINDWIW.BLR.net          YYYYYYY     PowerEdge R640   True               True
      
        ==============================================
            Groups being Monitored by Power Manager
        ==============================================

        GROUP_TYPE      GROUP_ID  GROUP_PARENT_ID  GROUP_NAME        DEVICES_IN_WORKING_SET

        PHYSICAL_GROUP  10489     10488            AISLE2            3
        STATIC_GROUP    10116     1021             G1_PMP1.0         5

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

#Define Group Type Dictionary
group_type_dictionary = {
    1:"STATIC_GROUP",
    2:"PHYSICAL_GROUP"}

# Funtion to parse the PMP device JSON content & store the data
def store_pmp_device_elem(pmp_device_content):
    
    device_column_data = []
    # For every elements in Power Manager monitored devices response, store the details in the table
    for pmp_device_elem in pmp_device_content["value"]:
        
        pmp_device_data = [pmp_device_elem["Id"],pmp_device_elem["DeviceName"],pmp_device_elem["ServiceTag"],pmp_device_elem["Model"],pmp_device_elem["IsPartOfGroup"],pmp_device_elem["PowerPolicyCapable"]]
        device_column_data.append(pmp_device_data)
    
    return device_column_data

# Funtion to parse the PMP device JSON content & store the data
def store_pmp_group_elem(pmp_group_content):
    
    group_column_data = []
    # For every elements in Power Manager monitored devices response, store the details in the table
    for pmp_group_elem in pmp_group_content["value"]:
        
        pmp_group_data = [group_type_dictionary[int(pmp_group_elem["Type"])], pmp_group_elem["Id"],pmp_group_elem["ParentId"],pmp_group_elem["Name"],pmp_group_elem["DevicesInWorkingSet"]]
        group_column_data.append(pmp_group_data)
    
    return group_column_data

def get_power_manager_monitoring_list(ip_address, user_name, password):
    """ Authenticate with OpenManage Enterprise, get power manager monitored devices"""
    try:
        #Define the Base URL, Session URL & headers
        base_uri = 'https://%s' %(ip_address)
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        
        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        #Define Power Manager Device & Group URL
        pmp_device_url = "https://%s/api/PowerService/MonitoredDevices?$top=500" % (ip_address)
        pmp_group_url = "https://%s/api/PowerService/MonitoredGroups?$top=100" % (ip_address)
        
        # Defining OUTPUT format
        device_output_column_headers = ['Device_ID', 'Device_Name', 'ServiceTag', 'Model', 'Is_Part_Of_Group?', 'Is_Power_Policy_Capable?']
        device_output_column_data = []
        group_output_column_headers = ['Group_Type', 'Group_ID', 'Group_Parent_ID', 'Group_Name', 'Devices_In_Working_Set']
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
                    print("Unable to create a session with  %s. Please try again later" % (ip_address))
                else:
                    extended_error_content = error_content['@Message.ExtendedInfo']
                    print("Unable to create a session with  %s. See below ExtendedInfo for more information" % (ip_address))
                    print(extended_error_content[0]['Message'])
            else:
                print("Unable to create a session with  %s. Please try again later" % (ip_address))
        else:
        
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            
            #Get Devices being monitored Power Manager API call with OpenManage Enterprise
            pmp_device_response = requests.get(pmp_device_url, headers=headers, verify=False)
            pmp_device_json_data = pmp_device_response.json()
            
            #If PMP Device API doesn't respond or failed, message the user with error
            if pmp_device_response.status_code != 201 & pmp_device_response.status_code != 200:
                
                if 'error' in pmp_device_json_data:
                    error_content = pmp_device_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager devices list from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager devices list from  %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager devices list from %s" % (ip_address))
            else:
            
                # Get the pmp device count from the JSON response data
                pmp_device_count = pmp_device_json_data['@odata.count']
                
                #If the pmp device count is 0, then error out immediately
                if pmp_device_count <= 0:
                    print("No Devices being monitored by Power Manager in %s" % (ip_address))
                
                #If the PMP device count is not 0, then get the content & further process it to get devices
                else:
                    pmp_device_content = json.loads(pmp_device_response.content)
                    
                    #If there is no nextLink, then process the content to parse & store the capable Power Manager devices
                    if '@odata.nextLink' not in pmp_device_json_data:
                        device_output_column_data = store_pmp_device_elem(pmp_device_content)
                    
                    #Else if the next link exist, process to get, parse & store the Power Manager devices until the nextLink exhaust.
                    else:
                        print("\n   !!! INFO :: There are more than 500 devices being monitored by Power Manager in %s !!! \n  It may take several minutes to get the result. Please wait..." %(ip_address))
                        
                        #Process the first set of Devices content to parse & store the capable Power Manager devices
                        device_output_column_data = store_pmp_device_elem(pmp_device_content)
                                                
                        #Define the nextLink URL
                        next_link_url = base_uri + pmp_device_json_data['@odata.nextLink']
                        
                        #Until nextLink exhaust
                        while next_link_url:
                            
                            #Get next set of Devices API call with OpenManage Enterprise
                            next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                            
                            if next_link_response.status_code != 200 & next_link_response.status_code != 201:
                                print("Unable to retrieve Power Manager devices list from nextLink %s" % (next_link_url))
                            else:
                                pmp_device_content = json.loads(next_link_response.content)
                                device_output_column_data += store_pmp_device_elem(pmp_device_content)
                                
                                next_link_json_data = next_link_response.json()
                                
                                if '@odata.nextLink' in next_link_json_data:
                                    next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                                else:
                                    next_link_url = None
                    
                    device_table = columnar(device_output_column_data, device_output_column_headers, no_borders=True)
                    print("\n   ==============================================")
                    print("      Devices being Monitored by Power Manager ")
                    print("   ==============================================")
                    print(device_table)
            
            #Get Groups being monitored Power Manager API call with OpenManage Enterprise
            pmp_group_response = requests.get(pmp_group_url, headers=headers, verify=False)
            pmp_group_json_data = pmp_group_response.json()
            
            #If PMP Group API doesn't respond or failed, message the user with error
            if pmp_group_response.status_code != 201 & pmp_group_response.status_code != 200:
                
                if 'error' in pmp_group_json_data:
                    error_content = pmp_group_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager groups list from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve Power Manager groups list from  %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager groups list from %s" % (ip_address))
            else:
                
                 #Get the PMP group count from the JSON response data
                pmp_group_count = pmp_group_json_data['@odata.count']
                
                #If PMP group count is 0, then error out immediately
                if pmp_group_count <= 0:
                    print("No Devices being monitored by Power Manager in %s" % (ip_address))
                
                #If PMP group count is not 0, then get the content & further process it to get device capabilities.
                else:
                    pmp_group_content = json.loads(pmp_group_response.content)
                    
                    #If there is no nextLink, then process the content to parse & store the capable Power Manager devices
                    if '@odata.nextLink' not in pmp_group_json_data:
                        group_output_column_data = store_pmp_group_elem(pmp_group_content)
                    
                    #Else if the next link exist, process to get, parse & store the capable Power Manager devices until the nextLink exhaust.
                    else:
                        
                        print("\n   !!! INFO :: There are more than 100 groups being managed by Power Manager in %s !!! \n  It may take several minutes to get the result. Please wait..." %(ip_address))
                        #Process the first set of Devices content to parse & store the capable Power Manager devices
                        group_output_column_data = store_pmp_group_elem(pmp_group_content)

                        #Define the nextLink URL
                        next_link_url = base_uri + pmp_group_json_data['@odata.nextLink']
                        
                        #Until nextLink exhaust
                        while next_link_url:
                            
                            #Get next set of Devices API call with OpenManage Enterprise
                            next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                            
                            if next_link_response.status_code != 200 & next_link_response.status_code != 201:
                                print("Unable to retrieve Power Manager groups list from nextLink %s" % (next_link_url))
                            else:
                                pmp_group_content = json.loads(next_link_response.content)
                                group_output_column_data += store_pmp_group_elem(pmp_group_content)
                                
                                next_link_json_data = next_link_response.json()
                                
                                if '@odata.nextLink' in next_link_json_data:
                                    next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                                else:
                                    next_link_url = None
                    
                    group_table = columnar(group_output_column_data, group_output_column_headers, no_borders=True)
                    print("\n   ==============================================")
                    print("      Groups being Monitored by Power Manager ")
                    print("   ==============================================")
                    print(group_table)
    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP <- Mandatory")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OpenManage Enterprise  <- Optional; default = admin", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise  <- Mandatory")

    ARGS = PARSER.parse_args()
    
    get_power_manager_monitoring_list(ARGS.ip, ARGS.username, ARGS.password)