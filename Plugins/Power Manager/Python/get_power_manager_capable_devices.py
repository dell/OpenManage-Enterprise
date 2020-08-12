#
#  Python script using OpenManage Enterprise API to get device list which are capable to be monitored/managed by Power Manager.
#
# _author_ = Mahendran P <Mahendran_P@Dell.com>
# _version_ = 0.2
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
   Script to get the list of devices from OpenManage Enterprise which are capable to be monitored/managed by Power Manager

DESCRIPTION:
   This script exercises the OpenManage Enterprise REST API to get a list of devices currently being managed by OpenManage Enterprise & capable to be monitored/managed by Power Manager.
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python Get_Power_Manager_Capable_Devices.py --ip <xx> --username <username> --password <pwd>
   
    Output:
    
       =====================================================
          Devices List with Power Manager capablilities
       =====================================================

      DEVICE_ID  SERVICE_TAG  MODEL            DEVICE_NAME              POWER_MANAGER_CAPABILITY

      10113      XXXXXXX      PowerEdge R640   WIN2K12356.BLR.net       Monitor + Management
      10106      XXXXXXX      PowerEdge R640   WINDOWS2019.BLR.net      Monitor only
      10105      XXXXXXX      PowerEdge R640   WINHIRTK12.BLR.net       Monitor + Management
      10111      XXXXXXX      PowerEdge R640   WINKKLLLL.BLR.net        Monitor only
      10109      XXXXXXX      PowerEdge R640   WIN2019SCALAB.BLR.net    Monitor + Management

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

# Funtion to parse the JSON content & store the data
def store_device_elem(device_content):
    
    column_data = []
    # For every elements in the Power Manager Devices response, store the details in the table
    for device_elem in device_content["value"]:
        
        # Check for Server type devices
        if device_elem["Type"] == 1000:
            
            #Check for all capabilities
            if(all(cap_bit in str(device_elem["DeviceCapabilities"]) for cap_bit in ['1006', '1105', '1101'])):
                device_data = [device_elem["Id"],device_elem["Identifier"],device_elem["Model"],device_elem["DeviceName"],"Monitor + Management"]
                column_data.append(device_data)
                
            #Check if only monitoring capable
            elif(all(cap_bit in str(device_elem["DeviceCapabilities"]) for cap_bit in ['1006', '1101'])):
                device_data = [device_elem["Id"],device_elem["Identifier"],device_elem["Model"],device_elem["DeviceName"],"Monitor only"]
                column_data.append(device_data)
                                
        # Check for Chassis type devices
        elif device_elem["Type"] == 2000:
                            
            #Check for all capabilities
            if(all(cap_bit in str(device_elem["DeviceCapabilities"]) for cap_bit in ['1105', '1101'])):
                device_data = [device_elem["Id"],device_elem["Identifier"],device_elem["Model"],device_elem["DeviceName"],"Monitor + Management"]
                column_data.append(device_data)
                            
            #Check if only monitoring capable
            elif(all(cap_bit in str(device_elem["DeviceCapabilities"]) for cap_bit in ['1101'])):
                device_data = [device_elem["Id"],device_elem["Identifier"],device_elem["Model"],device_elem["DeviceName"],"Monitor only"]
                column_data.append(device_data)
    
    return column_data


def get_power_manager_capable_devices(ip_address, user_name, password):
    """ Authenticate with OpenManage Enterprise, enumerate and filter power manager capabale devices"""
    try:
        
        #Define the Base URL, Session URL & headers
        base_uri = 'https://%s' %(ip_address)
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        
        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Define the device URL to get top 500 devices (considering scaled OpenManage Enterprise) & then get nextLink in the business logic below to further process the devices
        device_url = "https://%s/api/DeviceService/Devices?$top=500" % (ip_address)
        
        # Define OUTPUT header & data format
        output_column_headers = ['Device_ID', 'Service_Tag', 'Model', 'Device_Name', 'Power_Manager_Capability']
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
                    print("Unable to create a session with  %s. Please try again later" % (ip_address))
                else:
                    extended_error_content = error_content['@Message.ExtendedInfo']
                    print("Unable to create a session with  %s. See below ExtendedInfo for more information" % (ip_address))
                    print(extended_error_content[0]['Message'])
            else:
                print("Unable to create a session with  %s. Please try again later" % (ip_address))
        else:
            
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            
            #Get Devices API call with OpenManage Enterprise
            device_response = requests.get(device_url, headers=headers, verify=False)
            device_json_data = device_response.json()
            
            #If device API doesn't respond or failed, message the user with error
            if device_response.status_code != 201 & device_response.status_code != 200:
                
                if 'error' in device_json_data:
                    error_content = device_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve device list from %s" % (ip_address))
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print("Unable to retrieve device list from  %s. See below ExtendedInfo for more information" % (ip_address))
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve device list from %s" % (ip_address))
            else:
                
                # Get the device count from the JSON response data
                device_count = device_json_data['@odata.count']
                
                #If the device count is 0, then error out immediately
                if device_count <= 0:
                    print("No devices managed by %s" % (ip_address))
                
                #If the device count is not 0, then get the content & further process it to get device capabilities.
                else:
                    device_content = json.loads(device_response.content)
                    
                    #If there is no nextLink, then process the content to parse & store the capable Power Manager devices
                    if '@odata.nextLink' not in device_json_data:
                        output_column_data = store_device_elem(device_content)
                    
                    #Else if the next link exist, process to get, parse & store the capable Power Manager devices until the nextLink exhaust.
                    else:
                        
                        print("\n   !!! INFO :: There are more than 500 devices being managed in %s !!! \n  It may take several minutes to get the result. Please wait..." %(ip_address))
                        #Process the first set of Devices content to parse & store the capable Power Manager devices
                        output_column_data = store_device_elem(device_content)
                                                
                        #Define the nextLink URL
                        next_link_url = base_uri + device_json_data['@odata.nextLink']
                        
                        #Until nextLink exhaust
                        while next_link_url:
                            
                            #Get next set of Devices API call with OpenManage Enterprise
                            next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                            
                            if next_link_response.status_code != 200 & next_link_response.status_code != 201:
                                print("Unable to retrieve device list from nextLink %s" % (next_link_url))
                            else:
                                device_content = json.loads(next_link_response.content)
                                output_column_data += store_device_elem(device_content)
                                
                                next_link_json_data = next_link_response.json()
                                
                                if '@odata.nextLink' in next_link_json_data:
                                    next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                                else:
                                    next_link_url = None
                    
                    table = columnar(output_column_data, output_column_headers, no_borders=True)
                    print("\n   =====================================================")
                    print("      Devices List with Power Manager capablilities")
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
    
    get_power_manager_capable_devices(ARGS.ip, ARGS.username, ARGS.password)
