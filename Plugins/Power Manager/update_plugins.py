#
#  Python script using OME API to get or update Plugin details & actions respectively.
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
   Script to get or update Plugin details & actions respectively on OME appliance

DESCRIPTION:
   This script exercises the OME REST API to get & update Plugin details & actions respectively.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_update_plugins.py --ip <xx> --username <username> --password <pwd>

"""

import sys
import argparse
from argparse import RawTextHelpFormatter
import json
import requests
import urllib3
from columnar import columnar
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_plugin_details(ip_address, user_name, password):
    """ Authenticate with OME, get plugin details"""
    try:
        # Deinfing OUTPUT format
        output_column_headers = ['Plugin_ID', 'Plugin_Name', 'Is_Installed?', 'Is_Enabled?', 'Is_Downloaded?', "Installed_Version", "Is_Update_Available", "Installed_Date", "Last_Updated_Date", "Last_Disabled_Date"]
        output_column_data = []
        
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Defining Plugins URL
        plugin_url = "https://%s/api/PluginService/Plugins" % (ip_address)
        
        # Create the session with OME
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201 or session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            
            #Get Plugins API call with OME
            plugin_response = requests.get(plugin_url, headers=headers, verify=False)
            if plugin_response.status_code == 201 or plugin_response.status_code == 200:
                plugin_content = json.loads(plugin_response.content)
                
                # For every elements in the Plugins response, store the details in the table
                for plugin_elem in plugin_content["value"]:
                    
                    if "Downloaded" not in plugin_elem:
                        Is_Downloaded = "NULL"
                    else:
                        Is_Downloaded = plugin_elem["Downloaded"]
                    
                    plugin_data = [plugin_elem["Id"], plugin_elem["Name"], plugin_elem["Installed"], plugin_elem["Enabled"], Is_Downloaded, plugin_elem["CurrentVersion"], plugin_elem["UpdateAvailable"], plugin_elem["InstalledDate"], plugin_elem["LastUpdatedDate"], plugin_elem["LastDisabledDate"] ]
                    output_column_data.append(plugin_data)
                    
                table = columnar(output_column_data, output_column_headers, no_borders=True)
                print("\n   ====================================")
                print("      List of Available Plugins  ")
                print("   ====================================")
                print(table)
                return 1
            else:
                print("Unable to retrieve Available Plugins Details. Please try again later")
                return 0
        else:
            print("[get_plugin_details]: Unable to create a session with appliance %s, please check connectivity, UserName/Password" % (ip_address))
            return 0
    except:
        print ("[get_plugin_details]: Unexpected error:", sys.exc_info()[0])
        return 0

def update_console_plugin(ip_address, user_name, password, plugin_id, plugin_action):
    """ Authenticate with OME, update console plugin"""
    try:
        
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        
        # Defining Console Plugin Update URL
        plugin_action_url = "https://%s/api/PluginService/Actions/PluginService.UpdateConsolePlugins" % (ip_address)
        
        # if the plugin action is install/update, then requires pre-req check about the OME compatibility & plugin available version
        if plugin_action == "Install" or plugin_action == "Update":
            #Define & call the console info URL to get current ome version
            console_info_url = "https://%s//api/ApplicationService/Info" % (ip_address)
            console_info_response = requests.get(console_info_url, headers=headers, verify=False)
            console_info_content = json.loads(console_info_response.content)
            console_ome_version = console_info_content["Version"]
            
            #Define the URL to get the plugin available version's supported minimum OME version
            plugin_availability_url = "https://%s/api/PluginService/Plugins('%s')/AvailableVersionDetails" % (ip_address,plugin_id)
            plugin_availability_response = requests.get(plugin_availability_url, headers=headers, verify=False)
            plugin_availability_content = json.loads(plugin_availability_response.content)
            
            if plugin_availability_content["@odata.count"] == 1:
                minimum_ome_version = plugin_availability_content["value"][0]["MinimumOmeVersionRequired"]
                plugin_version = plugin_availability_content["value"][0]["Version"]
                #if the minimum ome version is not compatible with the current console ome version, then message
                if minimum_ome_version < console_ome_version and minimum_ome_version != console_ome_version:
                    print("Current plugin available version is not compatible with OME console version")
                else:
                    plugin_action_payload = {"Plugins":[{"Id": plugin_id, "Version": plugin_version, "Action": plugin_action}]}
            elif plugin_availability_content["@odata.count"] == 2:
                if plugin_availability_content["value"][0]["Version"] > plugin_availability_content["value"][1]["Version"]:
                    plugin_version = plugin_availability_content["value"][0]["Version"]
                    minimum_ome_version = plugin_availability_content["value"][0]["MinimumOmeVersionRequired"]
                    if minimum_ome_version < console_ome_version and minimum_ome_version != console_ome_version:
                        print("Current plugin available version is not compatible with OME console version")
                    else:
                        plugin_action_payload = {"Plugins":[{"Id": plugin_id, "Version": plugin_version, "Action": plugin_action}]}
        else:
            plugin_action_payload = {"Plugins":[{"Id": plugin_id, "Action": settings_value}]}
        
        # Create the session with OME
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201 or session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            
            #Console Plugin update API call with OME
            plugin_action_response = requests.post(plugin_action_url, data=json.dumps(plugin_action_payload), headers=headers, verify=False)
            
            if plugin_action_response.status_code == 201 or plugin_action_response.status_code == 200:
                print("Plugin Action - %s has been triggered. It may take 10-15 mins. Please check the status some time later" %(plugin_action))
            else:
                print("Unable to do Console Plugin update. Please try again later")
        else:
            print("[update_console_plugin]: Unable to create a session with appliance %s, please check connectivity, UserName/Password" % (ip_address))
    except:
        print ("[update_console_plugin]: Unexpected error:", sys.exc_info()[0])
        return 0

def plugin_states(ip_address, user_name, password, plugin_id):
    ''' Get the plugin states'''
    try:
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                            'Password': password,
                            'SessionType': 'API'}
        # Defining Plugin details URL
        plugin_url = "https://%s/api/PluginService/Plugins('%s')" % (ip_address, plugin_id)
        
        # Create the session with OME
        session_info = requests.post(session_url, verify=False,
                                         data=json.dumps(user_details),
                                         headers=headers)
        if session_info.status_code == 201 or session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            
            #Get Plugin details API call with OME
            plugin_response = requests.get(plugin_url, headers=headers, verify=False)
            if plugin_response.status_code == 201 or plugin_response.status_code == 200:
                plugin_content = json.loads(plugin_response.content)
                return plugin_content["Installed"], plugin_content["Enabled"], plugin_content["UpdateAvailable"]
            else:
                print("Unable to retrieve Plugin specific states details. Please try again later")
        else:
            print("[plugin_states]: Unable to create a session with appliance %s, please check connectivity, UserName/Password" % (ip_address))
    except:
        print ("[plugin_states]: Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP <- Mandatory")
    PARSER.add_argument("--username", "-u", required=False, help="Username for OME Appliance <- Optional; default = admin", default="admin")
    PARSER.add_argument("--password", "-p", required=True, help="Password for OME Appliance <- Mandatory")

    ARGS = PARSER.parse_args()
    
    return_value = get_plugin_details(ARGS.ip, ARGS.username, ARGS.password)
    
    # Only if get_plugin_details returns success, then proceed to do set.
    if return_value is 1:
        get_inputs = input("Do you want to do plugin action - Install/Uninstall/Enable/Disable/Update (Yes/No) : ")
        
        #Until user says NO to do any actions on plugin
        while get_inputs not in ('NO','No','N','n'):
            
            #Get the plugin ID as user input.
            plugin_ID_input = input("Please enter plugin_ID : ")
            
            #get plugin current states
            is_installed, is_enabled, is_UpdateAvailable = plugin_states(ARGS.ip, ARGS.username, ARGS.password,plugin_ID_input)
                        
            if None not in (is_installed, is_enabled, is_UpdateAvailable):
                print("\nSupported plugin actions: \n ")
                if(is_installed == True and is_enabled == True and is_UpdateAvailable == True):
                    print("     Disable/Uninstall/Update <- the current installed version")
                elif (is_installed == True and is_enabled == True and is_UpdateAvailable == False):
                    print("     Disable/Uninstall <- the current installed version")
                elif (is_installed == True and is_enabled == False and is_UpdateAvailable == True):
                    print("     Enable/Uninstall/Update <- the current installed version")
                elif (is_installed == True and is_enabled == False and is_UpdateAvailable == False):
                    print("     Disable/Uninstall <- the current installed version")
                elif (is_installed == False):
                    print("     Install <- the latest available + compatible version")
                
                #Get the input from user for plugin actione
                plugin_action_input = input("\nPlease enter Plugin action : ")
                
                update_console_plugin(ARGS.ip, ARGS.username, ARGS.password, plugin_ID_input, plugin_action_input)
                
            else:
                continue
            
            get_inputs = input("\nDo you want to do plugin action - Install/Uninstall/Enable/Disable/Update (Yes/No) : ")