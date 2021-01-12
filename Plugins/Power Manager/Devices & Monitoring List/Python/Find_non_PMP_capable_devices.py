#
# Python script using OME-M APIs to create an MCM group,
#  assign a backup lead and add all possible members to the
#  created group
#
# Copyright (c) 2021 Dell EMC Corporation
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
 Script to Find devices which are not capable for power policy, 
 including servers which are not capable for power monitoring too.

Description: 
 This script gets all devices where a power policy cannot be applied 
 from power manager.
 Note:
 1. Credentials entered are not stored to disk.
 2. For a large number of devices ,time taken for script to finish might 
 increase ,also depending on network speed.
 (upto 6-7 minutes for 8000 devices at 100Mbps network )
 3. This script doesn't need OMEnt-Power manager to be already installed 
 on the OMEnt and works with or without OMEnt-Power manager
 4:User executing the script should have privilege to cerate a new file 
 in the path where script is located.

Example:
python Find_non_Power_policy_capable_devices.py --ip <ip addr> --user root
    --password <passwd> 
Finds all non-policy power capable  devices
API workflow is below:
1: POST on SessionService/Sessions
2: If new session is created (201) parse headers
   for x-auth token and update headers with token
3: All subsequent requests use X-auth token and not
   user name and password entered by user
4: From All devices list fetch for the servers not having 1006 (monitoring capability)
devicecapability bit set.
5:For Chassis type devices do not check anything as chassis are always monitoring 
and do not have 1006 in devicecapabilities
5.Print all such devices(deviceId and ServiceTag) into a csv file 
Non_compatible_devices.csv

"""

import json
import sys
import argparse
from argparse import RawTextHelpFormatter
import urllib3
import requests
import requests
import json
import csv
from requests.auth import HTTPBasicAuth
import threading
import time
import os
import pickle
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_non_capable_devices(ip_address, user_name, password):
    """ Authenticate with OME and enumerate groups """
    try:
        AllDeviceIDs=[]
        session_url = 'https://%s/api/SessionService/Sessions' % ip_address
        dev_url = "https://%s/api/DeviceService/Devices?$top=8000" % ip_address
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}

        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201 or session_info.status_code == 200:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            response2 = requests.get(dev_url, headers=headers, verify=False)
            if response2.status_code == (200 or 201):
                json_obj1 = json.loads(response2.content)
                for ele in json_obj1["value"]:
                	AllDeviceIDs.append(ele["Id"])
                with open('Non_compatible_devices.csv', 'w', newline='') as file:
                	writer = csv. writer(file,)
                	writer. writerow(["DeviceID","Service Tag"])
                	for i in range(0,len(AllDeviceIDs)):
                		if "1006" not in str(json_obj1['value'][i]["DeviceCapabilities"]) and json_obj1['value'][i]["Type"]!= 2000:
                			writer. writerow([json_obj1['value'][i]["Id"],json_obj1['value'][i]["DeviceServiceTag"]])
    except Exception as error:
        print("Unexpected error:", str(error))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=True,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    args = parser.parse_args()
    get_non_capable_devices(args.ip, args.user, args.password)