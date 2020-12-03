#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
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
#### Synopsis
Script to get the device inventory details

#### Description
This script uses the OME REST API to get detailed inventory
for a device given ID/Name/Service Tag
and Inventory type (os,cpus,disks,memory,controllers) of the device
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_device_inventory.py -i <ip addr> -u admin
    -p <password> -fby Name -f "iDRAC-abcdef" -invtype os`
"""
import argparse
import json
from argparse import RawTextHelpFormatter
from getpass import getpass

import requests
import urllib3


def get_device_inventory(ip_address, user_name, password, filter_by, field, inventory_type):
    """ Get inventory details for a device based on filters """
    filter_map = {'Name': 'DeviceName',
                  'Id': 'Id',
                  'SvcTag': 'DeviceServiceTag'}
    inventory_types = {
        "cpus": "serverProcessors",
        "os": "serverOperatingSystems",
        "disks": "serverArrayDisks",
        "controllers": "serverRaidControllers",
        "memory": "serverMemoryDevices"}

    try:

        session_url = 'https://%s/api/SessionService/Sessions' % ip_address
        base_url = "https://%s/api/DeviceService/Devices?$filter=%s eq" % (ip_address, filter_map[filter_by])
        if filter_by == 'Id':
            device_url = "%s %s" % (base_url, field)
        else:
            device_url = "%s '%s'" % (base_url, field)
        headers = {'content-type': 'application/json'}

        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            response = requests.get(device_url, headers=headers, verify=False)
            if response.status_code == 200:
                json_data = response.json()
                if json_data['@odata.count'] > 1:
                    print("WARNING: Filter returned more than one result. Ignore all results except the first.")
                if json_data['@odata.count'] > 0:
                    device_id = json_data['value'][0]['Id']
                    inventory_url = "https://%s/api/DeviceService/Devices(%s)/InventoryDetails" % (
                        ip_address, device_id)
                    if inventory_type:
                        inventory_url = "https://%s/api/DeviceService/Devices(%s)/InventoryDetails(\'%s\')" % \
                                        (ip_address, device_id, inventory_types[inventory_type])
                    inven_resp = requests.get(inventory_url, headers=headers,
                                              verify=False)
                    if inven_resp.status_code == 200:
                        print("\n*** Inventory for device (%s) ***" % field)
                        print(json.dumps(inven_resp.json(), indent=4,
                                         sort_keys=True))
                    elif inven_resp.status_code == 400:
                        print("Inventory type %s not applicable for device with Id %s" % (inventory_type, device_id))
                    else:
                        print("Unable to retrieve inventory for device %s due to status code %s" %
                              (device_id, inven_resp.status_code))
                else:
                    print("Unable to retrieve details for device (%s) from %s" % (field, ip_address))
            else:
                print("No device data retrieved from %s" % ip_address)
        else:
            print("Unable to create a session with appliance %s" % ip_address)
    except Exception as error:
        print("Unexpected error:", str(error))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=True,
                        help="Username for OME Appliance",
                        default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--filterby", "-fby", required=True,
                        choices=('Id', 'Name', 'SvcTag'),
                        help="Filter by id/name/service tag")
    parser.add_argument("--field", "-f", required=True,
                        help="Field to filter by (id/name/svc tag)")
    parser.add_argument("--inventorytype", "-invtype", required=False,
                        choices=('cpus', 'os', 'disks', 'controllers', 'memory'),
                        help="Get inventory by cpus/os/disks/controllers,memory")
    args = parser.parse_args()
    if not args.password:
        args.password = getpass()

    get_device_inventory(args.ip, args.user, args.password,
                         args.filterby, str(args.field), args.inventorytype)
