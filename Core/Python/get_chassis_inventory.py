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
Script to get chassis inventory details in CSV format

#### Description
This script uses the OME REST API to get chassis inventory
in a CSV format for external consumption
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_chassis_inventory.py -i <ip addr> -u admin -p <password>`
"""
import argparse
import csv
import json
from argparse import RawTextHelpFormatter
from getpass import getpass

import requests
import urllib3


def authenticate_with_ome(ip_address, user_name, password):
    """ X-auth session creation """
    auth_success = False
    session_url = "https://%s/api/SessionService/Sessions" % ip_address
    user_details = {'UserName': user_name,
                    'Password': password,
                    'SessionType': 'API'}
    headers = {'content-type': 'application/json'}
    session_info = requests.post(session_url, verify=False,
                                 data=json.dumps(user_details),
                                 headers=headers)
    if session_info.status_code == 201:
        headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        auth_success = True
    else:
        error_msg = "*** ERROR: Failed create of session with {0} - Status code = {1}"
        print(error_msg.format(ip_address, session_info.status_code))
    return auth_success, headers


def write_output_csv_file(csv_data, csv_columns):
    csv_file = "chassis_inventory.csv"
    try:
        with open(csv_file, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns,
                                    lineterminator='\r')
            writer.writeheader()
            for chassis in csv_data:
                for data in csv_data[chassis]:
                    writer.writerow(data)
        print("Completed writing output to file chassis_inventory.csv")
    except IOError:
        print("I/O error.. Check if file is open in another app")
    except Exception as error:
        print("Unexpected error:", str(error))


def get_managed_device_count(ip_address, headers):
    try:
        count = 0
        count_url = "https://%s/api/DeviceService/Devices?$count=true&$top=0" % ip_address
        print("Determining number of managed devices ...")
        count_resp = requests.get(count_url, headers=headers,
                                  verify=False)
        if count_resp.status_code == 200:
            count_info = count_resp.json()
            count = int(count_info['@odata.count'])
            print("Total managed device count : %d" % count)
        else:
            print("*** ERROR: Unable to retrieve device count from %s" % ip_address)
    except Exception as error:
        print("Unexpected error:", str(error))
    return count


def parse_non_server_mac_addresses(device_info):
    device_mgmt_addresses = {}
    try:
        mgmt_info = device_info['DeviceManagement']
        if mgmt_info:
            mac_ctr = 1
            for mgmt_node in mgmt_info:
                if mgmt_node.get('MacAddress'):
                    curr_mac = "System_MAC_" + str(mac_ctr)
                    device_mgmt_addresses[curr_mac] = str(mgmt_node['MacAddress'])
                    mac_ctr = mac_ctr + 1
    except Exception as error:
        print("Unexpected error:", str(error))
    return device_mgmt_addresses


def parse_server_mac_addresses(device_info, ip_address, headers):
    device_mgmt_addresses = {}
    try:
        # Parse BMC Mac info
        print("Determining BMC MAC address information ...")
        mgmt_info = device_info['DeviceManagement']
        if mgmt_info:
            mac_ctr = 1
            for mgmt_node in mgmt_info:
                if mgmt_node.get('MacAddress'):
                    curr_mac = "BMC_MAC_" + str(mac_ctr)
                    device_mgmt_addresses[curr_mac] = str(mgmt_node['MacAddress'])
                    break

        device_id = device_info['Id']
        device_url = "https://%s/api/DeviceService/Devices" % ip_address
        device_inven_url = device_url + "(" + str(device_id) + ")/InventoryDetails('serverNetworkInterfaces')"
        device_inventory_dets = requests.get(device_inven_url, headers=headers,
                                             verify=False)
        if device_inventory_dets.status_code == 200:
            device_inventory_info = device_inventory_dets.json()
            if len(device_inventory_info['InventoryInfo']) > 0:
                for nic_info in device_inventory_info['InventoryInfo']:
                    mac_ctr = 1
                    for nic_data in nic_info['Ports']:
                        curr_mac = "System_MAC_" + str(mac_ctr)
                        full_prod_name = str(nic_data['ProductName'])
                        print("Analyzing %s" % full_prod_name)
                        if "-" in full_prod_name:
                            product_name, mac_addr = full_prod_name.rsplit('-', 1)
                            device_mgmt_addresses[curr_mac] = mac_addr
                            mac_ctr = mac_ctr + 1
                        else:
                            for nic_partitions in nic_data['Partitions']:
                                if nic_partitions.get('CurrentMacAddress'):
                                    mac_addr = nic_partitions['CurrentMacAddress']
                                    device_mgmt_addresses[curr_mac] = mac_addr
                                    mac_ctr = mac_ctr + 1
            else:
                print("*** ERROR: No network inventory info returned for %s" % (device_info['DeviceServiceTag']))
        else:
            print("*** WARN: No network inventory info returned for %s" % (device_info['DeviceServiceTag']))
    except Exception as error:
        print("Unexpected error:", str(error))
    return device_mgmt_addresses


def get_device_inventory(ip_address, headers):
    try:
        # Fields requested by customer
        csv_columns = ['Hostname', 'Unit', 'SerialNumber', 'System_MAC_1',
                       'System_MAC_2', 'System_MAC_3', 'System_MAC_4',
                       'System_MAC_5', 'System_MAC_6', 'System_MAC_7',
                       'System_MAC_8', 'BMC_MAC_1', 'Chassis',
                       'Chassis_Location', 'Model']
        # customer nomenclature
        unit_map = {1000: 'System', 2000: 'Chassis',
                    3000: 'Storage', 4000: 'Switch',
                    8000: 'Storage-IOM'}

        csv_data = {}
        device_url = "https://%s/api/DeviceService/Devices" % ip_address
        device_count = get_managed_device_count(ip_address, headers)
        if device_count > 0:
            all_device_url = device_url + "?$skip=0&$top=" + str(device_count)
            print("Enumerating all device info ...")
            all_device_resp = requests.get(all_device_url, headers=headers,
                                           verify=False)
            if all_device_resp.status_code == 200:
                all_device_info = all_device_resp.json()
                print("Iterating through devices and correlating data ...")

                for device_info in all_device_info['value']:
                    device_id = device_info['Id']
                    device_type = device_info['Type']
                    device_unit_name = None
                    if unit_map.get(device_type):
                        device_unit_name = unit_map[device_type]
                    device_model = None
                    if device_info['Model']:
                        device_model = str(device_info['Model'])
                    device_svc_tag = None
                    if device_info['DeviceServiceTag']:
                        device_svc_tag = str(device_info['DeviceServiceTag'])
                    device_hostname = None
                    if device_info['DeviceName']:
                        device_hostname = str(device_info['DeviceName'])
                    print("Processing ID: %d,Type:%s,Model:%s,SvcTag:%s,Host:%s" % (device_id,
                                                                                    device_unit_name,
                                                                                    device_model,
                                                                                    device_svc_tag,
                                                                                    device_hostname))

                    # Assemble device dictionary info
                    temp_hash = {'Model': device_model, 'SerialNumber': device_svc_tag, 'Hostname': device_hostname,
                                 'Unit': device_unit_name}

                    if device_unit_name:
                        if device_unit_name == "Chassis":
                            if device_svc_tag:
                                if not csv_data.get(device_svc_tag):
                                    # print("Creating new chassis entry with svc tag %s" %(device_svc_tag))
                                    csv_data[device_svc_tag] = []
                            else:
                                print("*** WARNING: Chassis service tag is NULL...")

                            mac_addrs = parse_non_server_mac_addresses(device_info)

                            for mac_addr in mac_addrs.keys():
                                temp_hash[mac_addr] = mac_addrs[mac_addr]

                            csv_data[device_svc_tag].append(temp_hash)
                        else:
                            chassis_svc_tag = None
                            if device_info['ChassisServiceTag']:
                                chassis_svc_tag = str(device_info['ChassisServiceTag'])
                            else:
                                print("Warning...Chassis service tag is Null")
                            temp_hash['Chassis'] = chassis_svc_tag

                            if device_info.get('SlotConfiguration'):
                                if device_info['SlotConfiguration'].get('SlotName'):
                                    temp_hash['Chassis_Location'] = str(device_info['SlotConfiguration']['SlotName'])
                            else:
                                print("*** WARNING: No slot configuration information available ")

                            if device_unit_name != "System":
                                mac_addrs = parse_non_server_mac_addresses(device_info)
                            else:
                                mac_addrs = parse_server_mac_addresses(device_info, ip_address, headers)

                            for mac_addr in mac_addrs.keys():
                                temp_hash[mac_addr] = mac_addrs[mac_addr]

                            if chassis_svc_tag:
                                if not csv_data.get(chassis_svc_tag):
                                    # print("Creating new chassis entry with svc tag %s" %(chassis_svc_tag))
                                    csv_data[chassis_svc_tag] = []

                                csv_data[chassis_svc_tag].append(temp_hash)
                            else:
                                print("*** WARNING: Unable to add (%d,%s) - chassis_svc_tag is NULL" % (
                                    device_id, device_svc_tag))
                    else:
                        print("*** ERROR: Unable to find a mapping for device in unit map")

                # print csv_data
                if csv_data:
                    write_output_csv_file(csv_data, csv_columns)
            else:
                print("*** ERROR: Unable to retrieve all device info from %s .. Exiting" % ip_address)
        else:
            print("*** ERROR: No devices retrieved from %s" % ip_address)
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
    args = parser.parse_args()
    ip_address = args.ip
    user_name = args.user
    if args.password:
        password = args.password
    else:
        password = getpass()

    try:
        auth_success, headers = authenticate_with_ome(ip_address, user_name,
                                                      password)
        if auth_success:
            get_device_inventory(ip_address, headers)
        else:
            print("*** ERROR: Unable to authenticate with endpoint .. Check IP/Username/Pwd")
    except Exception as error:
        print("Unexpected error:", str(error))
