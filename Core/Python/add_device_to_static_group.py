#
#  Python script using OME API to create a new static group
#
# _author_ = Grant Curell <grant_curell@dell.com>
# _version_ = 0.1
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
   Add one or more hosts to an existing static group.

DESCRIPTION:
   This script exercises the OME REST API to add one or more
   hosts to an existing static group. For authentication X-Auth
   is used over Basic Authentication. Note: The credentials entered
   are not stored to disk.

EXAMPLE:
   python add_device_to_static_group.py --ip <xx> --user <username>
        --password <pwd> --groupname "Random Test Group" --devicenames "cmc1,host3,192.168.1.5"
"""

import json
import argparse
from argparse import RawTextHelpFormatter
import urllib3
import requests


def get_device_list(ome_ip_address: str, headers: dict) -> dict:
    """
    Retrieves a list of all devices being handled by this OME server

    Args:
        ome_ip_address: The IP address of the OME server
        headers: Headers used for authentication to the OME server

    Returns: A list of all devices managed by the this OME server

    """

    print("Retrieving a list of all devices...")
    next_link_url = "https://%s/api/DeviceService/Devices" % ome_ip_address
    device_data = None

    while next_link_url is not None:
        device_response = requests.get(next_link_url, headers=headers, verify=False)
        next_link_url = None
        if device_response.status_code == 200:
            data = device_response.json()
            if data['@odata.count'] <= 0:
                print("No devices are managed by OME server: " + ome_ip_address + ". Exiting.")
                return {}
            if '@odata.nextLink' in data:
                next_link_url = "https://%s" + data['@odata.nextLink']
            if device_data is None:
                device_data = data["value"]
            else:
                device_data += data["value"]
        else:
            print("Unable to retrieve device list from %s" % ome_ip_address)
            return {}

    # Create id - service tag index to avoid O(n) lookups on each search
    # This is relevant when operating on hundreds of devices
    id_service_tag_dict = {}
    for device in device_data:
        id_service_tag_dict[device["DeviceServiceTag"]] = device["Id"]

    return id_service_tag_dict


def get_group_id_by_name(ome_ip_address: str, group_name: str, headers: dict) -> int:
    """
    Retrieves the ID of a group given its name.

    Args:
        ome_ip_address: The IP address of the OME server
        group_name: The name of the group whose ID you want to resolve.
        headers: Headers used for authentication to the OME server

    Returns: Returns the ID of the group as an integer.

    """

    print("Searching for the requested group.")
    groups_url = "https://%s/api/GroupService/Groups?$filter=Name eq '%s'" % (ome_ip_address, group_name)

    group_response = requests.get(groups_url, headers=headers, verify=False)

    if group_response.status_code == 200:
        json_data = json.loads(group_response.content)

        if json_data['@odata.count'] > 1:
            print("WARNING: We found more than one name that matched the group name: " + group_name +
                  ". We are picking the first entry.")
        if json_data['@odata.count'] == 1 or json_data['@odata.count'] > 1:
            group_id = json_data['value'][0]['Id']
            if not isinstance(group_id, int):
                print("The server did not return an integer ID. Something went wrong.")
                return -1
            return group_id
        else:
            print("Error: We could not find the group " + group_name + ". Exiting.")
            return -1
    else:
        print("Unable to retrieve groups. Exiting.")
        return -1


def get_device_id_by_name(ome_ip_address: str, device_name: str, headers: dict) -> int:
    """
    Resolves the name of a server to an OME ID

    Args:
        ome_ip_address: IP address of the OME server
        device_name: Name of the device whose ID you want to resolve
        headers: Headers used for authentication to the OME server

    Returns:
        The ID of the server or 0 if it couldn't find it
    """

    url = "https://%s/api/DeviceService/Devices?$filter=DeviceName eq \'%s\'" % (ome_ip_address, device_name)

    response = requests.get(url, headers=headers, verify=False)
    print("Getting the device ID for system with name " + device_name + "...")

    if response.status_code == 200:
        json_data = response.json()

        if json_data['@odata.count'] > 1:
            print("WARNING: We found more than one name that matched the device name: " + device_name +
                  ". We are skipping this entry.")
        elif json_data['@odata.count'] == 1:
            server_id = json_data['value'][0]['Id']
            if not isinstance(server_id, int):
                print("The server did not return an integer ID. Something went wrong.")
                return -1
            return server_id
        else:
            print("WARNING: No results returned for device ID look up for name " + device_name + ". Skipping it.")
            return 0
    else:
        print("Connection failed with response code " + str(response.status_code) + " while we were retrieving a "
              "device ID from the server.")
        return -1


def add_device_to_static_group(ome_ip_address: str, ome_username: str, ome_password: str, group_name: str,
                               device_names: list = None, device_tags: list = None):
    """
    Adds a device to an existing static group

    Args:
        ome_ip_address: IP address of the OME server
        ome_username:  Username for OME
        ome_password: OME password
        group_name: The group name to which you want to add servers
        device_names: A list of device names which you want added to the group
        device_tags: A list of device service tags which you want added to the group

    """

    try:
        session_url = 'https://%s/api/SessionService/Sessions' % ome_ip_address
        group_add_device_url = "https://%s/api/GroupService/Actions/GroupService.AddMemberDevices" % ome_ip_address
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': ome_username,
                        'Password': ome_password,
                        'SessionType': 'API'}

        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == 201:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']

            group_id = get_group_id_by_name(ome_ip_address, group_name, headers)

            if group_id == -1:
                exit(1)

            device_ids = []
            if device_names:
                for device in device_names:
                    device_id = get_device_id_by_name(ome_ip_address, device, headers)
                    if device_id > 0:
                        device_ids.append(device_id)
                    elif device_id == -1:
                        exit(1)
            elif device_tags:
                id_service_tag_dict = get_device_list(ome_ip_address, headers)

                if len(id_service_tag_dict) == 0:
                    exit(1)

                # Check for each service tag in our index
                for device_tag in device_tags:
                    if device_tag in id_service_tag_dict:
                        device_ids.append(id_service_tag_dict[device_tag])
                    else:
                        print("WARNING: Could not find the service tag " + device_tag + ". Skipping.")

            if len(device_ids) > 0:
                # Add devices to the group
                payload = {
                    "GroupId": group_id,
                    "MemberDeviceIds": device_ids
                }
                create_resp = requests.post(group_add_device_url, headers=headers,
                                            verify=False, data=json.dumps(payload))
                if create_resp.status_code == 200 or create_resp.status_code == 204:
                    if create_resp.text != "":
                        print("Finished adding devices to group. Response returned was: ", create_resp.text)
                    else:
                        print("Finished adding devices to group.")
                elif create_resp.status_code == 400 \
                        and "Unable to update group members because the entered ID(s)" in \
                        json.loads(create_resp.content)["error"]["@Message.ExtendedInfo"][0]["Message"]:
                    print("The IDs " +
                          str(json.loads(create_resp.content)["error"]["@Message.ExtendedInfo"][0]["MessageArgs"]) +
                          " were invalid. This usually means the servers were already in the requested group.")
                elif create_resp.status_code == 400:
                    print("Device add failed. Error:")
                    print(json.dumps(create_resp.json(), indent=4, sort_keys=False))
                else:
                    print("Unknown error occurred. Received HTTP response code: " + str(create_resp.status_code) +
                          " with error: " + create_resp.text)
    except Exception as e:
        print("Unexpected error:", str(e))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for the OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for the OME Appliance")
    PARSER.add_argument("--groupname", "-g", required=True,
                        help="The name of the group to which you want to add servers.")
    exclusive_group = PARSER.add_mutually_exclusive_group(required=True)
    exclusive_group.add_argument("--devicenames", "-n", help="The names of the device you want to add to the group in "
                                                             "format: \'device1,device2,device3,etc\'")
    exclusive_group.add_argument("--devicetags", "-t", help="A list of service tags which you want to add to the group "
                                                            "in format: \'tag1,tag2,tag3,etc\'")
    ARGS = PARSER.parse_args()

    if ARGS.devicetags:
        add_device_to_static_group(ARGS.ip, ARGS.user, ARGS.password, ARGS.groupname,
                                   device_tags=ARGS.devicetags.split(","))
    elif ARGS.devicenames:
        add_device_to_static_group(ARGS.ip, ARGS.user, ARGS.password, ARGS.groupname,
                                   device_names=ARGS.devicenames.split(","))
