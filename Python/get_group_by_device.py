#
# _author_ = Grant Curell <grant_curell@dell.com>
#
# Copyright (c) 2022 Dell EMC Corporation
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
Takes as input a device(s) and returns all groups to which that device belongs.

#### Description
This script uses the OME REST API to find all groups to which a device belongs. Note: The credentials entered are not
 stored to disk. Multiple devices can be specified. It will produce output in the following format:

```
-----------------------------
Device 192.168.1.120 belongs to groups:
-----------------------------
Group Name: All Devices        Group ID: 1031
Group Name: Dell iDRAC Servers        Group ID: 1010
Group Name: Servers        Group ID: 1009
Group Name: Some group        Group ID: 14382
Group Name: System Groups        Group ID: 500
Group Name: fx2cmc        Group ID: 14377
```

#### Python Example
    python get_group_by_device.py --ip 192.168.1.85 --user admin --password password --idrac-ip 192.168.1.120
    python get_group_by_device.py --ip 192.168.1.85 --user admin --password password --service-tags AAAAA,BBBBB
"""

import argparse
import json
import sys
from argparse import RawTextHelpFormatter
from getpass import getpass
from pprint import pprint
from urllib.parse import urlparse

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
    sys.exit(0)


def authenticate(ome_ip_address: str, ome_username: str, ome_password: str) -> dict:
    """
    Authenticates with OME and creates a session

    Args:
        ome_ip_address: IP address of the OME server
        ome_username:  Username for OME
        ome_password: OME password

    Returns: A dictionary of HTTP headers

    Raises:
        Exception: A generic exception in the event of a failure to connect.
    """

    authenticated_headers = {'content-type': 'application/json'}
    session_url = 'https://%s/api/SessionService/Sessions' % ome_ip_address
    user_details = {'UserName': ome_username,
                    'Password': ome_password,
                    'SessionType': 'API'}
    try:
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=authenticated_headers)
    except requests.exceptions.ConnectionError:
        print("Failed to connect to OME. This typically indicates a network connectivity problem. Can you ping OME?")
        sys.exit(0)

    if session_info.status_code == 201:
        authenticated_headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        return authenticated_headers

    print("There was a problem authenticating with OME. Are you sure you have the right username, password, "
          "and IP?")
    raise Exception("There was a problem authenticating with OME. Are you sure you have the right username, "
                    "password, and IP?")


def get_data(authenticated_headers: dict, url: str, odata_filter: str = None, max_pages: int = None) -> dict:
    """
    This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
    handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
    pages to get a complete listing.

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        url: The API url against which you would like to make a request
        odata_filter: An optional parameter for providing an odata filter to run against the API endpoint.
        max_pages: The maximum number of pages you would like to return

    Returns: Returns a dictionary of data received from OME

    """

    next_link_url = None

    if odata_filter:
        count_data = requests.get(url + '?$filter=' + odata_filter, headers=authenticated_headers, verify=False)

        if count_data.status_code == 400:
            print("Received an error while retrieving data from %s:" % url + '?$filter=' + odata_filter)
            pprint(count_data.json()['error'])
            return {}

        count_data = count_data.json()
        if count_data['@odata.count'] <= 0:
            print("No results found!")
            return {}
    else:
        count_data = requests.get(url, headers=authenticated_headers, verify=False).json()

    if 'value' in count_data:
        data = count_data['value']
    else:
        data = count_data

    if '@odata.nextLink' in count_data:
        # Grab the base URI
        next_link_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url)) + count_data['@odata.nextLink']

    i = 1
    while next_link_url is not None:
        # Break if we have reached the maximum number of pages to be returned
        if max_pages:
            if i >= max_pages:
                break
            else:
                i = i + 1
        response = requests.get(next_link_url, headers=authenticated_headers, verify=False)
        next_link_url = None
        if response.status_code == 200:
            requested_data = response.json()
            if requested_data['@odata.count'] <= 0:
                print("No results found!")
                return {}

            # The @odata.nextLink key is only present in data if there are additional pages. We check for it and if it
            # is present we get a link to the page with the next set of results.
            if '@odata.nextLink' in requested_data:
                next_link_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url)) + \
                                requested_data['@odata.nextLink']

            if 'value' in requested_data:
                data += requested_data['value']
            else:
                data += requested_data
        else:
            print("Unknown error occurred. Received HTTP response code: " + str(response.status_code) +
                  " with error: " + response.text)
            raise Exception("Unknown error occurred. Received HTTP response code: " + str(response.status_code)
                            + " with error: " + response.text)

    return data


def get_device_id(authenticated_headers: dict,
                  ome_ip_address: str,
                  service_tag: str = None,
                  device_idrac_ip: str = None,
                  device_name: str = None) -> int:
    """
    Resolves a service tag, idrac IP or device name to a device ID

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        service_tag: (optional) The service tag of a host
        device_idrac_ip: (optional) The idrac IP of a host
        device_name: (optional): The name of a host

    Returns: Returns the device ID or -1 if it couldn't be found
    """

    if not service_tag and not device_idrac_ip and not device_name:
        print("No argument provided to get_device_id. Must provide service tag, device idrac IP or device name.")
        return -1

    # If the user passed a device name, resolve that name to a device ID
    if device_name:
        device_id = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                             "DeviceName eq \'%s\'" % device_name)
        if len(device_id) == 0:
            print("Error: We were unable to find device name " + device_name + " on this OME server. Exiting.")
            return -1

        device_id = device_id[0]['Id']

    elif service_tag:
        device_id = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                             "DeviceServiceTag eq \'%s\'" % service_tag)

        if len(device_id) == 0:
            print("Error: We were unable to find service tag " + service_tag + " on this OME server. Exiting.")
            return -1

        device_id = device_id[0]['Id']

    elif device_idrac_ip:
        device_id = -1
        device_ids = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                              "DeviceManagement/any(d:d/NetworkAddress eq '%s')" % device_idrac_ip)

        if len(device_ids) == 0:
            print("Error: We were unable to find idrac IP " + device_idrac_ip + " on this OME server. Exiting.")
            return -1

        # TODO - This is necessary because the filter above could possibly return multiple results
        # TODO - See https://github.com/dell/OpenManage-Enterprise/issues/87
        for device_id in device_ids:
            if device_id['DeviceManagement'][0]['NetworkAddress'] == device_idrac_ip:
                device_id = device_id['Id']

        if device_id == -1:
            print("Error: We were unable to find idrac IP " + device_idrac_ip + " on this OME server. Exiting.")
            return -1
    else:
        device_id = -1

    return device_id


def populate_groups_dictionary(authenticated_headers: dict, ome_ip_address: str) -> dict:
    """
    Generates a dictionary in the format {"group_name", {devices: [member_device_ids], group_id: integer_id}}

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server

    Returns: Returns a dictionary containing each group's member device IDs or an empty dictionary if there
             are no groups.
    """

    groups_dictionary = {}

    group_list = get_data(authenticated_headers,'https://%s/api/GroupService/Groups' % ome_ip_address)  # type: dict

    if len(group_list) == 0:
        print("Error: We were unable to find any groups! Does your OME instance have any?")
        return groups_dictionary

    for group in group_list:
        print("Processing group %s..." % group['Name'])
        new_group = {'group_id': group['Id'], 'devices': []}
        new_group_devices = get_data(authenticated_headers, "https://%s%s" % (ome_ip_address, group['Devices@odata.navigationLink']))
        if len(new_group_devices) > 0:
            for device in new_group_devices:
                new_group['devices'].append(device['Id'])

            groups_dictionary[group['Name']] = new_group
        else:
            print("Group %s has no devices. Skipping it." % group['Name'])

    print("Finished creating groups dictionary")
    return groups_dictionary


def get_group(groups_dictionaries: dict, target_id) -> list:
    """
    Searches through the groups dictionary and looks for the queried device ID

    Args:
        groups_dictionaries: A dictionary as defined in _populate_groups_dictionary
        ome_ip_address: IP address of the OME server

    Returns: Returns a list of group tuples representing each group and its group ID. Ex: [(group1, 11111),
             (group2, 22222) ... (groupn, 99999)]
    """

    groups_list = []

    for group_name,values in groups_dictionaries.items():
        if target_id in values['devices']:
            groups_list.append((group_name, values['group_id']))

    return groups_list


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for the OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for the OME Appliance")
    parser.add_argument("--device-ids", "-d", help="A comma separated list of device-ids whose group you want to look "
                                                   "up.")
    parser.add_argument("--service-tags", "-s", help="A comma separated list of service tags whose group you want to"
                                                     " look up.")
    parser.add_argument("--idrac-ips", "-r", help="A comma separated list of idrac IPs whose group you want to look "
                                                  "up.")
    parser.add_argument("--device-names", "-n", help="A comma separated list of device names whose group you want to "
                                                     "look up.")
    args = parser.parse_args()

    if not args.password:
        if not sys.stdin.isatty():
            # notify user that they have a bad terminal
            # perhaps if os.name == 'nt': , prompt them to use winpty?
            print("Your terminal is not compatible with Python's getpass module. You will need to provide the"
                  " --password argument instead. See https://stackoverflow.com/a/58277159/4427375")
            sys.exit(0)
        else:
            password = getpass()
    else:
        password = args.password

    try:

        headers = authenticate(args.ip, args.user, password)

        if not headers:
            sys.exit(0)

        target_ids = []

        # NOTE: This variant of device resolution deviates from the standard. Do not copy and paste. Use API reference
        # code.

        device_id_mapping = {}

        if args.device_ids:
            device_ids_arg = args.device_ids.split(',')
            for device in args.device_ids.split(','):
                device_id_mapping[device] = device
        else:
            device_ids_arg = None

        if args.service_tags:
            service_tags = args.service_tags.split(',')
            for service_tag in service_tags:
                target = get_device_id(headers, args.ip, service_tag=service_tag)
                if target != -1:
                    target_ids.append(target)
                    device_id_mapping[target] = service_tag
                else:
                    print("Could not resolve ID for: " + service_tag)
        else:
            service_tags = None

        if args.idrac_ips:
            device_idrac_ips = args.idrac_ips.split(',')
            for device_idrac_ip in device_idrac_ips:
                target = get_device_id(headers, args.ip, device_idrac_ip=device_idrac_ip)
                if target != -1:
                    target_ids.append(target)
                    device_id_mapping[target] = device_idrac_ip
                else:
                    print("Could not resolve ID for: " + device_idrac_ip)
        else:
            device_idrac_ips = None

        if args.device_names:
            device_names = args.device_names.split(',')
            for device_name in device_names:
                target = get_device_id(headers, args.ip, device_name=device_name)
                if target != -1:
                    target_ids.append(target)
                    device_id_mapping[target] = device_name
                else:
                    print("Could not resolve ID for: " + device_name)
        else:
            device_names = None

        # Eliminate any duplicate IDs in the list
        target_ids = list(dict.fromkeys(target_ids))

        if len(target_ids) < 1:
            print("Error: No IDs found. Did you provide an argument?")
            sys.exit(0)

        # Create an offline dictionary of all the groups on the target OME instance
        groups_dictionary = populate_groups_dictionary(headers, args.ip)

        # Look up the groups
        if len(groups_dictionary) > 0:
            for target_id in target_ids:
                print("-----------------------------")
                print("Device %s belongs to groups: " % device_id_mapping[target_id])
                print("-----------------------------")
                for group in get_group(groups_dictionary, target_id):
                    print("Group Name: %s        Group ID: %s" % (group[0], group[1]))
        else:
            print("It doesn't look like you have any populated groups. Does your OME instance have any devices?")

    except Exception as error:
        pprint(error)
