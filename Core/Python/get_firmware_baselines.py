#
# _author_ = Grant Curell <grant_curell@dell.com>
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
Gets a list of all firmware baselines available from an OME server or baselines associated
with a specific device.

#### Description
This script uses the OME REST API to find baselines associated
with a given server. For authentication X-Auth is used over Basic
Authentication. Note: The credentials entered are not stored to disk.

#### Python Example
`python get_firmware_baseline.py -i 192.168.1.93 -u admin -p somepass -r 192.168.1.45`
"""

import argparse
import json
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse
from getpass import getpass

import requests
import urllib3


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
    session_info = requests.post(session_url, verify=False,
                                 data=json.dumps(user_details),
                                 headers=authenticated_headers)

    if session_info.status_code == 201:
        authenticated_headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        return authenticated_headers
    else:
        print("There was a problem authenticating with OME. Are you sure you have the right username, password, "
              "and IP?")
        raise Exception("There was a problem authenticating with OME. Are you sure you have the right username, "
                        "password, and IP?")


def get_data(authenticated_headers: dict, url: str, odata_filter: str = None) -> list:
    """
    This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
    handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
    pages to get a complete listing.

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        url: The API url against which you would like to make a request
        odata_filter: An optional parameter for providing an odata filter to run against the API endpoint.

    Returns: Returns a list of dictionaries of the data received from OME

    """

    next_link_url = None

    if odata_filter:
        count_data = requests.get(url + '?$filter=' + odata_filter, headers=authenticated_headers, verify=False)

        if count_data.status_code == 400:
            print("Received an error while retrieving data from %s:" % url + '?$filter=' + odata_filter)
            pprint(count_data.json()['error'])
            return []

        count_data = count_data.json()
        if count_data['@odata.count'] <= 0:
            print("No results found!")
            return []
    else:
        count_data = requests.get(url, headers=authenticated_headers, verify=False).json()

    if 'value' in count_data:
        data = count_data['value']
    else:
        data = count_data

    if '@odata.nextLink' in count_data:
        # Grab the base URI
        next_link_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url)) + count_data['@odata.nextLink']

    while next_link_url is not None:
        response = requests.get(next_link_url, headers=authenticated_headers, verify=False)
        next_link_url = None
        if response.status_code == 200:
            requested_data = response.json()
            if requested_data['@odata.count'] <= 0:
                print("No results found!")
                return []

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


def get_firmware_baselines(authenticated_headers: dict,
                           ome_ip_address: str,
                           device_id: int = None,
                           service_tag: str = None,
                           device_idrac_ip: str = None,
                           device_name: str = None):
    """
    Gets a list of firmware baselines from OME

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        device_id: (optional) The device ID of a host whose firmware baselines a user wants retrieved
        service_tag: (optional) The service tag of a host whose firmware baselines a user wants retrieved
        device_idrac_ip: (optional) The idrac IP of a host whose firmware baselines a user wants retrieved
        device_name: (optional): The name of a host whose firmware baselines a user wants retrieved
    """

    print("Retrieving a list of firmware")
    firmware_baselines = \
        get_data(authenticated_headers, "https://%s/api/UpdateService/Baselines" % ome_ip_address)  # type: list

    if not firmware_baselines:
        print("Unable to retrieve firmware list from %s. This could happen for many reasons but the most likely is a"
              " failure in the connection." % ome_ip_address)
        exit(0)

    if len(firmware_baselines) <= 0:
        print("No firmware baselines found on this OME server: " + ome_ip_address + ". Exiting.")
        exit(0)

    # At this point all firmware data is contained in the variable firmware_baselines. This next part simply collects
    # the names in a list and prints them.

    # If the user passed a device name, resolve that name to a device ID
    if device_name:
        device_id = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                             "DeviceName eq \'%s\'" % device_name)
        if not device_id:
            print("Error: We were unable to find device name " + device_name + " on this OME server. Exiting.")
            exit(0)
        else:
            device_id = device_id[0]['Id']
    elif service_tag:
        device_id = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                             "DeviceServiceTag eq \'%s\'" % service_tag)

        if not device_id:
            print("Error: We were unable to find service tag " + service_tag + " on this OME server. Exiting.")
            exit(0)
        else:
            device_id = device_id[0]['Id']
    elif device_idrac_ip:
        device_list = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address)

        if not device_list:
            print("Unable to get device list from %s. This could happen for many reasons but the most likely is a"
                  " failure in the connection." % ome_ip_address)
            exit(0)

        if len(device_list) <= 0:
            print("No devices found on this OME server: " + ome_ip_address + ". Exiting.")
            exit(0)

        for device_dictionary in device_list:
            if device_dictionary['DeviceManagement'][0]['NetworkAddress'] == device_idrac_ip.strip():
                device_id = device_dictionary['Id']
                break

        if not device_idrac_ip:
            print("Error: We were unable to find idrac IP " + device_idrac_ip + " on this OME server. Exiting.")
            exit(0)

    firmware_baseline_names = []  # type: list
    for firmware_baseline in firmware_baselines:
        if device_id:
            if len(firmware_baseline['Targets']) > 0:
                for target in firmware_baseline['Targets']:
                    if target["Id"] == device_id:
                        firmware_baseline_names.append(firmware_baseline["Name"])
        else:
            firmware_baseline_names.append(firmware_baseline["Name"])

    if len(firmware_baseline_names) > 0:
        print("Baselines are:")
        print(firmware_baseline_names)
    else:
        print("No firmware baselines found!")


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for the OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=False,
                        help="Password for the OME Appliance")
    exclusive_group = PARSER.add_mutually_exclusive_group(required=False)
    exclusive_group.add_argument("--device-id", "-d", help="The device ID ")
    exclusive_group.add_argument("--service-tag", "-s", help="A device service tag")
    exclusive_group.add_argument("--idrac-ip", "-r", help="A device idrac IP")
    exclusive_group.add_argument("--device-name", "-n", help="The name of the device in OME")
    ARGS = PARSER.parse_args()
    if not ARGS.password:
        ARGS.password = getpass()

    try:
        headers = authenticate(ARGS.ip, ARGS.user, ARGS.password)

        if not headers:
            exit(0)

        get_firmware_baselines(headers, ARGS.ip, ARGS.device_id, ARGS.service_tag, ARGS.idrac_ip, ARGS.device_name)
    except Exception as error:
        print("Unexpected error:", str(error))
