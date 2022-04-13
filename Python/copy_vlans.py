#
# _author_ = Hemanth Vishwanath <hemanth_vishwanath@dell.com>
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

"""

#### Synopsis
Copies all VLANs from one OME instance to another

#### Description:
This script expects input in JSON format with two entries. The first should be a json array of dictionaries called
targets identifying the OME instances to which you want to push VLANs and the second is a single dictionary defining
the source instance. For example:

    {
        "target": [
            {
                "ip": "100.97.173.67",
                "port": "443",
                "user_name": "admin",
                "password": "your_password"
            },
            {
                "ip": "100.97.173.61",
                "port": "443",
                "user_name": "admin",
                "password": "your_password"
            }
        ],
        "source": {
            "ip": "100.97.173.76",
            "port": "443",
            "user_name": "admin",
            "password": "your_password"
        }
    }

#### Python Example
    python copy_vlans.py --inputs <JSON_FILE_NAME>
"""

import argparse
import json
import sys
from argparse import RawTextHelpFormatter
from pprint import pprint
from urllib.parse import urlparse

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
    sys.exit(0)

urllib3.disable_warnings()
VLAN_URL = "https://{}/api/NetworkConfigurationService/Networks"


def authenticate(ome_ip_address: str, ome_username: str, ome_password: str) -> dict:
    """
    Authenticates with OME and creates a session

    Args:
        ome_ip_address: IP address of the OME server
        ome_username:  Username for OME
        ome_password: OME password

    Returns: A dictionary of HTTP headers

    Raises:
        Exception: A generic exception in the event of a failure to connect
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


def get_vlan(ome_ip: str, authenticated_headers: dict) -> []:
    """
    Retrieves a list of dictionaries representing the VLAN entries on a specified OME instance

    Args:
        ome_ip: IP address of the OME instance
        authenticated_headers: The authenticated headers for the target OME instance

    Returns: List of dictionaries representing each VLAN entry in OME

    """

    vlan_list = []

    vlan_data = get_data(authenticated_headers, VLAN_URL.format(ome_ip))

    for vlan in vlan_data:
        vlan_list.append({'Name': vlan['Name'],
                          'Description': vlan['Description'],
                          'VlanMaximum': vlan['VlanMaximum'],
                          'VlanMinimum': vlan['VlanMinimum'],
                          'Type': vlan['Type']})
    return vlan_list


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--inputs", "-i", required=True, help="The name of the JSON file containing the required input"
                                                              " data")
    args = parser.parse_args()

    # Read inputs
    with open(args.inputs) as file_obj:
        inputs = json.load(file_obj)

    headers = authenticate(inputs['source']['ip'], inputs['source']['user_name'], inputs['source']['password'])

    if not headers:
        sys.exit(0)

    source_vlan_list = get_vlan(inputs['source']['ip'], headers)

    # Loop over each target OME instance and grab its VLANs
    for target in inputs['target']:

        target_headers = authenticate(target['ip'], target['user_name'], target['password'])

        if not target_headers:
            print("Error: There was a problem authenticating to target " + target['ip'])
            sys.exit(0)

        target_vlan_list = get_vlan(target['ip'], target_headers)

        for source_vlan_payload in source_vlan_list:
            print('Replicating VLAN {}-{} on target {}'.format(source_vlan_payload['VlanMinimum'],
                                                               source_vlan_payload['VlanMaximum'], target['ip']))

            # Determine if VLANs overlap between source and dest OME instances
            overlap_present = False

            source_vlan_range = range(source_vlan_payload['VlanMinimum'], source_vlan_payload['VlanMaximum'] + 1)

            for target_vlan_payload in target_vlan_list:
                target_vlan_range = range(target_vlan_payload['VlanMinimum'], target_vlan_payload['VlanMaximum'] + 1)

                overlap_present = any(index in target_vlan_range for index in source_vlan_range)

            # Deploy the VLANs to the new OME instance
            if overlap_present:
                print('WARNING: Unable to replicate vlan {}-{} on target {} as the VLANs overlap'.format(
                    source_vlan_payload['VlanMinimum'], source_vlan_payload['VlanMaximum'], target['ip']))
                print('*' * 180)
            else:
                source_vlan_payload = json.dumps(source_vlan_payload)
                response = requests.post(VLAN_URL.format(target['ip']), headers=target_headers, verify=False,
                                         data=source_vlan_payload)

                json_response = response.json()
                json_dump = json.dumps(json_response, indent=4)
                print(json_dump)
                print('*' * 180)
