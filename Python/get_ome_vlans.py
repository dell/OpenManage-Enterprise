#
# _author_ = Greg Bowersock <Greg.Bowersock@Dell.com>
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
# _author_ = Grant Curell <grant_curell@dell.com>
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
#### Synopsis
Retrieves data regarding the VLANs on an OME instance.

#### Description
The --out-file argument is optional. If specified output will go to screen and a file. Otherwise it only prints to
screen.

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_ome_vlans.py --ip <xx> --user <username> --password <pwd> --out-file <exported csv file>`
"""

import argparse
import csv
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


def get_networktypes(ome_base_uri: str, authenticated_headers: dict):
    """
    Display the different types of network to which you can assign an OME VLAN

    Args:
        ome_base_uri: The base portion of the API URI. This is "https://<OME_IP>"
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
    """
    networktype_url = ome_base_uri + '/api/NetworkConfigurationService/NetworkTypes'
    networktype_response = requests.get(networktype_url, headers=authenticated_headers, verify=False)
    if networktype_response.status_code == 200 or networktype_response.status_code == 201:
        networktype_data = networktype_response.json()
        networktype_data = networktype_data['value']
        for i in networktype_data:
            print("Id: %s, Name: %s, Description: %s" % (i["Id"], i["Name"], i["Description"]))
    else:
        print("Unable to retrieve list from %s" % networktype_url)


def get_networks(ome_base_uri: str, authenticated_headers: dict, out_file: str = None):
    """
    Enumerates the VLANs on the OME instance and prints them to screen. Will also optional output to a file

    Args:
        ome_base_uri: The base portion of the API URI. This is "https://<OME_IP>"
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        out_file: The name of a file to which you want to output the VLANs

    """
    network_url = ome_base_uri + '/api/NetworkConfigurationService/Networks'
    network_data = get_data(authenticated_headers, network_url)
    if out_file:
        # Use UTF 8 in case there are non-ASCII characters like 格蘭特
        print("Writing CSV to file...")
        with open(out_file, 'w', encoding='utf-8', newline='') as csv_file:
            csv_columns = ["Id", "Name", "Description", "VlanMaximum", "VlanMinimum", "Type"]
            writer = csv.DictWriter(csv_file, fieldnames=csv_columns, extrasaction='ignore')
            writer.writeheader()
            for network in network_data:
                writer.writerow(network)
    for network in network_data:
        print("Id: %s, Name: %s, Description: %s, VLAN Min: %s, VLAN Max: %s, Type: %s, Created By: %s"
              % (network["Id"],
                 network["Name"],
                 network["Description"],
                 network["VlanMinimum"],
                 network["VlanMaximum"],
                 network["Type"],
                 network["CreatedBy"]))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--list-networktypes", "-lt", required=False, action='store_true',
                        help="Prints the different network types to which you can assign a VLAN in OME")
    parser.add_argument("--out-file", "-f", required=False,
                        help="The name of a file to which you want to write your VLANs")
    args = parser.parse_args()

    base_uri = 'https://%s' % args.ip
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

        if args.list_networktypes:
            get_networktypes(base_uri, headers)
        else:
            get_networks(base_uri, headers, args.out_file)
    except Exception as error:
        pprint(error)
