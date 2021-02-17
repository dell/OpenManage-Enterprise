#
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
Retrieves the warranty information for all devices on an OME instance.

#### Description
You can provide a keyword argument to filter devices by the service description. For example you can specify 'pro'
and that would match a Service Level Description of 'Silver Support or ProSupport'

For authentication X-Auth is used over Basic Authentication Note that the credentials entered are not stored to disk.

#### Example
    python get_warranty_information.py --ip 192.168.1.93 --user admin --password password --warranty-keyword prosupport --out-file <csv_file>
"""

import argparse
import csv
import json
import sys
from os.path import isfile
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse
from getpass import getpass
from pprint import pprint

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


def query_yes_no(question: str, default: str = "yes") -> bool:
    """
    Prompts the user with a yes/no question

    Args:
        question: The question to ask the user
        default: Whether the default answer is no or yes. Defaults to yes

    Returns: A boolean - true if yes and false if no

    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def confirm_isvalid(output_filepath: str = "", input_filepath: str = "") -> bool:
    """
    Tests whether a filepath is valid or not. You can only provide either input_filepath or output_filepath. Not both.

    Args:
        output_filepath: The path to an output file you want to test
        input_filepath:The path to an input file you want to test

    Returns:
        Returns true if the path is valid and false if it is not
    """

    if input_filepath != "" and output_filepath != "":
        print("You can only provide either an InputFilePath or an OutputFilePath.")
        sys.exit(0)

    if isfile(output_filepath):
        if not query_yes_no(output_filepath + " already exists? Do you want to continue? (y/n): ", "no"):
            return False

    if output_filepath:
        try:
            open(output_filepath, 'w')
        except OSError:
            print("The filepath %s does not appear to be valid. This could be due to an incorrect path or a permissions"
                  " issue." % output_filepath)
            return False

    if input_filepath:
        try:
            open(output_filepath, 'r')
        except OSError:
            print("The filepath %s does not appear to be valid. This could be due to an incorrect path or a permissions"
                  " issue." % input_filepath)
            return False


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--out-file", "-f", required=False,
                        help="The name of a file to which you want to write your VLANs")
    parser.add_argument("--warranty-keyword", "-k", required=False, type=str,
                        help="Performs a case insensitive search against the field 'Service Level Description' in the "
                             "OME UI. This allows you to search for a specific type of warranty. For example, searching"
                             " prosupport would return all warranties with the word prosupport in their description.")
    args = parser.parse_args()

    base_uri = 'https://%s/api/WarrantyService/Warranties' % args.ip

    if not args.password:
        args.password = getpass()

    try:
        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        print("Sending the request to OME...")

        warranty_info = get_data(headers, base_uri)

        if warranty_info:

            if args.warranty_keyword:
                # Use a list comprehension to filter the dictionaries
                warranty_info = [warranty for warranty in warranty_info if
                                 args.warranty_keyword.lower() in warranty['ServiceLevelDescription'].lower()]

            if args.out_file:

                if not confirm_isvalid(output_filepath=args.out_file):
                    sys.exit(0)

                # Use UTF 8 in case there are non-ASCII characters like 格蘭特
                print("Writing CSV to file...")
                with open(args.out_file, 'w', encoding='utf-8', newline='') as csv_file:
                    # This code takes the list of dictionaries called warranty info, extracts the first dictionary in
                    # the list, which we assume will have keys identical to the other dictionaries in the list,
                    # creates an iterable from its keys, and then runs it through a lambda function which will remove
                    # any elements that have the string @odata in them. It will show add all other elements to the CSV
                    # file. In this way we do not need to manually enumerate the CSV header elements.
                    csv_columns = list(filter(lambda elem: '@odata' not in elem, warranty_info[0].keys()))
                    writer = csv.DictWriter(csv_file, fieldnames=csv_columns, extrasaction='ignore')
                    writer.writeheader()
                    for warranty in warranty_info:
                        writer.writerow(warranty)
            else:
                pprint(warranty_info)
        else:
            print("There was a problem retrieving the SupportAssist data from OME! Exiting.")
            sys.exit(0)

        print("Task completed successfully!")

    except Exception as error:
        pprint(error)
