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
Retrieves the audit logs from a target OME instance and can either save them in an CSV on a fileshare or
print them to screen.

#### Description
It performs X-Auth with basic authentication. Note: Credentials are not stored on disk.

#### Python Example
`python get_audit_logs.py -i 192.168.1.93 -u admin -p somepass
--share \\192.168.1.7\gelante\test.csv --smbuser someuser --smbpass somepass`
"""

import argparse
import csv
import json
import sys
from argparse import RawTextHelpFormatter
from pprint import pprint
from urllib.parse import urlparse
from getpass import getpass

try:
    import urllib3
    import requests
    import smbclient
except ModuleNotFoundError:
    print("This program requires urllib3, requests, smbprotocol, and gssapi. To install them on most systems run "
          "`pip install requests urllib3 smbprotocol[kerberos]`")
    sys.exit(0)
try:
    from gssapi.raw import inquire_sec_context_by_oid
except ImportError as error:
    print("-----WARNING-----")
    print("python-gssapi extension is not available. You need to install it with `pip install gssapi`: %s" % str(error))
    print("You will also need a Kerberos installation. See https://pypi.org/project/smbprotocol/ for details.")
    print("You can ignore this if you do not plan on using Kerberos for authentication.")
    print("-----------------")
except OSError as error:
    print("Encountered an OS error. This usually means you are missing kerberos dependencies. The error was:",
          str(error))
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
    session_info = requests.post(session_url, verify=False,
                                 data=json.dumps(user_details),
                                 headers=authenticated_headers)

    if session_info.status_code == 201:
        authenticated_headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        return authenticated_headers

    print("There was a problem authenticating with OME. Are you sure you have the right username, password, "
          "and IP?")
    raise Exception("There was a problem authenticating with OME. Are you sure you have the right username, "
                    "password, and IP?")


def get_data(authenticated_headers: dict, url: str, odata_filter: str = None, max_pages: int = None) -> list:
    """
    This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
    handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
    pages to get a complete listing.

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        url: The API url against which you would like to make a request
        odata_filter: An optional parameter for providing an odata filter to run against the API endpoint.
        max_pages: The maximum number of pages you would like to return

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


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False, help="Username for the OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False, help="Password for the OME Appliance")
    parser.add_argument("--share", "-s", required=False,
                        help="A path to the share which you want to in format "
                             "\\\\<ip_address>\\<share_name>\\<file_name>")
    parser.add_argument("--smbuser", "-su", required=False, help="The username for SMB")
    parser.add_argument("--smbpass", "-sp", required=False, help="Password for SMB")
    args = parser.parse_args()

    if not args.password:
        args.password = getpass()

    try:
        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        audit_logs = get_data(headers, "https://%s/api/ApplicationService/AuditLogs" % args.ip)

        if args.share:
            if not args.smbuser or not args.smbpass:
                print("You must provide the arguments --smbuser and --smbpass when connecting to a share.")
                sys.exit(0)
            with smbclient.open_file(args.share, username=args.smbuser, password=args.smbpass, mode='w',
                                     encoding='utf-8-sig', newline='') as smbfile:
                csv_columns = ["Severity", "Message", "Category", "UserName", "IpAddress", "MessageArgs", "MessageID",
                               "CreatedDate"]
                writer = csv.DictWriter(smbfile, fieldnames=csv_columns, extrasaction='ignore')
                writer.writeheader()
                for row in audit_logs:
                    writer.writerow(row)
        else:
            pprint(audit_logs)

    except Exception as error:
        print("Unexpected error:", str(error))
