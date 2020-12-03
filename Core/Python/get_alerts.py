#
# _author_ = Grant Curell <grant_curell@dell.com>
# _contributor_ = Raajeev Kalyanaraman wrote the method for getting alerts
#                 by group
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
Retrieves alerts from a target OME Instance.

#### Description
This script provides a large number of ways to get alerts with various filters. With no arguments it will pull all
alerts from the OME instance. The below filters are available:

- top - Pull top records
- skip - Skip N number of records
- orderby - Order by a specific column
- id - Filter by the OME internal event ID
- Alert device ID - Filter by the OME internal ID for the device
- Alert Device Identifier / Service Tag - Filter by the device identifier or service tag of a device
- Device type - Filter by device type (server, chassis, etc)
- Severity type - The severity of the alert - warning, critical, info, etc
- Status type - The status of the device - normal, warning, critical, etc
- Category Name - The type of alert generated. Audit, configuration, storage, system health, etc
- Subcategory ID - Filter by a specific subcategory. The list is long - see the --get-subcategories option for details
- Subcategory name - Same as above except the name of the category instead of the ID
- Message - Filter by the message generated with the alert
- TimeStampBegin - Not currently available. See https://github.com/dell/OpenManage-Enterprise/issues/101
- TimeStampEnd - Not currently available. See https://github.com/dell/OpenManage-Enterprise/issues/101
- Device name - Filter by a specific device name
- Group name - Filter alerts by a group name
- Group description - Filter alerts by a group description

Authentication is done over x-auth with basic authentication. Note: Credentials are not stored on disk.

#### Python Examples
```
python get_alerts --ip 192.168.1.93 --password somepass --top 1 --skip 5
python get_alerts --ip 192.168.1.93 --password somepass --alerts-by-group-name "Test" --severity-type CRITICAL --top 5
python get_alerts --ip 192.168.1.93 --password somepass --orderby Message --category-name AUDIT --alert-device-type STORAGE
```
"""

import argparse
import json
import sys
from argparse import RawTextHelpFormatter
from pprint import pprint
from urllib.parse import urlparse
from getpass import getpass

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3, requests. To install them on most systems run "
          "`pip install requests urllib3`")
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
    parser.add_argument("--top", required=False, help="Top records to return.")
    parser.add_argument('--pages', required=False, type=int,
                        help="You will generally not need to change this unless you are using a large value for top"
                             " - typically more than 50 devices. In the UI the results come in pages. Even when"
                             " not using the UI the results are still delivered in 'pages'. The 'top' argument"
                             " effectively sets the page size to the value you select and will return *everything*"
                             " , albeit much slower, by iterating over all pages in OME. To prevent this we tell it"
                             " to only return a certain number of pages. By default this value is 1. If you want"
                             " more than one page of results you can set this.")
    parser.add_argument("--skip", required=False, help="The number of records, starting at the top, to skip.")
    parser.add_argument("--orderby",
                        choices=['AlertDeviceIdentifier', 'AlertDeviceType', 'SeverityType',
                                 'StatusType', 'SubCategoryName', 'Message', 'TimeStampDescending',
                                 'TimeStampAscending', 'AlertDeviceName'], required=False,
                        help="Order to apply to the output.")
    parser.add_argument("--id", required=False, help="Filter by the OME internal event ID.")
    parser.add_argument("--alert-device-id", required=False, help="Filter by OME internal device ID.")
    parser.add_argument("--alert-device-identifier", "--service-tag", required=False,
                        help="Filter by the device identifier. For servers this is the service tag.")
    parser.add_argument("--alert-device-type",
                        choices=['SERVER', 'CHASSIS', 'NETWORK_CONTROLLER', 'NETWORK_IOM', 'STORAGE', 'STORAGE_IOM'],
                        required=False, help="Filter by device type.")
    parser.add_argument("--severity-type", choices=['WARNING', 'CRITICAL', 'INFO', 'NORMAL', 'UNKNOWN'], required=False,
                        help="Filter by the severity type of the alert.")
    parser.add_argument("--status-type", choices=['NORMAL', 'UNKNOWN', 'WARNING', 'CRITICAL', 'NOSTATUS'],
                        required=False, help="Filter by status type of the device.")
    parser.add_argument("--category-name",
                        choices=['AUDIT', 'CONFIGURATION', 'MISCELLANEOUS', 'STORAGE', 'SYSTEM_HEALTH', 'UPDATES',
                                 'WORK_NOTES'], required=False, help="Filter by category name.")
    parser.add_argument("--get-subcategories", required=False, action='store_true',
                        help="Grabs a list of subcategories from the OME instance.")
    parser.add_argument("--subcategory-id", required=False,
                        help="Filter by subcategory ID. To get a list of subcategory IDs available run this program "
                             "with the --get-subcategories option.")
    parser.add_argument("--subcategory-name", required=False,
                        help="Filter by subcategory name. To get a list of subcategory names available run this "
                             "program with the --get-subcategories option.")
    parser.add_argument("--message", required=False, help="Filter by message.")
    parser.add_argument("--time-stamp-begin", required=False,
                        help="Filter by starting time of alerts. This is not currently implemented. See: "
                             "https://github.com/dell/OpenManage-Enterprise/issues/101")
    parser.add_argument("--time-stamp-end", required=False,
                        help="Filter by ending time of alerts. This is not currently implemented. See: "
                             "https://github.com/dell/OpenManage-Enterprise/issues/101")
    parser.add_argument("--alert-device-name", required=False, help="Filter by the OME device name.")
    parser.add_argument("--alerts-by-group-name", required=False,
                        help="The name of the group on which you want to filter.")
    parser.add_argument("--alerts-by-group-description", required=False,
                        help="The description of the group on which you want to filter.")

    args = parser.parse_args()

    if not args.password:
        args.password = getpass()

    SEVERITY_TYPE = {'WARNING': '8', 'CRITICAL': '16', 'INFO': '2', 'NORMAL': '4', 'UNKNOWN': '1'}
    STATUS_TYPE = {'NORMAL': '1000', 'UNKNOWN': '2000', 'WARNING': '3000', 'CRITICAL': '4000', 'NOSTATUS': '5000'}
    ALERT_DEVICE_TYPE = {'SERVER': '1000', 'CHASSIS': '2000', 'NETWORK_CONTROLLER': '9000', 'NETWORK_IOM': '4000',
                         'STORAGE': '3000', 'STORAGE_IOM': '8000'}
    CATEGORY_ID = {'AUDIT': '4', 'CONFIGURATION': 5, 'MISCELLANEOUS': 7, 'STORAGE': 2, 'SYSTEM_HEALTH': 1, 'UPDATES': 3,
                   'WORK_NOTES': 6}

    try:
        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        if args.get_subcategories:
            pprint(get_data(headers, "https://%s/api/AlertService/AlertCategories" % args.ip))
            sys.exit(0)

        if args.pages and not args.top:
            parser.error("You cannot provide the pages argument without the top argument.")

        if args.top and not args.pages:
            args.pages = 1

        audit_logs_url = 'https://%s/api/AlertService/Alerts' % args.ip

        odata_filter = []

        if args.id:
            odata_filter.append("Id eq %s" % args.id)

        if args.alert_device_id:
            odata_filter.append("AlertDeviceId eq %s" % args.alert_device_id)

        if args.alert_device_identifier:
            odata_filter.append("AlertDeviceIdentifier eq '%s'" % args.alert_device_identifier)

        if args.alert_device_type:
            odata_filter.append("AlertDeviceType eq %s" % ALERT_DEVICE_TYPE[args.alert_device_type])

        if args.severity_type:
            odata_filter.append("SeverityType eq %s" % SEVERITY_TYPE[args.severity_type])

        if args.status_type:
            odata_filter.append("StatusType eq %s" % STATUS_TYPE[args.status_type])

        if args.category_name:
            odata_filter.append("CategoryId eq %s" % CATEGORY_ID[args.category_name])

        if args.subcategory_id:
            odata_filter.append("SubCategoryId eq %s" % args.subcategory_id)

        if args.subcategory_name:
            odata_filter.append("SubCategoryName eq '%s'" % args.subcategory_name)

        if args.alert_device_name:
            odata_filter.append("AlertDeviceName eq '%s'" % args.alert_device_name)

        if args.message:
            odata_filter.append("Message eq '%s'" % args.message)

        if args.time_stamp_begin:
            # TODO https://github.com/dell/OpenManage-Enterprise/issues/101
            parser.error("Error: time-stamp-start is not currently implemented. See "
                         "https://github.com/dell/OpenManage-Enterprise/issues/101")

        if args.time_stamp_end:
            # TODO https://github.com/dell/OpenManage-Enterprise/issues/101
            parser.error("Error: time-stamp-end is not currently implemented. See "
                         "https://github.com/dell/OpenManage-Enterprise/issues/101")

        group_url = "https://%s/api/GroupService/Groups" % args.ip
        groups = None
        group_id = ""
        if args.alerts_by_group_name:
            groups = get_data(headers, group_url, "Name eq '%s'" % args.alerts_by_group_name)

            if len(groups) < 1:
                print("Error: We were unable to find a group matching the name %s." % args.alerts_by_group_name)
                sys.exit(0)

            group_id = groups[0]['Id']

        elif args.alerts_by_group_description:
            groups = get_data(headers, group_url, "Description eq '%s'" % args.alerts_by_group_description)

            if len(groups) < 1:
                print("Error: We were unable to find a group matching the description %s."
                      % args.alerts_by_group_description)
                sys.exit(0)

            group_id = groups[0]['Id']

        if args.alerts_by_group_name or args.alerts_by_group_description:
            odata_filter.append("AlertDeviceGroup eq %s" % group_id)

        url_filter = None
        if len(odata_filter) > 0:
            url_filter = ''
            for index, filter_data in enumerate(odata_filter):
                # Do not append and on the last element of the filter
                if index == len(odata_filter) - 1:
                    url_filter = url_filter + filter_data
                else:
                    url_filter = url_filter + filter_data + ' and '

        if args.orderby:
            if args.orderby == 'TimeStampAscending':
                args.orderby = 'TimeStamp asc'
            elif args.orderby == 'TimeStampDescending':
                args.orderby = 'TimeStamp desc'

        # These are arguments which aren't filters: top, skip, and orderby
        non_filter_args = []
        if not url_filter:
            if args.top:
                non_filter_args.append("top=" + args.top)
            if args.skip:
                non_filter_args.append("skip=" + args.skip)
            if args.orderby:
                non_filter_args.append("orderby=" + args.orderby)

            # Create the URL if there is no filter argument
            non_filter_url = None
            if len(non_filter_args) > 0:
                non_filter_url = ''
                for index, non_filter_arg in enumerate(non_filter_args):
                    # Do not append &$ on the last element of the filter
                    if index == 0:
                        non_filter_url = non_filter_url + '?$' + non_filter_arg
                    else:
                        non_filter_url = non_filter_url + '&$' + non_filter_arg
                audit_logs_url = audit_logs_url + non_filter_url
        else:
            if args.top:
                url_filter = url_filter + '&$top=' + args.top

            if args.skip:
                url_filter = url_filter + '&$skip=' + args.skip

            if args.orderby:
                url_filter = url_filter + '&$orderby=' + args.orderby

        if url_filter:
            print("The URL is " + audit_logs_url + '?$filter=' + url_filter)
            print("You can modify this URL in accordance with the odata 4 standard. See "
                  "http://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part2-url-conventions.html for details.")
            pprint(get_data(headers, audit_logs_url, url_filter, max_pages=args.pages))
        else:
            print("The URL is " + audit_logs_url)
            pprint(get_data(headers, audit_logs_url, max_pages=args.pages))

    except Exception as error:
        pprint(error)
