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
Add one or more hosts to an existing static group.

#### Description
This script uses the OME REST API to add one or more hosts to an existing static group. You can provide specific
 devices or you can provide the job ID for a previous discovery job containing a set of servers. The script will pull
 from the discovery job and add those servers to a gorup. For authentication X-Auth is used over Basic Authentication.
Note: The credentials entered are not stored to disk.

#### Python Example
    ```
    python add_device_to_static_group.py --idrac-ips 192.168.1.45,192.168.1.63 --groupname 格蘭特 --password somepass --ip 192.168.1.93 --use-discovery-job-id 14028
    python add_device_to_static_group.py --service-tags servtag1,servtag2,servtag3 --groupname 格蘭特 --password somepass --ip 192.168.1.93
    ```
"""

import argparse
import json
import sys
from pprint import pprint
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse
from getpass import getpass

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

        # TODO - This is necessary because the filter above could possibly return mulitple results
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


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for the OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for the OME Appliance")
    parser.add_argument("--groupname", "-g", required=True,
                        help="The name of the group to which you want to add servers.")
    parser.add_argument("--device-ids", "-d", help="A comma separated list of device-ids which you want to add to a "
                                                   "group.")
    parser.add_argument("--service-tags", "-s", help="A comma separated list of service tags which you want to add "
                                                     "to a group.")
    parser.add_argument("--idrac-ips", "-r", help="A comma separated list of idrac IPs which you want to add to a "
                                                  "group.")
    parser.add_argument("--device-names", "-n", help="A comma separated list of device names which you want to add "
                                                     "to a group.")
    parser.add_argument("--use-discovery-job-id", required=False, help="This option allows you to provide the job ID"
                        " from a discovery job and will pull the servers from that job ID and assign them to the "
                        "specified group. You can either retrieve the job ID programatically or you can get it "
                        "manually from the UI by clicking on the job and pulling it from the URL. Ex: "
                        "https://192.168.1.93/core/console/console.html#/core/monitor/monitor_portal/jobsDetails?jobsId=14026")
    args = parser.parse_args()

    if not args.password:
        args.password = getpass()

    try:

        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        group_add_device_url = "https://%s/api/GroupService/Actions/GroupService.AddMemberDevices" % args.ip

        group_url = "https://%s/api/GroupService/Groups" % args.ip
        groups = get_data(headers, group_url, "Name eq '%s'" % args.groupname)

        if len(groups) < 1:
            print("Error: We were unable to find a group matching the name %s." % args.groupname)
            sys.exit(0)

        group_id = groups[0]['Id']

        if group_id == -1:
            sys.exit(1)

        target_ids = []

        if args.device_ids:
            device_ids_arg = args.device_ids.split(',')
        else:
            device_ids_arg = None

        if args.service_tags:
            service_tags = args.service_tags.split(',')
            for service_tag in service_tags:
                target = get_device_id(headers, args.ip, service_tag=service_tag)
                if target != -1:
                    target_ids.append(target)
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
                else:
                    print("Could not resolve ID for: " + device_name)
        else:
            device_names = None

        if args.use_discovery_job_id:
            job_info = get_data(headers, "https://%s/api/JobService/Jobs(%s)" % (args.ip, args.use_discovery_job_id))

            if 'ExecutionHistories@odata.navigationLink' in job_info:
                job_info = get_data(headers, "https://" + args.ip + job_info['ExecutionHistories@odata.navigationLink'])
            else:
                print("Error: Something went wrong getting the job with ID " + str(args.args.use_discovery_job_id))
                sys.exit(0)

            if 'ExecutionHistoryDetails@odata.navigationLink' in job_info[0]:
                details_url = "https://" + args.ip + job_info[0]['ExecutionHistoryDetails@odata.navigationLink']
                job_info = get_data(headers, details_url)
            else:
                print("Error: Something went wrong getting the execution details")
                sys.exit(0)

            if len(job_info) > 0:
                for host in job_info:
                    target = get_device_id(headers, args.ip, device_idrac_ip=host['Key'])
                    if target != -1:
                        target_ids.append(target)
                    else:
                        print("Could not resolve ID for: " + host['Key'])
            else:
                print("The job info array returned empty. Exiting.")
                sys.exit(0)

        # Eliminate any duplicate IDs in the list
        target_ids = list(dict.fromkeys(target_ids))

        if len(target_ids) < 1:
            print("Error: No IDs found. Did you provide an argument?")
            sys.exit(0)

        # Add devices to the group
        print("Adding devices to the group...")
        payload = {
            "GroupId": group_id,
            "MemberDeviceIds": target_ids
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

    except Exception as error:
        pprint(error)
