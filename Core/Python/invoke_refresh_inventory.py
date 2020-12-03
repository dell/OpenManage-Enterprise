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
Refreshes the inventory on a set of target devices. This includes the configuration inventory tab.

#### Description
This script uses the OME REST API to refresh the inventory of a targeted server. It performs X-Auth
with basic authentication. Note: Credentials are not stored on disk.

#### Python Example
`python invoke_refresh_inventory.py -i 192.168.1.93 -u admin -p somepass --idrac-ips 192.168.1.63,192.168.1.45`
"""

import argparse
import json
import sys
import time
from argparse import RawTextHelpFormatter
from pprint import pprint
from typing import List
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


def get_group_id_by_name(ome_ip_address: str, group_name: str, authenticated_headers: dict) -> int:
    """
    Retrieves the ID of a group given its name.

    Args:
        ome_ip_address: The IP address of the OME server
        group_name: The name of the group whose ID you want to resolve.
        authenticated_headers: Headers used for authentication to the OME server

    Returns: Returns the ID of the group as an integer or -1 if it couldn't be found.

    """

    print("Searching for the requested group.")
    groups_url = "https://%s/api/GroupService/Groups?$filter=Name eq '%s'" % (ome_ip_address, group_name)

    group_response = requests.get(groups_url, headers=authenticated_headers, verify=False)

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
        print("Error: We could not find the group " + group_name + ". Exiting.")
        return -1
    print("Unable to retrieve groups. Exiting.")
    return -1


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


def track_job_to_completion(ome_ip_address: str,
                            authenticated_headers: dict,
                            tracked_job_id,
                            max_retries: int = 20,
                            sleep_interval: int = 30) -> bool:
    """
    Tracks a job to either completion or a failure within the job.

    Args:
        ome_ip_address: The IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        tracked_job_id: The ID of the job which you would like to track
        max_retries: The maximum number of times the function should contact the server to see if the job has completed
        sleep_interval: The frequency with which the function should check the server for job completion

    Returns: True if the job completed successfully or completed with errors. Returns false if the job failed.
    """
    job_status_map = {
        "2020": "Scheduled",
        "2030": "Queued",
        "2040": "Starting",
        "2050": "Running",
        "2060": "Completed",
        "2070": "Failed",
        "2090": "Warning",
        "2080": "New",
        "2100": "Aborted",
        "2101": "Paused",
        "2102": "Stopped",
        "2103": "Canceled"
    }

    failed_job_status = [2070, 2090, 2100, 2101, 2102, 2103]
    job_url = 'https://%s/api/JobService/Jobs(%s)' % (ome_ip_address, tracked_job_id)
    loop_ctr = 0
    job_incomplete = True
    print("Polling %s to completion ..." % tracked_job_id)

    while loop_ctr < max_retries:
        loop_ctr += 1
        time.sleep(sleep_interval)
        job_resp = requests.get(job_url, headers=authenticated_headers, verify=False)

        if job_resp.status_code == 200:
            job_status = str((job_resp.json())['LastRunStatus']['Id'])
            job_status_str = job_status_map[job_status]
            print("Iteration %s: Status of %s is %s" % (loop_ctr, tracked_job_id, job_status_str))

            if int(job_status) == 2060:
                job_incomplete = False
                print("Job completed successfully!")
                break
            elif int(job_status) in failed_job_status:
                job_incomplete = True

                if job_status_str == "Warning":
                    print("Completed with errors")
                else:
                    print("Error: Job failed.")

                job_hist_url = str(job_url) + "/ExecutionHistories"
                job_hist_resp = requests.get(job_hist_url, headers=authenticated_headers, verify=False)

                if job_hist_resp.status_code == 200:
                    # Get the job's execution details
                    job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
                    execution_hist_detail = "(" + job_history_id + ")/ExecutionHistoryDetails"
                    job_hist_det_url = str(job_hist_url) + execution_hist_detail
                    job_hist_det_resp = requests.get(job_hist_det_url,
                                                     headers=authenticated_headers,
                                                     verify=False)
                    if job_hist_det_resp.status_code == 200:
                        pprint(job_hist_det_resp.json()['value'])
                    else:
                        print("Unable to parse job execution history... exiting")
                break
        else:
            print("Unable to poll status of %s - Iteration %s " % (tracked_job_id, loop_ctr))

    if job_incomplete:
        print("Job %s incomplete after polling %s times...Check status" % (tracked_job_id, max_retries))
        return False

    return True


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


def refresh_device_inventory(authenticated_headers: dict,
                             ome_ip_address: str,
                             group_name: str,
                             skip_config_inventory: bool,
                             device_ids: list = None,
                             service_tags: str = None,
                             device_idrac_ips: str = None,
                             device_names: str = None,
                             ignore_group: bool = False):
    """
    Refresh the inventory of targeted hosts

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        group_name: The name of the group which contains the servers whose inventories you want to refresh
        skip_config_inventory: A boolean defining whether you would like to skip gathering the config inventory
        device_ids: (optional) The device ID of a host whose inventory you want to refresh
        service_tags: (optional) The service tag of a host whose inventory you want to refresh
        device_idrac_ips: (optional) The idrac IP of a host whose inventory you want to refresh
        device_names: (optional): The name of a host whose inventory you want to refresh
        ignore_group: (optional): Controls whether you want to ignore using groups or not
    """

    jobs_url = "https://%s/api/JobService/Jobs" % ome_ip_address

    target_ids = []

    if service_tags:
        service_tags = service_tags.split(',')
        for service_tag in service_tags:
            target = get_device_id(headers, ome_ip_address, service_tag=service_tag)
            if target != -1:
                target_ids.append(target)
            else:
                print("Could not resolve ID for: " + service_tag)

    if device_idrac_ips:
        device_idrac_ips = args.idrac_ips.split(',')
        for device_idrac_ip in device_idrac_ips:
            target = get_device_id(headers, ome_ip_address, device_idrac_ip=device_idrac_ip)
            if target != -1:
                target_ids.append(target)
            else:
                print("Could not resolve ID for: " + device_idrac_ip)

    if device_names:
        device_names = device_names.split(',')
        for device_name in device_names:
            target = get_device_id(headers, ome_ip_address, device_name=device_name)
            if target != -1:
                target_ids.append(target)
            else:
                print("Could not resolve ID for: " + device_name)

    if device_ids:
        for device_id in device_ids:
            target_ids.append(device_id)

    if not skip_config_inventory:
        group_id = get_group_id_by_name(ome_ip_address, group_name, authenticated_headers)

        if group_id == -1:
            print("We were unable to find the ID for group name " + group_name + " ... exiting.")
            sys.exit(0)

    if not ignore_group:
        group_devices = get_data(headers, "https://%s/api/GroupService/Groups(%s)/Devices" % (ome_ip_address, group_id))

        if len(group_devices) < 1:
            print("Error: There was a problem retrieving the devices for group " + args.groupname + ". Exiting")
            sys.exit(0)

        for device in group_devices:
            target_ids.append(device['Id'])

    targets_payload = []
    for id_to_refresh in target_ids:
        targets_payload.append({
            "Id": id_to_refresh,
            "Data": "",
            "TargetType": {
                "Id": 1000,
                "Name": "DEVICE"
            }
        })

    payload = {
        "Id": 0,
        "JobName": "Inventory refresh via the API.",
        "JobDescription": "Refreshes the inventories for targeted hardware.",
        "Schedule": "startnow",
        "State": "Enabled",
        "JobType": {
            "Name": "Inventory_Task"
        },
        "Targets": targets_payload
    }

    print("Beginning standard inventory refresh...")
    create_resp = requests.post(jobs_url, headers=authenticated_headers, verify=False, data=json.dumps(payload))

    if create_resp.status_code == 201:
        job_id_generic_refresh = json.loads(create_resp.content)["Id"]
    else:
        print("Error: Failed to refresh inventory. We aren't sure what went wrong.")
        sys.exit(1)

    if job_id_generic_refresh is None:
        print("Received invalid job ID from OME for standard inventory. Exiting.")
        sys.exit(1)

    # ------------------------------------------------------

    if not skip_config_inventory:

        payload = {
            "JobDescription": "Run config inventory collection task on selected devices",
            "JobName": "Part 1 - API refresh config inventory",
            "JobType": {"Id": 50, "Name": "Device_Config_Task"},
            "Params": [{"Key": "action", "Value": "CONFIG_INVENTORY"}],
            "Schedule": "startnow",
            "StartTime": "",
            "State": "Enabled",
            "Targets": [{
                "Data": "",
                "Id": group_id,
                "JobId": -1,
                "TargetType": {"Id": 6000, "Name": "GROUP"}
            }]
        }

        print("Beginning part 1 of 2 of the configuration inventory refresh.")
        create_resp = requests.post(jobs_url, headers=authenticated_headers, verify=False, data=json.dumps(payload))

        if create_resp.status_code == 201:
            config_inventory_refresh_job_1 = json.loads(create_resp.content)["Id"]
        else:
            print("Error: Failed to refresh inventory. We aren't sure what went wrong.")
            sys.exit(1)

        if config_inventory_refresh_job_1 is None:
            print("Received invalid job ID from OME for part 1 of configuration inventory refresh... exiting.")
            sys.exit(1)

        print("Waiting for part 1 of configuration inventory refresh to finish. This could take a couple of minutes.")
        if track_job_to_completion(ome_ip_address, authenticated_headers, config_inventory_refresh_job_1):
            print("Part 1 of configuration inventory refresh completed successfully.")
        else:
            print("Something went wrong. See text output above for more details.")

        # ------------------------------------------------------

        payload = {
            "JobDescription": "Create Inventory",
            "JobName": "Part 2 - API refresh config inventory",
            "JobType": {"Id": 8, "Name": "Inventory_Task"},
            "Params": [
                {"Key": "action", "Value": "CONFIG_INVENTORY"},
                {"Key": "isCollectDriverInventory", "Value": "true"}],
            "Schedule": "startnow",
            "StartTime": "",
            "State": "Enabled",
            "Targets": [{
                "Data": "",
                "Id": group_id,
                "JobId": -1,
                "TargetType": {"Id": 6000, "Name": "GROUP"}
            }]
        }

        print("Beginning part 2 of 2 of the configuration inventory refresh")
        create_resp = requests.post(jobs_url, headers=authenticated_headers, verify=False, data=json.dumps(payload))

        if create_resp.status_code == 201:
            config_inventory_refresh_job_2 = json.loads(create_resp.content)["Id"]
        else:
            print("Error: Failed to refresh inventory. We aren't sure what went wrong.")
            sys.exit(1)

        if config_inventory_refresh_job_2 is None:
            print("Received invalid job ID from OME for part 2 of the configuration inventory refresh... exiting.")
            sys.exit(1)

        print("Waiting for part 2 of the configuration inventory refresh to finish. "
              "This could take a couple of minutes.")
        if track_job_to_completion(ome_ip_address, authenticated_headers, config_inventory_refresh_job_2):
            print("Inventory refresh completed successfully.")
        else:
            print("Something went wrong. See text output above for more details.")

    print("Tracking standard inventory to completion.")
    if track_job_to_completion(ome_ip_address, authenticated_headers, job_id_generic_refresh):
        print("Inventory refresh completed successfully.")
    else:
        print("Something went wrong. See text output above for more details.")

    print("Inventory refresh complete!")


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for the OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for the OME Appliance")
    parser.add_argument("--groupname", "-g", required=False, default="All Devices",
                        help="The name of the group containing the devices whose inventory you want to refresh. "
                             "Defaults to all devices. Due to the way the API functions, if you want to refresh the "
                             "configuration inventory, you must have all applicable devices in a group. The "
                             "configuration inventory is specific to the tab called \"Configuration Inventory\" under "
                             "a device's view. You can use the create_static_group and add_device_to_static group "
                             "modules to do this programmatically.")
    parser.add_argument("--device-ids", "-d", help="A comma separated list of device-ids to refresh. Applies to "
                                                   "regular inventory only. This does not impact the configuration "
                                                   "inventory tab. That is controlled by the group name.")
    parser.add_argument("--service-tags", "-s", help="A comma separated list of service tags to refresh. Applies to "
                                                     "regular inventory only. This does not impact the configuration "
                                                     "inventory tab. That is controlled by the group name.")
    parser.add_argument("--idrac-ips", "-r", help="A comma separated list of idrac IPs to refresh. Applies to regular "
                                                  "inventory only. This does not impact the configuration inventory "
                                                  "tab. That is controlled by the group name.")
    parser.add_argument("--device-names", "-n", help="A comma separated list of device names to refresh. Applies to "
                                                     "regular inventory only. This does not impact the configuration "
                                                     "inventory tab. That is controlled by the group name.")
    parser.add_argument("--skip-config-inventory", "-skip", default=False, action='store_true',
                        help="The configuration inventory is the inventory you see specifically under the tab for a"
                             " specific device. In order to obtain a config inventory that server must be part of a"
                             " group or you have to run an inventory update against all devices which can be time "
                             "consuming. A regular inventory run will update things like firmware assuming that the"
                             " version change is reflected in idrac. A config inventory is launched in the GUI by "
                             "clicking \"Run inventory\" on quick links on the devices page. A regular inventory is "
                             "the same as clicking \"Run inventory\" on a specific device\'s page.")
    parser.add_argument("--ignore-group", default=False, action='store_true', help="Used when you only want to run a"
                        " regular inventory and you do not want to provide a group.")
    args = parser.parse_args()
    if not args.password:
        args.password = getpass()

    try:
        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        if args.device_ids:
            device_ids_arg = args.device_ids.split(',')
        else:
            device_ids_arg = None
        if args.service_tags:
            service_tags_arg = args.service_tags.split(',')
        else:
            service_tags_arg = None
        if args.idrac_ips:
            idrac_ips_arg = args.idrac_ips.split(',')
        else:
            idrac_ips_arg = None
        if args.device_names:
            device_names_arg = args.device_names.split(',')
        else:
            device_names_arg = None

        print("WARNING: To reflect firmware changes you may have to power cycle the server first before running this. "
              "It is situation dependent.")

        if args.groupname == 'All Devices':
            print("WARNING: No argument was provided for groupname. Defaulting to \'All Devices\' for the "
                  "inventory refresh. See help for details. This will also display if the argument  was manually set "
                  "to \'All Devices\' and can be safely ignored. If you do not want to use a group AND you do not want"
                  " to update the configuration inventory tab, use the --skip-config-inventory and --ignore-group"
                  " switches together. If you want to use a group to update regular inventories only and not the"
                  " configuration inventory tab use the --skip-config-inventory switch by itself.")

        refresh_device_inventory(headers, args.ip, args.groupname, args.skip_config_inventory, device_ids_arg,
                                 service_tags_arg, idrac_ips_arg, device_names_arg, args.ignore_group)

    except Exception as error:
        print("Unexpected error:", str(error))

