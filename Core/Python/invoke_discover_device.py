#
# _maintainer_ = Grant Curell <grant_curell@dell.com>
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
"""
#### Synopsis
Script to discover devices managed by OME Enterprise

#### Description

Currently the PowerShell version of this script offers substantially more capability. See:
https://github.com/dell/OpenManage-Enterprise/issues/119

**Python**
This script uses the OME REST API to discover devices.
For authentication X-Auth is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

**PowerShell**
This script currently allows the discovery of servers, chassis, and network devices. Storage devices are not
currently supported. If it would be helpful to you leave a comment on
https://github.com/dell/OpenManage-Enterprise/issues/114 to let us know this is a priority for you. Currently only
SNMPv2c is supported for network devices. It does not support SNMPv1 and OME does not currently support SNMPv3. If
SNMPv1 is a priority for you please open an issue at https://github.com/dell/OpenManage-Enterprise/issues.

#### Python Example
```bash
python invoke_discover_device.py --ip <ip addr> --user admin
--password <passwd> --targetUserName <user name>
--targetPassword <password> --deviceType <{Device_Type}>
--targetIpAddresses <10.xx.xx.x,10.xx.xx.xx-10.yy.yy.yy,10.xx.xx.xx> or --targetIpAddrCsvFile xyz.csv
```
where {Device_Type} can be server,chassis
"""

import argparse
import csv
import json
import os
import sys
import time
from urllib.parse import urlparse
from argparse import RawTextHelpFormatter
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


def get_discover_device_payload() -> dict:
    """
    Creates the payload needed to discover device payloads

    Returns: A dictionary containing the payload required for discovering devices
    """
    discovery_config_details = {
        "server": {
            "DiscoveryConfigGroupName": "Server Discovery",
            "DiscoveryConfigModels": [
                {
                    "DiscoveryConfigTargets": [
                        {
                            "NetworkAddressDetail": ""
                        }],
                    "ConnectionProfile": "{\"profileName\":\"\",\"profileDescription\": \
                          \"\",\"type\":\"DISCOVERY\",\"credentials\" :[{\"type\":\
                           \"WSMAN\",\"authType\":\"Basic\",\"modified\":false,\"credentials\":\
                           {\"username\":\"\",\"password\":\"\",\"port\":443,\"retries\":3,\"timeout\":\
                           60}}]}",
                    "DeviceType": [1000]}],
            "Schedule": {
                "RunNow": True,
                "Cron": "startnow"
            }
        },
        "network_switch": {
            "DiscoveryConfigGroupName": "Network switch Discovery ",
            "DiscoveryConfigModels": [{
                "DiscoveryConfigTargets": [
                    {
                        "NetworkAddressDetail": ""
                    }],
                "ConnectionProfile": "{\"profileName\" : \"\",\"profileDescription\" :\
                      \"\",  \"type\" : \"DISCOVERY\",\"credentials\" : [ {\"type\" :\
                      \"SNMP\",\"authType\" : \"Basic\",\"modified\" : false,\"credentials\" :\
                      {\"community\" : \"public\",\"port\" : 161,\"enableV3\" :\
                      false,\"enableV1V2\" : true,\"retries\" : 3,\"timeout\" : 60}} ]}",
                "DeviceType": [7000]}],
            "Schedule": {
                "RunNow": True,
                "Cron": "startnow"
            }
        },
        "dell_storage": {
            "DiscoveryConfigGroupName": "Storage Discovery",
            "DiscoveryConfigModels": [{
                "DiscoveryConfigTargets": [
                    {
                        "NetworkAddressDetail": ""
                    }],
                "ConnectionProfile": "{\"profileName\" : \"\",\"profileDescription\" : \
                      \"\",  \"type\" : \"DISCOVERY\",\"credentials\" : [ {\"type\" : \
                      \"SNMP\",\"authType\" : \"Basic\",\"modified\" : false,\"credentials\" : \
                      {\"community\" : \"public\",\"port\" : 161,\"enableV3\" : \
                      false,\"enableV1V2\" : true,\"retries\" : 3,\"timeout\" : 60}} ]}",
                "DeviceType": [5000]}],
            "Schedule": {
                "RunNow": True,
                "Cron": "startnow"
            }
        },
        "chassis": {
            "DiscoveryConfigGroupName": "Chassis Discovery",
            "DiscoveryConfigModels": [{
                "DiscoveryConfigTargets": [
                    {
                        "NetworkAddressDetail": ""
                    }],
                "ConnectionProfile": "{\"profileName\":\"\",\"profileDescription\":\
             \"\",\"type\":\"DISCOVERY\",\"credentials\" :[{\"type\":\
             \"WSMAN\",\"authType\":\"Basic\",\"modified\":false,\"credentials\":\
             {\"username\":\"\",\"password\":\"\",\"port\":443,\"retries\":3,\"timeout\":\
             60}}]}",
                "DeviceType": [2000]}],
            "Schedule": {
                "RunNow": True,
                "Cron": "startnow"}
        }
    }

    return discovery_config_details


def discover_device(ome_ip_address,
                    authenticated_headers,
                    device_discover_username,
                    device_discover_password,
                    list_of_device_ips,
                    device_type) -> requests.models.Response:
    """
    Discovers devices and adds them to the target OME instance

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        device_discover_username: Username for the targeted device(s)
        device_discover_password: Password for the targeted device(s)
        list_of_device_ips: A list of IP addresses you want to discover
        device_type: The type of device to be discovered

    Returns: Returns a response object containing the details of the discovery job from the server

    """
    discover_payloads = get_discover_device_payload()
    discover_payload = discover_payloads.get(device_type)
    discover_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"][:] = []
    for ip_adds in list_of_device_ips:
        if ip_adds != ' ':
            discover_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"].append(
                {"NetworkAddressDetail": ip_adds})
    if device_type in ('server', 'chassis'):
        connection_profile = json.loads(discover_payload["DiscoveryConfigModels"][0]["ConnectionProfile"])
        connection_profile['credentials'][0]['credentials']['username'] = device_discover_username
        connection_profile['credentials'][0]['credentials']['password'] = device_discover_password
        discover_payload["DiscoveryConfigModels"][0]["ConnectionProfile"] = json.dumps(connection_profile)
    pprint(discover_payload)
    url = 'https://%s/api/DiscoveryConfigService/DiscoveryConfigGroups' % ome_ip_address
    discover_resp = requests.post(url, headers=authenticated_headers,
                                  data=json.dumps(discover_payload), verify=False)
    print(type(discover_resp))
    return discover_resp


def get_job_id(ome_ip_address, authenticated_headers, discovery_config_group_id) -> int:
    """
    Get job id

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        discovery_config_group_id: The group ID of all devices being discovered as part of this job

    Returns: An integer containing the job ID or -1 if the job ID could not be found
    """

    job_id = -1
    url = 'https://%s/api/DiscoveryConfigService/Jobs' % ome_ip_address
    job_resp = requests.get(url, headers=authenticated_headers, verify=False)
    if job_resp.status_code == 200:
        job_resp_object = job_resp.json()
        if job_resp_object['@odata.count'] > 0:
            for value_object in job_resp_object['value']:
                if value_object['DiscoveryConfigGroupId'] == discovery_config_group_id:
                    job_id = value_object['JobId']
                    break
        else:
            print("unable to get job id " + job_resp_object)
    else:
        print("unable to get job id.Status code:  " + str(job_resp.status_code))

    return job_id


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
        job_resp = get_data(authenticated_headers, job_url)
        requests.get(job_url, headers=authenticated_headers, verify=False)

        try:
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
        except AttributeError:
            print("There was a problem getting the job info during the wait. Full error details:")
            pprint(job_resp.json())
            return False

    if job_incomplete:
        print("Job %s incomplete after polling %s times...Check status" % (tracked_job_id, loop_ctr))
        return False

    return True


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", required=True, help="OME Appliance IP")
    parser.add_argument("--user", required=False,
                        help="Username for OME Appliance",
                        default="admin")
    parser.add_argument("--password", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--targetUserName", required=True,
                        help="Username to discover devices")
    parser.add_argument("--targetPassword", required=False,
                        help="Password to discover devices")
    parser.add_argument("--deviceType", required=True,
                        choices=('server', 'chassis'),
                        help="Device Type  to discover devices")
    MUTEX_GROUP = parser.add_mutually_exclusive_group(required=True)
    MUTEX_GROUP.add_argument("--targetIpAddresses",
                             help="Array of Ip address to discover devices ")
    MUTEX_GROUP.add_argument("--targetIpAddrCsvFile",
                             help="Path to Csv file that contains IP address to discover devices")
    args = parser.parse_args()
    ip_address = args.ip
    user_name = args.user
    if args.password:
        password = args.password
    else:
        password = getpass("Password for OME Appliance: ")
    discover_user_name = args.targetUserName
    if args.targetPassword:
        discover_password = args.targetPassword
    else:
        discover_password: getpass("Password to discover devices: ")
    ip_array = args.targetIpAddresses
    csv_file_path = args.targetIpAddrCsvFile
    device_type = args.deviceType
    list_of_ip = []
    list_of_ipaddresses = []
    if ip_array:
        list_of_ip = ip_array.split(',')
    else:
        if os.path.isfile(csv_file_path):
            if os.path.getsize(csv_file_path) > 0:
                csv_file = open(csv_file_path, 'r')
                csv_data = csv.reader(csv_file)
                csv_list = list(csv_data)
                for csv_data in csv_list:
                    for ip in csv_data:
                        list_of_ip.append(ip)
            else:
                print("File %s seems to be empty ... Exiting" % csv_file_path)
        else:
            raise Exception("File not found ...  Retry")

    for ip in list_of_ip:
        if '-' in ip:
            ips = ip.split('-')
        else:
            ips = ip
        if isinstance(ips, list):
            for ip in ips:
                list_of_ipaddresses.append(ip)
        else:
            list_of_ipaddresses.append(ips)
        for ip_addr in list_of_ipaddresses:
            ip_bytes = ip_addr.split('.')
            if len(ip_bytes) != 4:
                raise Exception("Invalid IP address " + ip_addr + " Example of valid ip  192.168.1.0")
            for ip_byte in ip_bytes:
                if not ip_byte.isdigit():
                    raise Exception("Invalid IP address" + ip_addr +
                                    " Only digits are allowed. Example of valid ip 192.168.1.0")
                octet = int(ip_byte)
                if octet < 0 or octet > 255:
                    raise Exception(
                        "Invalid IP address " + ip_addr +
                        " single byte must be 0 <= byte < 256. Example of valid ip 192.168.1.0")

    try:
        headers = authenticate(ip_address, user_name, password)

        discovery_resp = discover_device(ip_address, headers,
                                         discover_user_name, discover_password,
                                         list_of_ip, device_type)
        if discovery_resp.status_code == 201:
            print("Discovering devices.....")
            time.sleep(30)
            discovery_config_group_id = (discovery_resp.json())["DiscoveryConfigGroupId"]
            job_id = get_job_id(ip_address, headers, discovery_config_group_id)
            if job_id != -1:
                track_job_to_completion(ip_address, headers, job_id)
            else:
                print("There was a problem retrieving the job ID for discovery. Exiting.")
        else:
            print("unable to discover devices ", discovery_resp.text)

    except Exception as error:
        print("Unexpected error:", str(error))
