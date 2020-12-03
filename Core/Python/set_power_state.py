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

"""
#### Synopsis
Script to change the power state of a device, set of devices, and/or group in OME.

#### Description
This script employs the OME REST API to perform power control operations. It accepts idrac IPs, group names, device
names, service tags, or device ids as arguments. It can optionally write the output of the operation to a CSV file.
For authentication X-Auth is used over Basic Authentication. Note that the credentials entered are not stored to disk.

#### Python Example
'''
python set_power_state.py --ip 192.168.1.93 --password somepass --groupname Test --idrac-ips 192.168.1.45 --state {state} --csv-file test.csv
python set_power_state.py --ip 192.168.1.93 --password somepass --groupname Test --device-names 格蘭特,192.168.1.63 --state {state}
'''
where {state} can be "POWER_ON", "POWER_OFF_GRACEFUL", "POWER_CYCLE", "POWER_OFF_NON_GRACEFUL", "MASTER_BUS_RESET"
"""

import argparse
import json
import sys
import time
import csv
from pprint import pprint
from urllib.parse import urlparse
from argparse import RawTextHelpFormatter
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


def power_control_servers(device_targets: list, authenticated_headers: dict, ome_ip: str, desired_power_state: int,
                          target_group_id: int = None) -> bool:
    """
    This function handles changing the power state of a device

    Args:
        device_targets: The targets whose power state you want to change.
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip: The IP address of the OME server
        desired_power_state: The power state to which you would like to set devices
        target_group_id: (optional) The group ID of a group of devices whose power state you want to change

    Returns: Returns true if the power change was successful or false otherwise
    """

    jobs_url = "https://%s/api/JobService/Jobs" % ome_ip

    targets = []
    for id_to_refresh in device_targets:
        targets.append({
            "Id": int(id_to_refresh),
            "Data": "",
            "TargetType": {
                "Id": 1000,
                "Name": "DEVICE"
            }
        })

    if target_group_id:
        targets.append(
            {
                "Data": "",
                "Id": target_group_id,
                "TargetType": {"Id": 6000, "Name": "GROUP"}
            }
        )

    payload = {
        "Id": 0,
        "JobName": "Power operation",
        "JobDescription": "Performing a power operation",
        "State": "Enabled",
        "Schedule": "startnow",
        "JobType": {
            "Name": "DeviceAction_Task"
        },
        "Targets": targets,
        "Params": [{
            "Key": "override",
            "Value": "true"
        }, {
            "Key": "powerState",
            "Value": desired_power_state
        }, {
            "Key": "operationName",
            "Value": "POWER_CONTROL"
        }, {
            "Key": "deviceTypes",
            "Value": "1000"
        }]}

    create_resp = requests.post(jobs_url, headers=authenticated_headers, verify=False, data=json.dumps(payload))

    if create_resp.status_code == 201:
        job_id = json.loads(create_resp.content)["Id"]
    else:
        print("Error: Power operation failed. Error was " + str(json.loads(create_resp.content)))
        return False

    if job_id is None:
        print("Error: Received invalid job ID from OME. Exiting.")
        return False

    print("Waiting for the power operation to complete.")
    job_status = track_job_to_completion(ome_ip, authenticated_headers, job_id, sleep_interval=15)
    print("Power operation completed.")

    return job_status


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


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", required=True, help="OME Appliance IP")
    parser.add_argument("--user", required=False,
                        help="Username for OME Appliance",
                        default="admin")
    parser.add_argument("--password", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--groupname", "-g", required=False, default="All Devices",
                        help="The name of the group containing the devices whose power state you want to change.")
    parser.add_argument("--device-ids", "-d", help="A comma separated list of device-ids whose power state you want to"
                                                   " change.")
    parser.add_argument("--service-tags", "-s", help="A comma separated list of service tags whose power state you "
                                                     "want to change.")
    parser.add_argument("--idrac-ips", "-r", help="A comma separated list of idrac IPs whose power state you want to"
                                                  " change.")
    parser.add_argument("--device-names", "-n", help="A comma separated list of device names whose power state you want"
                                                     " to change.")
    parser.add_argument("--csv-file", required=False, help="Optional. If you want to write the output to an CSV you"
                                                           " can use this.")
    parser.add_argument("--state", required=True,
                        choices=("POWER_ON", "POWER_OFF_GRACEFUL", "POWER_CYCLE", "POWER_OFF_NON_GRACEFUL",
                                 "MASTER_BUS_RESET"), help="Type of power operation you would like to perform.")
    args = parser.parse_args()
    if not args.password:
        args.password = getpass()

    POWER_STATE_MAPPING = {
        "Power On": "2",
        "Power Cycle": "5",
        "Power Off Non-Graceful": "8",
        "Master Bus Reset": "10",  # Performs hardware reset on the system. (warm boot)
        "Power Off Graceful": "12"
    }

    POWER_STATE_MAP = {17: "Powered On", 18: "Powered Off", 20: "Powering On", 21: "Powering Off"}

    try:
        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

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

        group_id = None
        group_url = "https://%s/api/GroupService/Groups" % args.ip
        if args.groupname:
            groups = get_data(headers, group_url, "Name eq '%s'" % args.groupname)

            if len(groups) < 1:
                print("Error: We were unable to find a group matching the name %s." % args.groupname)
                sys.exit(0)

            group_id = groups[0]['Id']
        else:
            groups = None

        if device_ids_arg is None and service_tags is None and device_idrac_ips is None and device_names is None\
                and args.groupname is None:
            print("Error: You must provide one or more of the following: device IDs, service tags, idrac IPs, or "
                  "device names.")
            sys.exit(0)

        if args.state == 'POWER_ON':
            power_state = POWER_STATE_MAPPING["Power On"]
            print("Powering on servers...")
        elif args.state == 'POWER_CYCLE':
            power_state = POWER_STATE_MAPPING["Power Cycle"]
            print("Power cycling servers...")
        elif args.state == 'POWER_OFF_NON_GRACEFUL':
            power_state = POWER_STATE_MAPPING["Power Off Non-Graceful"]
            print("Non-gracefully shutting down servers...")
        elif args.state == 'MASTER_BUS_RESET':
            power_state = POWER_STATE_MAPPING["Master Bus Reset"]
            print("Performing a master bus reset on the servers...")
        elif args.state == 'POWER_OFF_GRACEFUL':
            power_state = POWER_STATE_MAPPING["Power Off Graceful"]
            print("Performing a graceful shutdown on the servers...")
        else:
            power_state = -1

        if power_control_servers(target_ids, headers, args.ip, power_state, group_id):
            print("Power state changed successfully!")
        else:
            print("Error: There was a problem changing device power state. See the output above for details.")

        if group_id:
            group_devices = get_data(headers, group_url + "(%s)/Devices" % group_id)

            if len(group_devices) < 1:
                print("Error: There was a problem retrieving the devices for group " + args.groupname + ". Exiting")
                sys.exit(0)

            for device in group_devices:
                target_ids.append(device['Id'])

        device_power_states = []
        for device_id in target_ids:
            device_status = get_data(headers, "https://%s/api/DeviceService/Devices(%s)" % (args.ip, device_id))
            device_power_state = {'OME ID': device_status['Id'], 'Identifier': device_status['Identifier'],
                                  'Model': device_status['Model'], 'Device Name': device_status['DeviceName'],
                                  'idrac IP': device_status['DeviceManagement'][0]['NetworkAddress'],
                                  'Power State': POWER_STATE_MAP[device_status['PowerState']]}
            device_power_states.append(device_power_state)

        if args.csv_file:
            # Use UTF 8 in case there are non-ASCII characters like 格蘭特
            print("Writing CSV to file...")
            with open(args.csv_file, 'w', encoding='utf-8', newline='') as csv_file:
                csv_columns = ["OME ID", "Identifier", "Model", "Device Name", "idrac IP", "Power State"]
                writer = csv.DictWriter(csv_file, fieldnames=csv_columns, extrasaction='ignore')
                writer.writeheader()
                for device in device_power_states:
                    writer.writerow(device)
        else:
            pprint(device_power_states)

    except Exception as error:
        pprint(error)


