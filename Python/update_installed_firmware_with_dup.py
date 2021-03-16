#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
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
 Script to update firmware for a device or applicable devices
 within a group using a DUP

#### Description
 This script uses the OME REST API to allow updating a device
 or a group of devices by using a single DUP file.

 Note that the credentials entered are not stored to disk.

#### Python Example

    python update_installed_firmware_with_dup.py --ip <ip addr> --user admin
        --password <passwd> --groupid 25315
        --dupfile iDRAC-with-Lifecycle-Controller_Firmware_387FW_WN64_3.21.21.21_A00.EXE

#### API workflow:

1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
   for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
   user name and password entered by user
4. Upload the DUP file to OME and retrieve a file
   token to use in subsequent requests
   POST on UpdateService.UploadFile
5. Determine device or groups that DUP file applies to
   using a POST on UpdateService.GetSingleDupReport
6. Create a firmware update task with the required targets
   using a POST on /api/JobService/Jobs
7. Parse returned job id and monitor it to completion
8. If job fails then GET Job Execution History Details
   and print info to screen
"""
import argparse
import copy
import json
import os
import sys
import time
from argparse import RawTextHelpFormatter
from getpass import getpass

import requests
import urllib3


def authenticate_with_ome(ip_address, user_name, password):
    """ X-auth session creation """
    auth_success = False
    session_url = "https://%s/api/SessionService/Sessions" % ip_address
    user_details = {'UserName': user_name,
                    'Password': password,
                    'SessionType': 'API'}
    headers = {'content-type': 'application/json'}
    session_info = requests.post(session_url, verify=False,
                                 data=json.dumps(user_details),
                                 headers=headers)
    if session_info.status_code == 201:
        headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        auth_success = True
    else:
        error_msg = "Failed create of session with {0} - Status code = {1}"
        print(error_msg.format(ip_address, session_info.status_code))
    return auth_success, headers


def get_group_list(ip_address, headers):
    """ Get list of groups from OME """
    group_list = None
    group_url = 'https://%s/api/GroupService/Groups' % ip_address
    response = requests.get(group_url, headers=headers, verify=False)
    if response.status_code == 200:
        group_response = response.json()
        if group_response['@odata.count'] > 0:
            group_list = [x['Id'] for x in group_response['value']]
        else:
            print("No groups found at ", ip_address)
    else:
        print("No groups found at ", ip_address)
    return group_list


def get_device_list(ip_address, headers):
    """ Get list of devices from OME """
    ome_device_list = []
    next_link_url = 'https://%s/api/DeviceService/Devices' % ip_address
    while next_link_url is not None:
        device_response = requests.get(next_link_url, headers=headers, verify=False)
        next_link_url = None
        if device_response.status_code == 200:
            dev_json_response = device_response.json()
            if dev_json_response['@odata.count'] <= 0:
                print("No devices found at ", ip_address)
                return

            if '@odata.nextLink' in dev_json_response:
                next_link_url = 'https://%s/' % ip_address + dev_json_response['@odata.nextLink']

            if dev_json_response['@odata.count'] > 0:
                ome_device_list = ome_device_list + [x['Id'] for x in dev_json_response['value']]
        else:
            print("No devices found at ", ip_address)

    return ome_device_list


def upload_dup_file(ip_address, headers, file_path):
    """ Upload DUP file to OME and get a file token in return """
    token = None
    upload_success = False
    url = 'https://%s/api/UpdateService/Actions/UpdateService.UploadFile' % ip_address
    curr_headers = copy.deepcopy(headers)
    curr_headers['content-type'] = 'application/octet-stream'
    if os.path.isfile(file_path):
        if os.path.getsize(file_path) > 0:
            with open(file_path, 'rb') as payload:
                print("Uploading %s .. This may take a while" % file_path)
                response = requests.post(url, data=payload, verify=False,
                                         headers=curr_headers)
                if response.status_code == 200:
                    upload_success = True
                    token = str(response.text)
                    print("Successfully uploaded ", file_path)
                else:
                    print("Unable to upload %s to %s" % (file_path, ip_address))
                    print("Request Status Code = %s" % response.status_code)
        else:
            print("File %s seems to be empty ... Exiting" % file_path)

    else:
        print("File not found ... Retry")
    return upload_success, token


def get_dup_applicability_payload(file_token, param_map):
    """ Returns the DUP applicability JSON payload """
    dup_applicability_payload = {'SingleUpdateReportBaseline': [],
                                 'SingleUpdateReportGroup': [],
                                 'SingleUpdateReportTargets': [],
                                 'SingleUpdateReportFileToken': file_token
                                 }

    if param_map['group_id']:
        dup_applicability_payload['SingleUpdateReportGroup'].append(param_map['group_id'])
    elif param_map['device_id']:
        dup_applicability_payload['SingleUpdateReportTargets'].append(param_map['device_id'])
    else:
        pass
    return dup_applicability_payload


def get_applicable_components(ip_address, headers, dup_payload):
    """ Get the target array to be used in spawning jobs for update """
    # Parse the single dup update report and print out versions needing
    # an update. In addition add them to the target_data as needed for
    # the job payload
    target_data = []
    dup_url = 'https://%s/api/UpdateService/Actions/UpdateService.GetSingleDupReport' % ip_address
    dup_resp = requests.post(dup_url, headers=headers,
                             data=json.dumps(dup_payload), verify=False)
    if dup_resp.status_code == 200:
        dup_data = dup_resp.json()
        file_token = str(dup_payload['SingleUpdateReportFileToken'])
        for device in dup_data:
            device_name = str(device['DeviceReport']['DeviceServiceTag'])
            device_ip = str(device['DeviceReport']['DeviceIPAddress'])
            for component in device['DeviceReport']['Components']:
                curr_ver = str(component['ComponentCurrentVersion'])
                avail_ver = str(component['ComponentVersion'])
                upd_action = str(component['ComponentUpdateAction'])
                update_crit = str(component['ComponentCriticality'])
                reboot_req = str(component['ComponentRebootRequired'])
                comp_name = str(component['ComponentName'])
                print("\n---------------------------------------------------")
                print("Device =", device_name)
                print("IPAddress =", device_ip)
                print("Current Ver =", curr_ver)
                print("Avail Ver =", avail_ver)
                print("Action =", upd_action)
                print("Criticality =", update_crit)
                print("Reboot Req =", reboot_req)
                print("Component Name =", comp_name)

                if avail_ver > curr_ver:
                    temp_map = {'Id': device['DeviceId'],
                                'Data': str(component['ComponentSourceName']) + "=" + file_token, 'TargetType': {}}
                    temp_map['TargetType']['Id'] = int(device['DeviceReport']['DeviceTypeId'])
                    temp_map['TargetType']['Name'] = str(device['DeviceReport']['DeviceTypeName'])
                    target_data.append(temp_map)
    else:
        print("Unable to get components DUP applies to .. Exiting")
    return target_data


def form_job_payload_for_update(target_data):
    """ Formulate the payload to initiate a firmware update job """
    payload = {
        "Id": 0,
        "JobName": "Firmware Update Task",
        "JobDescription": "dup test",
        "Schedule": "startnow",
        "State": "Enabled",
        "CreatedBy": "admin",
        "JobType": {
            "Id": 5,
            "Name": "Update_Task"
        },
        "Targets": target_data,
        "Params": [
            {
                "JobId": 0,
                "Key": "operationName",
                "Value": "INSTALL_FIRMWARE"
            },
            {
                "JobId": 0,
                "Key": "complianceUpdate",
                "Value": "false"
            },
            {
                "JobId": 0,
                "Key": "stagingValue",
                "Value": "false"
            },
            {
                "JobId": 0,
                "Key": "signVerify",
                "Value": "true"
            }
        ]
    }
    return payload


def spawn_update_job(ip_address, headers, job_payload):
    """ Spawns an update job and tracks it to completion """
    job_id = -1
    job_url = 'https://%s/api/JobService/Jobs' % ip_address
    job_resp = requests.post(job_url, headers=headers,
                             json=job_payload,
                             verify=False)
    if job_resp.status_code == 201:
        job_id = (job_resp.json())['Id']
        print("Successfully spawned update job", job_id)
    else:
        print("Unable to spawn update job .. Exiting")
    return job_id


def track_job_to_completion(ip_address, headers, job_id):
    """ Tracks the update job to completion / error """
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

    max_retries = 20
    sleep_interval = 60
    failed_job_status = [2070, 2090, 2100, 2101, 2102, 2103]
    job_url = 'https://%s/api/JobService/Jobs(%s)' % (ip_address, job_id)
    loop_ctr = 0
    job_incomplete = True
    print("Polling %s to completion ..." % job_id)
    while loop_ctr < max_retries:
        loop_ctr += 1
        time.sleep(sleep_interval)
        job_resp = requests.get(job_url, headers=headers, verify=False)
        if job_resp.status_code == 200:
            job_status = str((job_resp.json())['LastRunStatus']['Id'])
            print("Iteration %s: Status of %s is %s" % (loop_ctr, job_id, job_status_map[job_status]))
            if int(job_status) == 2060:
                job_incomplete = False
                print("Completed updating firmware successfully ... Exiting")
                break
            elif int(job_status) in failed_job_status:
                job_incomplete = False
                print("Update job failed ... ")
                job_hist_url = str(job_url) + "/ExecutionHistories"
                job_hist_resp = requests.get(job_hist_url, headers=headers, verify=False)
                if job_hist_resp.status_code == 200:
                    job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
                    job_hist_det_url = str(job_hist_url) + "(" + job_history_id + ")/ExecutionHistoryDetails"
                    job_hist_det_resp = requests.get(job_hist_det_url,
                                                     headers=headers,
                                                     verify=False)
                    if job_hist_det_resp.status_code == 200:
                        print(job_hist_det_resp.text)
                    else:
                        print("Unable to parse job execution history .. Exiting")
                break
        else:
            print("Unable to poll status of %s - Iteration %s " % (job_id, loop_ctr))
    if job_incomplete:
        print("Job %s incomplete after polling %s times...Check status" % (job_id, max_retries))


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", required=True, help="OME Appliance IP")
    parser.add_argument("--user", required=False,
                        help="Username for OME Appliance",
                        default="admin")
    parser.add_argument("--password", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--dupfile", required=True,
                        help="Path to DUP file that will be flashed")
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument("--groupid", type=int,
                             help="Id of the group to update")
    mutex_group.add_argument("--deviceid", type=int,
                             help="Id of the device to update")
    args = parser.parse_args()
    ip_address = args.ip
    user_name = args.user

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

    dup_file = args.dupfile
    param_map = {}
    target_data = []
    try:
        auth_success, headers = authenticate_with_ome(ip_address, user_name,
                                                      password)
        if auth_success:
            if args.groupid:
                group_id = args.groupid
                param_map['group_id'] = group_id
                param_map['device_id'] = None
                group_list = get_group_list(ip_address, headers)
                if group_list:
                    if group_id in group_list:
                        pass
                    else:
                        raise ValueError("Group %s not found on %s ... Exiting" % (group_id, ip_address))

            else:
                device_id = args.deviceid
                param_map['device_id'] = device_id
                param_map['group_id'] = None
                device_list = get_device_list(ip_address, headers)
                if device_list:
                    if device_id in device_list:
                        pass
                    else:
                        raise ValueError("Device %s not found on %s ... Exiting" % (device_id, ip_address))

            upload_success, file_token = upload_dup_file(ip_address, headers,
                                                         dup_file)
            if upload_success:
                report_payload = get_dup_applicability_payload(file_token, param_map)
                if report_payload:
                    print("Determining which components the DUP file applies to ... ")
                    target_data = get_applicable_components(ip_address,
                                                            headers,
                                                            report_payload)
                    if target_data:
                        print("Forming job payload for update ... ")
                        job_payload = form_job_payload_for_update(target_data)
                        job_id = spawn_update_job(ip_address,
                                                  headers,
                                                  job_payload)
                        if job_id != -1:
                            track_job_to_completion(ip_address, headers,
                                                    job_id)
                    else:
                        print("No components available for update ... Exiting")
        else:
            print("Unable to authenticate with OME .. Check IP/Username/Pwd")
    except Exception as error:
        print("Unexpected error:", str(error))
