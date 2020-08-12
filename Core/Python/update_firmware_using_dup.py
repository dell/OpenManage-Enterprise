#
#  Python script using OME API to update firmware on devices
#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
# _version_ = 0.1
#
# Copyright (c) 2018 Dell EMC Corporation
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
SYNOPSIS
---------------------------------------------------------------------
 Script to update firmware for a device or applicable devices
 within a group

DESCRIPTION
---------------------------------------------------------------------
 This script exercises the OME REST API to allow updating a device
 or a group of devices by using a single DUP file.

 Note that the credentials entered are not stored to disk.

EXAMPLE
---------------------------------------------------------------------
python update_firmware_using_dup.py --ip <ip addr> --user admin
    --password <passwd> --groupid 25315
    --dupfile iDRAC-with-Lifecycle-Controller_Firmware_387FW_WN64_3.21.21.21_A00.EXE

Allow updating a device or a group of devices using
a single DUP file

API workflow is below:

1: POST on SessionService/Sessions
2: If new session is created (201) parse headers
   for x-auth token and update headers with token
3: All subsequent requests use X-auth token and not
   user name and password entered by user
4: Upload the DUP file to OME and retrieve a file
   token to use in subsequent requests
   POST on UpdateService.UploadFile
5: Determine device or groups that DUP file applies to
   using a POST on UpdateService.GetSingleDupReport
6: Create a firmware update task with the required targets
   using a POST on /api/JobService/Jobs
7: Parse returned job id and monitor it to completion
8: If job fails then GET Job Execution History Details
   and print info to screen
"""
import os
import sys
import copy
import time
import argparse
from argparse import RawTextHelpFormatter
import json
import urllib3
import requests


def authenticate_with_ome(ip_address, user_name, password):
    """ X-auth session creation """
    auth_success = False
    session_url = "https://%s/api/SessionService/Sessions" % (ip_address)
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
        print (error_msg.format(ip_address, session_info.status_code))
    return (auth_success, headers)


def get_group_list(ip_address, headers):
    """ Get list of groups from OME """
    group_list = None
    group_url = 'https://%s/api/GroupService/Groups' % (ip_address)
    response = requests.get(group_url, headers=headers, verify=False)
    if response.status_code == 200:
        group_response = response.json()
        if group_response['@odata.count'] > 0:
            group_list = [x['Id'] for x in group_response['value']]
        else:
            print ("No groups found at ", ip_address)
    else:
        print ("No groups found at ", ip_address)
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
				next_link_url = 'https://%s/' %ip_address + dev_json_response['@odata.nextLink']

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
                print ("Uploading %s .. This may take a while" % file_path)
                response = requests.post(url, data=payload, verify=False,
                                         headers=curr_headers)
                if response.status_code == 200:
                    upload_success = True
                    token = str(response.text)
                    print ("Successfully uploaded ", file_path)
                else:
                    print ("Unable to upload %s to %s" % (file_path, ip_address))
                    print ("Request Status Code = %s" % response.status_code)
        else:
            print ("File %s seems to be empty ... Exiting" % file_path)

    else:
        print ("File not found ... Retry")
    return (upload_success, token)


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
                print ("\n---------------------------------------------------")
                print ("Device =", device_name)
                print ("IPAddress =", device_ip)
                print ("Current Ver =", curr_ver)
                print ("Avail Ver =", avail_ver)
                print ("Action =", upd_action)
                print ("Criticality =", update_crit)
                print ("Reboot Req =", reboot_req)
                print ("Component Name =", comp_name)

                if avail_ver > curr_ver:
                    temp_map = {}
                    temp_map['Id'] = device['DeviceId']
                    temp_map['Data'] = str(component['ComponentSourceName']) + "=" + file_token
                    temp_map['TargetType'] = {}
                    temp_map['TargetType']['Id'] = int(device['DeviceReport']['DeviceTypeId'])
                    temp_map['TargetType']['Name'] = str(device['DeviceReport']['DeviceTypeName'])
                    target_data.append(temp_map)
                    #print "%s : Adding component %s to upgrade list" % (device_ip, comp_name)
    else:
        print ("Unable to get components DUP applies to .. Exiting")
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
        print ("Successfully spawned update job", job_id)
    else:
        print ("Unable to spawn update job .. Exiting")
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
    print ("Polling %s to completion ..." % job_id)
    while loop_ctr < max_retries:
        loop_ctr += 1
        time.sleep(sleep_interval)
        job_resp = requests.get(job_url, headers=headers, verify=False)
        if job_resp.status_code == 200:
            job_status = str((job_resp.json())['LastRunStatus']['Id'])
            print ("Iteration %s: Status of %s is %s" % (loop_ctr, job_id, job_status_map[job_status]))
            if int(job_status) == 2060:
                job_incomplete = False
                print ("Completed updating firmware successfully ... Exiting")
                break
            elif int(job_status) in failed_job_status:
                job_incomplete = False
                print ("Update job failed ... ")
                job_hist_url = str(job_url) + "/ExecutionHistories"
                job_hist_resp = requests.get(job_hist_url, headers=headers, verify=False)
                if job_hist_resp.status_code == 200:
                    job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
                    job_hist_det_url = str(job_hist_url) + "(" + job_history_id + ")/ExecutionHistoryDetails"
                    job_hist_det_resp = requests.get(job_hist_det_url,
                                                     headers=headers,
                                                     verify=False)
                    if job_hist_det_resp.status_code == 200:
                        print (job_hist_det_resp.text)
                    else:
                        print ("Unable to parse job execution history .. Exiting")
                break
        else:
            print ("Unable to poll status of %s - Iteration %s " % (job_id, loop_ctr))
    if job_incomplete:
        print ("Job %s incomplete after polling %s times...Check status" % (job_id, max_retries))

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", required=True,
                        help="Username for OME Appliance",
                        default="admin")
    PARSER.add_argument("--password", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--dupfile", required=True,
                        help="Path to DUP file that will be flashed")
    MUTEX_GROUP = PARSER.add_mutually_exclusive_group(required=True)
    MUTEX_GROUP.add_argument("--groupid", type=int,
                             help="Id of the group to update")
    MUTEX_GROUP.add_argument("--deviceid", type=int,
                             help="Id of the device to update")
    ARGS = PARSER.parse_args()
    IP_ADDRESS = ARGS.ip
    USER_NAME = ARGS.user
    PASSWORD = ARGS.password
    DUP_FILE = ARGS.dupfile
    PARAM_MAP = {}
    TARGET_DATA = []
    try:
        AUTH_SUCCESS, HEADERS = authenticate_with_ome(IP_ADDRESS, USER_NAME,
                                                      PASSWORD)
        if AUTH_SUCCESS:
            if ARGS.groupid:
                GROUP_ID = ARGS.groupid
                PARAM_MAP['group_id'] = GROUP_ID
                PARAM_MAP['device_id'] = None
                GROUP_LIST = get_group_list(IP_ADDRESS, HEADERS)
                if GROUP_LIST:
                    if GROUP_ID in GROUP_LIST:
                        pass
                    else:
                        raise ValueError("Group %s not found on %s ... Exiting" % (GROUP_ID, IP_ADDRESS))

            else:
                DEVICE_ID = ARGS.deviceid
                PARAM_MAP['device_id'] = DEVICE_ID
                PARAM_MAP['group_id'] = None
                DEVICE_LIST = get_device_list(IP_ADDRESS, HEADERS)
                if DEVICE_LIST:
                    if DEVICE_ID in DEVICE_LIST:
                        pass
                    else:
                        raise ValueError("Device %s not found on %s ... Exiting" % (DEVICE_ID, IP_ADDRESS))

            UPLOAD_SUCCESS, FILE_TOKEN = upload_dup_file(IP_ADDRESS, HEADERS,
                                                         DUP_FILE)
            if UPLOAD_SUCCESS:
                REPORT_PAYLOAD = get_dup_applicability_payload(FILE_TOKEN, PARAM_MAP)
                if REPORT_PAYLOAD:
                    print ("Determining which components the DUP file applies to ... ")
                    TARGET_DATA = get_applicable_components(IP_ADDRESS,
                                                            HEADERS,
                                                            REPORT_PAYLOAD)
                    if TARGET_DATA:
                        print ("Forming job payload for update ... ")
                        JOB_PAYLOAD = form_job_payload_for_update(TARGET_DATA)
                        JOB_ID = spawn_update_job(IP_ADDRESS,
                                                  HEADERS,
                                                  JOB_PAYLOAD)
                        if JOB_ID != -1:
                            track_job_to_completion(IP_ADDRESS, HEADERS,
                                                    JOB_ID)
                    else:
                        print ("No components available for update ... Exiting")
        else:
            print ("Unable to authenticate with OME .. Check IP/Username/Pwd")
    except:
        print ("Unexpected error:", sys.exc_info())
