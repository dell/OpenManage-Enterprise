#
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
Script to perform template deployment on the target devices.

#### Description:
This script performs template deployment. Note that the credentials entered are not stored to disk.

#### Python Example
`python set_system_configuration.py --ip <ip addr> --user admin
    --password <passwd> --sourceid <10089> --targetid/--groupid <10081>`
"""

import argparse
import json
import sys
import time
from argparse import RawTextHelpFormatter
from getpass import getpass

import requests
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# to disable urllib3 warnings while making an api call
# urllib3.disable_warnings()

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


def get_group_list(ip_address, headers):
    """ Get list of groups from OME """
    group_list = None
    group_list_url = 'https://%s/api/GroupService/Groups' % ip_address
    group_response = requests.get(group_list_url, headers=headers, verify=False)
    if group_response.status_code == 200:
        group_response = group_response.json()
        if group_response['@odata.count'] > 0:
            group_list = [x['Id'] for x in group_response['value']]
        else:
            print("No groups found at ", ip_address)
    else:
        print("No groups found at ", ip_address)
    return group_list


'''
    fetch server device id based on the device type
'''


def get_template_status(ip_address, headers, tmpl_id):
    """ Tracks the update job to completion / error """

    max_retries = 20
    sleep_interval = 60
    failed_job_status = [2070, 2090, 2100, 2101, 2102, 2103]
    tmpl_url = 'https://%s/api/TemplateService/Templates?$filter=Id%seq%s%s' % (ip_address, '%20', '%20', tmpl_id)
    loop_ctr = 0
    job_incomplete = True
    print("Polling %s to completion ..." % tmpl_id)
    while loop_ctr < max_retries:
        loop_ctr += 1
        time.sleep(sleep_interval)
        job_resp = requests.get(tmpl_url, headers=headers, verify=False)
        if job_resp.status_code == 200:
            job_status = str((job_resp.json())['value'][0]["Status"])
            # print("Iteration %s: Status of %s is %s" % (loop_ctr, job_id, job_status_map[job_status]))
            if int(job_status) == 2060:
                job_incomplete = False
                print("Template created successfully...")
                break
            elif int(job_status) in failed_job_status:
                job_incomplete = False
                print("Template status failed ... ")
                break
        else:
            print("Unable to poll status job status")
    if job_incomplete:
        print("Job incomplete after polling %s times...Check status" % max_retries)


def get_template_payload(device_id, component):
    payload = {
        "Name": "Template",
        "Description": "Template",
        "TypeId": 2,
        "ViewTypeId": 2,
        "SourceDeviceId": 25014,
        "Fqdds": "EventFilters"
    }
    tmpl_payload = payload.copy()
    tmpl_payload["SourceDeviceId"] = device_id
    if component:
        tmpl_payload["Fqdds"] = component
    else:
        tmpl_payload["Fqdds"] = "All"
    return tmpl_payload


def get_identity_pool_payload():
    payload = {
        "Name": "Identity Pool",
        "EthernetSettings": {
            "Mac": {
                "IdentityCount": 55,
                "StartingMacAddress": "UFBQUFAA"
            }
        },
        "IscsiSettings": {
            "Mac": {
                "IdentityCount": 65,
                "StartingMacAddress": "YGBgYGAA"
            },
            "InitiatorConfig": {
                "IqnPrefix": "iqn.dell.com"
            }
        },
        "FcoeSettings": {
            "Mac": {
                "IdentityCount": 75,
                "StartingMacAddress": "cHBwcHAA"
            }
        },
        "FcSettings": {
            "Wwnn": {
                "IdentityCount": 85,
                "StartingAddress": "IACAgICAgAA="
            },
            "Wwpn": {
                "IdentityCount": 85,
                "StartingAddress": "IAGAgICAgAA="
            }
        }
    }
    io_payload = payload.copy()
    return io_payload


def set_identities_to_target(ip_address, headers, tmpl_id, io_id):
    payload = {
        "TemplateId": 27,
        "IdentityPoolId": 14
    }
    assign_identity_payload = payload.copy()
    assign_identity_payload["TemplateId"] = tmpl_id
    assign_identity_payload["IdentityPoolId"] = io_id
    url = 'https://%s/api/TemplateService/Actions/TemplateService.UpdateNetworkConfig' % ip_address
    response = requests.post(url, verify=False,
                             data=json.dumps(assign_identity_payload),
                             headers=headers)
    return response


def deploy_template(ip_address, headers, tmpl_id, target_ids):
    payload = {
        "Id": 27,
        "TargetIds": [
            25014
        ]
    }
    deploy_payload = payload.copy()
    deploy_payload["Id"] = tmpl_id
    deploy_payload["TargetIds"][:] = []
    for target in target_ids:
        deploy_payload["TargetIds"].append(target)
    url = 'https://%s/api/TemplateService/Actions/TemplateService.Deploy' % ip_address
    response = requests.post(url, verify=False,
                             data=json.dumps(deploy_payload),
                             headers=headers)
    return response


def get_execution_detail(job_hist_resp, headers, job_hist_url):
    """ Get execution details """
    job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
    execution_hist_detail = "(" + job_history_id + ")/ExecutionHistoryDetails"
    job_hist_det_url = str(job_hist_url) + execution_hist_detail
    job_hist_det_resp = requests.get(job_hist_det_url,
                                     headers=headers,
                                     verify=False)
    if job_hist_det_resp.status_code == 200:
        print(job_hist_det_resp.text)
    else:
        print("Unable to parse job execution history .. Exiting")


def get_deploy_template_status(ip_address, headers, job_id):
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
            print("Iteration %s: Status of %s is %s" % (loop_ctr, job_id,
                                                        job_status_map[job_status]))
            if int(job_status) == 2060:
                job_incomplete = False
                print("Completed template deployment successfully ... Exiting")
                break
            elif int(job_status) in failed_job_status:
                job_incomplete = False
                print("Template job failed ... ")
                job_hist_url = str(job_url) + "/ExecutionHistories"
                job_hist_resp = requests.get(job_hist_url, headers=headers, verify=False)
                if job_hist_resp.status_code == 200:
                    get_execution_detail(job_hist_resp, headers, job_hist_url)
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
    parser.add_argument("--sourceid", type=int, required=True,
                        help="Source device id to clone the elements from the device")
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument("--groupid", type=int,
                             help="Id of the group to deploy template on the devices belong to the group")
    mutex_group.add_argument("--targetid", type=int,
                             help="Target device id to deploy template on the target device")
    parser.add_argument("--component", required=False,
                        choices=("iDRAC", "BIOS", "System", "NIC", "LifecycleController",
                                 "RAID", "EventFilters", "All"),
                        help="Component to clone from source device")
    args = parser.parse_args()
    ip_address = args.ip
    user_name = args.user
    if args.password:
        password = args.password
    else:
        password = getpass()
    DEVICE_ID = args.sourceid
    TARGET_IDS = []
    FQDDS = None
    try:
        auth_success, headers = authenticate_with_ome(
            ip_address, user_name, password)
        if auth_success:
            if args.component:
                FQDDS = args.component
            if args.groupid:
                GROUP_ID = args.groupid
                GROUP_LIST = get_group_list(ip_address, headers)
                if GROUP_LIST:
                    if GROUP_ID in GROUP_LIST:
                        GROUP_URL = "https://%s/api/GroupService/Groups(%s)/Devices" % (ip_address, GROUP_ID)
                        RESPONSE = requests.get(GROUP_URL, headers=headers, verify=False)
                        if RESPONSE.status_code == 200:
                            DEV_RESPONSE = RESPONSE.json()
                            if DEV_RESPONSE['@odata.count'] == 0:
                                raise Exception("No devices associated with this group id")
                            else:
                                DEVICE_LIST = DEV_RESPONSE["value"]
                                for dev in DEVICE_LIST:
                                    TARGET_IDS.append(dev.get('Id'))
                        else:
                            raise Exception("Unable to fetch group device details")
                    else:
                        raise ValueError("Group %s not found on %s ... Exiting" % (
                            GROUP_ID, ip_address))
            else:
                TARGET_ID = args.targetid
                DEVICE_LIST = get_device_list(ip_address, headers)
                if DEVICE_LIST:
                    if TARGET_ID in DEVICE_LIST:
                        TARGET_IDS.append(TARGET_ID)
                    else:
                        raise ValueError(
                            "Device with id %s not found on %s ... Exiting" % (TARGET_ID, ip_address))
                else:
                    raise ValueError("Device not found on %s ... Exiting" % ip_address)
            TMPL_ID = None
            IO_ID = None
            TMPL_PAYLOAD = get_template_payload(DEVICE_ID, FQDDS)
            URL = 'https://%s/api/TemplateService/Templates' % ip_address
            RESPONSE = requests.post(URL, verify=False,
                                     data=json.dumps(TMPL_PAYLOAD),
                                     headers=headers)

            if RESPONSE.status_code == 201:
                RESPONSE = RESPONSE.json()
                TMPL_ID = RESPONSE
                get_template_status(ip_address, headers, TMPL_ID)
                IO_POOL_PAYLOAD = get_identity_pool_payload()
                URL = 'https://%s/api/IdentityPoolService/IdentityPools' % ip_address
                RESPONSE = requests.post(URL, verify=False,
                                         data=json.dumps(IO_POOL_PAYLOAD),
                                         headers=headers)
                if RESPONSE.status_code == 201:
                    RESPONSE = RESPONSE.json()
                    IS_IO_SUCCESSFUL = RESPONSE["IsSuccessful"]
                    if IS_IO_SUCCESSFUL:
                        IO_ID = RESPONSE["Id"]
                        time.sleep(30)
                        ASSIGN_IDENTITY_RESPONSE = set_identities_to_target(ip_address, headers, TMPL_ID, IO_ID)
                        if ASSIGN_IDENTITY_RESPONSE.status_code == 200:
                            time.sleep(30)
                            DEPLOY_RESPONSE = deploy_template(ip_address, headers, TMPL_ID, TARGET_IDS)
                            if DEPLOY_RESPONSE.status_code == 200:
                                DEPLOY_RESPONSE = DEPLOY_RESPONSE.json()
                                job_id = DEPLOY_RESPONSE
                                # TODO - get_deploy_template_status returns nothing - is this correct?
                                STATUS = get_deploy_template_status(ip_address, headers, job_id)
                            else:
                                print("Failed to deploy template")
                        else:
                            print("Unable to assign identities..Exiting")
                    else:
                        print("Identity pool creation unsuccessful..Exiting")
                else:
                    print("Unable to create identity pool..Exiting")
            else:
                print("Unable to create template..Exiting")
        else:
            print("Unable to create a session with appliance %s" % ip_address)
    except OSError:
        print("Unexpected error:", sys.exc_info())
