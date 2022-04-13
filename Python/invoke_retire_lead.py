#
#
# Copyright (c) 2022 Dell EMC Corporation
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
Script to retire lead of MCM group and promote the exising backup lead as lead

#### Description:
This script retires the current lead and the backup lead gets promoted as the new lead

#### Python Example
`python invoke_retire_lead.py --ip <lead ip> --user <username> --password <password>`

Note:
1. Credentials entered are not stored to disk.

#### API Workflow
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
    for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
    user name and password entered by user
4. Retire lead and promote backup lead as the new lead
    with POST on /ManagementDomainService/Actions/ManagementDomainService.RetireLead
5. Parse returned job id and monitor it to completion
"""

import argparse
import json
import random
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


# Helper methods
def get_domains(ip_address, headers):
    members = []
    backup_lead = None
    lead = None
    url = 'https://%s/api/ManagementDomainService/Domains' % ip_address
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        response = response.json()
        member_devices = response.get('value')
        for member_device in member_devices:
            role = member_device.get('DomainRoleTypeValue')
            backup_lead_flag = member_device.get('BackupLead')
            if role == 'LEAD':
                if not lead:
                    lead = member_device
            elif backup_lead_flag:
                if not backup_lead:
                    backup_lead = member_device
            elif role == 'MEMBER':
                members.append(member_device)
    else:
        print('Failed to get domains and status code returned is %s', response.status_code)
    return {
        'lead': lead,
        'backup_lead': backup_lead,
        'members': members
    }


def assign_backup_lead(ip_address, headers):
    url = 'https://%s/api/ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead' % ip_address
    members = get_domains(ip_address, headers)
    job_id = None
    if members:
        member = random.choice(members["members"])
        member_id = member.get('Id')
        body = [{
            'Id': member_id
        }]
        print("members found")
        response = requests.post(url, headers=headers,
                                 data=json.dumps(body), verify=False)
        if response.status_code == 200:
            response = response.json()
            job_id = response.get('JobId')
        else:
            print('Failed to assign backup lead')
    else:
        print('Created group has no members. Failed to assign a backup lead')
    return job_id


def get_backup_lead(ip_address, headers):
    return get_domains(ip_address, headers)['backup_lead']


def retire_lead(ip_address, headers):
    assign_backup_lead_required = False
    backup_lead = get_backup_lead(ip_address, headers)
    if not backup_lead:
        assign_backup_lead_required = True
        print("No backup lead found. Assigning backup lead")
        job_id = assign_backup_lead(ip_address, headers)
        if job_id:
            print('Polling for assign backup lead job status')
            get_job_status(ip_address, headers, job_id)

    # Make sure the backup sync is healthy before retire
    if assign_backup_lead_required:
        print("Waiting for sync operation to complete for assign backup lead")
        time.sleep(900)
    backup_lead = get_backup_lead(ip_address, headers)
    print('Checking Backup lead health')
    backup_lead_health = backup_lead.get('BackupLeadHealth')
    if backup_lead_health != 1000:
        print("Backup lead health is CRITICAL or WARNING.")
        print("Please ensure backup lead is healty before retiring the lead")
        return

    url = 'https://%s/api/ManagementDomainService/Actions/ManagementDomainService.RetireLead' % ip_address
    body = {
        'PostRetirementRoleType': 'Member'
    }
    response = requests.post(url, headers=headers,
                             data=json.dumps(body), verify=False)

    if response.status_code == 200:
        response = response.json()
        job_id = response.get('JobId')
        if job_id:
            print('Created job to retire lead with job id: ' + str(job_id))
        return job_id
    else:
        print('Failed to retire lead')


def get_job_status(ip_address, headers, job_id):
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
                print("Completed job successfully ... Exiting")
                break
            elif int(job_status) in failed_job_status:
                job_incomplete = False
                print("Job failed ... ")
                job_hist_url = str(job_url) + "/ExecutionHistories"
                job_hist_resp = requests.get(job_hist_url, headers=headers, verify=False)
                if job_hist_resp.status_code == 200:
                    job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
                    job_hist_det_url = str(job_hist_url) + "(" + job_history_id + ")/ExecutionHistoryDetails"
                    job_hist_det_resp = requests.get(job_hist_det_url, headers=headers, verify=False)
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
    parser.add_argument("--ip", "-i", required=True, help="MSM IP (Lead chassis)")
    parser.add_argument("--user", "-u", required=True, help="Username for MSM", default="root")
    parser.add_argument("--password", "-p", required=False, help="Password for MSM")
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

    try:
        auth_success, headers = authenticate_with_ome(ip_address, user_name,
                                                      password)
        if auth_success:
            job_id = retire_lead(ip_address, headers)
            if job_id:
                print('Polling for retire lead job status')
                get_job_status(ip_address, headers, job_id)
        else:
            print('Unable to authenticate. Check IP/username/password')
    except Exception as error:
        print("Unexpected error:", str(error))
