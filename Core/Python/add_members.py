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
Script to add all standalone domains to the existing MCM group,
and assign a backup lead

#### Description
This script adds all standalone domains to the
existing group and assigns a member as backup lead.

#### Python Example
`python add_members.py --ip <ip addr> --user root --password <passwd>`

Note:
1. Credentials entered are not stored to disk.
2. Random member will be assigned as a backup lead

#### API Workflow
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
user name and password entered by user
4. Add all standalone members to the created group
with POST on /ManagementDomainService/Actions/ManagementDomainService.Domains
5. Parse returned job id and monitor it to completion
6. Assign a random member as backup lead
with POST on /ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead
7. Parse returned job id and monitor it to completion
"""

import argparse
import json
import random
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


def get_domain_info(ip_address, headers):
    members = []
    backup_lead = None
    lead = None
    url = 'https://%s/api/ManagementDomainService/Domains' % ip_address
    domains_info = requests.get(url, headers=headers, verify=False)
    if domains_info.status_code == 200:
        domains = domains_info.json()
        if domains.get('@odata.count') > 0:
            member_devices = domains.get('value')
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
            print("No domains discovered ... Error")
    else:
        print('Failed to discover domains - Status Code %s')

    return {
        'lead': lead,
        'backup_lead': backup_lead,
        'members': members
    }


def get_backup_lead(ip_address, headers):
    return get_domain_info(ip_address, headers)['backup_lead']


def get_domains(ip_address, headers):
    members = []
    url = 'https://%s/api/ManagementDomainService/Domains' % ip_address
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        response = response.json()
        member_devices = response.get('value')
        members = list(filter(lambda x: x.get(
            'DomainRoleTypeValue') == 'MEMBER', member_devices))

        if not members:
            print('No member device found')
    else:
        print('Failed to get domains and status code returned is %s', response.status_code)
    return members


def get_discovered_domains(ip_address, headers, role=None):
    discovered_domains = []
    url = 'https://%s/api/ManagementDomainService/DiscoveredDomains' % ip_address
    domains_info = requests.get(url, headers=headers, verify=False)
    if domains_info.status_code == 200:
        domains = domains_info.json()
        if domains.get('@odata.count') > 0:
            discovered_domains = domains.get('value')
        else:
            print("No domains discovered ... Error")
    else:
        print('Failed to discover domains - Status Code %s')

    if role:
        discovered_domains = list(filter(lambda x: x.get(
            'DomainRoleTypeValue') == role, discovered_domains))
    return discovered_domains


def add_all_members_via_lead(ip_address, headers):
    """ Add standalone domains to the group"""
    standalone_domains = get_discovered_domains(ip_address, headers, role='STANDALONE')
    job_id = None
    if standalone_domains:
        body = []
        for domain in standalone_domains:
            body.append({'GroupId': domain.get('GroupId')})

        url = 'https://%s/api/ManagementDomainService/Actions/ManagementDomainService.Domains' % ip_address
        response = requests.post(url, headers=headers,
                                 data=json.dumps(body), verify=False)
        if response.status_code == 200:
            response_data = response.json()
            job_id = response_data.get('JobId')
            print('Added members to the created group, Job ID = {0}'.format(job_id))
        else:
            print('Failed to add members to the group')
    else:
        print('No standalone chassis found to add as member to the created group')
    return job_id


def assign_backup_lead(ip_address, headers):
    url = 'https://%s/api/ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead' % ip_address
    members = get_domains(ip_address, headers)
    job_id = None
    if members:
        member = random.choice(members)
        member_id = member.get('Id')
        body = [{
            'Id': member_id
        }]
        response = requests.post(url, headers=headers,
                                 data=json.dumps(body), verify=False)
        if response.status_code == 200:
            response = response.json()
            job_id = response.get('JobId')
            print('Successfully assigned backup lead')
        else:
            print('Failed to assign backup lead')
    else:
        print('Created group has no members. Failed to assign a backup lead')
    return job_id


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
    parser.add_argument("--ip", "-i", required=True, help="MSM IP")
    parser.add_argument("--user", "-u", required=True, help="Username for MSM", default="root")
    parser.add_argument("--password", "-p", required=False, help="Password for MSM")

    args = parser.parse_args()
    ip_address = args.ip
    user_name = args.user
    if args.password:
        password = args.password
    else:
        password = getpass()

    try:
        auth_success, headers = authenticate_with_ome(ip_address, user_name,
                                                      password)
        if auth_success:
            print('Adding members to the group')
            job_id = add_all_members_via_lead(ip_address, headers)
            if job_id:
                print('Polling addition of members to group')
                get_job_status(ip_address, headers, job_id)
            backup_lead_found = get_backup_lead(ip_address, headers)
            if not backup_lead_found:
                print('Assigning backup lead ...')
                job_id = assign_backup_lead(ip_address, headers)
                if job_id:
                    print('Polling for assign backup lead job status')
                    get_job_status(ip_address, headers, job_id)
            else:
                print('Backup lead found,skipping backup lead operation ...')
        else:
            print('Unable to authenticate. Check IP/username/password')
    except Exception as error:
        print("Unexpected error:", str(error))
