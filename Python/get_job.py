#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
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
#

"""
#### Synopsis
Script to get a list of jobs, single job by id and optionally export job execution history to csv

#### Description
This script uses the OME REST API to get a list of jobs
currently being managed by that instance. For authentication X-Auth
is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_job.py --ip <xx> --user <username> --password <pwd>`
`python get_job.py --ip <xx> --user <username> --password <pwd> --job-id 10126`
`python get_job.py --ip <xx> --user <username> --password <pwd> --job-id 10126 --executionhistory-export y`
"""

import argparse
import json
import pprint
import sys
import csv
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
        Exception: A generic exception in the event of a failure to connect
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

def get_job_list(authenticated_headers: dict, ome_ip_address: str):
    """
    Get list of jobs
    
    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
    
    Returns: None
    """

    """ Authenticate with OME and enumerate groups """
    try:
        group_data = None
        next_link_url = 'https://%s/api/JobService/Jobs' % ome_ip_address

        while next_link_url is not None:
            group_response = requests.get(next_link_url, headers=authenticated_headers, verify=False)
            next_link_url = None

            if group_response.status_code == 200:
                data = group_response.json()
                if data['@odata.count'] <= 0:
                    print("No subgroups of static groups found on OME server: " + ome_ip_address)
                    return 0
                if '@odata.nextLink' in data:
                    next_link_url = ("https://%s" % ome_ip_address) + data['@odata.nextLink'] 
                if group_data is None:
                    group_data = data["value"]
                else:
                    group_data += data["value"]
            else:
                print("Unable to retrieve group list from %s" % next_link_url)
                sys.exit(1)

        pprint.pprint(group_data)

    except Exception as error:
        print("Encountered an error: " + str(error))
        sys.exit(1)

def get_job(authenticated_headers: dict, ome_ip_address: str, job_id):
    """
    Get job by id
    
    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        job_id: Job ID
    
    Returns: None
    """

    """ Authenticate with OME and enumerate groups """
    try:
        data = None
        job_url = 'https://%s/api/JobService/Jobs(%s)' % (ome_ip_address, job_id)

        group_response = requests.get(job_url, headers=authenticated_headers, verify=False)

        if group_response.status_code == 200:
            data = group_response.json()
        else:
            print("Unable to retrieve job from %s" % job_url)
            sys.exit(1)

        pprint.pprint(data)

    except Exception as error:
        print("Encountered an error: " + str(error))
        sys.exit(1)

def get_job_execution_history(authenticated_headers: dict, ome_ip_address: str, job_id, executionhistory_export):
    """
    Get job execution history
    
    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        job_id: Job ID
        executionhistory_export: Export job execution history to csv
    
    Returns: None
    """

    """ Authenticate with OME and enumerate groups """
    job_url = 'https://%s/api/JobService/Jobs(%s)/ExecutionHistories' % (ome_ip_address, job_id)

    group_response = requests.get(job_url, headers=headers, verify=False)

    if group_response.status_code == 200:
        data = group_response.json()
        job_histories = data["value"]
        header = ["JobName", "StartTime", "EndTime", "Progress", "ExecutedBy", "JobStatus", "ExecutionHistoryId", "ExecutionStartTime", "ExecutionEndTime", "ElapsedTime", "Key", "Value", "ExecutionJobStatus"]
        data_export = []
        for job_history in job_histories:
            job_history_detail_url = job_history['ExecutionHistoryDetails@odata.navigationLink']
            job_history_detail_url = ("https://%s" % ome_ip_address) + job_history_detail_url
            job_history_detail_response = requests.get(job_history_detail_url, headers=authenticated_headers, verify=False)
            if job_history_detail_response.status_code == 200:
                job_history_detail_data = job_history_detail_response.json()
                job_history_detail_data = job_history_detail_data["value"]
                for item in job_history_detail_data:
                    data_export.append([
                        job_history["JobName"],
                        job_history["StartTime"],
                        job_history["EndTime"],
                        job_history["ExecutedBy"],
                        job_history["JobStatus"]["Name"],
                        job_history["Id"],
                        item["Progress"],
                        item["StartTime"],
                        item["EndTime"],
                        item["ElapsedTime"],
                        item["Key"],
                        item["Value"],
                        item["JobStatus"]["Name"]
                    ])

        pprint.pprint(data_export)
        with open('get_job_execution_history.csv', 'w') as f:
            writer = csv.writer(f)
            # write the header
            writer.writerow(header)
            # write multiple rows
            writer.writerows(data_export)
    else:
        print("Unable to retrieve job from %s" % job_url)
        sys.exit(1)


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--job-id", "-j", required=False,
                        help="Job ID")
    parser.add_argument("--executionhistory-export", "-e", required=False,
                        help="Specify 'y' for parameter value. Export job execution history to a csv file named get_job_execution_history.csv in the current directory")
    args = parser.parse_args()

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

    headers = authenticate(args.ip, args.user, password)

    if not headers:
        sys.exit(0)

    if args.executionhistory_export:
        get_job_execution_history(headers, args.ip, args.job_id, args.executionhistory_export)
    elif args.job_id:
        get_job(headers, args.ip, args.job_id)
    else:
        get_job_list(headers, args.ip)
