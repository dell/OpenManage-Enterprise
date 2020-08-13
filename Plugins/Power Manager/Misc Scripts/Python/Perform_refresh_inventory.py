#
#  Python script using OME-M APIs to create an MCM group,
#  assign a backup lead and add all possible members to the
#  created group
#
# Copyright (c) 2019 Dell EMC Corporation
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
 Script to perform refresh inventory for all devices to detect power 
 monitoring capability after Power manager Installation.

DESCRIPTION
---------------------------------------------------------------------
 This script fetches the jobID for default inventory refresh and runs
 th job until completion, checking every 10 seconds.

 Note:
 1. Credentials entered are not stored to disk.

EXAMPLE
---------------------------------------------------------------------
python Perform_refresh_inventory.py --ip <ip addr> --user root
    --password <passwd> --groupname testgroup

Fetches jobID for default inventory task from OMEnt , and runs the job

API workflow is below:
1: POST on SessionService/Sessions
2: If new session is created (201) parse headers
   for x-auth token and update headers with token
3: All subsequent requests use X-auth token and not
   user name and password entered by user
4: Find the jobID of default inventory task from all jobs
   with GET on /JobService/Jobs
5: Parse returned job id to /JobService/Actions/JobService.RunJobs 
	and monitor it to completion, waiting every 10 seconds
"""
import json
import sys
import argparse
from argparse import RawTextHelpFormatter
import urllib3
import requests
import requests
import json
import csv
from requests.auth import HTTPBasicAuth
import threading
import time
import os
import pickle
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def refresh_inventory(ip_address, user_name, password):
    """ Authenticate with OME and enumerate groups """
    try:
        jobId=0
        session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
        jobsAPI = "https://%s/api/JobService/Jobs" % (ip_address)
        runJob="https://%s/api/JobService/Actions/JobService.RunJobs" % (ip_address)
        headers = {'content-type': 'application/json'}
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}

        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)
        if session_info.status_code == (201 or 200):
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
            response = requests.get(jobsAPI, headers=headers, verify=False)
            if response.status_code == (200 or 201):
                json_data=json.loads(response.content)
                for i in range (0,int(json_data["@odata.count"])):
                    if str(json_data["value"][i]["JobName"])== "Default Inventory Task":
                        jobId=json_data["value"][i]["Id"]
                    else:
                    	print("Fetching job id of default inventory Job failed, cannot continue")
                job_payload={"JobIds":[jobId]}
                print(job_payload)
                response1 = requests.post(runJob,data=json.dumps(job_payload), headers=headers, verify=False)
                if response1.status_code==204:
                    print("Inventory job created succesfully")
                    wait_flag=True
                    job_status_uri=jobsAPI+"(" + str(jobId) +")"
                    while wait_flag !=False:
                        response2=requests.get(job_status_uri, headers=headers,verify=False)
                        json_obj=json.loads(response2.content)
                        #print(json_obj)
                        if str(json_obj["LastRunStatus"]["Name"])== "Completed":
                            print("Inventory task completed successfully\n")
                            wait_flag=False
                        else:
                            print("Inventory task executing,sleeping for 10 seconds")
                            time.sleep(10)
                else:
                    print("Inventory task already running, try later")
            else:
            	print("Jobs are not returned from OMEnt")
        else:
        	print("Create session failed, cannot continue")

    except:
        print ("Unexpected error:", sys.exc_info()[0])


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=True,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    ARGS = PARSER.parse_args()
    refresh_inventory(ARGS.ip, ARGS.user, ARGS.password)