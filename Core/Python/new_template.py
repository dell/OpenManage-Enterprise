#
#  Python script to get the list of virtual addresses in an Identity Pool
#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
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
Script to manage templates in OpenManage Enterprise

#### Description
This script uses the OME REST API to create a template from file

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python .\new_template.py ---ip <xx> --user <username> --password <pwd> --name "TestTemplate" --in-file "Template.xml"`
"""

import sys
import traceback
import argparse
from argparse import RawTextHelpFormatter
import json
import requests
import urllib3
import os
import csv
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

session_auth_token = {}

def get_session(ip_address, username, password):
    session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
    headers = {'content-type': 'application/json'}
    user_details = {'UserName': username,
                    'Password': password,
                    'SessionType': 'API'}
    session_info = requests.post(session_url, verify=False,
                                    data=json.dumps(user_details),
                                    headers=headers)
    if session_info.status_code == 201:
        session_info_token = session_info.headers['X-Auth-Token']
        session_info_data = session_info.json()
        session_auth_token = {
            "token": session_info_token,
            "id": session_info_data['Id']
        }
    return session_auth_token

def delete_session(ip_address, headers, id):
    session_url = "https://%s/api/SessionService/Sessions('%s')" % (ip_address, id)
    session_info = requests.delete(session_url, verify=False, headers=headers)
    if session_info.status_code == 204:
        return True
    else: 
        print ("Unable to delete session %s" % id)
        return False

def import_template(base_uri, auth_token, name, filename):
    """
    Import template from file
    """
    try:
        payload = {
            "Name": "Template Import",
            "Type": 2,
            "ViewTypeId": 2,
            "Content" : ""
        }
        url = base_uri + '/api/TemplateService/Actions/TemplateService.Import'
        payload["Name"] = name
        f = open(filename, "r")
        content = f.read()
        payload["Content"] = content
        create_resp = requests.post(url, headers=headers,
                                    verify=False,
                                    data=json.dumps(payload))
        if create_resp.status_code == 200:
            print ("New template created %s" %(name))
        elif create_resp.status_code == 400:
            print ("Failed creation... ")
            print (json.dumps(create_resp.json(), indent=4,
                                sort_keys=False))
    except Exception as e:
        print(traceback.format_exc())

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--name", "-n", required=True,
                        help="Name of Template")
    PARSER.add_argument("--in-file", "-f", required=True,
                        help="Path of Template File to Import")

    ARGS = PARSER.parse_args()
    base_uri = 'https://%s' %(ARGS.ip)
    auth_token = get_session(ARGS.ip, ARGS.user, ARGS.password)
    headers = {'content-type': 'application/json'}
    if auth_token.get('token') != None:
        headers['X-Auth-Token'] = auth_token['token']
    else:
        print("Unable to create a session with appliance %s" % (base_uri))
        quit()
    
    try: 
        if ARGS.in_file:
            import_template(base_uri, headers, ARGS.name, ARGS.in_file)
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])
