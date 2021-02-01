#
#  Python script to get the list of virtual addresses in an Identity Pool
#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
# _version_ = 0.1
#
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
#### Synopsis
Script to manage templates in OpenManage Enterprise

#### Description
This script uses the OME REST API to export templates to a file
Will export to a CSV file the same name as the template in the current directory unless --export-directory is specified

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python .\get_template.py --ip <xx> --user <username> --password <pwd> --name "TestTemplate" --out-directory "C:\Backup"`
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

def get_template(base_uri, headers, name):
    if name:
        url = base_uri + "/api/TemplateService/Templates?$filter=Name eq '" + name + "'"
    else:
        url = base_uri + "/api/TemplateService/Templates"
    get_resp = requests.get(url, headers=headers, verify=False)
    if get_resp.status_code == 200:
        resp_data = get_resp.json()
        print(json.dumps(resp_data, indent=4))
        return resp_data["value"]
    elif get_resp.status_code == 400:
        print ("Failed creation... ")
        print (json.dumps(get_resp.json(), indent=4,
                            sort_keys=False))

def export_template(base_uri, headers, template_id, name, directory):
    try:
        payload = {
            "TemplateId": 1
        }
        url = base_uri + '/api/TemplateService/Actions/TemplateService.Export'
        payload["TemplateId"] = template_id
        create_resp = requests.post(url, headers=headers,
                                    verify=False,
                                    data=json.dumps(payload))
        if create_resp.status_code == 200:
            resp_data = create_resp.json()
            filename = os.path.join(directory, name + '.xml')
            f = open(filename, 'w' )
            f.write(resp_data["Content"])
            f.close()
            print ("Exported template to %s" %(filename))
        elif create_resp.status_code == 400:
            print ("Failed to export template... ")
            print (json.dumps(create_resp.json(), indent=4, sort_keys=False))
    except Exception as e:
        print(traceback.format_exc())

def import_template(base_uri, headers, name, filename):
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
        print(json.dumps(payload, indent=4))
        create_resp = requests.post(url, headers=headers,
                                    verify=False,
                                    data=json.dumps(payload))
        if create_resp.status_code == 201:
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
    PARSER.add_argument("--name", "-n", required=False,
                        help="Name of Template")
    PARSER.add_argument("--out-directory", "-d", required=True,
                        help="Directory to export Templates")
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
        if ARGS.out_directory:
            templates = get_template(base_uri, headers, ARGS.name)
            for template in templates:
                export_template(base_uri, headers, template["Id"], template["Name"], ARGS.out_directory)
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])
