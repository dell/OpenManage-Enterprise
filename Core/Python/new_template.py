#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
# _author_ = Grant Curell <grant_curell@dell.com>
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
    python new_template.py --ip 192.168.1.93 --password password --template-file gelante.xml
    python new_template.py --ip 192.168.1.93 --password password --template-file gelante.xml --template-name 格蘭特是最好的
"""
import argparse
import json
import sys
from argparse import RawTextHelpFormatter
from os import path
from pprint import pprint

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
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


def post_data(url: str, authenticated_headers: dict, payload: dict, error_message: str) -> dict:
    """
    Posts data to OME and returns the results

    Args:
        url: The URL to which you want to post
        authenticated_headers: Headers used for authentication to the OME server
        payload: A payload to post to the OME server
        error_message: If the POST fails this is the message which will be displayed to the user

    Returns: A dictionary with the results of the post request or an empty dictionary in the event of a failure. If the
             result is a 204 - No Content (which indicates success but there is no data) then it will return a
             dictionary with the value {'status_code': 204}

    """
    response = requests.post(url, headers=authenticated_headers, verify=False, data=json.dumps(payload))

    if response.status_code == 204:
        return {'status_code': 204}
    if response.status_code != 400:
        return json.loads(response.content)
    else:
        print(error_message + " Error was:")
        pprint(json.loads(response.content))
        return {}


def import_template(ome_ip_address, authenticated_headers, template_name, filename):
    """
    Imports a template from file

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: Headers used for authentication to the OME server
        template_name: The name of the template as you would like it to appear in OME
        filename: The filename of the template you would like to push

    Returns: True if the template pushed successfully and false otherwise

    """
    url = "https://%s/api/TemplateService/Actions/TemplateService.Import" % ome_ip_address

    with open(filename, "r") as template_file:

        payload = {
            "Name": template_name,
            "Type": 2,
            "ViewTypeId": 2,
            "Content": template_file.read()
        }

        print("POSTing the data to OME and beginning the template import.")

        if post_data(url, authenticated_headers, payload, "There was a problem posting the template."):
            print("Template import successful!")
            return True
        else:
            print("Could not create template. Exiting.")
            return False


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    parser.add_argument("--template-file", "-f", required=True,
                        help="Path of Template File to Import")
    parser.add_argument("--template-name", "-n", required=False,
                        help="The name of the template you would like to use. If it is not provided it defaults to the"
                             " name of the file provided with the extension dropped.")

    args = parser.parse_args()

    try:
        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        if path.isfile(args.template_file):
            if args.template_name:
                import_template(args.ip, headers, args.template_name, args.template_file)
            else:
                import_template(args.ip,
                                headers,
                                path.basename(path.splitext(args.template_file)[0]),
                                args.template_file)
        else:
            print("Error: It looks like %s does not exist! Are you sure the path is correct?" % args.template_file)
            sys.exit(0)

    except Exception as error:
        print("Unexpected error:", str(error))
