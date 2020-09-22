#
#  Python script using OME API to get device list.
#
# _author_ = Raajeev Kalyanaraman <Raajeev.Kalyanaraman@Dell.com>
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
SYNOPSIS:
   Script to get the list of devices managed by OM Enterprise

DESCRIPTION:
   This script exercises the OME REST API to get a list of devices
   currently being managed by that instance. For authentication X-Auth
   is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python get_device_list.py --ip <xx> --user <username> --password <pwd>
"""

import argparse
from argparse import RawTextHelpFormatter
import json
import csv
import os
import sys
import urllib3

class GetDeviceList:
    AUTH_SUCCESS = None
    HEADERS = None
    """ Authenticate with OME and enumerate devices """
    def __init__(self, session_input, output_details):
        self.__session_input = session_input
        self.__output_details = output_details
        if not self.__validateargs():
            return

        self.__base_uri = 'https://%s' % self.__session_input["ip"]

        try:
            self.AUTH_SUCCESS, self.HEADERS = self.__authenticate_with_ome()
            if not self.AUTH_SUCCESS:
                print("Unable to authenticate with OME .. Check IP/Username/Pwd")
                return
        except Exception:
            print("Unable to connect to OME appliance %s" % self.__session_input["ip"])
            return

        try:
            if self.__get_device_list() is False:
                print("Get device list failed.")
                return
        except Exception as get_ex:
            print("Unable to get device list from OME appliance %s" % self.__session_input["ip"])
            print(get_ex)
            return
        if self.__output_details["format"] == 'json':
            self.__format_json()
        elif self.__output_details["format"] == 'csv':
            self.__format_csv()

    def __request(self,url, payload=None, method='GET'):
        """ Returns status and data """
        request_obj = pool.urlopen(method, url, headers=self.HEADERS, body=json.dumps(payload))
        if request_obj.data and request_obj.status != 400:
            data = json.loads(request_obj.data)
        else:
            data = request_obj.data
        return request_obj.status, data

    def __authenticate_with_ome(self):
        """ Authenticate with OME and X-auth session creation """
        auth_success = False
        session_url = "https://%s/api/SessionService/Sessions" % self.__session_input["ip"]
        user_details = {'UserName': self.__session_input["user"],
                        'Password': self.__session_input["password"],
                        'SessionType': 'API'}
        headers = {'content-type': 'application/json'}
        session_response = pool.urlopen('POST', session_url, headers=headers,
                                        body=json.dumps(user_details))
        if session_response.status == 201:
            headers['X-Auth-Token'] = session_response.headers['X-Auth-Token']
            auth_success = True
        else:
            error_msg = "Failed create of session with {0} - Status code = {1}"
            print(error_msg.format(self.__session_input["ip"], session_response.status_code))
        return auth_success, headers

    def __get_device_from_uri(self,uri):
        json_data = {}
        status, device_response = self.__request(uri, method='GET')
        if status == 200:
            json_data = device_response
        else:
            print("Unable to retrieve device list from %s" % uri)
        return json_data

    def __get_device_list(self):

        next_link_url = self.__base_uri + '/api/DeviceService/Devices'
        self.json_data = None

        while next_link_url is not None:
            data = self.__get_device_from_uri(next_link_url)
            next_link_url = None
            if data['@odata.count'] <= 0:
                print("No devices managed by %s" % self.__session_input["ip"])
                return False
            if '@odata.nextLink' in data:
                next_link_url = self.__base_uri + data['@odata.nextLink']
            if self.json_data is None:
                self.json_data = data
            else:
                self.json_data['value'] += data['value']
        return True

    def __format_json(self):
        # print to console in the absence of a specified file path
        json_object = json.dumps(self.json_data, indent=4, sort_keys=True)
        if self.__output_details["path"] == '':
            print("*** Device List ***")
            print(json_object)
            return
        # If file path is specified then write to file.
        modified_filepath = self.__get_unique_filename()
        with open(modified_filepath, "w") as json_file:
            json_file.write(json_object)

    def __format_csv(self):
        exportable_props = ["Id", "Identifier", "DeviceServiceTag",
                            "ChassisServiceTag", "Model", "DeviceName"]
        csv_file = None
        if self.__output_details["path"] == '':
            print("*** Device List ***")
            writer = csv.writer(sys.stdout, lineterminator=os.linesep)
        else:
            modified_filepath = self.__get_unique_filename()
            csv_file = open(modified_filepath, 'w', newline='')
            writer = csv.writer(csv_file)

        devices = self.json_data["value"]
        writer.writerow(exportable_props)
        for device in devices:
            device_props = []
            for prop in exportable_props:
                device_props.append(device[prop])
            writer.writerow(device_props)
        if csv_file is not None:
            csv_file.close()

    def __get_unique_filename(self):
        i = 1
        new_filepath = self.__output_details["path"]
        exists = os.path.isfile(new_filepath)
        while os.path.isfile(new_filepath):
            (root, ext) = os.path.splitext(self.__output_details["path"])
            new_filepath = root + "({0})".format(i) + ext
            i += 1
        if exists:
            print("Output file exists. Writing to {}".format(new_filepath))
        return new_filepath

    def __validateargs(self):
        if self.__output_details["path"] != '' and \
                os.path.splitext(self.__output_details["path"])[1] != '' and \
                os.path.splitext(self.__output_details["path"])[1][1:] != self.__output_details["format"]:
            print("Output filename must match requested file format")
            return False
        return True


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--outformat", "-of", required=False, default="json",
                        choices=('json', 'csv'),
                        help="Output format type")
    PARSER.add_argument("--outpath", "-op", required=False, default="",
                        help="Path to output file")
    ARGS = PARSER.parse_args()

    pool = urllib3.HTTPSConnectionPool(ARGS.ip, port=443,
                                       cert_reqs='CERT_NONE', assert_hostname=False)

    GetDeviceList({"ip":ARGS.ip, "user":ARGS.user, "password":ARGS.password},
                 {"format":ARGS.outformat, "path":ARGS.outpath})
