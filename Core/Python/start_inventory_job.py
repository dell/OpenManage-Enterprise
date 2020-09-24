#
#  Python script using OME API to get device list.
#
# _author_ = Prasad Rao <prasad_rao1@Dell.com>
# _version_ = 0.1
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
#

"""
SYNOPSIS:
   Script to run inventory on specified devices managed by OM Enterprise

DESCRIPTION:
   This script exercises the OME REST API to get the inventory for a list of devices
   currently being managed by that instance. For authentication X-Auth
   is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python start_inventory_job.py --ip <xx> --user <username> --password <pwd> --name <jobname> --desc <jobname> --groupid <OME group id>
   python start_inventory_job.py --ip <xx> --user <username> --password <pwd> --name <jobname>  --deviceid <OME group id>
   python start_inventory_job.py --ip <xx> --user <username> --password <pwd>  --desc <jobname> --servicetags <space seperated service tags>
"""
import sys
import argparse
from argparse import RawTextHelpFormatter
import json
import enum
import time
import copy
import traceback
import urllib3

class InventoryJobController:
    AUTH_SUCCESS = None
    HEADERS = {'content-type': 'application/json'}
    """ Authenticate with OME"""
    def __init__(self, session_input):
        self.__session_input = session_input
        self.__base_uri = 'https://%s' % self.__session_input["ip"]

        try:
            self.AUTH_SUCCESS = self.__authenticate_with_ome()
            if not self.AUTH_SUCCESS:
                print("Unable to authenticate with OME .. Check IP/Username/Pwd", file=sys.stderr)
                return None
        except Exception as e:
            print(e, file=sys.stderr)
            print("Unable to connect to OME appliance %s" % self.__session_input["ip"], file=sys.stderr)
            raise

    def __authenticate_with_ome(self):
        """ Authenticate with OME and X-auth session creation """
        auth_success = False
        session_url = "https://%s/api/SessionService/Sessions" % self.__session_input["ip"]
        user_details = {'UserName': self.__session_input["user"],
                        'Password': self.__session_input["password"],
                        'SessionType': 'API'}
        session_response = pool.urlopen('POST', session_url, headers=self.HEADERS,
                                        body=json.dumps(user_details))
        if session_response.status == 201:
            self.HEADERS['X-Auth-Token'] = session_response.headers['X-Auth-Token']
            auth_success = True
        else:
            error_msg = "Failed create of session with {0} - Status code = {1}"
            print(error_msg.format(self.__session_input["ip"], session_response.status_code), file=sys.stderr)
        return auth_success

    def __request(self,url, payload=None, method='GET'):
        """ Returns status and data """
        request_obj = pool.urlopen(method, url, headers=self.HEADERS, body=json.dumps(payload))
        if request_obj.data and request_obj.status != 400:
            data = json.loads(request_obj.data)
        else:
            data = request_obj.data
        return request_obj.status, data

    def createJob(self, targets, jobname = None, jobdesc = None):
        url = 'https://%s/api/JobService/Jobs' % self.__session_input["ip"]
        try:
            status, device_response = self.__request(url, payload=self._getJobPayload(targets, jobname, jobdesc), method='POST')
        except Exception as e:
            print(e, file=sys.stderr)
            print("Failed to schedule the inventory job", file=sys.stderr)
            raise

    def _getJobPayload(self, targets, jobname, jobdesc):
        target_template = {
            "Id": "<device or group id>",
            "Data": "",
            "TargetType": {
                "Id": 2000,
                "Name": "GROUP"
            }
        }
        payload={
            "Id":0,
            "JobName": jobname if jobname else "Inventory Job - " + time.strftime(":%Y:%m:%d-%H:%M:%S"),
            "JobDescription": jobdesc if jobdesc else "",
            "Schedule": "startnow",
            "State": "Enabled",
            "JobType": {
                "Name": "Inventory_Task"
            },
            "Targets": [
            ]
        }
        if targets["group_id"]:
            group_type, group_name = self.get_group_details(targets["group_id"])
            target = target_template
            target["Id"] = targets["group_id"]
            target["TargetType"]["Id"] = group_type
            target["TargetType"]["Name"] = group_name
            payload['Targets'].append(target)
        elif targets["device_ids"]:
            device_details = self.get_device_details(targets["device_ids"])
            for device_id, device_detail in device_details.items():
                target = copy.deepcopy(target_template)
                target["Id"] = device_id
                target["TargetType"]["Id"] = device_detail["Type"]
                target["TargetType"]["Name"] = device_detail['DeviceName']
                payload['Targets'].append(target)
        return payload

    def get_group_details(self, group_id):
        """ Get  group details  from OME """
        group_service_url = 'https://%s/api/GroupService/Groups(%s)' % (self.__session_input["ip"], group_id)
        status, group_json_response = self.__request(group_service_url, method='GET')
        if status == 200:
            if group_json_response['Id'] == group_id:
                group_type = group_json_response["TypeId"]
                group_name = group_json_response["Name"]
                return group_type, group_name
            raise Exception("Unable to find group id")
        raise Exception("Unable to fetch group details")

    def get_device_details(self, device_ids):
        """ Get device details  from OME """
        query_string = ""
        device_details = {device_id: {'Type': None, 'DeviceName': None} for device_id in device_ids}
        for device_id in device_ids:
            query_string = query_string + "{}".format(device_id) + ','
        query_string = query_string[0:-1]

        device_url = 'https://%s/api/DeviceService/Devices?Id=%s' % (self.__session_input["ip"], query_string)
        status, device_details_json_response = self.__request(device_url, method='GET')

        if status == 200:
            if device_details_json_response['@odata.count'] != len(device_ids):
                raise Exception("One or more device id's are not valid.")
            for i in range(device_details_json_response['@odata.count']):
                device_details[device_details_json_response["value"][i]['Id']]["Type"] = \
                    device_details_json_response["value"][i]["Type"]
                device_details[device_details_json_response["value"][i]['Id']]["DeviceName"] = \
                    device_details_json_response["value"][i]["DeviceName"]
            return device_details
        raise Exception("Unable to fetch device details")


    def get_device_from_uri(self, uri):
        json_data = {}
        status, device_response = self.__request(uri, method='GET')
        if status == 200:
            json_data = device_response
        else:
            raise ValueError("Unable to retrieve device list from %s" % uri)
        return json_data

    def get_device_list(self, servicetags):
        """ Get list of devices from OME """
        if not servicetags or len(servicetags) == 0:
            return []

        base_uri = 'https://%s' % self.__session_input["ip"]
        next_link_url = base_uri + '/api/DeviceService/Devices'

        ome_device_list = None
        ome_service_tags = None
        json_data = None

        while next_link_url is not None:
            data = self.get_device_from_uri(next_link_url)
            next_link_url = None
            if data['@odata.count'] > 0:
                if '@odata.nextLink' in data:
                    next_link_url = base_uri + data['@odata.nextLink']
                if json_data is None:
                    json_data = data
                else:
                    json_data['value'] += data['value']
            else:
                print('No devices managed by %s' % self.__session_input["ip"], file=sys.stderr)

        if json_data is None:
            pass
        else:
            ome_device_list = [x['Id'] for x in json_data['value']]
            ome_service_tags = [x['DeviceServiceTag'] for x in json_data['value']]
            mapping = dict(zip(ome_service_tags, ome_device_list))
            intersection_set = set(mapping.keys()).intersection(set(servicetags))
            if len(intersection_set) <= 0:
                raise ValueError("None of the devices are managed through OME... Exiting")
            if len(intersection_set) != len(servicetags):
                unmanaged_devices = list(set(servicetags).difference(intersection_set))
                raise ValueError("Devices {} not managed through OME ... Exiting".format(unmanaged_devices))
            return [mapping[tag] for tag in intersection_set]

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--name", "-n", required=False,
                        help="Name for the job")
    PARSER.add_argument("--desc", "-d", required=False,
                        help="Description for the job")
    MUTEX_GROUP = PARSER.add_mutually_exclusive_group(required=True)
    MUTEX_GROUP.add_argument("--groupid", type=int,
                             help="Id of the group to run inventory on")
    MUTEX_GROUP.add_argument("--deviceid", type=int,
                             help="Id of the device to run inventory on")
    MUTEX_GROUP.add_argument("--servicetags", nargs="*",
                             help="Servicetags of devices to run inventory on")
    ARGS = PARSER.parse_args()

    pool = urllib3.HTTPSConnectionPool(ARGS.ip, port=443,
                                       cert_reqs='CERT_NONE', assert_hostname=False)

    try:
        controller = InventoryJobController({"ip":ARGS.ip, "user":ARGS.user, "password":ARGS.password})
        targets = {
            "group_id": ARGS.groupid,
            "device_ids": [ARGS.deviceid] if ARGS.deviceid else controller.get_device_list(ARGS.servicetags)
        }
        controller.createJob(targets, ARGS.name, ARGS.desc)
    except:
        traceback.print_exc()
        print("Script execution unsuccessful", file=sys.stderr)