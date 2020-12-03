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
Script to update an existing discovery job in OME

#### Description
This script uses the OME REST API to update an existing discovery job(if found) with the credentials and also
it updates networkaddress if user passs iprange.
For authentication X-Auth is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

#### Python Example
```bash
python edit_discovery_job.py --ip <ip addr> --user admin
--password <passwd> --jobNamePattern <Existing Discovery Job name>
--targetUserName <user name> --targetPassword <password>
--targetIpAddresses <10.xx.xx.x,10.xx.xx.xx-10.yy.yy.yy,10.xx.xx.xx>
```
where {jobNamePattern} can be existing discovery job name(Discovery_Essentials_10.xx.xx.xx)
or the job name pattern(Discovery_Essentials)
"""
import argparse
import json
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


def get_discovery_config_payload():
    """ Payload for modifying discovery job """
    discovery_config_details = {
        "DiscoveryConfigGroupId": 222,
        "DiscoveryConfigGroupName": "Discovery_Essentials_IP_foo.194",
        "DiscoveryConfigModels": [
            {
                "DiscoveryConfigId": 2,
                "DiscoveryConfigStatus": None,
                "DiscoveryConfigTargets": [
                    {
                        "DiscoveryConfigTargetId": 2,
                        "NetworkAddressDetail": None,
                        "SubnetMask": None,
                        "AddressType": 3,
                        "Disabled": False,
                        "Exclude": False
                    }
                ],
                "ConnectionProfileId": 10079,
                "ConnectionProfile": "{\n  \"profileId\" : 10079,\n  \"profileName\" : \"\","
                                     "\n  \"profileDescription\" : \"\",\n  \"type\" : \"DISCOVERY\","
                                     "\n  \"updatedBy\" : null,\n  \"updateTime\" : 1580413699634,\n  \"credentials\" "
                                     ": [ {\n    \"type\" : \"WSMAN\",\n    \"authType\" : \"Basic\","
                                     "\n    \"modified\" : false,\n    \"id\" : 3,\n    \"credentials\" : {\n      "
                                     "\"username\" : \"root\",\n      \"password\" : null,\n      \"domain\" : null,"
                                     "\n      \"caCheck\" : false,\n      \"cnCheck\" : false,"
                                     "\n      \"certificateData\" : null,\n      \"certificateDetail\" : null,"
                                     "\n      \"port\" : 443,\n      \"retries\" : 3,\n      \"timeout\" : 60,"
                                     "\n      \"isHttp\" : false,\n      \"keepAlive\" : false\n    }\n  }, "
                                     "{\n    \"type\" : \"REDFISH\",\n    \"authType\" : \"Basic\",\n    \"modified\" "
                                     ": false,\n    \"id\" : 4,\n    \"credentials\" : {\n      \"username\" : "
                                     "\"root\",\n      \"password\" : null,\n      \"domain\" : null,"
                                     "\n      \"caCheck\" : false,\n      \"cnCheck\" : false,"
                                     "\n      \"certificateData\" : null,\n      \"certificateDetail\" : null,"
                                     "\n      \"port\" : 443,\n      \"retries\" : 3,\n      \"timeout\" : 60,"
                                     "\n      \"isHttp\" : false,\n      \"keepAlive\" : true,\n      \"version\" : "
                                     "null\n    }\n  } ]\n}",
                "DeviceType": [
                    1000
                ]
            }
        ],
        "Schedule": {
            "RunNow": True,
            "RunLater": False,
            "Recurring": None,
            "Cron": "startnow",
            "StartTime": None,
            "EndTime": None
        },
        "CreateGroup": True,
        "TrapDestination": False,
        "CommunityString": False
    }
    return discovery_config_details


def modify_discovery_job(ip_address, headers, device_user_name, device_password, ip_list, job_name_pattern):
    """ Discover devices """
    discovery_payload = get_discovery_config_payload()
    url = 'https://%s/api/DiscoveryConfigService/DiscoveryConfigGroups' % ip_address
    discovery_config_resp = requests.get(url, headers=headers, verify=False)
    config_group_id = None
    connection_profile = None
    temp_target_list = []
    if discovery_config_resp.status_code == 200:
        config_json_data = discovery_config_resp.json()
        if config_json_data['@odata.count'] > 0:
            for config in config_json_data['value']:
                if job_name_pattern in config['DiscoveryConfigGroupName']:
                    config_group_id = config['DiscoveryConfigGroupId']
                    discovery_config_targets = config["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"]
                    discovery_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"][:] = []
                    if len(ip_list):
                        for ip in ip_list:
                            temp_target_list.append({"NetworkAddressDetail": ip})
                        discovery_payload["DiscoveryConfigModels"][0]["DiscoveryConfigTargets"] = temp_target_list
                    else:
                        discovery_payload["DiscoveryConfigModels"][0][
                            "DiscoveryConfigTargets"] = discovery_config_targets
                    discovery_payload['DiscoveryConfigGroupId'] = config_group_id
                    connection_profile = json.loads(discovery_payload["DiscoveryConfigModels"][0]["ConnectionProfile"])
                    connection_profile['credentials'][0]['credentials']['username'] = device_user_name
                    connection_profile['credentials'][0]['credentials']['password'] = device_password
                    connection_profile['credentials'][1]['credentials']['username'] = device_user_name
                    connection_profile['credentials'][1]['credentials']['password'] = device_password
                    discovery_payload["DiscoveryConfigModels"][0]["ConnectionProfile"] = json.dumps(connection_profile)
                    break
        else:
            print("Unable to get device config data")
    else:
        print("Unable to get device config data")

    if config_group_id:
        config_grp_url = 'https://%s/api/DiscoveryConfigService/DiscoveryConfigGroups(%s)' \
                         % (ip_address, config_group_id)
        discovery_resp = requests.put(config_grp_url, headers=headers,
                                      data=json.dumps(discovery_payload), verify=False)
        if discovery_resp.status_code == 200:
            print("Successfully modified the discovery config group")
            get_job_status(ip_address, headers, job_name_pattern)
    else:
        print("Unable to find discovery config groupname corresponding to the discovery job name pattern passed")


def get_job_status(ip_address, headers, job_name_pattern):
    """ Tracks the Running job status """
    sleep_time = 3
    time.sleep(sleep_time)
    print("Polling job status")
    base_uri = 'https://%s' % ip_address
    job_url = base_uri + '/api/JobService/Jobs'
    next_link_url = None
    job_match_found = None
    job_resp = requests.get(job_url, headers=headers, verify=False)
    if job_resp.status_code == 200:
        job_info = job_resp.json()
        job_list = job_info['value']
        total_jobs = job_info['@odata.count']
        if total_jobs > 0:
            if '@odata.nextLink' in job_info:
                next_link_url = base_uri + job_info['@odata.nextLink']
            while next_link_url:
                next_link_response = requests.get(next_link_url, headers=headers, verify=False)
                if next_link_response.status_code == 200:
                    next_link_json_data = next_link_response.json()
                    job_list += next_link_json_data['value']
                    if '@odata.nextLink' in next_link_json_data:
                        next_link_url = base_uri + next_link_json_data['@odata.nextLink']
                    else:
                        next_link_url = None
                else:
                    print("Unable to retrieve device list from nextLink %s" % next_link_url)
        else:
            print("Job results are empty")

        for job in job_list:
            if job_name_pattern in job["JobName"] and job["LastRunStatus"]["Name"] == "Running":
                print("Discovery config job status is %s" % (job["LastRunStatus"]["Name"]))
                job_match_found = True

        if not job_match_found:
            print("Unable to track running discovery config job")
    else:
        print("Unable to fetch jobs")


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", required=True, help="OME Appliance IP")
    parser.add_argument("--user", required=False,
                        help="Username for OME Appliance",
                        default="admin")
    parser.add_argument("--password", required=False,
                        help="Password for OME Appliance")
    parser.add_argument("--jobNamePattern", required=True,
                        help="Job name pattern")
    parser.add_argument("--targetUserName", required=True,
                        help="Username to discover devices")
    parser.add_argument("--targetPassword", required=False,
                        help="Password to discover devices")
    parser.add_argument("--targetIpAddresses",
                        help="ip address to modify discovery job config group")

    args = parser.parse_args()
    ip_address = args.ip
    user_name = args.user
    if args.password:
        password = args.password
    else:
        password = getpass("Password for OME Appliance: ")
    device_user_name = args.targetUserName
    if args.targetPassword:
        device_password = args.targetPassword
    else:
        device_password = getpass("Password to discover devices: ")
    ip_array = args.targetIpAddresses
    discovery_job_name = args.jobNamePattern

    list_of_ip = []
    list_of_ipaddress = []
    if ip_array:
        list_of_ip = ip_array.split(',')

    for ip in list_of_ip:
        if '-' in ip:
            ips = ip.split('-')
        else:
            ips = ip
        if type(ips) is list:
            for ip in ips:
                list_of_ipaddress.append(ip)
        else:
            list_of_ipaddress.append(ips)
        for ip_addr in list_of_ipaddress:
            ip_bytes = ip_addr.split('.')
            if len(ip_bytes) != 4:
                raise Exception("Invalid IP address " + ip_addr + " Example of valid ip  192.168.1.0")
            for ip_byte in ip_bytes:
                if not ip_byte.isdigit():
                    raise Exception(
                        "Invalid IP address" + ip_addr + " Only digits are allowed. Example of valid ip 192.168.1.0")
                octet = int(ip_byte)
                if octet < 0 or octet > 255:
                    raise Exception(
                        "Invalid IP address " + ip_addr +
                        " single byte must be 0 <= byte < 256. Example of valid ip 192.168.1.0")

    try:
        auth_success, headers = authenticate_with_ome(ip_address, user_name,
                                                      password)
        if auth_success:
            modify_discovery_job(ip_address, headers,
                                 device_user_name, device_password,
                                 list_of_ip, discovery_job_name)
    except Exception as error:
        print("Unexpected error:", str(error))
