#
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

"""

#### Synopsis
Script to perform template deployment with or without identity pools on the target devices.

#### Description:
This script performs template deployment with or without an associated identity pool. Limitations:

- Currently the script only supports servers. It does not support chassis or IO modules. If this is something you would like please let us known by leaving an issue at https://github.com/dell/OpenManage-Enterprise/issues.
- The script does not provide an interface for changing the values in the identity pool. If you want to change the default values see the variable `identity_pool_payload`. You may update the values there
- The script allows you to either templatize all values from a target or only one value. Possible values are listed below. We did not add the ability to include arrays. If this is something you would like feel free to open an issue and let us know at https://github.com/dell/OpenManage-Enterprise/issues
    - iDRAC
    - BIOS
    - System
    - NIC
    - Lifecycle Controller
    - RAID
    - EventFilters
    - Fiber Channel
    - All

*WARNING*: To use identity pools the template must include NICs.

Note: The PowerShell version of this code has not been tested in some time. We suggest using the Python version. If an
update to the PowerShell version is a high priority to you please leave an issue at
https://github.com/dell/OpenManage-Enterprise/issues

#### Python Example
    python deploy_template.py --ip 192.168.1.93 --password PASSWORD --source-idrac-ip 192.168.1.10 --idrac-ips 192.168.1.45 --use-identity-pool
"""

import argparse
import json
import sys
import time
from argparse import RawTextHelpFormatter
from getpass import getpass
from urllib.parse import urlparse
from pprint import pprint
from datetime import datetime

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
        Exception: A generic exception in the event of a failure to connect.
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


def get_data(authenticated_headers: dict, url: str, odata_filter: str = None, max_pages: int = None) -> dict:
    """
    This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
    handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
    pages to get a complete listing.

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        url: The API url against which you would like to make a request
        odata_filter: An optional parameter for providing an odata filter to run against the API endpoint.
        max_pages: The maximum number of pages you would like to return

    Returns: Returns a dictionary of data received from OME

    """

    next_link_url = None

    if odata_filter:
        count_data = requests.get(url + '?$filter=' + odata_filter, headers=authenticated_headers, verify=False)

        if count_data.status_code == 400:
            print("Received an error while retrieving data from %s:" % url + '?$filter=' + odata_filter)
            pprint(count_data.json()['error'])
            return {}

        count_data = count_data.json()
        if count_data['@odata.count'] <= 0:
            print("No results found!")
            return {}
    else:
        count_data = requests.get(url, headers=authenticated_headers, verify=False).json()

    if 'value' in count_data:
        data = count_data['value']
    else:
        data = count_data

    if '@odata.nextLink' in count_data:
        # Grab the base URI
        next_link_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url)) + count_data['@odata.nextLink']

    i = 1
    while next_link_url is not None:
        # Break if we have reached the maximum number of pages to be returned
        if max_pages:
            if i >= max_pages:
                break
            else:
                i = i + 1
        response = requests.get(next_link_url, headers=authenticated_headers, verify=False)
        next_link_url = None
        if response.status_code == 200:
            requested_data = response.json()
            if requested_data['@odata.count'] <= 0:
                print("No results found!")
                return {}

            # The @odata.nextLink key is only present in data if there are additional pages. We check for it and if it
            # is present we get a link to the page with the next set of results.
            if '@odata.nextLink' in requested_data:
                next_link_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url)) + \
                                requested_data['@odata.nextLink']

            if 'value' in requested_data:
                data += requested_data['value']
            else:
                data += requested_data
        else:
            print("Unknown error occurred. Received HTTP response code: " + str(response.status_code) +
                  " with error: " + response.text)
            raise Exception("Unknown error occurred. Received HTTP response code: " + str(response.status_code)
                            + " with error: " + response.text)

    return data


def get_device_id(authenticated_headers: dict,
                  ome_ip_address: str,
                  service_tag: str = None,
                  device_idrac_ip: str = None,
                  device_name: str = None) -> int:
    """
    Resolves a service tag, idrac IP or device name to a device ID

    Args:
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        ome_ip_address: IP address of the OME server
        service_tag: (optional) The service tag of a host
        device_idrac_ip: (optional) The idrac IP of a host
        device_name: (optional): The name of a host

    Returns: Returns the device ID or -1 if it couldn't be found
    """

    if not service_tag and not device_idrac_ip and not device_name:
        print("No argument provided to get_device_id. Must provide service tag, device idrac IP or device name.")
        return -1

    # If the user passed a device name, resolve that name to a device ID
    if device_name:
        device_id = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                             "DeviceName eq \'%s\'" % device_name)
        if len(device_id) == 0:
            print("Error: We were unable to find device name " + device_name + " on this OME server. Exiting.")
            return -1

        device_id = device_id[0]['Id']

    elif service_tag:
        device_id = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                             "DeviceServiceTag eq \'%s\'" % service_tag)

        if len(device_id) == 0:
            print("Error: We were unable to find service tag " + service_tag + " on this OME server. Exiting.")
            return -1

        device_id = device_id[0]['Id']

    elif device_idrac_ip:
        device_id = -1
        device_ids = get_data(authenticated_headers, "https://%s/api/DeviceService/Devices" % ome_ip_address,
                              "DeviceManagement/any(d:d/NetworkAddress eq '%s')" % device_idrac_ip)

        if len(device_ids) == 0:
            print("Error: We were unable to find idrac IP " + device_idrac_ip + " on this OME server. Exiting.")
            return -1

        # TODO - This is necessary because the filter above could possibly return mulitple results
        # TODO - See https://github.com/dell/OpenManage-Enterprise/issues/87
        for device_id in device_ids:
            if device_id['DeviceManagement'][0]['NetworkAddress'] == device_idrac_ip:
                device_id = device_id['Id']

        if device_id == -1:
            print("Error: We were unable to find idrac IP " + device_idrac_ip + " on this OME server. Exiting.")
            return -1
    else:
        device_id = -1

    return device_id


def track_job_to_completion(ome_ip_address: str,
                            authenticated_headers: dict,
                            tracked_job_id,
                            max_retries: int = 20,
                            sleep_interval: int = 30) -> bool:
    """
    Tracks a job to either completion or a failure within the job.

    Args:
        ome_ip_address: The IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        tracked_job_id: The ID of the job which you would like to track
        max_retries: The maximum number of times the function should contact the server to see if the job has completed
        sleep_interval: The frequency with which the function should check the server for job completion

    Returns: True if the job completed successfully or completed with errors. Returns false if the job failed.
    """
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

    failed_job_status = [2070, 2090, 2100, 2101, 2102, 2103]
    job_url = 'https://%s/api/JobService/Jobs(%s)' % (ome_ip_address, tracked_job_id)
    loop_ctr = 0
    job_incomplete = True
    print("Polling %s to completion ..." % tracked_job_id)

    while loop_ctr < max_retries:
        loop_ctr += 1
        time.sleep(sleep_interval)
        job_resp = get_data(authenticated_headers, job_url)
        requests.get(job_url, headers=authenticated_headers, verify=False)

        try:
            if job_resp.status_code == 200:
                job_status = str((job_resp.json())['LastRunStatus']['Id'])
                job_status_str = job_status_map[job_status]
                print("Iteration %s: Status of %s is %s" % (loop_ctr, tracked_job_id, job_status_str))

                if int(job_status) == 2060:
                    job_incomplete = False
                    print("Job completed successfully!")
                    break
                elif int(job_status) in failed_job_status:
                    job_incomplete = True

                    if job_status_str == "Warning":
                        print("Completed with errors")
                    else:
                        print("Error: Job failed.")

                    job_hist_url = str(job_url) + "/ExecutionHistories"
                    job_hist_resp = requests.get(job_hist_url, headers=authenticated_headers, verify=False)

                    if job_hist_resp.status_code == 200:
                        # Get the job's execution details
                        job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
                        execution_hist_detail = "(" + job_history_id + ")/ExecutionHistoryDetails"
                        job_hist_det_url = str(job_hist_url) + execution_hist_detail
                        job_hist_det_resp = requests.get(job_hist_det_url,
                                                         headers=authenticated_headers,
                                                         verify=False)
                        if job_hist_det_resp.status_code == 200:
                            pprint(job_hist_det_resp.json()['value'])
                        else:
                            print("Unable to parse job execution history... exiting")
                    break
            else:
                print("Unable to poll status of %s - Iteration %s " % (tracked_job_id, loop_ctr))
        except AttributeError:
            print("There was a problem getting the job info during the wait. Full error details:")
            pprint(job_resp.json())
            return False

    if job_incomplete:
        print("Job %s incomplete after polling %s times...Check status" % (tracked_job_id, max_retries))
        return False

    return True


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", required=True, help="OME Appliance IP")
    parser.add_argument("-u", "--user", required=False,
                        help="Username for OME Appliance",
                        default="admin")
    parser.add_argument("-p", "--password", required=False,
                        help="Password for OME Appliance")
    exclusive_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_group.add_argument("--source-device-id", help="ID of the device to serve as source template")
    exclusive_group.add_argument("--source-service-tag", help="Service tag of the device to serve as source template")
    exclusive_group.add_argument("--source-idrac-ip", help="idrac IP of the device to serve as source template")
    exclusive_group.add_argument("--source-device-name", help="Name of the device to serve as source template")
    parser.add_argument("--groupname", "-g", required=False,
                        help="The name of the group containing the devices whose power state you want to change.")
    parser.add_argument("--device-ids", "-d", help="A comma separated list of device-ids to whom you want to deploy "
                                                   "the template.")
    parser.add_argument("--service-tags", "-s", help="A comma separated list of service tags to whom you want to "
                                                     "deploy the template.")
    parser.add_argument("--idrac-ips", "-r", help="A comma separated list of idrac IPs to whom you want to deploy the "
                                                  "template.")
    parser.add_argument("--device-names", "-n", help="A comma separated list of device names to whom you want to "
                                                     "deploy the template.")
    parser.add_argument("--component", required=False,
                        choices=("iDRAC", "BIOS", "System", "NIC", "LifecycleController", "RAID", "EventFilters",
                                 "All"), help="Component to clone from source device", default='All')
    parser.add_argument("--use-identity-pool", required=False, default=False, action='store_true')

    args = parser.parse_args()

    if not args.password:
        args.password = getpass()

    if args.use_identity_pool and (args.component != 'All' and args.component != 'NIC'):
        print("Error: When using identity pools you must set component to either All or NIC.")
        sys.exit(0)

    try:

        headers = authenticate(args.ip, args.user, args.password)

        if not headers:
            sys.exit(0)

        source_id = -1

        if args.source_service_tag:
            source_id = get_device_id(headers, args.ip, service_tag=args.source_service_tag)
            if source_id == -1:
                print("Could not resolve source device ID from: " + args.source_service_tag)

        elif args.source_idrac_ip:
            source_id = get_device_id(headers, args.ip, device_idrac_ip=args.source_idrac_ip)
            if source_id == -1:
                print("Could not resolve source device ID from: " + args.source_idrac_ip)

        elif args.source_device_name:
            source_id = get_device_id(headers, args.ip, device_name=args.source_device_name)
            if source_id == -1:
                print("Could not resolve source device ID from: " + args.source_device_name)

        elif args.source_device_id:
            source_id = args.source_device_id

        #############################################
        # Resolve names to IDs and populate targets #
        #############################################
        target_ids = []

        if args.service_tags:
            service_tags = args.service_tags.split(',')
            for service_tag in service_tags:
                target = get_device_id(headers, args.ip, service_tag=service_tag)
                if target != -1:
                    target_ids.append(target)
                else:
                    print("Could not resolve ID for: " + service_tag)
        else:
            service_tags = None

        if args.idrac_ips:
            device_idrac_ips = args.idrac_ips.split(',')
            for device_idrac_ip in device_idrac_ips:
                target = get_device_id(headers, args.ip, device_idrac_ip=device_idrac_ip)
                if target != -1:
                    target_ids.append(target)
                else:
                    print("Could not resolve ID for: " + device_idrac_ip)
        else:
            device_idrac_ips = None

        if args.device_names:
            device_names = args.device_names.split(',')
            for device_name in device_names:
                target = get_device_id(headers, args.ip, device_name=device_name)
                if target != -1:
                    target_ids.append(target)
                else:
                    print("Could not resolve ID for: " + device_name)
        else:
            device_names = None

        # Resolve any devices in a group to ID and add them to targets
        if args.groupname:

            group_url = "https://%s/api/GroupService/Groups" % args.ip

            group_data = get_data(headers, group_url,
                                  "Name eq '%s'" % args.groupname)

            if len(group_data) < 1:
                print("No groups were found with name " + args.groupname)
                sys.exit(0)

            print("Found group " + group_data[0]['Name'] + "!")

            group_devices = get_data(headers, group_url + "(%s)/Devices" % group_data[0]['Id'])

            if len(group_devices) < 1:
                print("Error: There was a problem retrieving the devices for group " + args.groupname + ". Exiting")
                sys.exit(0)

            for device in group_devices:
                target_ids.append(device['Id'])

        ############################
        # Get the template payload #
        ############################
        template_id = None
        identity_pool_id = None
        name = str(datetime.now())

        # TODO - Possible enhancement. Make it so we can also run against chassis and network devices

        template_payload = {
            "Name": name,
            "Description": "Template",
            "TypeId": 2,  # This is the template type for servers.
            "ViewTypeId": 2,  # This viewtype corresponds to a deployment (as opposed to compliance/inventory)
            "SourceDeviceId": source_id,
            "Fqdds": args.component
        }

        # This will create the template from the source IP and make it available to other devices
        template_post_response = requests.post('https://%s/api/TemplateService/Templates' % args.ip, verify=False,
                                               data=json.dumps(template_payload),
                                               headers=headers)
        #######################
        # Create the template #
        #######################
        if template_post_response.status_code == 201:
            template_id = template_post_response.json()
        else:
            print("Unable to create template... exiting")
            sys.exit(0)

        attempts = 0
        while True:
            template_test = get_data(headers, "https://%s/api/TemplateService/Templates(%s)" % (args.ip, template_id))
            print("Checking to see if the template has been created... attempt " + str(attempts + 1))
            if 'Status' in template_test:
                # Status 2060 corresponds to completed. 2050 corresponds to running. Those are the only two statuses
                # we should see here. 0 is what is returned for the brief moment while the template is being created
                if template_test['Status'] == 2060:
                    print("Template created successfully!")
                    break
                elif template_test['Status'] != 2050 and template_test['Status'] != 0:
                    print("Error: There was a problem creating the template. See the OME job logs for details. "
                          "Template's ID is " + str(template_id))
                    sys.exit(0)
            time.sleep(5)
            if attempts > 30:
                print("Error: There was a problem creating the template. See the OME job logs for details. "
                      "Template's ID is " + str(template_id))
                sys.exit(0)
            attempts = attempts + 1

        # For an explanation of how this works see:
        # https://github.com/grantcurell/dell/tree/master/IO%20Identities%20with%20LifeCycle%20Controller
        if args.use_identity_pool:

            ############################
            # Create the identity pool #
            ############################

            # TODO Possible enhancement - make these configurable

            identity_pool_payload = {
                "Name": name,
                "EthernetSettings": {
                    "Mac": {
                        "IdentityCount": 55,
                        "StartingMacAddress": "UFBQUFAA"
                    }
                },
                "IscsiSettings": {
                    "Mac": {
                        "IdentityCount": 65,
                        "StartingMacAddress": "YGBgYGAA"
                    },
                    "InitiatorConfig": {
                        "IqnPrefix": "iqn.dell.com"
                    }
                },
                "FcoeSettings": {
                    "Mac": {
                        "IdentityCount": 75,
                        "StartingMacAddress": "cHBwcHAA"
                    }
                },
                "FcSettings": {
                    "Wwnn": {
                        "IdentityCount": 85,
                        "StartingAddress": "IACAgICAgAA="
                    },
                    "Wwpn": {
                        "IdentityCount": 85,
                        "StartingAddress": "IAGAgICAgAA="
                    }
                }
            }

            URL = 'https://%s/api/IdentityPoolService/IdentityPools' % args.ip
            identity_pool_post_response = requests.post(URL, verify=False,
                                                        data=json.dumps(identity_pool_payload),
                                                        headers=headers)
            if identity_pool_post_response.status_code == 201:
                identity_pool_post_response = identity_pool_post_response.json()
                is_io_successful = identity_pool_post_response["IsSuccessful"]
                if is_io_successful:
                    print("Identity pool creation successful!")
                else:
                    print("Identity pool creation unsuccessful.. exiting.")
                    sys.exit(0)
            elif "Range overlap" in identity_pool_post_response.text:
                pprint(identity_pool_post_response.json())
                print("Error. Overlap in the requested identity pool ranges found. Double check any existing identity"
                      " pools and delete them or update them so that there is no overlap.")
                sys.exit(0)
            else:
                print("Unable to create identity pool. Full error below:")
                pprint(identity_pool_post_response.json())

            identity_pool_id = identity_pool_post_response["Id"]

            attempts = 0
            while True:
                identity_pool_test = get_data(headers, "https://%s/api/IdentityPoolService/IdentityPools(%s)" %
                                              (args.ip, str(identity_pool_id)))
                print("Checking to see if the identity pool has been created... attempt " + str(attempts + 1))
                if 'Id' in identity_pool_test:
                    print("Identity pool created successfully!")
                    break
                time.sleep(5)
                if attempts > 30:
                    print("Error: There was a problem creating the identity pool. See the OME job logs for details. "
                          "Template's ID is " + str(identity_pool_id))
                    sys.exit(0)
                attempts = attempts + 1

            ############################
            # Assign the identity pool #
            ############################
            payload = {
                "TemplateId": int(template_id),
                "IdentityPoolId": int(identity_pool_id)
            }
    
            assign_ip_response = requests.post('https://%s/api/TemplateService/Actions/TemplateService.UpdateNetworkConfig'
                                               % args.ip, verify=False,
                                               data=json.dumps(payload),
                                               headers=headers)

            if assign_ip_response.status_code == 200:
                print("Identity pool successfully assigned to template!")
            else:
                pprint(assign_ip_response.json())
                print("There was a problem assigning the identity pool to the template. Error above.")
                sys.exit(0)

        #######################
        # Deploy the template #
        #######################

        template_payload = {
            "Id": int(template_id),
            "TargetIds": target_ids
        }

        print("Creating job to deploy template...")
        url = 'https://%s/api/TemplateService/Actions/TemplateService.Deploy' % args.ip
        deploy_response = requests.post(url, verify=False,
                                        data=json.dumps(template_payload),
                                        headers=headers)

        if deploy_response.status_code == 200:
            deploy_response = deploy_response.json()
            job_id = deploy_response
            print("Waiting for template deploy to complete...")
            track_job_to_completion(args.ip, headers, job_id)
        else:
            print("Failed to deploy template")

    except Exception as error:
        pprint(error)
