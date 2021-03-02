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
Script to update firmware using catalog

#### Description:
This script uses the OME REST API to update firmware using a catalog. Note: The Python version is more feature rich
currently than the PowerShell version. The primary functionality difference is the ability to specify a catalog instead
of deleting old catalogs/baselines and creating new ones. If the PowerShell version is a priority for you please leave
a comment on https://github.com/dell/OpenManage-Enterprise/issues/194

Note that the credentials entered are not stored to disk.

#### Python Example
    python update_firmware_using_catalog.py --ip <ip addr> --user admin --password <passwd> --groupname Test
    python update_firmware_using_catalog.py --ip 192.168.1.93 --user admin --password <passwd> --updateactions upgrade --service-tags AAAAAA --idrac-ips 192.168.1.63 --reposourceip 192.168.1.153 --catalogpath OpenManage/Current_1.01_Catalog.xml --repouser <username> --repopassword <passwd> --repotype CIFS --refresh-retry-length 5
    python update_firmware_using_catalog.py --ip 192.168.1.93 --user admin --password <passwd> --updateactions upgrade --idrac-ips 192.168.1.63,192.168.1.120 --catalog-name Dell_Online --refresh
    python update_firmware_using_catalog.py --ip 192.168.1.93 --updateactions upgrade --idrac-ips 192.168.1.63,192.168.1.120 --device-names "Test-Device" --catalog-name Dell_Online
"""

import argparse
import json
import os
import sys
import time
from argparse import RawTextHelpFormatter
from getpass import getpass
from urllib.parse import urlparse
from pprint import pprint

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
    sys.exit(0)


def query_yes_no(question: str, default: str = "yes") -> bool:
    """
    Prompts the user with a yes/no question

    Args:
        question: The question to ask the user
        default: Whether the default answer is no or yes. Defaults to yes

    Returns: A boolean - true if yes and false if no

    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


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


def catalog_creation_payload(repo_type: str,
                             repo_source_ip: str,
                             catalog_path: str,
                             repo_user: str = "",
                             repo_domain: str = "",
                             repo_password: str = "") -> dict:
    """
    Creates the payload required to create a new catalog in OME

    Args:
        repo_type: The repository type (HTTP, CIFS, DELL_ONLINE, etc)
        repo_source_ip: The IP address of the repository
        catalog_path: The path to the catalog. Ex: 192.168.1.53/thisis/thepath/catalog.xml (but not the IP)
        repo_user: (Optional) Username for the repository
        repo_domain: (Optional) Domain for the repository
        repo_password: (Optional) Password for the repository

    Returns: A dictionary with the payload required for creating the catalog

    """
    source_path = ""
    filename = ""
    if repo_type == 'DELL_ONLINE':
        source = "downloads.dell.com"
    else:
        source = repo_source_ip
        path_tuple = os.path.split(catalog_path)
        source_path = path_tuple[0]
        filename = path_tuple[1]

    return {
        "Filename": filename,
        "SourcePath": source_path,
        "Repository": {
            "Name": repo_type + '_' + repo_source_ip + '_' + time.strftime(":%Y:%m:%d-%H:%M:%S"),
            "Description": "Catalog created automatically by the OME API",
            "RepositoryType": repo_type,
            "Source": source,
            "DomainName": repo_domain,
            "Username": repo_user,
            "Password": repo_password,
            "CheckCertificate": False
        }
    }


def refresh_catalog(ome_ip_address: str, authenticated_headers: dict, catalog_identifier: int,
                    max_retries: int = 20, retry_length: int = 60) -> bool:
    """
    Refreshes a target catalog and makes sure it is up to date

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        catalog_identifier: The ID of the catalog which you want to refresh
        max_retries: The number of times to check whether updating the catalog was successful
        retry_length: The number of seconds to wait for each retry

    Returns: True if the refresh is successful or false if it is not

    """

    url = 'https://%s/api/UpdateService/Actions/UpdateService.RefreshCatalogs' % ome_ip_address
    print("Launching the catalog update job...")
    data = post_data(url, authenticated_headers, {"CatalogIds": [catalog_identifier],
                                                  "AllCatalogs": "false"},
                     "The post request for refreshing the catalog failed!")

    if 'status_code' in data:
        retry = 0
        while retry < max_retries:
            print("Waiting %s seconds and then checking if the catalog refresh has finished..." % retry_length)
            time.sleep(retry_length)

            catalog_refresh_data = get_data(authenticated_headers,
                                            'https://%s/api/UpdateService/Catalogs(%s)' %
                                            (ome_ip_address, catalog_identifier))

            if catalog_refresh_data['Status'] != 'Running':
                print("Catalog update completed.")

                if catalog_refresh_data['Status'] == 'Failed':
                    if query_yes_no("There was a problem updating the catalog! Check OME's UI for more "
                                    "information. Do you want to continue? (y/n): "):
                        return True
                    else:
                        return False

                else:
                    print("Catalog update completed successfully!")
                    return True
            else:
                print("Catalog status is %s. Waiting another %s and then rechecking. This is attempt %s" %
                      (catalog_refresh_data['Status'], retry_length, retry))
                retry = retry + 1

        print("Reached the maximum number of retries. The catalog update has failed!")
        return False

    else:
        print("Catalog refresh failed. Exiting!")
        return False


def get_catalog_identifier(ome_ip_address: str, authenticated_headers: dict, catalog_name: str, refresh: bool = False,
                           max_retries: int = 20, retry_length: int = 60) -> tuple:
    """
    Looks up the catalog and repository IDs of an existing catalog

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        catalog_name: Name of the catalog which you want to lookup
        refresh: Whether or not you want to force a refresh of the catalog
        max_retries: The number of times to check whether updating the catalog was successful
        retry_length: The number of seconds to wait for each retry

    Returns: Returns a tuple consisting of type (catalog ID, repo ID)

    """

    url = 'https://%s/api/UpdateService/Catalogs' % ome_ip_address
    print("Getting a list of catalogs...")
    all_repo_profiles = get_data(authenticated_headers, url)

    # First retrieve a listing of all existing repos so that we can establish if the repo in question already exists
    if len(all_repo_profiles) > 0:
        catalog = next((sub for sub in all_repo_profiles if sub['Repository']['Name'] == catalog_name), {})

        if not catalog:
            print("Could not find the catalog with name " + catalog_name + "! Exiting.")
            return -1, -1

        # Found a repo that matches the user request - either refresh or just return
        if refresh:
            if refresh_catalog(ome_ip_address, authenticated_headers, catalog["Id"], max_retries, retry_length):
                return catalog["Id"], catalog["Repository"]["Id"]
            else:
                return -1, -1

        else:
            return catalog["Id"], catalog["Repository"]["Id"]
    else:
        print("There was a problem retrieving the catalogs from OME. Is there a connection issue?")
        return -1, -1


def create_catalog(ome_ip_address: str,
                   authenticated_headers: dict,
                   repo_type: str = None,
                   repo_source_ip: str = None,
                   catalog_path: str = None,
                   repo_user: str = None,
                   repo_password: str = None,
                   repo_domain: str = None,
                   max_retries: int = 20,
                   retry_length: int = 60):
    """
    Creates a new catalog with an associated repository

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        repo_type: The repository type (HTTP, CIFS, DELL_ONLINE, etc)
        repo_source_ip: The IP address of the repository
        catalog_path: The path to the catalog. Ex: 192.168.1.53/thisis/thepath/catalog.xml (but not the IP)
        repo_user: (Optional) Username for the repository
        repo_password: (Optional) Password for the repository
        repo_domain: (Optional) Domain for the repository
        max_retries: The number of times to check whether updating the catalog was successful
        retry_length: The number of seconds to wait for each retry

    Returns: Returns a tuple consisting of (catalog ID, repo ID)

    """

    url = 'https://%s/api/UpdateService/Catalogs' % ome_ip_address
    print("Creating new catalog...")
    payload = catalog_creation_payload(repo_type,
                                       repo_source_ip,
                                       catalog_path,
                                       repo_user,
                                       repo_domain,
                                       repo_password)

    data = post_data(url, authenticated_headers, payload, "There was a problem creating the catalog! "
                                                          "Are you sure you have the full path to the catalog?")
    if not data:
        return -1, -1

    catalog_name = data['Repository']['Name']

    if not track_job_to_completion(ome_ip_address, authenticated_headers, data['TaskId'], max_retries, retry_length):
        print("Failed to create the catalog!")
        return -1, -1

    return get_catalog_identifier(ome_ip_address, authenticated_headers, catalog_name, refresh=False)


def baseline_creation_payload(catalog_identifier: int, repo_identifier: int, device_details: dict) -> dict:
    """
    Creates the JSON payload required to create the baseline

    Args:
        catalog_identifier: The ID for the target catalog
        repo_identifier: The ID of the repository associated with the catalog
        device_details: A dictionary containing the device type IDs and the device type names

    Returns: A dictionary with the payload required to create a new baseline in OME

    """
    baseline_payload = {'Name': "Dell baseline update" + time.strftime(":%Y:%m:%d-%H:%M:%S"),
                        'Description': "Baseline update job launched via the OME API", 'CatalogId': catalog_identifier,
                        'RepositoryId': repo_identifier, 'DowngradeEnabled': True,
                        'Is64Bit': True, 'Targets': []}

    for target_id, target_type_dictionary in device_details.items():
        baseline_payload['Targets'].append({
            "Id": target_id,
            "Type": target_type_dictionary
        })

    return baseline_payload


def get_device_details(ome_ip_address: str, authenticated_headers: dict, device_ids: list) -> dict:
    """
    For all target devices, retrieves the device info. We are specifically interested in the device type name and ID
    For example, for a server the device type is SERVER and the ID is 1000

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        device_ids: A list of all the target device IDs

    Returns: Either a dictionary of dictionariesin the form device_id: {'Type': <TYPE>, 'DeviceName': <NAME>} or an
             empty dictionary if the function encounters a problem

    """
    query_string = ""
    device_details = {device_id: {'Id': None, 'Name': None} for device_id in device_ids}
    for device_id in device_ids:
        query_string = query_string + "{}".format(device_id) + ','
    query_string = query_string[0:-1]

    device_url = 'https://%s/api/DeviceService/Devices?Id=%s' % (ome_ip_address, query_string)
    print("Retrieving information for all devices...")
    device_info = get_data(authenticated_headers, device_url)

    if len(device_info) < 1:
        print("There was a problem retrieving the device type names. Quitting.")
        return {}

    # You need this to resolve the device type ID to a name
    device_type_info = get_data(authenticated_headers, 'https://%s/api/DeviceService/DeviceType' % ome_ip_address)

    for device_dictionary in device_info:

        # Assign the device type ID
        device_details[device_dictionary['Id']]['Id'] = device_dictionary['Type']

        # Assign the device type name (server, chassis, etc)
        for device_type in device_type_info:
            if device_dictionary['Type'] == device_type['DeviceType']:
                device_details[device_dictionary['Id']]['Name'] = device_type['Name']

        if device_details[device_dictionary['Id']]['Name'] is None:
            print("There was a problem finding the device type name. Quitting.")
            return {}

    if len(device_details) > 0:
        return device_details
    else:
        print("We shouldn't have ever been here. There was a problem retrieving the device details. The program should"
              " exit.")
        return {}


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
        job_resp = requests.get(job_url, headers=authenticated_headers, verify=False)

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
            pprint(job_resp)
            return False

    if job_incomplete:
        print("Job %s incomplete after polling %s times...Check status" % (tracked_job_id, loop_ctr))
        return False

    return True


def get_baseline_id(ome_ip_address: str, authenticated_headers: dict, baseline_name: str) -> int:
    """
    Resolves a baseline name to an ID

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        baseline_name: The name of the baseline whose ID you  want to resolve

    Returns: The integer identifier of the baseline or -1 if it couldn't be found

    """
    url = 'https://%s/api/UpdateService/Baselines' % ome_ip_address

    baselines = get_data(authenticated_headers, url)

    baseline = next((sub for sub in baselines if sub['Name'] == baseline_name), {})

    if 'Id' in baseline:
        return baseline['Id']
    else:
        return -1


def baseline_creation(ome_ip_address: str, authenticated_headers: dict, targets: list, catalog_identifier: int,
                      repo_identifier: int) -> tuple:
    """
    Creates a new firmware baseline against the previously created catalog

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        targets: A list of all the device IDs to be updated
        catalog_identifier: The ID of the catalog
        repo_identifier: The ID of the repository which the catalog is using

    Returns: Returns a tuple consisting of (dict, int, int) where the dictionary is the type information for the device,
             the first integer is the ID of the baseline, and the second is the ID of the baseline compliance job. We
             save the ID of the baseline compliance job so we can run it again later

    """
    url = 'https://%s/api/UpdateService/Baselines' % ome_ip_address
    print("Creating a new Baseline!")

    device_details = get_device_details(ome_ip_address, authenticated_headers, targets)
    payload = baseline_creation_payload(catalog_identifier, repo_identifier, device_details)

    baseline_data = post_data(url, authenticated_headers, payload,
                              "There was a problem posting the job to create the baseline!")

    if not baseline_data:
        return {}, -1, -1
    baseline_task_id = baseline_data["TaskId"]
    track_job_to_completion(ome_ip_address, authenticated_headers, baseline_task_id, 30, 10)
    return device_details, get_baseline_id(ome_ip_address, authenticated_headers,
                                           baseline_data['Name']), baseline_task_id


def check_device_compliance_report(ome_ip_address: str, authenticated_headers: dict, baseline_identifier: int,
                                   desired_action) -> list:
    """
    Generates a list of all the components for each device which do not meet the specified baseline

    Args:
        ome_ip_address: The IP address of the OME server
        authenticated_headers: Headers used for authentication to the OME server
        baseline_identifier: ID of the baseline against which to compare
        desired_action: The action which the user wants to apply (UPGRADE, DOWNGRADE, FLASH_ALL)

    Returns: A list of dictionaries. Each dictionary includes the id of the device and a string containing all the
             devices which require a change

    """
    compliance_report_list = []
    source_names = None
    compl_url = "https://%s/api/UpdateService/Baselines(%s)/DeviceComplianceReports" % \
                (ome_ip_address, baseline_identifier)
    component_data = get_data(authenticated_headers, compl_url)

    if len(component_data) < 0:
        print("There was a problem retrieving the data for the devices! We are unable to check device compliance.")
        return []

    for device_dict in component_data:

        if 'ComponentComplianceReports' not in device_dict:
            print("Error: the field ComponentComplianceReports is missing from the device information for device:")
            pprint(device_dict)
            return []

        compliance_findings = device_dict.get('ComponentComplianceReports')

        if compliance_findings:
            for finding in compliance_findings:

                # After checking the compliance of the baseline, identify any devices whose update action matches the
                # action which the user wants to take. (upgrade/downgrade)
                if finding["UpdateAction"] in desired_action:
                    if source_names:
                        source_names = source_names + ';' + finding["SourceName"]
                        print("Updating %s %s from version %s to version %s" %
                              (device_dict['ServiceTag'], finding['Name'], finding['CurrentVersion'],
                               finding['Version']))
                    else:
                        source_names = finding["SourceName"]

            if source_names:
                compliance_report_list.append({"Id": device_dict.get("DeviceId"), "Data": source_names})
            else:
                print("WARNING: Device %s was part of the compliance report but had no results. This means it was "
                      "either completely up to date or the catalog did not have any updates that matched the "
                      "device type." % device_dict['ServiceTag'])

    return compliance_report_list


def create_firmware_update_payload(device_info: dict, compliance_data_list: list) -> list:
    """
    Creates the payload to send to OME to execute the firmware update

    Args:
        device_info: A dictionary of dictionaries containing the type information for each device
        compliance_data_list: A list of dictionaries containing the firmware changes which need to be made on each
                              device

    Returns: A list of dictionaries representing the payload for each device
    """
    target_list = []
    for data in compliance_data_list:
        target_list.append({'Id': data['Id'],
                            'TargetType': device_info[data['Id']],
                            'Data': data['Data']})
    return target_list


def create_payload_for_firmware_update(job_type_id: int, baseline_identifier: str,
                                       catalog_identifier: str, repository_id: str, target_data: list):
    """
    Generate the payload to initiate a firmware update job

    Args:
        job_type_id: ID of the job with name 'Update_Task'. This must be a variable because while it is unlikely to
                     change inside of OME, it could. So we look it up every time the script runs.
        baseline_identifier: ID of the baseline which we will update against
        catalog_identifier: ID of the catalog which we will update against
        repository_id: ID of the repository which we will update against
        target_data: A list of dictionaries containing the information required to tell OME what nodes
                     (servers/chassis) to update and the specific devices on those nodes

    Returns: A dictonary representing the firmware upadte payload

    """
    return {
        "JobName": "Update Firmware-Test:" + baseline_identifier,
        "JobDescription": "Firmware Update Job",
        "Schedule": "startNow",
        "State": "Enabled",
        "JobType": {
            "Id": job_type_id,
            "Name": "Update_Task"
        },
        "Params": [{
            "Key": "complianceReportId",
            "Value": baseline_identifier
        }, {
            "Key": "repositoryId",
            "Value": repository_id
        }, {
            "Key": "catalogId",
            "Value": catalog_identifier
        }, {
            "Key": "operationName",
            "Value": "INSTALL_FIRMWARE"
        }, {
            "Key": "complianceUpdate",
            "Value": "true"
        }, {
            "Key": "signVerify",
            "Value": "true"
        }, {
            "Key": "stagingValue",
            "Value": "false"
        }],
        "Targets": target_data
    }


def firmware_update(ome_ip_address: str, authenticated_headers: dict, repository_id: int, catalog_identifier: int,
                    baseline_identifier: int, target_data: list) -> bool:
    """
    Executes the firmware update job

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        repository_id: ID of the repository which we will update against
        catalog_identifier: ID of the catalog which we will update against
        baseline_identifier: ID of the baseline which we will update against
        target_data: A list of dictionaries containing the information required to tell OME what nodes
                     (servers/chassis) to update and the specific devices on those nodes

    Returns: A boolean - true if the job completed successfully or false otherwise

    """
    job_data = get_data(authenticated_headers, "https://{0}/api/JobService/JobTypes".format(ip_address))
    update_task = next((sub for sub in job_data if sub['Name'] == 'Update_Task'), {})

    if not update_task:
        print("Error: This is unusual - we went to retrieve the update task ID from OME but the retrieval failed. "
              "Can you reach https://{0}/api/JobService/JobTypes ?".format(ip_address))
        return False

    payload = create_payload_for_firmware_update(update_task['Id'], str(baseline_identifier),
                                                 str(catalog_identifier), str(repository_id), target_data)
    url = 'https://{0}/api/JobService/Jobs'.format(ome_ip_address)
    update_data = post_data(url, authenticated_headers, payload,
                            "There was a problem submitting the firmware update job!")
    if not update_data:
        return False

    return track_job_to_completion(ome_ip_address, authenticated_headers, update_data["Id"])


def refresh_compliance_data(ome_ip_address: str, authenticated_headers: dict, baseline_job_id: int) -> bool:
    """
    Reruns baseline job to refresh inventory data

    Args:
        ome_ip_address: IP address of the OME server
        authenticated_headers: A dictionary of HTTP headers generated from an authenticated session with OME
        baseline_job_id: The identifier for the job in OpenManage for checking the baseline's compliance

    Returns: A boolean - true if the job completed successfully or false otherwise

    """
    url = 'https://%s/api/JobService/Actions/JobService.RunJobs' % ome_ip_address
    payload = {
        "JobIds": [int(baseline_job_id)]
    }

    print("Submitting a job to recheck compliance post update. Note: You may also have to refresh the device inventory"
          " for compliance to display correctly.")
    data = post_data(url, authenticated_headers, payload,
                     "There was a problem resubmitting the baseline compliance job after the update!")

    if data:
        print("Job submitted, waiting for completion...")
    else:
        return False

    return track_job_to_completion(ome_ip_address, authenticated_headers, baseline_job_id)


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

        # TODO - This is necessary because the filter above could possibly return multiple results
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


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", required=True, help="OME Appliance IP")
    parser.add_argument("--user", required=False, help="Username for OME Appliance", default="admin")
    parser.add_argument("--password", required=False, help="Password for OME Appliance")
    parser.add_argument("--updateactions", required=False, nargs="*",
                        help="Desired action to take. Can be upgrade, downgrade, or flash-all.",
                        choices=['upgrade', 'downgrade', 'flash-all'], default='upgrade')
    parser.add_argument("--groupname", "-g", help="The name of a group whose devices should be updated")
    parser.add_argument("--device-ids", "-d", help="A comma separated list of device-ids to update")
    parser.add_argument("--service-tags", "-s", help="A comma separated list of service tags to update")
    parser.add_argument("--idrac-ips", "-r", help="A comma separated list of idrac IPs to update")
    parser.add_argument("--device-names", "-n", help="A comma separated list of device names to update.")
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument("--repotype", help="The repository type you would like to create. Using this option will "
                                                "cause the script to create a new catalog and associate it with a "
                                                "baseline.",
                             choices=['DELL_ONLINE', 'NFS', 'CIFS'], type=str)
    mutex_group.add_argument("--catalog-name", help="The name of an existing catalog that you would like to use.",
                             type=str)
    parser.add_argument("--reposourceip", required=False, type=str,
                        help="The IP address or hostname of the repository.")
    parser.add_argument("--catalogpath", required=False, type=str,
                        help="The path to the catalog file. For example, if the full path were"
                             " 192.168.1.153/OpenManage/Current_1.01_Catalog.xml then the catalog path would be"
                             " OpenManage/Current_1.01_Catalog.xml. Do not include a leading slash!")
    parser.add_argument("--repouser", required=False, type=str,
                        help="Username for a CIFS repository")
    parser.add_argument("--repodomain", required=False, type=str,
                        help="Domain for CIFS repository credentials")
    parser.add_argument("--repopassword", required=False, type=str,
                        help="Password for CIFS repository")
    parser.add_argument("--refresh", required=False, default=False, action='store_true',
                        help="refresh/create online catalog or use existing one.")
    parser.add_argument("--refresh-retry-length", type=int, required=False, default=60,
                        help="How long you want to wait between attempts to check if a catalog refresh "
                             "completed successfully. Defaults to 60 seconds. This is typically longer than necessary.")
    args = parser.parse_args()
    if args.repotype == 'CIFS':
        if args.reposourceip is None or args.catalogpath is None or args.repouser is None:
            parser.error("CIFS repository requires --reposourceip, --catalogpath, "
                         "--repouser and --repopassword.")
        if not args.repopassword:
            args.repopassword = getpass("Password for CIFS repository: ")
    if args.repotype == 'NFS' and (args.reposourceip is None or args.catalogpath is None):
        parser.error("NFS repository requires --reposourceip, --catalogpath.")

    if 'flash-all' in args.updateactions or 'downgrade' in args.updateactions:
        if not query_yes_no("WARNING: Downgrade and flash all have not been tested! If this is a priority for you,"
                            " let us know at https://github.com/dell/OpenManage-Enterprise/issues/193 "
                            "Do you want to continue? (y/n): "):
            sys.exit(0)

    ip_address = args.ip
    user_name = args.user

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

    update_actions = set()
    for action in args.updateactions:
        if action == "flash-all":
            update_actions.add('UPGRADE')
            update_actions.add('DOWNGRADE')
            break
        update_actions.add(action.upper())

    if args.refresh and not args.catalog_name:
        print("WARNING: You provided the refresh switch. This can only be used with the catalog-name argument.")

    if (args.reposourceip or args.catalogpath or args.repouser or args.repodomain or args.repopassword) \
            and not args.repotype:
        print("WARNING: - The arguments reposourceip, catalogpath, repouser, repodomain, and repopassword can only "
              "be used with repotype. We are ignoring these arguments!")

    try:
        pool = urllib3.HTTPSConnectionPool(ip_address, port=443,
                                           cert_reqs='CERT_NONE', assert_hostname=False)
        headers = authenticate(ip_address, user_name, password)

        ######################
        # Resolve device IDs #
        ######################

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

        ##################################
        # Resolve Group IDs and targets  #
        ##################################

        group_id = -1

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

        # Eliminate any duplicate IDs in the list
        target_ids = list(dict.fromkeys(target_ids))

        #################################################################
        # Main - Check catalog, create baseline, run updates/downgrades #
        #################################################################

        if args.repotype:
            catalog_id, repo_id = \
                create_catalog(ome_ip_address=ip_address, authenticated_headers=headers, repo_type=args.repotype,
                               repo_source_ip=args.reposourceip, catalog_path=args.catalogpath,
                               repo_user=args.repouser, repo_password=args.repopassword,
                               repo_domain=args.repodomain, retry_length=args.refresh_retry_length)
        else:
            catalog_id, repo_id = get_catalog_identifier(ome_ip_address=ip_address,
                                                         authenticated_headers=headers,
                                                         catalog_name=args.catalog_name,
                                                         refresh=args.refresh,
                                                         retry_length=args.refresh_retry_length)

        if catalog_id != -1 and repo_id != -1:
            print("Successfully retrieved the catalog!")
        else:
            print("Unable to create Catalog!")
            sys.exit(0)

        device_information, baseline_id, baseline_job_identifier = baseline_creation(ome_ip_address=ip_address,
                                                                                     authenticated_headers=headers,
                                                                                     targets=target_ids,
                                                                                     catalog_identifier=catalog_id,
                                                                                     repo_identifier=repo_id)

        if baseline_id == -1:
            print("Unable to create baseline")
            sys.exit(0)

        print("Successfully created baseline")

        print("Checking device compliance against the newly created baseline...")
        compliance_list = check_device_compliance_report(ome_ip_address=ip_address,
                                                         authenticated_headers=headers,
                                                         baseline_identifier=baseline_id,
                                                         desired_action=update_actions)

        if compliance_list:
            target_payload = create_firmware_update_payload(device_information, compliance_list)

            print("Initiating the firmware update...")
            if not firmware_update(ome_ip_address=ip_address,
                                   authenticated_headers=headers,
                                   repository_id=repo_id,
                                   catalog_identifier=catalog_id,
                                   baseline_identifier=baseline_id,
                                   target_data=target_payload):
                print("Error: The firmware update job did not complete successfully! See above for details.")
                sys.exit(0)

            # Initiate compliance refresh
            refresh_compliance_data(ome_ip_address=ip_address, authenticated_headers=headers,
                                    baseline_job_id=baseline_job_identifier)

        else:
            print("No components found which required an update! Script is exiting.")

    except OSError:
        print("Unexpected error:", sys.exc_info())
