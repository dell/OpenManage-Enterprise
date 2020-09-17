"""
SYNOPSIS
---------------------------------------------------------------------
 Script to update firmware using catalog

DESCRIPTION
---------------------------------------------------------------------
 This script exercises the OME REST API to allow updating a firmware using catalog.

 Note that the credentials entered are not stored to disk.

EXAMPLE
---------------------------------------------------------------------
python update_firmware_using_catalog_3.0.py --ip <ip addr> --user admin
    --password <passwd> --groupid 25315
"""

import json
import sys
import time
import argparse
import os
from argparse import RawTextHelpFormatter
import urllib3

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def request(url, header, payload=None, method='GET'):
    """ Returns status and data """
    request_obj = pool.urlopen(method, url, headers=header, body=json.dumps(payload))
    if request_obj.data and request_obj.status != 400:
        data = json.loads(request_obj.data)
    else:
        data = request_obj.data
    return request_obj.status, data

def authenticate_with_ome(ip_address, user_name, password):
    """ Authenticate with OME and X-auth session creation """
    auth_success = False
    session_url = "https://%s/api/SessionService/Sessions" % ip_address
    user_details = {'UserName': user_name,
                    'Password': password,
                    'SessionType': 'API'}
    headers = {'content-type': 'application/json'}
    session_response = pool.urlopen('POST', session_url, headers=headers,
                                    body=json.dumps(user_details))
    if session_response.status == 201:
        headers['X-Auth-Token'] = session_response.headers['X-Auth-Token']
        auth_success = True
    else:
        error_msg = "Failed create of session with {0} - Status code = {1}"
        print(error_msg.format(ip_address, session_response.status_code))
    return auth_success, headers

def get_group_list(ip_address, headers):
    """ Get list of groups from OME """
    group_list = None
    group_list_url = 'https://%s/api/GroupService/Groups' % ip_address
    status, group_response = request(group_list_url, headers, method='GET')
    if status == 200:
        if group_response['@odata.count'] > 0:
            group_list = [x['Id'] for x in group_response['value']]
        else:
            print("No groups found at ", ip_address)
    else:
        print("No groups found at ", ip_address)
    return group_list

def get_device_from_uri(uri,headers):
    json_data = {}
    status, device_response = request(uri, headers, method='GET')
    if status == 200:
        json_data = device_response
    else:
        print("Unable to retrieve device list from %s" % uri)
    return json_data

def get_device_list(ip_address, headers):
    """ Get list of devices from OME """
    base_uri = 'https://%s' % ip_address
    next_link_url = base_uri + '/api/DeviceService/Devices'
    
    ome_device_list = None
    ome_service_tags = None
    json_data = None

    while next_link_url is not None:
        data = get_device_from_uri(next_link_url, headers)
        next_link_url = None
        if data['@odata.count'] > 0:
            if '@odata.nextLink' in data:
                next_link_url = base_uri + data['@odata.nextLink']
            if json_data is None:
                json_data = data
            else:
                json_data['value'] += data['value']
        else:
            print('No devices managed by %s' % ip_address)

    if json_data is None:
        pass
    else:
        ome_device_list = [x['Id'] for x in json_data['value']]
        ome_service_tags = [x['DeviceServiceTag'] for x in json_data['value']]
    return dict(zip(ome_service_tags, ome_device_list))


def catalog_creation_payload(**kwargs):
    """
    :return: dict representing the payload
    """
    catalog_type = kwargs['repo_type']
    source = None
    source_path = ""
    filename = ""
    user = ""
    domain = ""
    password = ""
    if catalog_type == 'DELL_ONLINE':
        source = "downloads.dell.com"
    else:
        source = kwargs['repo_source_ip']
        path_tuple = os.path.split(kwargs['catalog_path'])
        source_path = path_tuple[0]
        filename = path_tuple[1]
        if catalog_type == 'CIFS':
            user = kwargs['repo_user']
            domain = kwargs['repo_domain'] if 'repo_domain' in kwargs.keys() else ""
            password = kwargs['repo_password']
            if user is not None and '\\' in user:
                domain = kwargs['repo_user'].split('\\')[0]
                user = user.split('\\')[1]

    return {
        "Filename": filename,
        "SourcePath": source_path,
        "Repository": {
            "Name": 'Test' + time.strftime(":%Y:%m:%d-%H:%M:%S"),
            "Description": "Factory test",
            "RepositoryType": catalog_type,
            "Source": source,
            "DomainName": domain,
            "Username": user,
            "Password": password,
            "CheckCertificate": False
        }
    }

def catalog_refresh_payload(repoId):
    refresh_payload = {
            "CatalogIds": [repoId],
            "AllCatalogs": "false"
    }
    return refresh_payload


def create_or_refresh_catalog(ip_address, headers, **kwargs):
    """Get all catalogs first"""
    url = 'https://%s/api/UpdateService/Catalogs' % ip_address
    status, data = request(url=url, header=headers, method='GET')
    if status != 200:
        raise Exception("Unable to get the catalog", data)
    else:
        allrepoProfiles  = data["value"]
        if allrepoProfiles and data["@odata.count"] != 0:
            for repoProfile in allrepoProfiles:
                repositoryType = repoProfile["Repository"]["RepositoryType"]
                if(repositoryType == kwargs['repo_type']):
                    if kwargs['refresh']:
                        url = 'https://%s/api/UpdateService/Actions/UpdateService.RefreshCatalogs' % ip_address
                        refresh_payload = catalog_refresh_payload(repoProfile["Id"])
                        status, data = request(url=url,
                                               header=headers,  payload=refresh_payload,method='POST')
                        if status != 204:
                            raise Exception("Unable to refresh the catalog of " + repositoryType, data)
                        else:
                            time.sleep(60)
                            print("Catalog refreshed ")
                            return repoProfile["Id"], repoProfile["Repository"]["Id"]
                    else:
                        return repoProfile["Id"], repoProfile["Repository"]["Id"]

    """ Create new catalog """
    url = 'https://%s/api/UpdateService/Catalogs' % ip_address
    print("Creating new catalog.!")
    payload = catalog_creation_payload(**kwargs)
    status, data = request(url=url,
                           header=headers, payload=payload, method='POST')
    if status != 201:
        raise Exception("Unable to create catalog", data)
    time.sleep(180)
    repo_name = payload['Repository']['Name']
    get_catalog_status, get_catalog_data = request(url=url, header=headers)
    if get_catalog_status == 200 and get_catalog_data["@odata.count"] != 0:
        for repo_entry in get_catalog_data.get("value"):
            if repo_entry.get("Repository").get("Name") == repo_name:
                return repo_entry.get("Id"), repo_entry.get("Repository").get('Id')
    raise Exception("Exiting the code, Unable to create catalog : System Info ", sys.exc_info())

def get_group_details(ip_address, headers, group_id):
    """ Get  group details  from OME """
    group_service_url = 'https://%s/api/GroupService/Groups(%s)' % (ip_address, group_id)
    status, group_json_response = request(group_service_url, headers, method='GET')
    if status == 200:
        if group_json_response['Id'] == group_id:
            group_type = group_json_response["TypeId"]
            group_name = group_json_response["Name"]
            return group_type, group_name
        raise Exception("Unable to find group id")
    raise Exception("Unable to fetch group details")

def baseline_creation_payload(id_cat, repository_id, target_name, **kwargs):
    """ Return payload for Baseline creation """
    baseline_payload = {'Name': "Factory Baseline" + time.strftime(":%Y:%m:%d-%H:%M:%S"),
                        'Description': "Factory test1", 'CatalogId': id_cat,
                        'RepositoryId': repository_id, 'DowngradeEnabled': True,
                        'Is64Bit': True, 'Targets': []}
    target_payload = {
        "Id": None,
        "Type": {
            "Id": None,
            "Name": None
        }
    }
    if target_name == "GROUP":
        target_payload['Id'] = kwargs['group_id']
        target_payload['Type']['Id'] = kwargs['type']
        target_payload['Type']['Name'] = target_name
        baseline_payload['Targets'].append(target_payload)
    else:
        for target_id, target_details in kwargs['device_details'].items():
            target_payload['Id'] = target_id
            target_payload['Type']['Id'] = target_details['Type']
            target_payload['Type']['Name'] = target_details['DeviceName']
            baseline_payload['Targets'].append(target_payload)
    return baseline_payload

def get_device_details(ip_address, headers, device_ids):
    """ Get device details  from OME """
    query_string = ""
    device_details = {device_id: {'Type': None, 'DeviceName': None} for device_id in device_ids}
    for device_id in device_ids:
        query_string = query_string + "{}".format(device_id) + ','
    query_string = query_string[0:-1]

    device_url = 'https://%s/api/DeviceService/Devices?Id=%s' % (ip_address, query_string)
    status, device_details_json_response = request(device_url, headers, method='GET')

    if status == 200:
        for i in range(device_details_json_response['@odata.count']):
            device_details[device_details_json_response["value"][i]['Id']]["Type"] = \
                device_details_json_response["value"][i]["Type"]
            device_details[device_details_json_response["value"][i]['Id']]["DeviceName"] = \
                device_details_json_response["value"][i]["DeviceName"]
        return device_details
    print("Unable to fetch device details")
    return 0

def get_execution_detail(job_hist_resp, headers, job_hist_url):
    """ Get execution details """
    job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
    execution_hist_detail = "(" + job_history_id + ")/ExecutionHistoryDetails"
    job_hist_det_url = str(job_hist_url) + execution_hist_detail
    status, job_hist_det_resp = request(job_hist_det_url, headers, method='GET')
    if status == 200:
        print(job_hist_det_resp)
    else:
        print("Unable to parse job execution history .. Exiting")

def track_job_to_completion(ip_address, headers, job_id, job_name):
    """ Tracks the update job to completion / error """
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
    max_retries = 20
    sleep_interval = 60
    failed_job_status = [2070, 2090, 2100, 2101, 2102, 2103]
    job_url = 'https://%s/api/JobService/Jobs(%s)' % (ip_address, job_id)
    loop_ctr = 0
    job_incomplete = True
    print("Polling %s to completion ..." % job_id)
    while loop_ctr < max_retries:
        loop_ctr += 1
        time.sleep(sleep_interval)
        status, job_resp = request(job_url, headers, method='GET')
        if status == 200:
            job_status = str(job_resp['LastRunStatus']['Id'])
            print("Iteration %s: Status of %s is %s" % (loop_ctr, job_id,
                                                        job_status_map[job_status]))
            if int(job_status) == 2060:
                job_incomplete = False
                print("%s completed successfully ... Exiting" % job_name)
                break
            if int(job_status) in failed_job_status:
                job_incomplete = False
                print("%s job failed ... " % job_name)
                job_hist_url = str(job_url) + "/ExecutionHistories"
                status, job_hist_resp = request(job_hist_url, headers, method='GET')
                if status == 200:
                    get_execution_detail(job_hist_resp, headers, job_hist_url)
                break
        else:
            print("Unable to poll status of %s - Iteration %s " % (job_id, loop_ctr))
    if job_incomplete:
        print("Job %s incomplete after polling %s times...Check status" % (job_id, max_retries))

def get_baseline_id(ip_address, headers, id_repo, id_cat):
    """ Get Baseline id """
    url = 'https://%s/api/UpdateService/Baselines' % ip_address
    status, data = request(url=url, header=headers)
    if status == 200:
        if data["@odata.count"]:
            i = 0
            while i < len(data["value"]):
                repo_data = data["value"][i]["RepositoryId"]
                catalog_data = data["value"][i]["CatalogId"]
                if id_repo == repo_data and id_cat == catalog_data:
                    return data["value"][i]["Id"], data["value"][i]["TaskId"]
                if i == len(data["value"]):
                    print("unable to find  the corresponding baseline")
                    return 0
                i += 1
        else:
            return 0
    print("unable to get baseline id")
    return 0

def baseline_creation(ip_address, headers, param_map, catalog_id, repo_id):
    """ Create new baseline """
    url = 'https://%s/api/UpdateService/Baselines' % ip_address
    print("Creating new Baseline.!")
    if param_map['group_id']:
        group_type, group_name = get_group_details(ip_address, headers, param_map['group_id'])
        payload = baseline_creation_payload(catalog_id,
                                            repo_id, "GROUP",
                                            group_id=param_map['group_id'], type=group_type)
    else:
        device_details = get_device_details(ip_address, headers, param_map['device_ids'])
        payload = baseline_creation_payload(catalog_id,
                                            repo_id, "DEVICES",
                                            device_details=device_details)
    baseline_status, baseline_data = request(url=url,
                                             header=headers, payload=payload, method='POST')
    if baseline_status == 201:
        baseline_task_id = baseline_data["TaskId"]
        track_job_to_completion(ip_address, headers, baseline_task_id, 'Baseline job')
        return get_baseline_id(ip_address, headers, repo_id, catalog_id)
    raise Exception("Unable to create baseline, Job status : ", baseline_status)

def check_response_type(comp_val_list):
    """ Checks whether response contains ComponentComplianceReports or not """
    flag = False
    for val in comp_val_list:
        if 'ComponentComplianceReports' in val:
            flag = True
    return flag

def check_device_compliance_report(ip_address, headers, id_baseline, required_action):
    """ Checks device compliances """
    compliance_report_list = []
    source_names = None
    compl_url = "https://%s/api/UpdateService/Baselines(%s)/DeviceComplianceReports" % \
                (ip_address, id_baseline)
    component_status, component_data = request(url=compl_url, header=headers)
    if component_status == 200 and component_data["value"]:
        comp_val_list = component_data["value"]
        response_flag = check_response_type(comp_val_list)
        if response_flag:
            for compliance_dict in comp_val_list:
                compliance_list = compliance_dict.get('ComponentComplianceReports')
                if compliance_list:
                    for component in compliance_list:
                        # if component["UpdateAction"] == "UPGRADE":
                        if component["UpdateAction"] in required_action:
                            if source_names:
                                source_names = source_names + ';' + component["SourceName"]
                            else:
                                source_names = component["SourceName"]
                    if source_names:
                        compliance_report_list.append({"Id": compliance_dict.get("DeviceId"),
                                                       "Data": source_names})
        else:
            for compliance_dict in comp_val_list:
                source_names = None
                navigation_url_link = \
                    compliance_dict.get('ComponentComplianceReports@odata.navigationLink')
                navigation_url = "https://%s%s" % (ip_address, navigation_url_link)
                component_status, component_data = \
                    request(url=navigation_url, header=headers)

                if component_status == 200 and component_data["value"]:
                    comp_val_list = component_data["value"]
                    for compliance_dicts in comp_val_list:
                        if compliance_dicts:
                            if compliance_dicts["UpdateAction"] in required_action:
                                if source_names:
                                    source_names = \
                                        source_names + ';' + compliance_dicts["SourceName"]
                                else:
                                    source_names = compliance_dicts["SourceName"]
                        if source_names:
                            compliance_report_list.append({"Id": compliance_dict.get("DeviceId"),
                                                           "Data": source_names})
                else:
                    sys.exit("component data is empty")
    else:
        raise Exception("Unable to get compliance data")
    return compliance_report_list

def create_target_payload(compliance_data_list):
    """ Create target for firmware payload """
    my_dist = {}
    target_list = []
    for data in compliance_data_list:
        for key, value in data.items():
            if key == "Id":
                my_dist["Id"] = value
                my_dist["TargetType"] = {
                    "Id": 1000,
                    "Name": "DEVICE"
                }
            if key == "Data":
                my_dist["Data"] = value

        if my_dist["Data"] != "":
            target_list.append(my_dist.copy())
    if target_list:
        return target_list
    return 0

def get_job_types(ip_address, header):
    """ Get job type """
    url = "https://{0}/api/JobService/JobTypes".format(ip_address)
    return request(url=url, header=header)

def get_job_type_id(values, job_type_response_data):
    """ Return the id of Job Type which has name Update Task """
    i = 0
    while i < values:
        if job_type_response_data["value"][i]["Name"] == "Update_Task":
            job_type_id = job_type_response_data["value"][i]["Id"]
            return job_type_id
        i += 1
    return 0

def create_payload_for_firmware_update(job_type_id, id_baseline,
                                       id_cat, repository_id, target_data):
    """ Formulate the payload to initiate a firmware update job """
    return {
        "JobName": "Update Firmware-Test:" + id_baseline,
        "JobDescription": "Firmware Update Job",
        "Schedule": "startNow",
        "State": "Enabled",
        "JobType": {
            "Id": job_type_id,
            "Name": "Update_Task"
        },
        "Params": [{
            "Key": "complianceReportId",
            "Value": id_baseline
        }, {
            "Key": "repositoryId",
            "Value": repository_id
        }, {
            "Key": "catalogId",
            "Value": id_cat
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

def firmware_update(ip_address, headers, repository_id, id_cat, id_baseline, target_data):
    """ Updates Firmware """
    status, job_type_response_data = get_job_types(ip_address, headers)
    if status == 200:
        values = len(job_type_response_data["value"])
        job_type_id = get_job_type_id(values, job_type_response_data)
        payload = create_payload_for_firmware_update(job_type_id, str(id_baseline),
                                                     str(id_cat), str(repository_id), target_data)
        url = 'https://{0}/api/JobService/Jobs'.format(ip_address)
        update_status, update_data = request(url=url,
                                             header=headers, payload=payload, method='POST')
        if update_status == 201 and update_data != 0:
            job_id = update_data["Id"]
            if job_id != -1 or job_id != 0 or job_id is not None:
                track_job_to_completion(ip_address, headers, job_id, 'Firmware Update')
        else:
            print("unsuccessful or Unable to get job id")
    else:
        print("unable to get job types")

def refresh_compliance_data(ip_address, headers, baseline_job_id):
    """ Reruns baseline job to refresh inventory data """
    url = 'https://%s/api/JobService/Actions/JobService.RunJobs' % ip_address
    payload = {
        "JobIds": [10203]
    }
    payload["JobIds"][:] = []
    payload["JobIds"].append(baseline_job_id)
    print("payload", payload)
    status, data = request(url=url,
                           header=headers,
                           payload=payload, method='POST')
    if status != 204:
        job_url = 'https://%s/api/JobService/Jobs(%s)' % (ip_address, baseline_job_id)
        status, job_response = request(job_url, headers, method='GET')
        job_status = job_response["LastRunStatus"]["Name"]
        if job_status == "Running":
            print("Baseline job is rerunning")
            track_job_to_completion(ip_address, headers, baseline_job_id, 'Baseline job')
    elif status == 204:
        print("Baseline rerun job created")
        track_job_to_completion(ip_address, headers, baseline_job_id, 'Baseline job')

def baseline_deletion_payload(baseline_list):
    """ Returns payload to delete baseline """
    return {
        "BaselineIds": baseline_list
    }

def delete_baseline(ip_address, headers, baseline_list):
    """ Delete existing baseline from dell repo """
    url = 'https://%s/api/UpdateService/Actions/UpdateService.RemoveBaselines' % ip_address
    payload = baseline_deletion_payload(baseline_list)
    status, data = request(url=url,
                           header=headers, payload=payload, method='POST')
    if status != 204:
        raise Exception("Failure in deleting baselines associated to dell online catalog")

def catalog_deletion_payload(catalog_list):
    """  Returns payload to delete catalog """
    return {
        "CatalogIds": catalog_list
    }

def delete_catalog(ip_address, headers, catalog_id):
    """ Delete existing catalog from dell repo """
    url = 'https://%s/api/UpdateService/Actions/UpdateService.RemoveCatalogs' % ip_address
    catalog_list = [catalog_id]
    payload = catalog_deletion_payload(catalog_list)
    status, data = request(url=url,
                           header=headers, payload=payload, method='POST')
    if status != 204:
        raise Exception("Failure in deleting dell online catalog")

def delete_online_catalog(ip_address, headers):
    target_catalog_id = None
    target_baseline_ids = []
    url = 'https://%s/api/UpdateService/Catalogs' % ip_address
    get_catalog_status, get_catalog_data = request(url, headers)
    if get_catalog_status == 200:
        if get_catalog_data["@odata.count"] != 0:
            for repo_entry in get_catalog_data.get("value"):
                if repo_entry.get("Repository").get("RepositoryType") == 'DELL_ONLINE':
                    target_catalog_id = repo_entry.get("Id")
                    for baseline in repo_entry.get("AssociatedBaselines"):
                        target_baseline_ids.append(baseline.get('BaselineId'))

            if len(target_baseline_ids) > 0:
                delete_baseline(ip_address, headers, target_baseline_ids)
            if target_catalog_id is not None:
                delete_catalog(ip_address, headers, target_catalog_id)
        return
    raise Exception("Failed to retrieve dell online catalog")

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", required=True,
                        help="Username for OME Appliance",
                        default="admin")
    PARSER.add_argument("--password", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--updateactions", required=True, nargs="*",
                        help="Update action required",
                        choices=['upgrade', 'downgrade', 'flash-all'])
    MUTEX_GROUP = PARSER.add_mutually_exclusive_group(required=True)
    MUTEX_GROUP.add_argument("--groupid", type=int,
                             help="Id of the group to update")
    MUTEX_GROUP.add_argument("--deviceid", type=int,
                             help="Id of the device to update")
    MUTEX_GROUP.add_argument("--servicetags", nargs="*",
                             help="Servicetags of devices to update")
    PARSER.add_argument("--repotype", required=True, help="Repository type",
                        default='DELL_ONLINE',
                        choices=['DELL_ONLINE', 'NFS', 'CIFS'])
    PARSER.add_argument("--reposourceip", required=False,
                        help="fully qualified repo path")
    PARSER.add_argument("--catalogpath", required=False,
                        help="fully qualified repo path")
    PARSER.add_argument("--repouser", required=False,
                        help="username for CIFS repository")
    PARSER.add_argument("--repodomain", required=False,
                        help="domian for CIFS repository credentials")
    PARSER.add_argument("--repopassword", required=False,
                        help="password for CIFS repository")
    PARSER.add_argument("--refresh", required=False, default=False, type=str2bool,
                        help="refresh/create online catalog or use existing one.")
    ARGS = PARSER.parse_args()
    if ARGS.repotype == 'CIFS' and (ARGS.reposourceip is None or ARGS.catalogpath is None
                                    or ARGS.repouser is None or ARGS.repopassword is None):
        PARSER.error("CIFS repository requires --reposourceip, --catalogpath, "
                     "--repouser and --repopassword.")
    if ARGS.repotype == 'NFS' and (ARGS.reposourceip is None or ARGS.catalogpath is None):
        PARSER.error("NFS repository requires --reposourceip, --catalogpath.")

    IP_ADDRESS = ARGS.ip
    USER_NAME = ARGS.user
    PASSWORD = ARGS.password
    UPDATE_ACTIONS = set()
    for action in ARGS.updateactions:
        if action == "flash-all":
            UPDATE_ACTIONS.add('UPGRADE')
            UPDATE_ACTIONS.add('DOWNGRADE')
            break
        UPDATE_ACTIONS.add(action.upper())

    PARAM_MAP = {'group_id': None, 'device_ids': None}
    TARGET_DATA = []
    try:
        pool = urllib3.HTTPSConnectionPool(IP_ADDRESS, port=443,
                                           cert_reqs='CERT_NONE', assert_hostname=False)
        AUTH_SUCCESS, HEADERS = authenticate_with_ome(IP_ADDRESS, USER_NAME,
                                                      PASSWORD)
        if not AUTH_SUCCESS:
            print("Unable to authenticate with OME .. Check IP/Username/Pwd")
            sys.exit(-1)
        elif ARGS.groupid:
            GROUP_ID = ARGS.groupid
            PARAM_MAP['group_id'] = GROUP_ID
            GROUP_LIST = get_group_list(IP_ADDRESS, HEADERS)
            if GROUP_LIST:
                if GROUP_ID in GROUP_LIST:
                    GROUP_URL = "https://%s/api/GroupService/Groups(%s)/Devices" % \
                                (IP_ADDRESS, GROUP_ID)
                    STATUS, DEV_RESPONSE = request(GROUP_URL, HEADERS)
                    if STATUS == 200:
                        if DEV_RESPONSE['@odata.count'] == 0:
                            raise Exception("No devices associated with this group id")
                    else:
                        formatted_error = json.dumps(DEV_RESPONSE.json(), indent=4, sort_keys=False)
                        raise Exception("Unable to fetch group device details. "
                                        "See error information below \n{}".format(formatted_error))
                else:
                    raise ValueError("Group %s not found on %s ... Exiting" % (
                        GROUP_ID, IP_ADDRESS))
        else:
            mapping = get_device_list(IP_ADDRESS, HEADERS)
            DEVICE_IDS = None
            if ARGS.servicetags:
                servicetags = ARGS.servicetags
                intersection_set = set(mapping.keys()).intersection(set(servicetags))
                if len(intersection_set) <= 0:
                    raise ValueError("None of the devices are managed through OME... Exiting")
                if len(intersection_set) != len(servicetags):
                    unmanaged_devices = list(set(servicetags).difference(intersection_set))
                    raise ValueError("Devices {} not managed through OME ... Exiting" %
                                     unmanaged_devices)
                DEVICE_IDS = [mapping[tag] for tag in intersection_set]
            elif ARGS.deviceid:
                if ARGS.deviceid not in mapping.values():
                    raise ValueError("Device %s not found on %s ... Exiting" % (
                        ARGS.deviceid, IP_ADDRESS))
                DEVICE_IDS = [ARGS.deviceid]

            PARAM_MAP['device_ids'] = DEVICE_IDS

        CATALOG_ID, REPO_ID = \
            create_or_refresh_catalog(ip_address=IP_ADDRESS, headers=HEADERS, repo_type=ARGS.repotype,
                             repo_source_ip=ARGS.reposourceip, catalog_path=ARGS.catalogpath,
                             repo_user=ARGS.repouser, repo_password=ARGS.repopassword,
                             repo_domain=ARGS.repodomain, refresh=ARGS.refresh)
        if CATALOG_ID:
            print("Successfully created or refreshed the catalog")
        else:
            raise Exception("Unable to create Catalog")
        BASELINE_ID, BASELINE_JOB_ID = baseline_creation(ip_address=IP_ADDRESS,
                                                         headers=HEADERS,
                                                         param_map=PARAM_MAP,
                                                         catalog_id=CATALOG_ID,
                                                         repo_id=REPO_ID)
        if BASELINE_ID == 0:
            raise Exception("Unable to create baseline")
        print("Successfully created baseline")

        COMPLIANCE_LIST = \
            check_device_compliance_report(ip_address=IP_ADDRESS, headers=HEADERS,
                                           id_baseline=BASELINE_ID, required_action=UPDATE_ACTIONS)
        print("Compliance List: %s" % COMPLIANCE_LIST)
        if COMPLIANCE_LIST:
            TARGET_PAYLOAD = create_target_payload(compliance_data_list=COMPLIANCE_LIST)
            # sys.exit(0)
            if TARGET_PAYLOAD != 0:
                firmware_update(ip_address=IP_ADDRESS, headers=HEADERS, repository_id=REPO_ID,
                                id_cat=CATALOG_ID,
                                id_baseline=BASELINE_ID, target_data=TARGET_PAYLOAD)
                # Initiate compliance refresh
                refresh_compliance_data(ip_address=IP_ADDRESS, headers=HEADERS,
                                        baseline_job_id=BASELINE_JOB_ID)
            else:
                print("No components found for update")
        else:
            print("No components found for update...skipping firmware update")

    except OSError:
        print("Unexpected error:", sys.exc_info())
