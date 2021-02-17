# Python Library Code

- [Python Library Code](#python-library-code)
  - [Authenticating to an OME Instance](#authenticating-to-an-ome-instance)
  - [Interact with an API Resource](#interact-with-an-api-resource)
    - [GET from an API resource](#get-from-an-api-resource)
    - [POST to an API resource](#post-to-an-api-resource)
  - [Resolve a device to its ID](#resolve-a-device-to-its-id)
    - [Helpful device ID pattern](#helpful-device-id-pattern)
    - [Get Group ID by Name](#get-group-id-by-name)
    - [Pattern for Getting a Group's ID and a List of Devices in the Group](#pattern-for-getting-a-groups-id-and-a-list-of-devices-in-the-group)
  - [Track a Job to Completion](#track-a-job-to-completion)
  - [Printing a Dictionary to a CSV File](#printing-a-dictionary-to-a-csv-file)
  - [Prompt a User with a Yes/No Question](#prompt-a-user-with-a-yesno-question)

## Authenticating to an OME Instance

Used to create a session to OME. You can then pass the resulting dictionary headers around to your various functions to authenticate.

```python
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
```

## Interact with an API Resource

### GET from an API resource
This is used to perform any sort of interaction with a REST API resource. It includes the ability to pass in odata filters. Anytime you need to POST or GET an API resource we recommend you use this function.

```python
from urllib.parse import urlparse
from pprint import pprint

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
    sys.exit(0)

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
```

### POST to an API resource

```python
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
```

## Resolve a device to its ID

Use this function to resolve a service tag, idrac IP, or an OME device name to its OME device ID. Most API resources require you to use the device ID to take action. Use this function to resolve any of the above to the OME device ID.

```python
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
```

### Helpful device ID pattern 
You frequently not only want to resolve device IDs, but check the output and then add the device IDs to a list of IDs. Below is a common pattern for this behavior.

```python
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
    
# Eliminate any duplicate IDs in the list
target_ids = list(dict.fromkeys(target_ids))
```

### Get Group ID by Name

```python
group_url = "https://%s/api/GroupService/Groups" % args.ip
groups = get_data(headers, group_url, "Name eq '%s'" % args.groupname)

if len(groups) < 1:
    print("Error: We were unable to find a group matching the name %s." % args.groupname)
    sys.exit(0)

group_id = groups[0]['Id']
```

### Pattern for Getting a Group's ID and a List of Devices in the Group
This is typically used with the ID pattern to populate a target list.

```python
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
```

## Track a Job to Completion

Track a job and wait for it to complete before continuing.

```python
from pprint import pprint

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
```

## Printing a Dictionary to a CSV File

```python
# Use UTF 8 in case there are non-ASCII characters like 格蘭特
print("Writing CSV to file...")
with open(out_file, 'w', encoding='utf-8', newline='') as csv_file:
    csv_columns = ["Id", "Name", "Description", "VlanMaximum", "VlanMinimum", "Type"]
    writer = csv.DictWriter(csv_file, fieldnames=csv_columns, extrasaction='ignore')
    writer.writeheader()
    for network in network_data:
        writer.writerow(network)
```

## Prompt a User with a Yes/No Question

```python
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
```
