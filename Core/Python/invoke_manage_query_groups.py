#
# _author_ = Texas Roemer <Texas_Roemer@dell.com> / Grant Curell <grant_curell@dell.com>
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
Python script for using the OME API to manage query groups

#### Description
Provides limited support for creating query groups via the API. Right now it only has support for devices. If you have
a use case requiring extension please comment on https://github.com/dell/OpenManage-Enterprise/issues/126 to let us
know there is a demand for this capability. For details on functionality see workflow.

##### WORKFLOW

The first step to creating a filter is to obtain the relevant IDs from OME. These can change over time so you should
get them from your specific instance. You can do this by running the script with the switch '--get-values'. This will
create a file called ome_query_values.txt. This file contains a listing of OID, FID, and comparison-fields values
available in your OME instance. FID corresponds to the field on which you want to query. For example, in my instance,
if I were to go to the UI and select "Device Sub-Type", that would correspond to FID 238. If I want to check if A
Device SubType were equivalent to something, I would use this value. Next you need to determine the value you are
comparing against. In my instance, 151 corresponds to 'Compellent Storage'. If I wanted to create a query group looking
 for devices with subtype 'Compellent Storage', I would pass the argument '--fid 238 --comparison-fields 151'. Finally,
  you need a comparison operator. This is at the beginning of the file ome_query_values.txt. In my case, ID 1
  corresponds to equivalence so I will pass --oid 1. If you want to chain multiple queries together you can use the
  --loid argument. 1 corresponds to AND and 2 corresponds to OR. If you are chaining multiple filters, pass an loid
  argument for each filter. For example if you want two filters to be related with an OR statement, pass 2,2.

For example, if I wanted to create a group that finds devices with service tag AAAAAAA or has a normal device status,
I could use --fid 231,229 --oid 1,1 --comparison-fields AAAAAAA,1000 --loid 2,2

#### Python Examples
```
invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --get-values
Reach out to OME and obtain the supported values for --fid and --oid

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --get-group-devices TestGroup
Get a listing of devices in the group TestGroup and their characteristics

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --get-group-filters TestGroup
Get a listing of all the filters used by TestGroup

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --create "Grant Group" --description "query created using python OME script" --fid 238 --comparison-values 151 --oid 1
Create a group called Grant Group which looks for devices equal to (1) sub-type (238) compellent storage (151)

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --fid 231,229 --oid 1,1 --comparison-fields AAAAAAA,1000 --loid 2,2 --create "Service Tag or Normal Status"
Create a group called "Service Tag or Normal Status" which looks for service tags (231) equal to (1) AAAAAAA or (2) device with status (229) equal to (1) normal status (1000)

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --delete "Some Group"
Deletes a group with the name "Some Group"
```
"""

import argparse
import json
import sys
import warnings
import re
from getpass import getpass
from pprint import pprint
from urllib.parse import urlparse

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
    sys.exit(0)
from argparse import RawTextHelpFormatter


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

    # Regex to match valid URLs
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    # Check to see if $NextLinkUrl is an absolute URI or a relative URI and adjust appropriately
    if '@odata.nextLink' in count_data:
        if re.match(regex, count_data['@odata.nextLink']):
            next_link_url = count_data['@odata.nextLink']
        else:
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
                if re.match(regex, requested_data['@odata.nextLink']):
                    next_link_url = requested_data['@odata.nextLink']
                else:
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


if __name__ == "__main__":

    warnings.filterwarnings("ignore")

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    parser.add_argument("--user", "-u", required=False,
                        help="Username for the OME Appliance", default="admin")
    parser.add_argument("--password", "-p", required=True,
                        help="Password for the OME Appliance")
    parser.add_argument('-g', '--get-groups',
                        help='Retrieves group listings from OME. To get a list of all OME query groups call with \"y\".'
                             ' To retrieve a specific group, pass in the group name.', required=False)
    parser.add_argument('-G', '--get-values',
                        help=' Reach out to OME and obtain the supported values for arguments --oid, --fid and '
                             '--comparison-fields. This is necessary because the values can change from version to'
                             'version of OME.', required=False, action='store_true')
    parser.add_argument('--create', help='Create a new OME query group. Takes as an argument the name of the new group.'
                                         'Must be accompanied by the fid, oid, and comparison-field arguments. '
                                         'Optionally takes the description argument.',
                        required=False)
    parser.add_argument('--update',
                        help='Update and existing OME query group, pass in the group name. When using this you must '
                             'also pass the fid, oid, and comparison-fields arguments. Optionally takes the description'
                             ' argument. WARNING: This will override all current settings for the group.',
                        required=False)
    parser.add_argument('--description', help='Create OME query group, pass in an unique description string',
                        required=False, default='')
    parser.add_argument('--fid',
                        help='See the --get-values argument and documentation for values.', required=False)
    parser.add_argument('--oid', help='See the --get-values argument and documentation for values.', required=False)
    parser.add_argument('--loid',
                        help='Allows you to logically tie multiple filters together. Use 1 for AND or 2 for OR. If you'
                             ' are only using a single filter you can omit this argument otherwise it should be present'
                             ' for every additional filter added, comma separated. See the documentation at the '
                             'beginning of the script for details.', required=False)
    parser.add_argument('--comparison-fields',
                        help='See the --get-values argument and documentation for values.', required=False)
    parser.add_argument('-q', '--get-group-filters',
                        help='Get query group filters. Takes as an argument the group name and returns all the filters'
                             ' associated with the group.', required=False)
    parser.add_argument('-d', '--get-group-devices',
                        help='Get a listing of devices which form part of a group. Takes the group name as an '
                             'argument.', required=False)
    parser.add_argument('-D', '--delete',
                        help='Delete an OME group. Takes the name as an argument.', required=False)

    args = parser.parse_args()

    if not args.password:
        args.password = getpass()

    ome_ip = args.ip
    ome_username = args.user
    ome_password = args.password

    if args.fid:
        if not args.oid:
            print("Error - when using FID you must provide OID as well.")
            sys.exit(0)
        if not args.comparison_fields:
            print("Error - when using FID you must provide a comparison value as well.")
            sys.exit(0)

    if args.oid:
        if not args.fid:
            print("Error - when using OID you must provide FID as well.")
            sys.exit(0)
        if not args.comparison_fields:
            print("Error - when using OID you must provide a comparison value as well.")
            sys.exit(0)

    if args.comparison_fields:
        if not args.fid:
            print("Error - when using a comparison value you must provide FID as well.")
            sys.exit(0)
        if not args.oid:
            print("Error - when using a comparison value you must provide OID as well.")
            sys.exit(0)

    if args.fid and args.oid and args.comparison_fields:
        if (',' in args.fid or ',' in args.oid or ',' in args.comparison_fields) and not args.loid:
            print("Found a ',' in your arguments but you did not pass loid! If you are combining multiple filters you "
                  "must use loid.")
            sys.exit(0)

    headers = authenticate(ome_ip, ome_username, ome_password)

    # --------------------
    # -- Delete a group --
    # --------------------
    if args.delete:

        group_data = get_data(headers, "https://%s/api/GroupService/Groups" % ome_ip,
                              "Name eq '%s'" % args.delete)

        if len(group_data) < 1:
            print("No groups were found with name " + args.delete)
            sys.exit(0)

        print("Found group " + group_data[0]['Name'] + "!")

        print("Executing POST command to delete group ID %s" % group_data[0]['Id'])
        url = "https://%s/api/GroupService/Actions/GroupService.DeleteGroup" % ome_ip
        payload = {"GroupIds": [group_data[0]['Id']]}
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
        if response.status_code == 200 or response.status_code == 202 or response.status_code == 204:
            print("POST command to delete group ID %s completed successfully!" % args.delete)
            print("Confirming group with ID %s no longer exists." % group_data[0]['Id'])

            group_data = get_data(headers, "https://%s/api/GroupService/Groups" % ome_ip,
                                  "Name eq '%s'" % args.delete)

            if len(group_data) < 1:
                print("Group deletion completed successfully.")
            else:
                print("Error: There was a problem deleting group " + args.delete)
                sys.exit(0)
        else:
            data = response.json()
            print("Error: POST command failed to delete group %s, detailed error results:" % args.delet)
            pprint(data)
            sys.exit(0)

    # ---------------------------------------------
    # -- Get supported values for group creation --
    # ---------------------------------------------
    elif args.get_values:

        print("Collecting OME query group operator and field ID information for OME instance %s" % ome_ip)

        with open("ome_query_values.txt", "w") as helper_file:
            message = "### OperatorID (--oid), Id property is the value you will pass to the oid argument to set the comparioson operator type.\n"
            helper_file.writelines("\n")
            helper_file.writelines(message)
            helper_file.writelines("\n")

            data = get_data(headers, 'https://%s/api/QuerySupportService/OperatorInfo' % ome_ip)

            if len(data) < 1:
                print(
                    "FAIL, GET request failed to get query group operator info.")
                sys.exit(0)

            for operator in data["Operators"]:
                for field in operator.items():
                    message = "%s: %s" % (field[0], field[1])
                    helper_file.writelines(message)
                    helper_file.writelines("\n")
                message = "\n"
                helper_file.writelines(message)

            data = get_data(headers, 'https://%s/api/QuerySupportService/QueryContexts' % ome_ip)

            if len(data) < 1:
                print("FAIL, GET request failed to get query group context info. Extended info is:")
                pprint(data)
                sys.exit(0)

            devices_uri = ""
            for i in data:
                if "Devices" in i.values():
                    devices_uri = i['@odata.id']
            if devices_uri == "":
                print("FAIL, unable to locate URI to get Devices information for field ID parameters")
                sys.exit(0)

            data = get_data(headers, 'https://%s%s' % (ome_ip, devices_uri))
            if len(data) < 1:
                print("FAIL, GET request failed to get query group field ID info. Extended error information:")
                pprint(data)
                sys.exit(0)

            helper_file.writelines("\n")
            info = """
### FieldID (--fid) and the possible values (--comparison-fields). 

The --fid argument will come from the 'Id' field at the top of each listing.

--comparison-fields is a bit more complicated. --comparison-fields has four different argument types and these are
defined by FieldIdTypeId.

1 = string
2 = integer
3 = data/time with format YYYY-MM-DDTHH:MM:SS
4 = An enum coming from the EnumOpts property. Not every comparison type offers this but where available it will have
    the format [{'Id': 1000, 'Name': 'Normal'}, {'Id': 2000, 'Name': 'Unknown'} ...] For example, 
    "Device Global Status" has a value of "normal" being equivalent to ID 1000 in my OME instance. You could pass
    --fid <ID of Device Global Status> --comparison-fields 1000 to indicate you want devices with global status of 
    normal.
5 = boolean (true/false)

            """
            helper_file.writelines(info)
            for field in data['Fields']:
                for value in field.items():
                    message = "%s: %s" % (value[0], value[1])
                    helper_file.writelines(message)
                    helper_file.writelines("\n")
                message = "\n"
                helper_file.writelines(message)

            print("Created ome_query_values.txt successfully.")

    # -----------------------------------------
    # -- Retrieve a list of OME Query Groups --
    # -----------------------------------------
    elif args.get_groups:
        if args.get_groups.lower() == "y":

            data = get_data(headers, 'https://%s/api/GroupService/Groups' % ome_ip)

            if len(data) < 1:
                print("No query groups found!")
            else:
                print("\n- WARNING, getting all group details for OpenManage Enterprise IP %s -\n" % ome_ip)
                for i in data:
                    for ii in i.items():
                        print("%s: %s" % (ii[0], ii[1]))
                    print("\n")
        else:

            group_data = get_data(headers, "https://%s/api/GroupService/Groups" % ome_ip,
                                  "Name eq '%s'" % args.get_groups)

            if len(group_data) < 1:
                print("No groups were found with name " + args.get_groups)
                sys.exit(0)

            print("Found group " + group_data[0]['Name'] + "!")

            data = get_data(headers, 'https://%s/api/GroupService/Groups(%s)' % (ome_ip, group_data[0]['Id']))

            if len(data) > 0:
                print("Details for group %s are:" % args.get_groups)
                for i in data.items():
                    print("%s: %s" % (i[0], i[1]))
            else:
                print("Error: request failed, detailed error results:")
                pprint(data)
                sys.exit(0)

    # --------------------------------------
    # -- Get a list of devices in a group --
    # --------------------------------------
    elif args.get_group_devices:

        group_data = get_data(headers, "https://%s/api/GroupService/Groups" % ome_ip,
                              "Name eq '%s'" % args.get_group_devices)

        if len(group_data) < 1:
            print("No groups were found with name " + args.get_group_devices)
            sys.exit(0)

        print("Found group " + group_data[0]['Name'] + "!")

        device_data = get_data(headers,
                               'https://%s/api/GroupService/Groups(%s)/Devices' % (ome_ip, group_data[0]['Id']))

        if len(device_data) < 1:
            print("WARNING: No devices detected in group %s" % group_data[0]['Name'])
            sys.exit(0)
        else:
            print("Found the following device(s) in group %s" % group_data[0]['Name'])
            for device in device_data:
                for field in device.items():
                    print("%s: %s" % (field[0], field[1]))
                print("\n")

    # ------------------------------------
    # -- Create or update a query group --
    # ------------------------------------
    elif args.create or args.update:

        if args.update:

            group_data = get_data(headers, "https://%s/api/GroupService/Groups" % ome_ip,
                                  "Name eq '%s'" % args.update)

            if len(group_data) < 1:
                print("No groups were found with name " + args.update)
                sys.exit(0)

            print("Found group " + group_data[0]['Name'] + "!")

            group_id = group_data[0]['Id']
            group_name = group_data[0]['Name']

        else:

            group_data = get_data(headers, "https://%s/api/GroupService/Groups" % ome_ip,
                                  "Name eq '%s'" % args.create)

            if len(group_data) > 0:
                print("Existing group found with name %s! If you want to change it use the --update argument instead."
                      % args.create)
                sys.exit(0)

            group_id = 0
            group_name = args.create

        # Group data consists of the top level categories like jobs, groups, alerts, devices, etc
        group_data = get_data(headers, 'https://%s/api/QuerySupportService/QueryContextSummaries' % ome_ip)

        # TODO - https://github.com/dell/OpenManage-Enterprise/issues/126
        context_id = ""
        for group in group_data:
            if "Devices" in group.values():
                context_id = group['Id']
                break

        if context_id == "":
            print("FAIL, unable to locate context device ID")
            sys.exit(0)

        device_data = get_data(headers, 'https://%s/api/QuerySupportService/QueryContexts(%s)' % (ome_ip, context_id))

        if len(device_data) < 1:
            pprint("FAIL, GET request failed to get query group field ID info. Extended error information %s"
                   % device_data)
            sys.exit(0)

        field_id_list = []
        for field in device_data['Fields']:

            # TODO: What is the significance of the magic value 2?
            if field['FieldTypeId'] == 2:
                field_id_list.append(str(field['Id']))

        query_groups_id = get_data(headers, "https://%s/api/GroupService/Groups"
                                   % ome_ip, "Name eq 'Query Groups'")

        if len(query_groups_id) < 1:
            print("There was an error getting the ID of query groups. See below for details.")
            pprint(query_groups_id)

        query_groups_id = query_groups_id[0]['Id']

        if args.fid and args.oid and args.comparison_fields:
            group_payload = {
                "GroupModel": {"Id": group_id, "Name": group_name, "Description": args.description, "GlobalStatus": 0,
                               "DefinitionId": 0, "MembershipTypeId": 24, "ParentId": query_groups_id},
                "GroupModelExtension": {"FilterId": 0, "ContextId": int(context_id), "Conditions": []}}

            if "," in args.fid and "," in args.oid and "," in args.comparison_fields and "," in args.loid:
                field_id_split = args.fid.split(",")
                operator_id_split = args.oid.split(",")
                value_split = args.comparison_fields.split(",")
                logical_operator_id_split = args.loid.split(",")
                for fid, oid, comparison_value, loid in zip(field_id_split, operator_id_split, value_split,
                                                            logical_operator_id_split):
                    if comparison_value in field_id_list:
                        comparison_value = int(comparison_value)
                    create_dict = {"LogicalOperatorId": int(loid), "LeftParen": True, "FieldId": int(fid),
                                   "OperatorId": int(oid), "Value": comparison_value, "RightParen": True}
                    group_payload["GroupModelExtension"]["Conditions"].append(create_dict)

            else:
                if args.comparison_fields in field_id_list:
                    create_dict = {"LogicalOperatorId": int(args.loid), "LeftParen": True, "FieldId": int(args.fid),
                                   "OperatorId": int(args.oid), "Value": int(args.comparison_fields),
                                   "RightParen": True}
                else:
                    create_dict = {"LogicalOperatorId": 0, "LeftParen": True, "FieldId": int(args.fid),
                                   "OperatorId": int(args.oid), "Value": int(args.comparison_fields),
                                   "RightParen": True}
                group_payload["GroupModelExtension"]["Conditions"].append(create_dict)

        else:

            group_payload = {"GroupModel": {
                "Id": group_id,
                "Name": group_name,
                "Description": args.description,
                "GlobalStatus": 0,
                "DefinitionId": 0,
                "MembershipTypeId": 24,
                "ParentId": query_groups_id
            }
            }

        if group_id == 0:
            target_url = 'https://%s/api/GroupService/Actions/GroupService.CreateGroup' % ome_ip
        else:
            target_url = 'https://%s/api/GroupService/Actions/GroupService.UpdateGroup' % ome_ip

        try:
            group_response = requests.post(target_url, data=json.dumps(group_payload), headers=headers, verify=False)
        except requests.ConnectionError as error_message:
            print("FAIL, POST action \"%s\" failed to create/update group." % error_message)
            sys.exit(0)

        if group_response.status_code == 200:
            print("Finished create/update operation on group with ID: %s" % group_response.json())
        else:
            group_data = group_response.json()
            print("Failed to update/create group. Status code %s returned. Detailed error information:"
                  % group_response.status_code)
            pprint(group_data)
            sys.exit(0)

    # -----------------------------------------
    # -- Get query information for the group --
    # -----------------------------------------
    elif args.get_group_filters:

        group_data = get_data(headers, "https://%s/api/GroupService/Groups" % ome_ip,
                              "Name eq '%s'" % args.get_group_filters)

        if len(group_data) < 1:
            print("No groups were found with name " + args.get_group_devices)
            sys.exit(0)

        print("Found group " + group_data[0]['Name'] + "!")

        data = get_data(headers, 'https://%s/api/GroupService/Groups(%s)/GroupQuery' % (ome_ip, group_data[0]['Id']))

        if len(data) < 1:
            print("Error: There was a problem retrieving the query group's data.")
            pprint(data)
            sys.exit(0)
        if len(data) < 1:
            print("No query information found for query group %s" % group_data[0]['Name'])
            sys.exit(0)
        print("Getting query information for OME group %s" % group_data[0]['Name'])
        for query in data:
            for field in query.items():
                print("%s: %s" % (field[0], field[1]))
            print("\n")
    else:
        parser.print_help()
