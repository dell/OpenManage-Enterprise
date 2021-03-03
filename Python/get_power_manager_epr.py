#
# _author_ = Mahendran P <Mahendran_P@Dell.com>
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
   Script to get Power Manager EPR applied for either Devices/Groups with optional filters

#### Descriptiontion
   This script exercises the Power Manager REST API to get Emergency Power Reductions policy enabled for devices or groups.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

EXAMPLE:
    python get_power_manager_epr.py --ip <xx> --username <username> --password <pwd> --filterBy <filter_name> --filterValue <filter_value>

    Output:

    ================================================
        Power Manager Emergency Reduction Policy
    ================================================

    EPR_POLICY_ID  EPR_TYPE  IS_EPR_POWERDOWN/THROTTLE?  EPR_ENABLED?  EPR_EXECUTION_STATE  IS_EPR_ON_GROUP/DEVICE?  GROUP/DEVICE_ASSIGNED_TO  CREATED_TIME

    13             MANUAL    Throttle                    True          SUCCESS              Device                   6W92WV2                   2020-03-22 15:14:15.111016

"""

# Import the modules required for this script
import argparse
import json
import sys
from argparse import RawTextHelpFormatter

# Import the modules required for this script
from requests.packages.urllib3.exceptions import InsecureRequestWarning

try:
    import urllib3
    import requests
    from columnar import columnar
except ModuleNotFoundError:
    print("This program requires urllib3, requests, and columnar. To install them on most systems run "
          "`pip install requests urllib3`")
    sys.exit(0)
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# EPR Type dictonary to display the output for better reading
EPR_type_dictionary = {
    1: "MANUAL",
    2: "TEMPERATURE-TRIGGERED"}

# EPR Execution State dictonary to display the output for better reading
EPR_execution_state_dictionary = {
    1: "NOSTATE",
    2: "EXECUTING",
    3: "SUCCESS",
    4: "PARTIAL_SUCCESS",
    5: "FAILED"}

# IsEprPowerDown dictonary to display the output for better reading
IsEprPowerDown_dictionary = {
    "True": "ShutDown",
    "False": "Throttle"}

# IsAssociatedToGroup dictonary to display the output for better reading
IsAssociatedToGroup_dictionary = {
    "True": "Group",
    "False": "Device"}


def get_power_manager_EPR(ip_address, user_name, password, filterBY, filterValue):
    """ Authenticate with OpenManage Enterprise, get power manager emergency power reduction policies"""
    try:
        # Defining Session URL & its headers
        session_url = 'https://%s/api/SessionService/Sessions' % ip_address
        headers = {'content-type': 'application/json'}

        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}

        # Define the EPR URL basis the filter existance & type
        if filterBY and filterValue:
            if filterBY in ('Enabled', 'Type'):
                EPR_url = "https://%s/api/PowerService/EPR?$filter=%s eq %s" % (ip_address, filterBY, filterValue)
            else:
                EPR_url = "https://%s/api/PowerService/EPR?$filter=contains(%s,'%s')" % (
                    ip_address, filterBY, filterValue)
        else:
            EPR_url = "https://%s/api/PowerService/EPR" % ip_address

        # Defining OUTPUT format
        output_column_headers = ['EPR_Policy_ID', 'EPR_Type', 'Is_EPR_PowerDown/Throttle?', 'EPR_Enabled?',
                                 "EPR_Execution_State", "Is_EPR_on_Group/Device?", "Group/Device_Assigned_To",
                                 "Created_Time"]
        output_column_data = []

        # Create the session with OpenManage Enterprise
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=headers)

        # If session doesn't create, message the user with error
        if session_info.status_code != 201 & session_info.status_code != 200:

            session_json_data = session_info.json()
            if 'error' in session_json_data:
                error_content = session_json_data['error']
                if '@Message.ExtendedInfo' not in error_content:
                    print("Unable to create a session with  %s" % ip_address)
                else:
                    extended_error_content = error_content['@Message.ExtendedInfo']
                    print(
                        "Unable to create a session with  %s. See below ExtendedInfo for more information" % ip_address)
                    print(extended_error_content[0]['Message'])
            else:
                print("Unable to create a session with  %s. Please try again later" % ip_address)
        else:
            headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']

            # Get Power Manager EPR API call with OpenManage Enterprise
            EPR_response = requests.get(EPR_url, headers=headers, verify=False)
            EPR_json_data = EPR_response.json()

            # If EPR API doesn't respond or failed, message the user with error
            if EPR_response.status_code != 201 & EPR_response.status_code != 200:
                if 'error' in EPR_json_data:
                    error_content = EPR_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print(
                            "Unable to retrieve Power Manager Emergency Power Reduction Policies from %s" % ip_address)
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print(
                            "Unable to retrieve Power Manager Emergency Power Reduction Policies from %s. See below ExtendedInfo for more information" % ip_address)
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager Emergency Power Reduction Policies from %s" % ip_address)
            else:
                EPR_count = EPR_json_data['@odata.count']

                # If the EPR count is 0, then error out immediately
                if EPR_count <= 0:
                    print("No Power Manager Emergency Power Reduction Policies created in %s" % ip_address)
                else:
                    EPR_content = json.loads(EPR_response.content)

                    if EPR_content:
                        # For every elements in the EPR policies response, store the details in the table
                        for EPR_elem in EPR_content["value"]:
                            EPR_data = [EPR_elem["PolicyId"], EPR_type_dictionary[int(EPR_elem["Type"])],
                                        IsEprPowerDown_dictionary[str(EPR_elem["IsEprPowerDown"])], EPR_elem["Enabled"],
                                        EPR_execution_state_dictionary[int(EPR_elem["ExecutionState"])],
                                        IsAssociatedToGroup_dictionary[str(EPR_elem["IsAssociatedToGroup"])],
                                        EPR_elem["AssignedTo"], EPR_elem["CreatedTime"]]
                            output_column_data.append(EPR_data)

                        table = columnar(output_column_data, output_column_headers, no_borders=True)
                        print("\n   ================================================")
                        print("      Power Manager Emergency Reduction Policy ")
                        print("   ================================================")
                        print(table)
                    else:
                        print("No Power Manager Emergency Power Reduction Policies created in %s" % ip_address)
    except Exception as error:
        print("Unexpected error:", str(error))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP <- Mandatory")
    parser.add_argument("--username", "-u", required=False,
                        help="Username for OpenManage Enterprise  <- Optional; default = admin", default="admin")
    parser.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise  <- Mandatory")
    parser.add_argument("--filterBy", "-b", required=False, help=''' Applicable Filters are:
        Enabled - EPR Enabled state
        AssignedTo - Device service tag or Group Name
        Type - EPR Type
    ''', default=None)
    parser.add_argument("--filterValue", "-v", required=False, help='''  Input value for filtersBy:
        Enabled - true or false
        AssignedTo - String Value
        Type - 1-Manual; 2-Temperature-Triggered
    ''', default=None)

    args = parser.parse_args()
    print("WARNING: THIS SCRIPT IS EXPERIMENTAL.")
    print("The Power Manager scripts were originally internal Dell scripts we then published externally. If you see "
          "this message and are using one of these scripts it would be very helpful if you open an issue on GitHub "
          "at https://github.com/dell/OpenManage-Enterprise/issues and tell us you are using the script. We have not "
          "dedicated any resources to optimizing them but are happy to do so if we know the community is using them. "
          "Likewise if you find a bug in one of these scripts feel free to open an issue and we will investigate.")

    get_power_manager_EPR(args.ip, args.username, args.password, args.filterBy, args.filterValue)

    print("WARNING: THIS SCRIPT IS EXPERIMENTAL.")
    print("The Power Manager scripts were originally internal Dell scripts we then published externally. If you see "
          "this message and are using one of these scripts it would be very helpful if you open an issue on GitHub "
          "at https://github.com/dell/OpenManage-Enterprise/issues and tell us you are using the script. We have not "
          "dedicated any resources to optimizing them but are happy to do so if we know the community is using them. "
          "Likewise if you find a bug in one of these scripts feel free to open an issue and we will investigate.")
