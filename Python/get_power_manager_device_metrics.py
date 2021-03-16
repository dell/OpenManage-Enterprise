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
   Script to get different Power Manager Metrics for devices which are being monitored by Power Manager

#### Description
   This script exercises the OpenManage Enterprise REST API to get different Power Manager Metrics for devices at different time duration which are being monitored by Power Manager.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.
    - Use "get_power_manager_monitoring_list.py" to get Device ID

#### Python Example
    python get_power_manager_device_metrics.py --ip <xx> --username <username> --password <pwd> --deviceID <ID of a device> --metricType <Metric Supported - 1,2,3...> --duration <Duration> --sort <Sort Order>

    Output:

        ==========================================================================================
              Power Manager Metrics for device ID -> 10313 collected in Six_hours time window
        ==========================================================================================

            METRIC_TYPE                       METRIC_VALUE  COLLECTED_AT

            Maximum_system_power_consumption  136.0         2020-03-22 06:45:28.891437
            Minimum_system_power_consumption  133.0         2020-03-22 06:45:28.891437
            Average_system_power_consumption  133.0         2020-03-22 06:45:28.891437
            Maximum_system_power_consumption  136.0         2020-03-22 07:00:18.443143
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

# Metric Type dictonary to display the output for better reading
metricType_dictionary = {
    1: "Maximum_system_power_consumption",
    2: "Minimum_system_power_consumption",
    3: "Average_system_power_consumption",
    4: "Instant_system_power",
    5: "Maximum_Inlet_Temperature",
    6: "Minimum_Inlet_Temperature",
    7: "Average_Inlet_Temperature",
    8: "Instant_Inlet_Temperature",
    9: "Maximum_CPU_utilization",
    10: "Minimum_CPU_utilization",
    11: "Average_CPU_utilization",
    12: "Maximum_memory_utilization",
    13: "Minimum_memory_utilization",
    14: "Average_memory_utilization",
    15: "Maximum_IO_utilization",
    16: "Minimum_IO_utilization",
    17: "Average_IO_utilization",
    18: "System_Air_Flow"}

# Duration dictonary to display the output for better reading
duration_dictionary = {
    0: "Recent",
    1: "One_hour",
    2: "Six_hours",
    3: "Twelve_hours",
    4: "One_day",
    5: "Seven_Days",
    6: "One_Month",
    7: "Three_Months",
    8: "Six_Months",
    9: "One_Year"}


def get_power_manager_device_metrics(ip_address, user_name, password, deviceID, metricType, duration, sort):
    """ Authenticate with OpenManage Enterprise, get Power Manager device metrics"""
    try:
        # Defining Session URL & headers
        session_url = 'https://%s/api/SessionService/Sessions' % ip_address
        headers = {'content-type': 'application/json'}

        # Define Payload for posting session API
        user_details = {'UserName': user_name,
                        'Password': password,
                        'SessionType': 'API'}

        # Define metric URL
        metric_url = "https://%s/api/MetricService/Metrics" % ip_address

        # Payload for posting metric API
        metrics_payload = {"PluginId": "2F6D05BE-EE4B-4B0E-B873-C8D2F64A4625",
                           "EntityType": 0,
                           "EntityId": int(deviceID),
                           "MetricTypes": metricType,
                           "Duration": int(duration),
                           "SortOrder": int(sort)}

        # Define OUTPUT header & data format
        output_column_headers = ['Metric_Type', 'Metric_Value', 'Collected_at']
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

            # Device Metric Post API call with OpenManage Enterprise
            device_metric_response = requests.post(metric_url,
                                                   data=json.dumps(metrics_payload), headers=headers, verify=False)
            device_metric_json_data = device_metric_response.json()

            # If device metric API doesn't respond or failed, message the user with error
            if device_metric_response.status_code != 201 & device_metric_response.status_code != 200:
                if 'error' in device_metric_json_data:
                    error_content = device_metric_json_data['error']
                    if '@Message.ExtendedInfo' not in error_content:
                        print("Unable to retrieve Power Manager metric from %s" % ip_address)
                    else:
                        extended_error_content = error_content['@Message.ExtendedInfo']
                        print(
                            "Unable to retrieve Power Manager metric from %s. See below ExtendedInfo for more information" % ip_address)
                        print(extended_error_content[0]['Message'])
                else:
                    print("Unable to retrieve Power Manager metric from %s" % ip_address)
            else:
                device_metric_content = json.loads(device_metric_response.content)

                if device_metric_content:
                    # For every elements in the metric response, store the details in the table
                    for metric_elem in device_metric_content["Value"]:
                        device_metric_data = [metricType_dictionary[int(metric_elem["Type"])], metric_elem["Value"],
                                              metric_elem["Timestamp"]]
                        output_column_data.append(device_metric_data)

                    table = columnar(output_column_data, output_column_headers, no_borders=True)
                    print(
                        "\n   ==========================================================================================")
                    print("      Power Manager Metrics for device ID -> %s collected in %s time window" % (
                        deviceID, duration_dictionary[int(duration)]))
                    print(
                        "   ==========================================================================================")
                    print(table)
                else:
                    print("No Power Manager Metrics for device ID -> %s collected in %s time window" % (
                        deviceID, duration_dictionary[int(duration)]))
    except Exception as error:
        print("Unexpected error:", str(error))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("--ip", "-i", required=True, help="OpenManage Enterprise  IP <- Mandatory")
    parser.add_argument("--username", "-u", required=False,
                        help="Username for OpenManage Enterprise  <- Optional; default = admin", default="admin")
    parser.add_argument("--password", "-p", required=True, help="Password for OpenManage Enterprise  <- Mandatory")
    parser.add_argument("--deviceID", "-id", required=True,
                        help="ID of a device <- Power Manager Metrics need to be fetched <- Mandatory")
    parser.add_argument("--metricType", "-mt", required=True,
                        help='''Metric Type to be fetched. Provide single metric type or multiple with comma separated like 1,2,3 <- Mandatory; See below supported Metric Types:
                        
    1	Maximum system power consumption
    2	Minimum system power consumption
    3	Average system power consumption
    4	Instant system power
    5	Maximum Inlet Temperature
    6	Minimum Inlet Temperature
    7	Average Inlet Temperature
    8	Instant Inlet Temperature
    9	Maximum CPU utilization
    10	Minimum CPU utilization
    11	Average CPU utilization
    12	Maximum memory utilization
    13	Minimum memory utilization
    14	Average memory utilization
    15	Maximum IO utilization
    16	Minimum IO utilization
    17	Average IO utilization
    18	System Air Flow
                        ''')
    parser.add_argument("--duration", "-d", required=False,
                        help='''Duration of the period that the metrics being collected. <- Optional; default = 0; See below supported duration:
                        
    0	Recent
    1	One hour
    2	Six hours
    3	Twelve hours
    4	One day
    5	Seven Days
    6	One Month
    7	Three Months
    8	Six Months
    9	One Year
                        ''', default=0)
    parser.add_argument("--sort", "-s", required=False,
                        help='''Duration of the period that the metrics being collected. <- Optional; default = 0; See below supported duration:
                        
    0	Descending
    1	Ascending
                        ''', default=0)

    args = parser.parse_args()

    print("WARNING: THIS SCRIPT IS EXPERIMENTAL.")
    print("The Power Manager scripts were originally internal Dell scripts we then published externally. If you see "
          "this message and are using one of these scripts it would be very helpful if you open an issue on GitHub "
          "at https://github.com/dell/OpenManage-Enterprise/issues and tell us you are using the script. We have not "
          "dedicated any resources to optimizing them but are happy to do so if we know the community is using them. "
          "Likewise if you find a bug in one of these scripts feel free to open an issue and we will investigate.")

    mt_list = []
    if args.metricType:
        if "," in args.metricType:
            for i in args.metricType.split(","):
                if not i.isdigit():
                    print(
                        "\n   !!! ERROR :: Wrong Metric Value Entered !!! \n  Please use --help/-h for proper metric value & try again")
                    exit()
                else:
                    if int(i) not in range(1, 19):
                        print(
                            "\n   !!! ERROR :: Wrong Metric Value Entered !!! \n  Please use --help/-h for proper metric value & try again")
                        exit()
                    else:
                        mt_list.append(int(i))
        else:
            if not args.metricType.isdigit():
                print(
                    "\n   !!! ERROR :: Wrong Metric Value Entered !!! \n  Please use --help/-h for proper metric value & try again")
                exit()
            else:
                if int(args.metricType) not in range(1, 19):
                    print(
                        "\n   !!! ERROR :: Wrong Metric Value Entered !!! \n  Please use --help/-h for proper metric value & try again")
                    exit()
                else:
                    mt_list.append(int(args.metricType))

    if args.duration and int(args.duration) not in range(0, 10):
        print(
            "\n   !!! ERROR :: Wrong Duration Value Entered !!! \n  Please use --help/-h for proper duration value & try again")
        exit()

    if args.sort and int(args.sort) not in range(0, 2):
        print(
            "\n   !!! ERROR :: Wrong Sort Value Entered !!! \n  Please use --help/-h for proper sort value & try again")
        exit()

    get_power_manager_device_metrics(args.ip, args.username, args.password, args.deviceID, mt_list, args.duration,
                                     args.sort)

    print("WARNING: THIS SCRIPT IS EXPERIMENTAL.")
    print("The Power Manager scripts were originally internal Dell scripts we then published externally. If you see "
          "this message and are using one of these scripts it would be very helpful if you open an issue on GitHub "
          "at https://github.com/dell/OpenManage-Enterprise/issues and tell us you are using the script. We have not "
          "dedicated any resources to optimizing them but are happy to do so if we know the community is using them. "
          "Likewise if you find a bug in one of these scripts feel free to open an issue and we will investigate.")