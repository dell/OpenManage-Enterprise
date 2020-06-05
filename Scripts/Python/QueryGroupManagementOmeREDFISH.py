#
# QueryGroupManagementOmeREDFISH. Python script using Redfish API with OEM extension to manage Open Manage Enterprise Query Groups
#
# _author_ = Texas Roemer <Texas_RoemerDell.com>
# _version_ = 1.0
#
# Copyright (c) 2020, Dell, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#




import requests, json, sys, re, time, warnings, argparse, os

from datetime import datetime

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description='Python script using Redfish API with OEM extension to create/update/delete Open Manage Enterprise Query Groups')
parser.add_argument('-ip', help='OME IP Address', required=True)
parser.add_argument('-u', help='OME username', required=True)
parser.add_argument('-p', help='OME password', required=True)
parser.add_argument('script_examples',action="store_true",help='QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -G y, this example will get current information needed for argument possible values to create a query group. QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin --create y --name "custom query group" --description "query created using python redfish script" --fid 54,63 --oid 1,1 --value M537C3S,Dell --loid 0,1, this example is going to create a custom query with 2 filters. Filters are: Service tag must equal M537C3S AND FRU Manfacturer must equal Dell. QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -g 10495, this example will get group details for group ID 10495. QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -q 10495, this example will return the custom filter queries for group ID 10495. QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -d 10495, this example will return any devices reported under group ID 10495. QueryGroupManagementOmeREDFISH.py -ip 192.1680.120 -u admin -p admin --update 10495 --name "custom query group" --description "query created using python redfish script" --fid 54,63 --oid 1,1 --value M537C3S,Dell --loid 0,2, this example will update changes for group ID 10495. QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -D 10495, this example deletes query group ID 10495.')
parser.add_argument('-g', help='Get all OME query groups, pass in \"y\". To get a specific group, pass in group ID', required=False)
parser.add_argument('-G', help='Get supported values for argument --oid, --fid and --values, pass in \"y\". Getting this data first is recommended and needed before you can create a query group. NOTE: Each OME could have different field ID values for properties. Make sure to get this information first before creating query group on each OME.', required=False)
parser.add_argument('-w', help='Get end 2 end workflow example of creating a query group, pass in \"y\" This will give you detailed information of walking through each step along with showing executing commands.', required=False)
parser.add_argument('--create', help='Create OME query group, pass in \"y\"', required=False)
parser.add_argument('--update', help='Update existing OME query group, pass in the group ID. You must also use name, description, fid, oid and value arguments. You can change one or all of these arguments but you must make sure you pass in all these arguments even if you didn\'t change the value, still pass in current value', required=False)
parser.add_argument('--name', help='Create OME query group, pass in an unique string name', required=False)
parser.add_argument('--description', help='Create OME query group, pass in an unique description string', required=False)
parser.add_argument('--fid', help='Create OME query group filter, pass in field ID integer value. Field ID is the type of entry you want to filter for like Service Tag. If creating multiple filters, pass in value using comma separator', required=False)
parser.add_argument('--oid', help='Create OME query group filter, pass in operator ID integer value. Operator ID is what operator you want to use like > or ==. If creating multiple filters, pass in value using comma separator', required=False)
parser.add_argument('--loid', help='Create OME query group filter, pass in logical operator ID integer value. Logical operator is used when setting multiple filters. Supported values are \"1\" for AND or \"2\" for OR. If only setting one filter for query group, pass in a value of 0 and if setting multiple filters for query group, the first filter will always be set to a value of 0. If creating multiple filters, pass in values using comma separator. Supported', required=False)
parser.add_argument('--value', help='Create OME query group filter, pass in suported value for the field ID you are selecting. Supported values are either integer, string or set value from a list. If creating multiple filters, pass in value using comma separator', required=False)
parser.add_argument('-q', help='Get query information for OME group, pass in the group ID. If needed, execute argument -g to get the group ID.', required=False)
parser.add_argument('-d', help='Get devices detected by OME group, pass in the group ID. If needed, execute argument -g to get the group ID.', required=False)
parser.add_argument('-D', help='Delete OME group, pass in the group ID. If needed, execute argument -g to get the group ID.', required=False)


args = vars(parser.parse_args())

ome_ip=args["ip"]
ome_username=args["u"]
ome_password=args["p"]



def get_oid_fid_value_possible_values():
    print("\n- WARNING, collecting OME query group operator and field ID information for OME %s\n" % ome_ip)
    try:
        os.remove("create_OME_query_group_paramater_help.txt")
    except:
        pass
    file_open = open("create_OME_query_group_paramater_help.txt", "a")
    message = "### OperatorID (--oid), Id property will be the integer value you pass in for argument --oid\n"
    file_open.writelines("\n")
    file_open.writelines(message)
    file_open.writelines("\n")
    response = requests.get('https://%s/api/QuerySupportService/OperatorInfo' % (ome_ip),verify=False,auth=(ome_username,ome_password))
    if response.status_code == 200 or response.status_code == 202:
        pass
    else:
        print("- FAIL, GET request failed to get query group operator info, status code %s returned" % response.status_code)
        sys.exit()
    data = response.json()
    for i in data["Operators"]:
        for ii in i.items():
            message = "%s: %s" % (ii[0],ii[1])
            file_open.writelines(message)
            file_open.writelines("\n")
        message = "\n"
        file_open.writelines(message)
    response = requests.get('https://%s/api/QuerySupportService/QueryContexts' % (ome_ip),verify=False,auth=(ome_username,ome_password))
    if response.status_code == 200 or response.status_code == 202:
        pass
    else:
        print("- FAIL, GET request failed to get query group context info, status code %s returned" % response.status_code)
        sys.exit()
    data = response.json()
    devices_uri = ""
    for i in data['value']:
        if "Devices" in i.values():
            devices_uri = i['@odata.id']
    if devices_uri == "":
        print("- FAIL, unable to locate URI to get Devices information for field ID parameters")
        sys.exit()
    response = requests.get('https://%s%s' % (ome_ip, devices_uri),verify=False,auth=(ome_username,ome_password))
    if response.status_code == 200 or response.status_code == 202:
        pass
    else:
        print("- FAIL, GET request failed to get query group field ID info, status code %s returned" % response.status_code)
        sys.exit()
    data = response.json()
    file_open.writelines("\n")
    info = """
### FieldID (--fid) and possible values (--value)

NOTE: In the output, Id property will be the field ID value you pass in for argument --fid

NOTE: In the output, FieldIdTypeId will tell you which type of value you can pass in for argument --value. Either 1 for string, 2 for integer, 3 for date/time format: YYYY-MM-DDTHH:MM:SS, 4 for enum where you need to use EnumOpts property to see possible values(see value for Name key) and 5 for boolean, pass in a value of true or false.

"""
    file_open.writelines(info)
    for i in data['Fields']:
        for ii in i.items():
            message = "%s: %s" % (ii[0],ii[1])
            file_open.writelines(message)
            file_open.writelines("\n")
        message = "\n"
        file_open.writelines(message)
    file_open.close()
    print("- PASS, output captured in file \"create_OME_query_group_paramater_help.txt\"")
   



def help_doc():
    help_text = """
1.	First step is run help text on the script to see script info, supported parameters, supported values and examples.

C:\Python38-32> QueryGroupManagementOmeREDFISH.py -h
usage: CreateQueryGroupOemREDFISH.py [-h] -ip IP -u U -p P [-g G] [-G G] [--create CREATE]
                                     [--update UPDATE] [--name NAME] [--description DESCRIPTION]
                                     [--fid FID] [--oid OID] [--loid LOID] [--value VALUE]
                                     [-q Q] [-d D] [-D D]

Python script using Redfish API with OEM extension to create/update/delete Open Manage
Enterprise Query Groups

positional arguments:
  script_examples       CreateQueryGroupOemREDFISH.py -ip 192.168.0.120 -u admin -p admin -G y,
                        this example will get current information needed for argument possible
                        values to create a query group. CreateQueryGroupOemREDFISH.py -ip
                        192.168.0.120 -u admin -p admin --create y --name "custom query group"
                        --description "query created using python redfish script" --fid 54,63
                        --oid 1,1 --value M537C3S,Dell --loid 0,1, this example is going to
                        create a custom query with 2 filters. Filters are: Service tag must
                        equal M537C3S AND FRU Manfacturer must equal Dell.
                        CreateQueryGroupOemREDFISH.py -ip 192.168.0.120 -u admin -p admin -g
                        10495, this example will get group details for group ID 10495.
                        CreateQueryGroupOemREDFISH.py -ip 192.168.0.120 -u admin -p admin -q
                        10495, this example will return the custom filter queries for group ID
                        10495. CreateQueryGroupOemREDFISH.py -ip 192.168.0.120 -u admin -p admin
                        -d 10495, this example will return any devices reported under group ID
                        10495. CreateQueryGroupOemREDFISH.py -ip 192.1680.120 -u admin -p admin
                        --update 10495 --name "custom query group" --description "query created
                        using python redfish script" --fid 54,63 --oid 1,1 --value M537C3S,Dell
                        --loid 0,2, this example will update changes for group ID 10495.
                        CreateQueryGroupOemREDFISH.py -ip 192.168.0.120 -u admin -p admin -D
                        10495, this example deletes query group ID 10495.

optional arguments:
  -h, --help            show this help message and exit
  -ip IP                OME IP Address
  -u U                  OME username
  -p P                  OME password
  -g G                  Get all OME query groups, pass in "y". To get a specific group, pass in
                        group ID
  -G G                  Get supported values for argument --oid, --fid and --values, pass in
                        "y". Getting this data first is recommended and needed before you can
                        create a query group.
  --create CREATE       Create OME query group, pass in "y"
  --update UPDATE       Update existing OME query group, pass in the group ID. You must also use
                        name, description, fid, oid and value arguments. You can change one or
                        all of these arguments but you must make sure you pass in all these
                        arguments even if you didn't change the value, still pass in current
                        value
  --name NAME           Create OME query group, pass in an unique string name
  --description DESCRIPTION
                        Create OME query group, pass in an unique description string
  --fid FID             Create OME query group filter, pass in field ID integer value. Field ID
                        is the type of entry you want to filter for like Service Tag. If
                        creating multiple filters, pass in value using comma separator
  --oid OID             Create OME query group filter, pass in operator ID integer value.
                        Operator ID is what operator you want to use like > or ==. If creating
                        multiple filters, pass in value using comma separator
  --loid LOID           Create OME query group filter, pass in logical operator ID integer
                        value. Logical operator is used when setting multiple filters. Supported
                        values are "1" for AND or "2" for OR. If only setting one filter for
                        query group, pass in a value of 0 and if setting multiple filters for
                        query group, the first filter will always be set to a value of 0. If
                        creating multiple filters, pass in values using comma separator.
                        Supported
  --value VALUE         Create OME query group filter, pass in suported value for the field ID
                        you are selecting. Supported values are either integer, string or set
                        value from a list. If creating multiple filters, pass in value using
                        comma separator
  -q Q                  Get query information for OME group, pass in the group ID. If needed,
                        execute argument -g to get the group ID.
  -d D                  Get devices detected by OME group, pass in the group ID. If needed,
                        execute argument -g to get the group ID.
  -D D                  Delete OME group, pass in the group ID. If needed, execute argument -g
                        to get the group ID.

2.	Next is to get information on the supported arguments / values for creating an OME query group. This is needed if you want to create custom filters for your group due to the large amount of possible options. If you just want to create a custom group and no filter options which you can always add later using the Update action, ignore this step. 
The output is captured in a text file. In this output, it will report arguments - - oid, - - fid  and - -  value and what values are supported. For - - oid and - - file, you will be passing in a integer conversion value. For - - value, see below for the type of value to pass in, either string, integer, date format or static set of possible values. 

C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 100.65.84.141 -u admin -p Dell1234# -G y

- WARNING, collecting OME query group field ID information for OME 100.65.84.141

- PASS, output captured in file "create_OME_query_group_paramater_help.txt"


3.	Once you figure out the filter(s) you want to configure for your query group, you will now want to create the query group. You can create one custom filter or multiple custom filters for your query group, just make sure you use comma separator for the values and the values line up for each argument. Example below I\'ll be setting two custom filters for the query group I\'m creating. 
List of arguments needed to create a query group with filtering (if you are creating a query group with no filtering, you only need to pass use Name and Description parameters):
-	Name
-	Description
-	Field ID
-	Operator ID
-	Value
-	Logical Operator ID
Filter one will be:
-	Field ID (I want to filter on device service tag so I will pass in a value of 54 for - - fid)
-	Operator ID (I want to find a specific string value for the service tag so I pass in 1 for - - oid which means =
-	Value (I pass in the the exact service tag string)
-	Logical Operator ID (Since this is the first filter, pass in a value of 0).
Filter two will be:
-	Field ID (I want to filter on FRU Manufacturer so I will pass in a value of 63 for - - fid)
-	Operator ID (I want to find a specific string value for FRU Manufacturer so I pass in 1 for - - oid which means =
-	Value (I pass in string value of 'Dell')
-	Logical Operator ID (since I want the first filter and second filter to find an exact match, I will pass in a value of 1 which means 'AND'. If I wanted filters to only match either and not both, I would pass in a value of 2 for 'OR')



C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin --create y --name "custom query group" --description "query created using python redfish script" --fid 54,63 --oid 1,1 --value M537C3S,Dell --loid 0,1

- PASS, POST action "CreateGroup" passed to create new OME group. New group ID number is: 10495


4.	If POST command passes, you will see a query group ID returned. You can now use this query ID to check information for the query group. Below I will check overall query group information using -g argument. 

C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -g 10495

- WARNING, detail information for OME group ID 10495 -

@odata.context: /api/$metadata#GroupService.Group
@odata.type: #GroupService.Group
@odata.id: /api/GroupService/Groups(10495)
Id: 10495
Name: custom query group
Description: query created using python redfish script
GlobalStatus: 3000
ParentId: 1022
CreationTime: 2020-03-16 20:44:50.897
UpdatedTime: 2020-03-16 20:45:00.964
CreatedBy: admin
UpdatedBy:
Visible: True
DefinitionId: 400
DefinitionDescription: UserDefined
TypeId: 3000
MembershipTypeId: 24
GroupQuery@odata.navigationLink: /api/GroupService/Groups(10495)/GroupQuery
DeviceStatusSummary@odata.navigationLink: /api/GroupService/Groups(10495)/DeviceStatusSummary
EventStatusSummary@odata.navigationLink: /api/GroupService/Groups(10495)/EventStatusSummary
EventSeveritySummary@odata.navigationLink: /api/GroupService/Groups(10495)/EventSeveritySummary
Devices@odata.navigationLink: /api/GroupService/Groups(10495)/Devices
AllLeafDevices@odata.navigationLink: /api/GroupService/Groups(10495)/AllLeafDevices
AllLeafDeviceSummaries@odata.navigationLink: /api/GroupService/Groups(10495)/AllLeafDeviceSummaries
GroupHierarchy@odata.navigationLink: /api/GroupService/Groups(10495)/GroupHierarchy
SubGroups@odata.navigationLink: /api/GroupService/Groups(10495)/SubGroups
GroupDevicesSummary@odata.navigationLink: /api/GroupService/Groups(10495)/GroupDevicesSummary
5.	Next I can check the filter details for this query job ID.

C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -q 10495

- WARNING, getting query information for OME group 10495 -

@odata.type: #GroupService.QueryCondition
LogicalOperatorId: 0
LeftParen: True
FieldId: 54
OperatorId: 1
Value: M537C3S
RightParen: True


@odata.type: #GroupService.QueryCondition
LogicalOperatorId: 1
LeftParen: True
FieldId: 63
OperatorId: 1
Value: Dell
RightParen: True

6.	Last step would be to check if any devices were detected by the filter queries for this query group using -d argument. You will notice below since I searched for a specific service tag match, only one server is reported for the query group which is expected. 

C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -d 10495

- Device(s) detected for OME group 10495 -

@odata.type: #DeviceService.Device
@odata.id: /api/DeviceService/Devices(10073)
Id: 10073
Type: 1000
Identifier: M537C3S
DeviceServiceTag: M537C3S
ChassisServiceTag:
Model: PowerEdge C6420
PowerState: 17
ManagedState: 3000
Status: 3000
ConnectionState: True
AssetTag: None
SystemId: 1879
DeviceName: WIN-4UI980INRK9
LastInventoryTime: 2020-03-16 05:00:55.439
LastStatusTime: 2020-03-16 20:00:04.329
DeviceSubscription: None
DeviceCapabilities: [1, 2, 3, 4, 5, 6, 7, 8, 9, 41, 11, 12, 13, 14, 15, 16, 1009, 17, 50, 18, 30, 31]
SlotConfiguration: {'ChassisName': None}
DeviceManagement: [{'ManagementId': 5004, 'NetworkAddress': '100.65.84.100', 'MacAddress': '10:98:36:b2:06:cd', 'ManagementType': 2, 'InstrumentationName': 'idrac-M537C3S', 'DnsName': 'idrac-M537C3S', 'ManagementProfile': [{'ManagementProfileId': 5004, 'ManagementId': 5004, 'AgentName': 'iDRAC', 'Version': '4.00.00.00', 'ManagementURL': 'https://100.65.84.100:443', 'HasCreds': 0, 'Status': 1000, 'StatusDateTime': '2020-03-10 03:43:20.994'}]}]
Actions: None
SensorHealth@odata.navigationLink: /api/DeviceService/Devices(10073)/SensorHealth
VirtualSession: {'@odata.id': '/api/DeviceService/Devices(10073)/VirtualSession'}
Baselines: {'@odata.id': '/api/DeviceService/Devices(10073)/Baselines'}
InventoryDetails@odata.navigationLink: /api/DeviceService/Devices(10073)/InventoryDetails
HardwareLogs@odata.navigationLink: /api/DeviceService/Devices(10073)/HardwareLogs
SubSystemHealth@odata.navigationLink: /api/DeviceService/Devices(10073)/SubSystemHealth
RecentActivity@odata.navigationLink: /api/DeviceService/Devices(10073)/RecentActivity
InventoryTypes: {'@odata.id': '/api/DeviceService/Devices(10073)/InventoryTypes'}
LogSeverities: {'@odata.id': '/api/DeviceService/Devices(10073)/LogSeverities'}
Settings@odata.navigationLink: /api/DeviceService/Devices(10073)/Settings
Temperature: {'@odata.id': '/api/DeviceService/Devices(10073)/Temperature'}
Power: {'@odata.id': '/api/DeviceService/Devices(10073)/Power'}
SystemUpTime: {'@odata.id': '/api/DeviceService/Devices(10073)/SystemUpTime'}
BlinkStatus: {'@odata.id': '/api/DeviceService/Devices(10073)/BlinkStatus'}
PowerUsageByDevice@odata.navigationLink: /api/DeviceService/Devices(10073)/PowerUsageByDevice
DeviceBladeSlots@odata.navigationLink: /api/DeviceService/Devices(10073)/DeviceBladeSlots
GraphicInfo: {'@odata.id': '/api/DeviceService/Devices(10073)/GraphicInfo'}
DeployRequired: {'@odata.id': '/api/DeviceService/Devices(10073)/DeployRequired'}

7.	Now I\'m going to show how to update an existing query group. You will use the same argument as - - create but instead use - - update argument passing in the group ID. Below I will be changing logical operator to 2 which means 'OR'.

C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 192.1680.120 -u admin -p admin --update 10495 --name "custom query group" --description "query created using python redfish script" --fid 54,63 --oid 1,1 --value M537C3S,Dell --loid 0,2

- PASS, POST action "UpdateGroup" passed to create new OME group. New group ID number is: 10495


8.	Now since I changed logical operator to OR, I should see all Dell servers detected by OME in the output when using -d argument.


C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -d 10495

- Device(s) detected for OME group 10495 -

@odata.type: #DeviceService.Device
@odata.id: /api/DeviceService/Devices(10071)
Id: 10071
Type: 1000
Identifier: M536C3S
DeviceServiceTag: M536C3S
ChassisServiceTag:
Model: PowerEdge C6420
PowerState: 17
ManagedState: 3000
Status: 1000
ConnectionState: True
AssetTag: C64202019
SystemId: 1879
DeviceName: MINWINPC
LastInventoryTime: 2020-03-16 05:00:40.591
LastStatusTime: 2020-03-16 20:00:04.497
DeviceSubscription: None
DeviceCapabilities: [1, 2, 3, 4, 5, 6, 7, 8, 9, 41, 11, 12, 13, 14, 15, 16, 1009, 17, 50, 18, 30, 31]
SlotConfiguration: {'ChassisName': None}
DeviceManagement: [{'ManagementId': 5000, 'NetworkAddress': '100.65.84.70', 'MacAddress': '10:98:36:b1:fe:09', 'ManagementType': 2, 'InstrumentationName': 'blade1', 'DnsName': 'blade1', 'ManagementProfile': [{'ManagementProfileId': 5000, 'ManagementId': 5000, 'AgentName': 'iDRAC', 'Version': '3.30.30.30', 'ManagementURL': 'https://100.65.84.70:443', 'HasCreds': 0, 'Status': 1000, 'StatusDateTime': '2020-03-10 03:43:10.981'}]}]
Actions: None
SensorHealth@odata.navigationLink: /api/DeviceService/Devices(10071)/SensorHealth
VirtualSession: {'@odata.id': '/api/DeviceService/Devices(10071)/VirtualSession'}
Baselines: {'@odata.id': '/api/DeviceService/Devices(10071)/Baselines'}
InventoryDetails@odata.navigationLink: /api/DeviceService/Devices(10071)/InventoryDetails
HardwareLogs@odata.navigationLink: /api/DeviceService/Devices(10071)/HardwareLogs
SubSystemHealth@odata.navigationLink: /api/DeviceService/Devices(10071)/SubSystemHealth
RecentActivity@odata.navigationLink: /api/DeviceService/Devices(10071)/RecentActivity
InventoryTypes: {'@odata.id': '/api/DeviceService/Devices(10071)/InventoryTypes'}
LogSeverities: {'@odata.id': '/api/DeviceService/Devices(10071)/LogSeverities'}
Settings@odata.navigationLink: /api/DeviceService/Devices(10071)/Settings
Temperature: {'@odata.id': '/api/DeviceService/Devices(10071)/Temperature'}
Power: {'@odata.id': '/api/DeviceService/Devices(10071)/Power'}
SystemUpTime: {'@odata.id': '/api/DeviceService/Devices(10071)/SystemUpTime'}
BlinkStatus: {'@odata.id': '/api/DeviceService/Devices(10071)/BlinkStatus'}
PowerUsageByDevice@odata.navigationLink: /api/DeviceService/Devices(10071)/PowerUsageByDevice
DeviceBladeSlots@odata.navigationLink: /api/DeviceService/Devices(10071)/DeviceBladeSlots
GraphicInfo: {'@odata.id': '/api/DeviceService/Devices(10071)/GraphicInfo'}
DeployRequired: {'@odata.id': '/api/DeviceService/Devices(10071)/DeployRequired'}


@odata.type: #DeviceService.Device
@odata.id: /api/DeviceService/Devices(10072)
Id: 10072
Type: 1000
Identifier: M538C3S
DeviceServiceTag: M538C3S
ChassisServiceTag:
Model: PowerEdge C6420
PowerState: 17
ManagedState: 3000
Status: 1000
ConnectionState: True
AssetTag: None
SystemId: 1879
DeviceName: 100.65.84.95
LastInventoryTime: 2020-03-16 05:00:55.492
LastStatusTime: 2020-03-16 20:00:04.391
DeviceSubscription: None
DeviceCapabilities: [1, 2, 3, 4, 5, 6, 7, 8, 9, 41, 11, 12, 13, 14, 15, 16, 17, 1009, 50, 18, 30, 31]
SlotConfiguration: {'ChassisName': None}
DeviceManagement: [{'ManagementId': 5002, 'NetworkAddress': '100.65.84.95', 'MacAddress': '10:98:36:b2:04:c3', 'ManagementType': 2, 'InstrumentationName': 'idrac-M538C3S', 'DnsName': 'idrac-M538C3S', 'ManagementProfile': [{'ManagementProfileId': 5002, 'ManagementId': 5002, 'AgentName': 'iDRAC', 'Version': '4.00.00.00', 'ManagementURL': 'https://100.65.84.95:443', 'HasCreds': 0, 'Status': 1000, 'StatusDateTime': '2020-03-10 03:43:20.418'}]}]
Actions: None
SensorHealth@odata.navigationLink: /api/DeviceService/Devices(10072)/SensorHealth
VirtualSession: {'@odata.id': '/api/DeviceService/Devices(10072)/VirtualSession'}
Baselines: {'@odata.id': '/api/DeviceService/Devices(10072)/Baselines'}
InventoryDetails@odata.navigationLink: /api/DeviceService/Devices(10072)/InventoryDetails
HardwareLogs@odata.navigationLink: /api/DeviceService/Devices(10072)/HardwareLogs
SubSystemHealth@odata.navigationLink: /api/DeviceService/Devices(10072)/SubSystemHealth
RecentActivity@odata.navigationLink: /api/DeviceService/Devices(10072)/RecentActivity
InventoryTypes: {'@odata.id': '/api/DeviceService/Devices(10072)/InventoryTypes'}
LogSeverities: {'@odata.id': '/api/DeviceService/Devices(10072)/LogSeverities'}
Settings@odata.navigationLink: /api/DeviceService/Devices(10072)/Settings
Temperature: {'@odata.id': '/api/DeviceService/Devices(10072)/Temperature'}
Power: {'@odata.id': '/api/DeviceService/Devices(10072)/Power'}
SystemUpTime: {'@odata.id': '/api/DeviceService/Devices(10072)/SystemUpTime'}
BlinkStatus: {'@odata.id': '/api/DeviceService/Devices(10072)/BlinkStatus'}
PowerUsageByDevice@odata.navigationLink: /api/DeviceService/Devices(10072)/PowerUsageByDevice
DeviceBladeSlots@odata.navigationLink: /api/DeviceService/Devices(10072)/DeviceBladeSlots
GraphicInfo: {'@odata.id': '/api/DeviceService/Devices(10072)/GraphicInfo'}
DeployRequired: {'@odata.id': '/api/DeviceService/Devices(10072)/DeployRequired'}


@odata.type: #DeviceService.Device
@odata.id: /api/DeviceService/Devices(10073)
Id: 10073
Type: 1000
Identifier: M537C3S
DeviceServiceTag: M537C3S
ChassisServiceTag:
Model: PowerEdge C6420
PowerState: 17
ManagedState: 3000
Status: 3000
ConnectionState: True
AssetTag: None
SystemId: 1879
DeviceName: WIN-4UI980INRK9
LastInventoryTime: 2020-03-16 05:00:55.439
LastStatusTime: 2020-03-16 20:00:04.329
DeviceSubscription: None
DeviceCapabilities: [1, 2, 3, 4, 5, 6, 7, 8, 9, 41, 11, 12, 13, 14, 15, 16, 1009, 17, 50, 18, 30, 31]
SlotConfiguration: {'ChassisName': None}
DeviceManagement: [{'ManagementId': 5004, 'NetworkAddress': '100.65.84.100', 'MacAddress': '10:98:36:b2:06:cd', 'ManagementType': 2, 'InstrumentationName': 'idrac-M537C3S', 'DnsName': 'idrac-M537C3S', 'ManagementProfile': [{'ManagementProfileId': 5004, 'ManagementId': 5004, 'AgentName': 'iDRAC', 'Version': '4.00.00.00', 'ManagementURL': 'https://100.65.84.100:443', 'HasCreds': 0, 'Status': 1000, 'StatusDateTime': '2020-03-10 03:43:20.994'}]}]
Actions: None
SensorHealth@odata.navigationLink: /api/DeviceService/Devices(10073)/SensorHealth
VirtualSession: {'@odata.id': '/api/DeviceService/Devices(10073)/VirtualSession'}
Baselines: {'@odata.id': '/api/DeviceService/Devices(10073)/Baselines'}
InventoryDetails@odata.navigationLink: /api/DeviceService/Devices(10073)/InventoryDetails
HardwareLogs@odata.navigationLink: /api/DeviceService/Devices(10073)/HardwareLogs
SubSystemHealth@odata.navigationLink: /api/DeviceService/Devices(10073)/SubSystemHealth
RecentActivity@odata.navigationLink: /api/DeviceService/Devices(10073)/RecentActivity
InventoryTypes: {'@odata.id': '/api/DeviceService/Devices(10073)/InventoryTypes'}
LogSeverities: {'@odata.id': '/api/DeviceService/Devices(10073)/LogSeverities'}
Settings@odata.navigationLink: /api/DeviceService/Devices(10073)/Settings
Temperature: {'@odata.id': '/api/DeviceService/Devices(10073)/Temperature'}
Power: {'@odata.id': '/api/DeviceService/Devices(10073)/Power'}
SystemUpTime: {'@odata.id': '/api/DeviceService/Devices(10073)/SystemUpTime'}
BlinkStatus: {'@odata.id': '/api/DeviceService/Devices(10073)/BlinkStatus'}
PowerUsageByDevice@odata.navigationLink: /api/DeviceService/Devices(10073)/PowerUsageByDevice
DeviceBladeSlots@odata.navigationLink: /api/DeviceService/Devices(10073)/DeviceBladeSlots
GraphicInfo: {'@odata.id': '/api/DeviceService/Devices(10073)/GraphicInfo'}
DeployRequired: {'@odata.id': '/api/DeviceService/Devices(10073)/DeployRequired'}


9.	Script also supported deleting a query group. Use -D argument to delete a query group.

C:\Python38-32> QueryGroupManagementOmeREDFISH.py -ip 192.168.0.120 -u admin -p admin -D 10495

- WARNING, executing POST command to delete group ID 10495
- PASS, POST command passed to delete group ID 10495
- WARNING, executing GET to validate group ID 10495 no longer exists
- PASS, validation of group ID 10495 no longer exist for OME"""

    print(help_text)
    with open("help_text_workflow.txt","w") as x:
        x.writelines(help_text)
    print("-"*100)
    print("\n- WARNING, end 2 end workflow example also captured in \"help_text_workflow.txt\" file")





def get_devices():
    print("\n- Devices detected for OME %s\n" % ome_ip)
    response = requests.get('https://%s/api/DeviceService/Devices' % ome_ip,verify=False,auth=(ome_username,ome_password))
    data = response.json()  
    print("\n- Servers managed by OpenManage Enterprise IP %s -\n" % ome_ip) 
    for i in data['value']:
        for ii in i.items():
            if ii[0] == "DeviceManagement":
                for iii in ii[1][0].items():
                    if iii[0] == 'NetworkAddress':
                        print("iDRAC IP: %s" % (iii[1]))
            elif ii[0] == "Model":
                print("Model: %s" % (ii[1]))
            elif ii[0] == "DeviceServiceTag":
                print("DeviceServiceTag: %s" % (ii[1]))
            
            elif ii[0] == "Id":
                print("Id: %s" % (ii[1]))
        print("\n")

def get_all_groups():
    if args["g"].lower() == "y":
        response = requests.get('https://%s/api/GroupService/Groups' % ome_ip,verify=False,auth=(ome_username,ome_password))
        data = response.json()
        print("\n- WARNING, getting all group details for OpenManage Enterprise IP %s -\n" % ome_ip)
        for i in data['value']:
            for ii in i.items():
                print("%s: %s" % (ii[0], ii[1]))
            print("\n")
    else:
        response = requests.get('https://%s/api/GroupService/Groups(%s)' % (ome_ip, args["g"]),verify=False,auth=(ome_username,ome_password))
        data = response.json()
        if response.status_code == 200 or response.status_code == 202:
            print("\n- WARNING, detail information for OME group ID %s -\n" % args["g"])
            for i in data.items():
                print("%s: %s" % (i[0], i[1]))
        else:
            print("\n- FAIL, GET request failed, status code %s returned, detailed error results: %s" % (response.status_code, data))
            sys.exit()
        


def get_group_query_info():
    response = requests.get('https://%s/api/GroupService/Groups(%s)/GroupQuery' % (ome_ip, args["q"]),verify=False,auth=(ome_username,ome_password))
    data = response.json()
    if response.status_code == 200 or response.status_code == 202:
        pass
    else:
        print("- FAIL, GET request failed, status code %s returned, detailed error results: \n%s" % (response.status_code, data))
        sys.exit()
    if data["value"] == []:
        print("\n- WARNING, no query information for OME group %s" % args["q"])
        sys.exit()
    print("\n- WARNING, getting query information for OME group %s -\n" % args["q"])
    for i in data['value']:
        for ii in i.items():
            print("%s: %s" % (ii[0], ii[1]))
        print("\n")

def get_group_devices():
    response = requests.get('https://%s/api/GroupService/Groups(%s)/Devices' % (ome_ip, args["d"]),verify=False,auth=(ome_username,ome_password))
    data = response.json()
    if data["value"] == []:
        print("\n- WARNING, no devices detected for group ID %s" % args["d"])
        sys.exit()
    else:
        print("\n- Device(s) detected for OME group %s -\n" % args["d"])
        for i in data["value"]:
            for ii in i.items():
                print("%s: %s" % (ii[0], ii[1]))
            print("\n")
    
                        

def create_update_group(ID):
    response = requests.get('https://%s/api/QuerySupportService/QueryContextSummaries' % (ome_ip),verify=False,auth=(ome_username,ome_password))
    data = response.json()
    context_id = ""
    for i in data["value"]:
        if "Devices" in i.values():
            context_id = i['Id']
    if context_id == "":
        print("- FAIL, unable to locate context device ID")
        sys.exit()
    else:
        pass
    response = requests.get('https://%s/api/QuerySupportService/QueryContexts(%s)' % (ome_ip, context_id),verify=False,auth=(ome_username,ome_password))
    if response.status_code == 200 or response.status_code == 202:
        pass
    else:
        print("- FAIL, GET request failed to get query group field ID info, status code %s returned" % response.status_code)
        sys.exit()
    data = response.json()
    field_id_list = []
    for i in data['Fields']:
        if i['FieldTypeId'] == 2:
            field_id_list.append(str(i['Id']))
    if args["fid"] and args["oid"] and args["value"]:
        payload = {"GroupModel":{"Id": ID,"Name": args["name"],"Description": args["description"],"GlobalStatus": 0,"DefinitionId": 0,"MembershipTypeId":24,"ParentId": 1022},"GroupModelExtension" :{"FilterId":0,"ContextId":int(context_id),"Conditions":[]}}
        if "," in args["fid"] and "," in args["oid"] and ","  in args["value"] and "," in args["loid"]:
            field_id_split = args["fid"].split(",")
            operator_id_split = args["oid"].split(",")
            value_split = args["value"].split(",")
            logical_operator_id_split = args["loid"].split(",")
            for i,ii,iii,iiii in zip(field_id_split, operator_id_split, value_split, logical_operator_id_split):
                if iii in field_id_list:
                    iii=int(iii)
                create_dict = {"LogicalOperatorId" : int(iiii), "LeftParen": True, "FieldId": int(i), "OperatorId": int(ii), "Value": iii, "RightParen": True}
                payload["GroupModelExtension"]["Conditions"].append(create_dict)
        
        else:
            if args["value"] in field_id_list:
                create_dict = {"LogicalOperatorId" : int(args["loid"]), "LeftParen": True, "FieldId": int(args["fid"]), "OperatorId": int(args["oid"]), "Value": int(args["value"]), "RightParen": True}
            else:
                create_dict = {"LogicalOperatorId" : 0, "LeftParen": True, "FieldId": int(args["fid"]), "OperatorId": int(args["oid"]), "Value": args["value"], "RightParen": True}
            payload["GroupModelExtension"]["Conditions"].append(create_dict)
                  
    else:
        payload = {"GroupModel":{"Id": ID,"Name": args["name"],"Description": args["description"],"GlobalStatus": 0,"DefinitionId": 0,"MembershipTypeId":24,"ParentId": 1022}}
    if ID == 0:
        url = 'https://%s/api/GroupService/Actions/GroupService.CreateGroup' % ome_ip
        method_name = "CreateGroup"
    else:
        url = 'https://%s/api/GroupService/Actions/GroupService.UpdateGroup' % ome_ip
        method_name = "UpdateGroup"
    headers = {'content-type': 'application/json'}
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False,auth=(ome_username,ome_password))
    except requests.ConnectionError as error_message:
        print("\n- FAIL, POST action \"%s\" failed to create new group, detail error results:\n" % error_message)
        sys.exit()
    if response.status_code == 200:
        if method_name == "CreateGroup":
            print("\n- PASS, POST action \"%s\" passed to create new OME group. New group ID number is: %s" % (method_name, response.json()))
        else:
            print("\n- PASS, POST action \"%s\" passed to update OME group ID %s" % (method_name, response.json()))
            
    else:
        data=response.json()
        print("\n- FAIL, POST action \"%s\" failed to create new group, status code %s returned, detail error results:\n %s" % (method_name, response.status_code, data))
        sys.exit()




def delete_group():
    print("\n- WARNING, executing POST command to delete group ID %s" % args["D"])
    url = "https://%s/api/GroupService/Actions/GroupService.DeleteGroup" % ome_ip
    payload = {"GroupIds": [int(args["D"])]}
    headers = {'content-type': 'application/json'}
    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False,auth=(ome_username,ome_password))
    if response.status_code == 200 or response.status_code == 202 or response.status_code == 204:
        print("- PASS, POST command passed to delete group ID %s" % args["D"])
        print("- WARNING, executing GET to validate group ID %s no longer exists" % args["D"])
        response = requests.get('https://%s/api/GroupService/Groups(%s)' % (ome_ip, args["D"]),verify=False,auth=(ome_username,ome_password))
        if response.status_code != 200:
            print("- PASS, validation of group ID %s no longer exist for OME" % args["D"])
        else:
            print("- FAIL, GET command still detects group ID exists")
            sys.exit()
    else:
        data=response.json()
        print("\n- FAIL, POST command failed to delete group ID, detail error results:\n")
        for i in data['error']['Message.ExtendedInfo'][0].items():
            print("%s: %s" % (i[0], i[1]))
        sys.exit()


def test_OME_creds():
    response = requests.get('https://%s/api/GroupService' % (ome_ip),verify=False,auth=(ome_username,ome_password))
   
    if response.status_code == 401:
        print("\n- FAIL, invalid OME username or password passed in")
        sys.exit()

    
if __name__ == "__main__":
    test_OME_creds()
    if args["D"]:
        delete_group()
    elif args["w"]:
        help_doc()
    elif args["G"]:
        get_oid_fid_value_possible_values()
    elif args["g"]:
        get_all_groups()
    elif args["d"]:
        get_group_devices()
    elif args["create"] and args["name"] and args["description"]:
        create_update_group(0)
    elif args["update"] and args["name"] and args["description"]:
        try:
            test = int(args["update"])
        except:
            print("\n- FAIL, make sure you pass in an integer group ID value")
            sys.exit()
        create_update_group(int(args["update"]))
    elif args["q"]:
        get_group_query_info()
    else:
        print("- FAIL, either missing arguments or invalid arguments passed in. If needed, check help text (-h) for more help and examples") 



    


