#
# _author_ = Rishi Mukherjee
#
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
   Script for importing Physical Groups and their device associations into OME programmatically from a CSV file

#### Description

**Use Cases**

1. Physical group creation
2. Device to Rack association

Considering the fact that recreation of physical group hierarchies are a painful and time taking activities for the users,
OpenManage Power Manager facilitates importing the existing hierarchy of a data center from a csv file.

**Prerequisites**
OpenManage Enterprise v3.4 or later
Power Manager plugin v1.2 or later

**Steps**
1. It is expected that this script run on Python version 3.x.
2. Create a file called physicalgroups.csv with the below format. Fill it in with your data:

        DC1,Room1,Aisle1,Rack1,100,42,1,GMJ3GL2
        DC1,Room1,Aisle1,Rack1,100,42,3,BN1JR42
        DC1,,Aisle1,Rack1,100,21,4,D4QBBS2
        DC1,,,Rack1,100,21,10,6SM09X2
        ,Room1,Aisle1,Rack1,100,48,1,BCF5GY1
        ,Room1,,Rack1,100,48,5,H2CHH32
        ,,Aisle1,Rack1,100,48,4,DR6R7C2
        ,,,Rack1,100,24,4,G72SQ12
        ,,Aisle4,Rack4,100,24,4,CQ2RG52

3. Create a file called configfile.properties with the below format. Complete the file with your data.

        [consoleaccessdetails]
        ipaddress = 10.10.10.10
        username = admin
        password = admin

**Usage**

Run the file new_power_manager_physical_group.py on the system where it is downloaded as mentioned in pre-requisites.
This script can be run on Windows and Linux operating systems. The command line interface is:

    python new_power_manager_physical_group.py

The script gets executed in a silent mode and generates following files
- physicalgroup_automation.log: This includes the script logs
- Date-timestamp-based report file having name report_<DateTimestamp>.txt: This includes the final outcome of the execution that reveals which all physical groups are created, failed and result on device to rack group association.

#### Python Example
     python new_power_manager_physical_group.py

"""

import configparser
import csv
import logging
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(filename='physicalgroup_automation.log',
                    format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)

dateTimeObj = datetime.now()
timestampStr = dateTimeObj.strftime("%d-%b-%Y_%H-%M-%S")
report_filename = 'report_' + timestampStr + ".txt"

config = None
ipaddress = ''
username = ''
password = ''


def traverse(o, tree_types=(list, tuple)):
    if isinstance(o, tree_types):
        for value in o:
            for subvalue in traverse(value, tree_types):
                yield subvalue
    else:
        yield o


def check_if_empty(string):
    if not string.strip():
        return True
    else:
        return False


def generate_report(operation_type, operation_result, payload, response=None):
    msg_physical_group_creation_sucess = "physical group with payload %s got created \n\n" % payload
    msg_physical_group_creation_failure = "creation of physical group with payload %s got failed with reason %s \n\n" % (
    payload, response)
    msg_device_association_sucess = "device associaiton with payload %s got created \n\n" % payload
    msg_device_association_failure = "creation of physical group with payload %s got failed with reason %s \n\n" % (
    payload, response)

    file = open(report_filename, 'a')

    if operation_type == 'create_physical_group' and operation_result == 'success':
        file.write(msg_physical_group_creation_sucess)
    if operation_type == 'create_physical_group' and operation_result == 'failure':
        file.write(msg_physical_group_creation_failure)
    if operation_type == 'create_device_association' and operation_result == 'success':
        file.write(msg_physical_group_creation_sucess)
    if operation_type == 'create_device_association' and operation_result == 'failure':
        file.write(msg_device_association_failure)

    file.close()


def create_physical_group(payload):
    '''
    This method will create the physical group
    '''
    logging.info("inside create physical group")
    url = "https://" + str(ipaddress) + "/api/GroupService/Actions/GroupService.CreateGroup"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    logging.debug("url: %s, payload: %s " % (url, payload))
    try:
        r = requests.post(url, auth=(username, password), verify=False, json=payload, headers=headers)
        status_code = r.status_code
        json = r.json()
        logging.debug("status_code: %s, response json: %s " % (status_code, json))
        if status_code == 200:
            generate_report('create_physical_group', 'success', payload)
        else:
            generate_report('create_physical_group', 'failure', payload, json)
        return status_code, json
    except Exception as ex:
        logging.error("Exception %s was raised while trying to create physical group having payload %s" % (ex, payload))


def get_physical_group_details(groupname, tag):
    '''
    This method will retreive physical group details
    '''
    logging.info("inside get physical group details")
    url = "https://" + str(
        ipaddress) + "/api/PowerService/PhysicalGroups/GroupDetails?$filter=contains(Name,'" + groupname + "') and contains(Tag,'" + tag + "')"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    logging.debug("url: %s" % url)
    try:
        r = requests.get(url, auth=(username, password), verify=False, headers=headers)
        status_code = r.status_code
        json = r.json()
        logging.debug("status_code: %s, response json: %s " % (status_code, json))
        return status_code, json
    except Exception as ex:
        logging.error(
            "Exception %s was raised while trying to get physical group info having name %s" % (ex, groupname))


def get_device_info(servicetag):
    '''
    This method will retreive the device info based on the service tag
    '''
    logging.info("inside get device info")
    url = "https://" + str(
        ipaddress) + "/api/DeviceService/Devices?$filter=DeviceServiceTag%20eq%20'" + servicetag + "'"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    logging.debug("url: %s" % url)
    try:
        r = requests.get(url, auth=(username, password), verify=False, headers=headers)
        status_code = r.status_code
        json = r.json()
        logging.debug("status_code: %s, response json: %s " % (status_code, json))
        return status_code, json
    except:
        logging.error(
            "Exception %s was raised while trying to create device info having service tag %s" % (ex, servicetag))


def associate_device_to_slot(payload):
    '''
    This method will associate device to a rack slot
    '''
    url = "https://" + str(ipaddress) + "//api/PowerService/PhysicalGroups/Actions/PhysicalGroup.AddMemberDevices"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    logging.debug("url: %s, payload: %s " % (url, payload))
    try:
        r = requests.post(url, auth=(username, password), verify=False, json=payload, headers=headers)
        status_code = r.status_code
        json = r.json()
        logging.debug("status_code: %s, response json: %s " % (status_code, json))
        if status_code == 200:
            generate_report('create_device_association', 'success', payload)
        else:
            generate_report('create_device_association', 'failure', payload, json)
        return status_code, json
    except:
        logging.error(
            "Exception %s was raised while trying to associate device to rack having payload %s" % (ex, payload))


if __name__ == "__main__":
    '''
    This is the main method
    '''

    print("WARNING: THIS SCRIPT IS EXPERIMENTAL.")
    print("The Power Manager scripts were originally internal Dell scripts we then published externally. If you see "
          "this message and are using one of these scripts it would be very helpful if you open an issue on GitHub "
          "at https://github.com/dell/OpenManage-Enterprise/issues and tell us you are using the script. We have not "
          "dedicated any resources to optimizing them but are happy to do so if we know the community is using them. "
          "Likewise if you find a bug in one of these scripts feel free to open an issue and we will investigate.")

    try:
        # ip address, username and the password will be read from property file configFile.properties
        config = configparser.ConfigParser()
        config.read('configfile.properties')

        ipaddress = config.get("consoleaccessdetails", "ipaddress")
        username = config.get("consoleaccessdetails", "username")
        password = config.get("consoleaccessdetails", "password")

        '''
        physical hierarchy and the device association to rack slot will be read from csv file myenterprise3.csv
        The order will be Datacenter,Room,Aisle,Rack,Rack powercapacity, Rack size, Rack Slot Number, Service Tag of the device
        '''
        with open('../Plugins/Power Manager/Import Physical Hierarchy/Python/physicalgroups.csv', newline='') as f:
            reader = csv.reader(f)
            data = list(reader)  # data will be list of lists, where each list represents rows of the csv file
        logging.debug("value read from the csv file is - %s " % data)

        '''
        physical_hierarchy_dict will be dictionary of list of lists
        first list will represent the hierarchy
        second list onwards will represent the device association information to rack slot
        example:
        {'ph1':[['datacenter1','room1','aisle1','rack1','10000','42'], ['1','D89RG52'], ['10','G89RG52']]}
        '''
        physical_hierarchy_dict = {}

        no_of_physical_hierarchy = 1  # this is defined to subscript the physical group key as 'ph1', 'ph2' as so on

        for lst in data:
            j = 0
            hierarchy_exists = False
            key_to_be_appended = ""
            physical_hierarchy = []  # list of lists to hold the physical hierarchy and the device associations from the individual row of csv file
            current_hierarchy = []  # list to hold the physical hierarchy from the individual row of csv file
            current_device_association = []  # list to hold the rack level device associations from the individual row of csv file

            '''
            From single row of the csv file, the first 6 attributes will be considered to build the physical hierarchy
            while the remaining 2 will be to build the rack level device association. Finally the list of lists will be build
            which will hold a single unique physical hierarchy and the respective device associations. This list of lists will be considered
            to build a dictionary element - {'ph1':[['datacenter1','room1','aisle1','rack1','10000','42'], ['1','D89RG52'], ['10','G89RG52']]}
            '''
            for element in lst:
                if j < 6:
                    current_hierarchy.append(element)
                elif not check_if_empty(element):
                    current_device_association.append(element)
                j += 1

            physical_hierarchy.append(current_hierarchy)
            physical_hierarchy.append(current_device_association)
            logging.debug("physical hierarchy and the device association got build is - %s " % physical_hierarchy)

            '''
            validates if the physical hierarchy is not getting duplicated. The idea is to build the 
            physical hierarchy uniquely
            '''
            for key in physical_hierarchy_dict.keys():
                if current_hierarchy == physical_hierarchy_dict[key][0]:
                    key_to_be_appended = key
                    logging.debug("physical hierarchy %s exists" % current_hierarchy)
                    hierarchy_exists = True
                    break

            if not hierarchy_exists:
                physical_hierarchy_dict['ph' + str(no_of_physical_hierarchy)] = physical_hierarchy
                logging.debug("New physical hierarchy %s got added to the dictionary with key %s" % (
                current_hierarchy, 'ph' + str(no_of_physical_hierarchy)))
            else:
                old_hierarchy = physical_hierarchy_dict.get(key_to_be_appended)
                physical_hierarchy_dict[key_to_be_appended].append(current_device_association)
                logging.debug("New device association %s got added to the dictionary with key %s" % (
                current_device_association, key_to_be_appended))

            '''
            The variables need to be reset for the next iteration
            '''
            hierarchy_exists = False
            physical_hierarchy = []
            current_hierarchy = []
            current_device_association = []
            no_of_physical_hierarchy += 1

        '''
        Will be iterating on the dictionary values for creating the physical groups and building the hierarchy.
        A dictionary element is a list of lists. The first list dictvalue[0] is the physical hierarchy, while
        the subsequent lists are rack level device associations.
        '''
        for dictvalue in physical_hierarchy_dict.values():
            arr_index = 0  # This will determine whether the consideration is to create physical group and build the hierarchy,
            # or to create the rack level device association
            length_of_value = len(dictvalue)
            while arr_index < length_of_value:
                if arr_index == 0:
                    '''
                    These three flags are defined to determine for each iteration on the physical group elements of the first list
                    dictvalue[0] which is the appropriate parent for that group
                    '''
                    flag_DC_present = False
                    flag_ROOM_present = False
                    flag_AISLE_present = False

                    ph = dictvalue[0]  # this will hold the physical hierarchy of each dictionary element
                    parent_groupid = 0  # this will hold the id of the parent physical group applicable for the current node to construct the hierarchy
                    status_code = 0  # this will hold the status code of the REST response
                    json = ''  # this will hold the response value of the REST call

                    '''
                    following field are defined to hold rack name, rack power capacity and rack size
                    location field with hierarchy into consideration of an existing physical group. This location field
                    will be referred to validate if the physical group which is required to be created is unique (since 
                    only with group name it cannot be resolved) and will be falling under which parent in the hierarchy
                    '''
                    rack_name = ''  # this will hold the rackname
                    rack_power_capacity = 0  # this will hold pwer capacity of a rack
                    rack_space_capacity = 0  # this will hold rack size
                    location = None  # this will hold the group name with the consideration of hierarchy
                    i = 0  # this will index the group type in the physical hierarchy

                    logging.info("Start of iterating through the physical group elements")
                    for element in ph:
                        logging.debug("Parent group id into consideration is - %s" % parent_groupid)
                        if i == 0:  # consideration of DATACENTER element
                            if not check_if_empty(element):  # datacenter element is non empty
                                logging.info("Considering the datacenter element %s" % element)
                                '''
                                this will handle the creation logic of datacenter element.
                                before creating we need to check if the datacenter already exists
                                if exists creation will be ignored otherwise will be created with parent group id as 1029 (root node)
                                '''
                                logging.info("Validating if datacenter group %s already exists" % element)
                                status_code, json = get_physical_group_details(element, "DATA_CENTER")
                                if status_code == 200:
                                    if len(json.get('value')) > 0:
                                        flag_DC_present = True
                                        parent_groupid = json.get('value')[0].get("Id")
                                        logging.info("datacenter group %s already exists and having group id - %s" % (
                                        element, parent_groupid))
                                    else:
                                        flag_DC_present = True
                                        payload = {
                                            "GroupModel": {"Name": element, "Description": "", "MembershipTypeId": 12,
                                                           "ParentId": 1029, "GroupTags": [{"Name": "DATA_CENTER"}]}}
                                        status_code, json = create_physical_group(payload)
                                        parent_groupid = json
                                        logging.info("datacenter group %s got created with group id - %s" % (
                                        element, parent_groupid))
                                location = str(element)
                            else:  # datacenter is empty
                                '''
                                if datacenter is not present in the hierarachy next non empty element will 
                                be the root node, hence parent_groupid is set to 0
                                '''
                                parent_groupid = 0
                        if i == 1:  # consideration of ROOM element
                            if not check_if_empty(element):  # room element is not empty
                                logging.info("Considering the room element %s" % element)
                                '''
                                this will handle the creation logic of room element.
                                before creating we need to check if the room already exists
                                if exists creation will be ignored otherwise will be created 
                                with parent group id as value in parent_groupid
                                '''

                                logging.info("Validating if room group %s already exists" % element)
                                status_code, json = get_physical_group_details(element, "ROOM")
                                if status_code == 200:
                                    if len(json.get('value')) > 0:
                                        location_in_pmp = ''
                                        flag_is_group_present = False
                                        for value in json.get('value'):
                                            location_in_pmp = value.get("Location")
                                            if location == location_in_pmp and element == value.get('Name'):
                                                parent_groupid = value.get("Id")
                                                flag_is_group_present = True
                                                break

                                        flag_ROOM_present = True
                                        if flag_is_group_present:
                                            logging.info("room group %s already exists and having group id - %s" % (
                                            element, parent_groupid))
                                            pass
                                        else:
                                            if parent_groupid > 0:
                                                logging.info("room group %s will be created as child of %s" % (
                                                element, parent_groupid))
                                                payload = {"GroupModel": {"Name": element, "Description": "",
                                                                          "MembershipTypeId": 12,
                                                                          "ParentId": parent_groupid,
                                                                          "GroupTags": [{"Name": "ROOM"}]}}
                                                status_code, json = create_physical_group(payload)
                                                parent_groupid = json
                                            else:
                                                logging.info("room group %s will be created as root node" % element)
                                                payload = {"GroupModel": {"Name": element, "Description": "",
                                                                          "MembershipTypeId": 12, "ParentId": 1029,
                                                                          "GroupTags": [{"Name": "ROOM"}]}}
                                                status_code, json = create_physical_group(payload)
                                                parent_groupid = json
                                            logging.info("room group %s got created with group id - %s" % (
                                            element, parent_groupid))
                                    else:
                                        flag_ROOM_present = True
                                        if parent_groupid > 0:
                                            logging.info("room group %s will be created as child of %s" % (
                                            element, parent_groupid))
                                            payload = {"GroupModel": {"Name": element, "Description": "",
                                                                      "MembershipTypeId": 12,
                                                                      "ParentId": parent_groupid,
                                                                      "GroupTags": [{"Name": "ROOM"}]}}
                                            status_code, json = create_physical_group(payload)
                                            parent_groupid = json
                                        else:
                                            logging.info("room group %s will be created as root node" % element)
                                            payload = {"GroupModel": {"Name": element, "Description": "",
                                                                      "MembershipTypeId": 12, "ParentId": 1029,
                                                                      "GroupTags": [{"Name": "ROOM"}]}}
                                            status_code, json = create_physical_group(payload)
                                            parent_groupid = json
                                        logging.info(
                                            "room group %s got created with group id - %s" % (element, parent_groupid))
                                if location != None:
                                    if len(location) > 0:
                                        location += " / " + str(element)
                                    else:
                                        location = str(element)
                                else:
                                    location = str(element)
                            else:  # room is empty
                                '''
                                if room is not present in the hierarachy next non empty element will 
                                be the root node if only datacenter is not present, hence parent_groupid is set to 0
                                with that consideration
                                '''
                                if not flag_DC_present:
                                    parent_groupid = 0
                        if i == 2:  # consideration of AISLE element
                            if not check_if_empty(element):  # aisle element is not empty
                                logging.info("Considering the aisle element %s" % element)
                                '''
                                this will handle the creation logic of aisle element.
                                before creating we need to check if the aisle already exists
                                if exists creation will be ignored otherwise will be created 
                                with parent group id as value in parent_groupid
                                '''

                                logging.info("Validating if aisle group %s already exists" % element)
                                status_code, json = get_physical_group_details(element, "AISLE")
                                if status_code == 200:
                                    if len(json.get('value')) > 0:
                                        location_in_pmp = ''
                                        flag_is_group_present = False
                                        for value in json.get('value'):
                                            location_in_pmp = value.get("Location")
                                            if location == location_in_pmp and element == value.get('Name'):
                                                parent_groupid = value.get("Id")
                                                flag_is_group_present = True
                                                break

                                        flag_AISLE_present = True
                                        if flag_is_group_present:
                                            logging.info("aisle group %s already exists and having group id - %s" % (
                                            element, parent_groupid))
                                            pass
                                        else:
                                            if parent_groupid > 0:
                                                logging.info("aisle group %s will be created as child of %s" % (
                                                element, parent_groupid))
                                                payload = {"GroupModel": {"Name": element, "Description": "",
                                                                          "MembershipTypeId": 12,
                                                                          "ParentId": parent_groupid,
                                                                          "GroupTags": [{"Name": "AISLE"}]}}
                                                status_code, json = create_physical_group(payload)
                                                parent_groupid = json
                                            else:
                                                logging.info("aisle group %s will be created as root node" % element)
                                                payload = {"GroupModel": {"Name": element, "Description": "",
                                                                          "MembershipTypeId": 12, "ParentId": 1029,
                                                                          "GroupTags": [{"Name": "AISLE"}]}}
                                                status_code, json = create_physical_group(payload)
                                                parent_groupid = json
                                            logging.info("aisle group %s got created with group id - %s" % (
                                            element, parent_groupid))
                                    else:
                                        if parent_groupid > 0:
                                            logging.info("aisle group %s will be created as child of %s" % (
                                            element, parent_groupid))
                                            payload = {"GroupModel": {"Name": element, "Description": "",
                                                                      "MembershipTypeId": 12,
                                                                      "ParentId": parent_groupid,
                                                                      "GroupTags": [{"Name": "AISLE"}]}}
                                            status_code, json = create_physical_group(payload)
                                            parent_groupid = json
                                        else:
                                            logging.info("aisle group %s will be created as root node" % element)
                                            payload = {"GroupModel": {"Name": element, "Description": "",
                                                                      "MembershipTypeId": 12, "ParentId": 1029,
                                                                      "GroupTags": [{"Name": "AISLE"}]}}
                                            status_code, json = create_physical_group(payload)
                                            parent_groupid = json
                                        logging.info(
                                            "aisle group %s got created with group id - %s" % (element, parent_groupid))
                                if location != None:
                                    if len(location) > 0:
                                        location += " / " + str(element)
                                    else:
                                        location = str(element)
                                else:
                                    location = str(element)
                            else:  # aisle is empty
                                '''
                                if aisle is not present in the hierarachy next non empty element will 
                                be the root node if only datacenter and room is not present, hence parent_groupid is set to 0
                                with that consideration
                                '''
                                if not flag_DC_present and not flag_ROOM_present:
                                    parent_groupid = 0
                        if i == 3 and not check_if_empty(element):  # consideration of rack name
                            rack_name = element
                        if i == 4 and not check_if_empty(element):  # consideration of rack power capacity
                            rack_power_capacity = element
                        if i == 5 and not check_if_empty(element):  # consideration of rack size
                            rack_space_capacity = element

                            logging.info("Considering the rack element %s" % rack_name)
                            '''
                            this will handle the creation logic of rack element.
                            before creating we need to check if the rack already exists
                            if exists creation will be ignored otherwise will be created 
                            with parent group id as value in parent_groupid
                            '''
                            logging.info("Validating if rack group %s already exists" % rack_name)
                            status_code, json = get_physical_group_details(rack_name, "RACK")
                            if status_code == 200:
                                if len(json.get('value')) > 0:
                                    location_in_pmp = ''
                                    flag_is_group_present = False
                                    for value in json.get('value'):
                                        location_in_pmp = value.get("Location")
                                        if location == location_in_pmp and rack_name == value.get('Name'):
                                            parent_groupid = value.get("Id")
                                            flag_is_group_present = True
                                            break

                                    if flag_is_group_present:
                                        logging.info("rack group %s already exists and having group id - %s" % (
                                        rack_name, parent_groupid))
                                        pass
                                    else:
                                        if parent_groupid > 0:
                                            logging.info("rack group %s will be created as child of %s" % (
                                            rack_name, parent_groupid))
                                            payload = {"GroupModel": {"Name": rack_name, "Description": "",
                                                                      "MembershipTypeId": 12,
                                                                      "ParentId": parent_groupid,
                                                                      "GroupTags": [{"Name": "RACK"}],
                                                                      "GroupAttributeTypeValues": [
                                                                          {"AttributeTypeName": "POWER_CAPACITY",
                                                                           "IdDataType": 2,
                                                                           "Value": rack_power_capacity},
                                                                          {"AttributeTypeName": "SPACE_CAPACITY",
                                                                           "IdDataType": 2,
                                                                           "Value": rack_space_capacity}]}}
                                            status_code, json = create_physical_group(payload)
                                            parent_groupid = json
                                        else:
                                            logging.info("rack group %s will be created as root node" % rack_name)
                                            payload = {"GroupModel": {"Name": rack_name, "Description": "",
                                                                      "MembershipTypeId": 12, "ParentId": 1029,
                                                                      "GroupTags": [{"Name": "RACK"}],
                                                                      "GroupAttributeTypeValues": [
                                                                          {"AttributeTypeName": "POWER_CAPACITY",
                                                                           "IdDataType": 2,
                                                                           "Value": rack_power_capacity},
                                                                          {"AttributeTypeName": "SPACE_CAPACITY",
                                                                           "IdDataType": 2,
                                                                           "Value": rack_space_capacity}]}}
                                            status_code, json = create_physical_group(payload)
                                            parent_groupid = json
                                else:
                                    if parent_groupid > 0:
                                        logging.info("rack group %s will be created as child of %s" % (
                                        rack_name, parent_groupid))
                                        payload = {
                                            "GroupModel": {"Name": rack_name, "Description": "", "MembershipTypeId": 12,
                                                           "ParentId": parent_groupid, "GroupTags": [{"Name": "RACK"}],
                                                           "GroupAttributeTypeValues": [
                                                               {"AttributeTypeName": "POWER_CAPACITY", "IdDataType": 2,
                                                                "Value": rack_power_capacity},
                                                               {"AttributeTypeName": "SPACE_CAPACITY", "IdDataType": 2,
                                                                "Value": rack_space_capacity}]}}
                                        status_code, json = create_physical_group(payload)
                                        parent_groupid = json
                                    else:
                                        logging.info("rack group %s will be created as root node" % rack_name)
                                        payload = {
                                            "GroupModel": {"Name": rack_name, "Description": "", "MembershipTypeId": 12,
                                                           "ParentId": 1029, "GroupTags": [{"Name": "RACK"}],
                                                           "GroupAttributeTypeValues": [
                                                               {"AttributeTypeName": "POWER_CAPACITY", "IdDataType": 2,
                                                                "Value": rack_power_capacity},
                                                               {"AttributeTypeName": "SPACE_CAPACITY", "IdDataType": 2,
                                                                "Value": rack_space_capacity}]}}
                                        status_code, json = create_physical_group(payload)
                                        parent_groupid = json

                            if location != None:
                                if len(location) > 0:
                                    location += " / " + str(rack_name)
                                else:
                                    location = str(rack_name)
                            else:
                                location = str(element)
                        i += 1  # move to the next element of the physical hierarachy
                else:
                    '''
                    consideration of rack level associaiton with devices
                    '''
                    slotnumber = 0
                    servicetag = ''
                    j = 0
                    for element in dictvalue[arr_index]:
                        if j == 0:
                            slotnumber = element
                        if j == 1:
                            servicetag = element
                            logging.info(
                                "validating device with service tag %s is discovered and managed and eligible to be associated with rack slot" % servicetag)
                            status_code, json = get_device_info(servicetag)
                            if status_code == 200:
                                if (len(json.get("value")) > 0):
                                    logging.info(
                                        "validating device with service tag %s is eligible to be associated with rack slot" % servicetag)
                                    deviceid = json.get("value")[0].get("Id")
                                    payload = {"GroupId": parent_groupid,
                                               "MemberDevices": [{"Id": deviceid, "SlotNumber": slotnumber}]}
                                    logging.info("associating device with service tag %s with rack slot %s " % (
                                    servicetag, slotnumber))
                                    status_code, json = associate_device_to_slot(payload)

                        j += 1  # consideration of next element for device allocation
                arr_index += 1  # consideration of next list in the list of lists

        print("WARNING: THIS SCRIPT IS EXPERIMENTAL.")
        print(
            "The Power Manager scripts were originally internal Dell scripts we then published externally. If you see "
            "this message and are using one of these scripts it would be very helpful if you open an issue on GitHub "
            "at https://github.com/dell/OpenManage-Enterprise/issues and tell us you are using the script. We have not "
            "dedicated any resources to optimizing them but are happy to do so if we know the community is using them. "
            "Likewise if you find a bug in one of these scripts feel free to open an issue and we will investigate.")

    except Exception as ex:
        logging.error("Exception %s has raised while processing the input from csv file" % ex)
