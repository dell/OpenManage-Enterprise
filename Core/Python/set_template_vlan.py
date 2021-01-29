#
#  Python script to get the list of virtual addresses in an Identity Pool
#
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
# _version_ = 0.1
#
#
# Copyright (c) 2018 Dell EMC Corporation
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
Script to manage templates in OpenManage Enterprise

#### Description
This script uses the OME REST API to export, import, assign vlans or identity pool to templates

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
```
python .\set_template_vlan.py --ip <xx> --user <username> --password <pwd> --name "MX840 Test" --network-card "NIC in Mezzanine 1A" --untagged-vlans "{1:0,2:'VLAN 1002'}" --tagged-vlans "{1:['VLAN 1003','VLAN 1004'],2:['VLAN 1004','VLAN 1005']}"
python .\set_template_vlan.py --ip <xx> --user <username> --password <pwd> --name "MX840 Test" --network-card "NIC in Mezzanine 1A" --untagged-vlans '{1:0,2:0}' --tagged-vlans '{1:[],2:[]}'
```
"""

import sys
import argparse
from argparse import RawTextHelpFormatter
import traceback
import json
import requests
import urllib3
import os
import csv
import ast
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

session_auth_token = {}

KEY_ATTR_NAME = 'DisplayName'
SUB_GRP_ATTR_NAME = 'SubAttributeGroups'
GRP_ATTR_NAME = 'Attributes'
GRP_NAME_ID_ATTR_NAME = 'GroupNameId'
CUSTOM_ID_ATTR_NAME = 'CustomId'

def get_session(ip_address, username, password):
    session_url = 'https://%s/api/SessionService/Sessions' % (ip_address)
    headers = {'content-type': 'application/json'}
    user_details = {'UserName': username,
                    'Password': password,
                    'SessionType': 'API'}
    session_info = requests.post(session_url, verify=False,
                                    data=json.dumps(user_details),
                                    headers=headers)
    if session_info.status_code == 201:
        session_info_token = session_info.headers['X-Auth-Token']
        session_info_data = session_info.json()
        session_auth_token = {
            "token": session_info_token,
            "id": session_info_data['Id']
        }
    return session_auth_token

def delete_session(ip_address, headers, id):
    session_url = "https://%s/api/SessionService/Sessions('%s')" % (ip_address, id)
    session_info = requests.delete(session_url, verify=False, headers=headers)
    if session_info.status_code == 204:
        return True
    else: 
        print ("Unable to delete session %s" % id)
        return False

def get_template_vlan_info(base_uri, headers, nic_identifier, template_id):
    url = base_uri + "/api/TemplateService/Templates({0})/Views({1})/AttributeViewDetails".format(template_id, 4)
    port_id_map = {}
    port_untagged_map = {}
    port_tagged_map = {}
    resp = requests.get(url, headers=headers, verify=False)
    if resp.status_code == 200:
        resp_data = resp.json()
        nic_model = resp_data.get('AttributeGroups', [])
        nic_group = nic_model[0]['SubAttributeGroups']
        nic_found = False
        for nic in nic_group:
            if nic_identifier == nic.get(KEY_ATTR_NAME):
                nic_found = True
                for port in nic.get(SUB_GRP_ATTR_NAME):  # ports
                    for partition in port.get(SUB_GRP_ATTR_NAME):  # partitions
                        for attribute in partition.get(GRP_ATTR_NAME):  # attributes
                            if attribute.get(CUSTOM_ID_ATTR_NAME) != 0:
                                port_number = port.get(GRP_NAME_ID_ATTR_NAME)
                                port_id_map[port_number] = attribute.get(CUSTOM_ID_ATTR_NAME)
                                if attribute.get(KEY_ATTR_NAME).lower() == "vlan untagged":
                                    port_untagged_map[port_number] = int(attribute['Value'])
                                if attribute.get(KEY_ATTR_NAME).lower() == "vlan tagged":
                                    port_tagged_map[port_number] = []
                                    if attribute['Value']:
                                        port_tagged_map[port_number] = \
                                            list(map(int, (attribute['Value']).replace(" ", "").split(",")))
        if not nic_found:
            print ("NIC with name '{0}' not found for template with id {1}".format(nic_identifier, template_id))

    return port_id_map, port_untagged_map, port_tagged_map


def get_networks(base_uri, headers):
    network_url = base_uri + '/api/NetworkConfigurationService/Networks'
    network_response = requests.get(network_url, headers=headers, verify=False)
    if network_response.status_code == 200 or network_response.status_code == 201:
        network_data = network_response.json()
        network_data = network_data['value']
        return network_data
    else:
        print("Unable to retrieve list from %s" % (network_url))

def get_network_id(networks, name):
    for network in networks:
        if network["Name"] == name:
            return network["Id"]

def get_vlan_payload(base_uri, headers, template_id, nic_identifier, untag_dict, tagged_dict):
    payload = {}
    payload["TemplateId"] = template_id
    # VlanAttributes
    port_id_map, port_untagged_map, port_tagged_map = get_template_vlan_info(base_uri, headers, nic_identifier, template_id)
    networks = get_networks(base_uri, headers)
    # Update VLAN Name with VLAN Id
    for utk, utv in untag_dict.items():
        if utv != 0: # Skip for 0 as this is used to clear the default untagged VLAN
            vlan_id = get_network_id(networks, utv)
            if vlan_id:
                untag_dict[utk] = vlan_id
            else:
                untag_dict[utk].pop(i)
                print("Unable to find VLAN %s" % (utv))

    for tk, tv in tagged_dict.items():
        for i, tagged_network in enumerate(tv):
            vlan_id = get_network_id(networks, tagged_network)
            if vlan_id:
                tagged_dict[tk][i] = vlan_id
            else:
                tagged_dict[tk].pop(i)
                print("Unable to find VLAN %s" % (tagged_network))

    vlan_attributes = []
    for pk, pv in port_id_map.items():
        mdict = {}
        if pk in untag_dict or pk in tagged_dict:
            mdict["Untagged"] = untag_dict.pop(pk, port_untagged_map.get(pk))
            mdict["Tagged"] = tagged_dict.pop(pk, port_tagged_map.get(pk))
            mdict["ComponentId"] = port_id_map.get(pk)
        if mdict:
            vlan_attributes.append(mdict)
    if untag_dict:
        print ("Invalid port(s) {0} found for untagged "
                             "vLAN".format(untag_dict.keys()))
    if tagged_dict:
        print("Invalid port(s) {0} found for tagged "
                             "vLAN".format(tagged_dict.keys()))
    payload["VlanAttributes"] = vlan_attributes
    #print (json.dumps(payload, indent=4))
    return payload

def template_assign_vlan(base_uri, headers, template_id, network_card, untag_dict, tagged_dict):
    try:
        url = base_uri + "/api/TemplateService/Actions/TemplateService.UpdateNetworkConfig"
        payload = get_vlan_payload(base_uri, headers, template_id, network_card, ast.literal_eval(untag_dict), ast.literal_eval(tagged_dict))
        resp = requests.post(url, headers=headers, verify=False, data=json.dumps(payload))
        if resp.status_code == 200:
            print("Successfully applied the network settings to the template")
        elif resp.status_code == 400:
            print ("Failed creation... ")
            print (json.dumps(resp.json(), indent=4,
                                sort_keys=False))
    except Exception as e:
        print(traceback.format_exc())

def get_template(base_uri, headers, name):
    if name:
        url = base_uri + "/api/TemplateService/Templates?$filter=Name eq '" + name + "'"
        get_resp = requests.get(url, headers=headers, verify=False)
        if get_resp.status_code == 200:
            resp_data = get_resp.json()
            #print(json.dumps(resp_data, indent=4))
            return resp_data["value"]
        elif get_resp.status_code == 400:
            print ("Failed creation... ")
            print (json.dumps(get_resp.json(), indent=4,
                                sort_keys=False))

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("--ip", "-i", required=True, help="OME Appliance IP")
    PARSER.add_argument("--user", "-u", required=False,
                        help="Username for OME Appliance", default="admin")
    PARSER.add_argument("--password", "-p", required=True,
                        help="Password for OME Appliance")
    PARSER.add_argument("--name", "-n", required=True,
                        help="Name of Template")
    PARSER.add_argument("--network-card", "-nc", required=False,
                        help="Name of NIC")
    PARSER.add_argument("--untagged-vlans", "-vu", required=False,
                        help="Untagged VLANS")
    PARSER.add_argument("--tagged-vlans", "-vt", required=False,
                        help="Tagged VLANS")
    ARGS = PARSER.parse_args()
    base_uri = 'https://%s' %(ARGS.ip)
    auth_token = get_session(ARGS.ip, ARGS.user, ARGS.password)
    headers = {'content-type': 'application/json'}
    if auth_token.get('token') != None:
        headers['X-Auth-Token'] = auth_token['token']
    else:
        print("Unable to create a session with appliance %s" % (base_uri))
        quit()

    try: 
        if ARGS.name:
            templates = get_template(base_uri, headers, ARGS.name)
            for template in templates:
                template_assign_vlan(base_uri, headers, template["Id"], ARGS.network_card, ARGS.untagged_vlans, ARGS.tagged_vlans)
    except Exception as e:
        print(traceback.format_exc())
    finally:
        delete_session(ARGS.ip, headers, auth_token['id'])
