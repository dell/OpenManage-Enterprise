import requests
import urllib3
import os
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


APPLIANCE_IP=os.environ.get('APPLIANCE_IP')
USER_DETAILS = {"input":{"UserName":"admin","Password":"linux"}}
X_AUTH_TOKEN = None

print ('Logging in to %s'%APPLIANCE_IP)
url = 'https://%s/api/SessionService/Sessions'%APPLIANCE_IP
pool = urllib3.HTTPSConnectionPool(APPLIANCE_IP, port=443, cert_reqs='CERT_NONE', assert_hostname=False)
body = json.dumps(USER_DETAILS.get("input"))
response = pool.urlopen('POST', url, headers={'Content-Type':'application/json'}, body=body)
X_AUTH_TOKEN = response.headers.get('X-Auth-Token')
print(X_AUTH_TOKEN)


DISCOVERY_CONFIG_DETAILS = {"input":
                             { 
                                 "DiscoveryConfigGroupName":"Discovery1",
                                 "DiscoveryConfigGroupDescription":"null",
                                 "DiscoveryConfigModels":[ 
                                            { "DiscoveryConfigId":331105536,
                                              "DiscoveryConfigDescription":"",
                                              "DiscoveryConfigStatus":"",
                                              "DiscoveryConfigTargets":[{ 
                                              "DiscoveryConfigTargetId":0,
                                              "NetworkAddressDetail":"ut1host",
                                              "AddressType":30,
                                              "Disabled":False,
                                              "Exclude":False
                                            },
                                            { 
                                              "DiscoveryConfigTargetId":0,
                                              "NetworkAddressDetail":"WIN-218V6VC2092",
                                              "AddressType":30,
                                              "Disabled":False,
                                              "Exclude":False
                                            },
                                            { 
                                              "DiscoveryConfigTargetId":0,
                                              "NetworkAddressDetail":"WIN-02G0DDHDJTC",
                                              "AddressType":30,
                                              "Disabled":False,
                                              "Exclude":False
                                            }],
                                 "ConnectionProfileId":0,"ConnectionProfile":"{\"profileName\":\"\",\"profileDescription\":\"\",\"type\":\"DISCOVERY\",\"credentials\":[{\"id\":0,\"type\":\"WSMAN\",\"authType\":\"Basic\",\"modified\":false,\"credentials\":{\"username\":\"root\",\"password\":\"calvin\",\"caCheck\":false,\"cnCheck\":false,\"port\":443,\"retries\":3,\"timeout\":60,\"isHttp\":false,\"keepAlive\":false}}]}",
                                 "DeviceType":[1000]}],
                                 "Schedule":{"RunNow":True,
                                 "RunLater":False,
                                 "Cron":"startnow",
                                 "StartTime":"",
                                 "EndTime":""
                            },
                            "CreateGroup":True,
                            "TrapDestination":False
                          }
}
print ('Creating discovery task')
url = 'https://%s/api/DiscoveryConfigService/DiscoveryConfigGroups'%APPLIANCE_IP
pool = urllib3.HTTPSConnectionPool(APPLIANCE_IP, port=443, cert_reqs='CERT_NONE', assert_hostname=False)
body = json.dumps(DISCOVERY_CONFIG_DETAILS.get("input"))
response = pool.urlopen('POST', url, headers={'Content-Type':'application/json', 'X-Auth-Token':X_AUTH_TOKEN}, body=body)
print(response.status)
print(response.data)

