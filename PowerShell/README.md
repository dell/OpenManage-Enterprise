# API Documentation

This repository is composed of two principal portions - OpenManage Enterprise (OME) API usage examples and plugins.

API usage examples are stored in PowerShell and Python for PowerShell and Python examples respectively.
Parity is generally maintained between PowerShell and Python examples. Available scripts are listed for each functionality
shown below. 

You can find a current copy of the OME API documentation [here](https://dl.dell.com/topicspdf/dell-openmanage-enterprise_Reference-Guide2_en-us.pdf).

## Table of Contents
<div class="toc">
<ul>
<li><a href="#deploy-scripts">Deploy Scripts</a></li>
<ul>

<li><a href="#add-device-to-static-group">Add Device To Static Group</a></li>

<li><a href="#add-members-to-mcm-group">Add Members To Mcm Group</a></li>

<li><a href="#copy-vlans">Copy Vlans</a></li>

<li><a href="#deploy-template">Deploy Template</a></li>

<li><a href="#edit-discovery-job">Edit Discovery Job</a></li>

<li><a href="#invoke-discover-device">Invoke Discover Device</a></li>

<li><a href="#invoke-manage-query-groups">Invoke Manage Query Groups</a></li>

<li><a href="#new-mcm-group">New Mcm Group</a></li>

<li><a href="#new-network">New Network</a></li>

<li><a href="#new-ome-user">New Ome User</a></li>

<li><a href="#new-static-group">New Static Group</a></li>

<li><a href="#new-template">New Template</a></li>

<li><a href="#set-power-state">Set Power State</a></li>

</ul>
<li><a href="#update-scripts">Update Scripts</a></li>
<ul>

<li><a href="#invoke-refresh-inventory">Invoke Refresh Inventory</a></li>

<li><a href="#update-firmware-using-catalog">Update Firmware Using Catalog</a></li>

<li><a href="#update-installed-firmware-with-dup">Update Installed Firmware With Dup</a></li>

</ul>
<li><a href="#monitor-scripts">Monitor Scripts</a></li>
<ul>

<li><a href="#get-alerts">Get Alerts</a></li>

<li><a href="#get-audit-logs">Get Audit Logs</a></li>

<li><a href="#get-chassis-inventory">Get Chassis Inventory</a></li>

<li><a href="#get-device-inventory">Get Device Inventory</a></li>

<li><a href="#get-device-list">Get Device List</a></li>

<li><a href="#get-firmware-baselines">Get Firmware Baselines</a></li>

<li><a href="#get-group-by-device">Get Group By Device</a></li>

<li><a href="#get-group-details">Get Group Details</a></li>

<li><a href="#get-group-details-by-filter">Get Group Details By Filter</a></li>

<li><a href="#get-group-list">Get Group List</a></li>

<li><a href="#get-identitypool-usage">Get Identitypool Usage</a></li>

<li><a href="#get-ome-users">Get Ome Users</a></li>

<li><a href="#get-ome-vlans">Get Ome Vlans</a></li>

<li><a href="#get-report-list">Get Report List</a></li>

<li><a href="#get-warranty-information">Get Warranty Information</a></li>

<li><a href="#invoke-report-execution">Invoke Report Execution</a></li>

</ul>
<li><a href="#maintenance-scripts">Maintenance Scripts</a></li>
<ul>

<li><a href="#invoke-retire-lead">Invoke Retire Lead</a></li>

<li><a href="#set-scale-vlan-profile">Set Scale Vlan Profile</a></li>

</ul>
<li><a href="#supportassist-enterprise-ome-plugin-scripts">SupportAssist Enterprise Plugin Scripts</a></li>
<ul>

<li><a href="#get-supportassist-cases">Get Supportassist Cases</a></li>

<li><a href="#invoke-manage-supportassist-groups">Invoke Manage Supportassist Groups</a></li>

</ul>
<li><a href="#ome-power-manager-plugin-scripts">OME Power Manager Plugin Scripts</a></li>
<ul>

<li><a href="#find-non-pmp-capable-devices">Find Non Pmp Capable Devices</a></li>

<li><a href="#find-non-power-policy-capable-devices">Find Non Power Policy Capable Devices</a></li>

<li><a href="#get-power-manager-alerts">Get Power Manager Alerts</a></li>

<li><a href="#get-power-manager-capable-devices">Get Power Manager Capable Devices</a></li>

<li><a href="#get-power-manager-device-metrics">Get Power Manager Device Metrics</a></li>

<li><a href="#get-power-manager-epr">Get Power Manager Epr</a></li>

<li><a href="#get-power-manager-group-metrics">Get Power Manager Group Metrics</a></li>

<li><a href="#get-power-manager-monitoring-list">Get Power Manager Monitoring List</a></li>

<li><a href="#get-power-manager-policies">Get Power Manager Policies</a></li>

<li><a href="#get-power-manager-reports">Get Power Manager Reports</a></li>

<li><a href="#get-power-manager-top-energy-consumers">Get Power Manager Top Energy Consumers</a></li>

<li><a href="#get-power-manager-top-offenders">Get Power Manager Top Offenders</a></li>

<li><a href="#get-set-power-manager-setting">Get Set Power Manager Setting</a></li>

<li><a href="#invoke-refresh-power-manager-inventory">Invoke Refresh Power Manager Inventory</a></li>

<li><a href="#new-power-manager-physical-group">New Power Manager Physical Group</a></li>

</ul>
</ul>
</div>

## Deploy Scripts
Deploy scripts include those things for discovery and generating the initial inventory, configuration, and os deployment.

---
### Add Device To Static Group

#### Available Scripts

- [add_device_to_static_group.py](../Python/add_device_to_static_group.py)

- [Add-DeviceToStaticGroup.ps1](../PowerShell/Add-DeviceToStaticGroup.ps1)


#### Synopsis
Add one or more hosts to an existing static group.

#### Description
This script uses the OME REST API to add one or more hosts to an existing static group. You can provide specific
 devices or you can provide the job ID for a previous discovery job containing a set of servers. The script will pull
 from the discovery job and add those servers to a group. For authentication X-Auth is used over Basic Authentication.
Note: The credentials entered are not stored to disk.

#### Python Example
    python add_device_to_static_group.py --idrac-ips 192.168.1.45,192.168.1.63 --groupname 格蘭特 --password somepass --ip 192.168.1.93 --use-discovery-job-id 14028
    python add_device_to_static_group.py --service-tags servtag1,servtag2,servtag3 --groupname 格蘭特 --password somepass --ip 192.168.1.93


#### PowerShell Example
```
PS C:\>$creds = Get-Credentials
    .\Add-DeviceToStaticGroup.ps1' -IpAddress 192.168.1.93 -Credentials $creds -GroupName 'YourGroup' -IdracIps '192.16
    8.1.45,192.168.1.63' -UseDiscoveryJobId 14094

```


---
### Add Members To Mcm Group

#### Available Scripts

- [Add-MembersToMcmGroup.ps1](../PowerShell/Add-MembersToMcmGroup.ps1)

- [add_members_to_mcm_group.py](../Python/add_members_to_mcm_group.py)


#### Synopsis
Script to add all standalone domains to the existing MCM group,
and assign a backup lead

#### Description
This script adds all standalone domains to the
existing group and assigns a member as backup lead.

#### Python Example
`python add_members.py --ip <ip addr> --user root --password <passwd>`

Note:
1. Credentials entered are not stored to disk.
2. Random member will be assigned as a backup lead

#### API Workflow
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
user name and password entered by user
4. Add all standalone members to the created group
with POST on /ManagementDomainService/Actions/ManagementDomainService.Domains
5. Parse returned job id and monitor it to completion
6. Assign a random member as backup lead
with POST on /ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead
7. Parse returned job id and monitor it to completion


#### PowerShell Example
```
PS C:\>Not available

```


---
### Copy Vlans

#### Available Scripts

- [copy_vlans.py](../Python/copy_vlans.py)

- [Copy-Vlans.ps1](../PowerShell/Copy-Vlans.ps1)


#### Synopsis
Copies all VLANs from one OME instance to another

#### Description:
This script expects input in JSON format with two entries. The first should be a json array of dictionaries called
targets identifying the OME instances to which you want to push VLANs and the second is a single dictionary defining
the source instance. For example:

    {
        "target": [
            {
                "ip": "100.97.173.67",
                "port": "443",
                "user_name": "admin",
                "password": "your_password"
            },
            {
                "ip": "100.97.173.61",
                "port": "443",
                "user_name": "admin",
                "password": "your_password"
            }
        ],
        "source": {
            "ip": "100.97.173.76",
            "port": "443",
            "user_name": "admin",
            "password": "your_password"
        }
    }

#### Python Example
    python copy_vlans.py --inputs <JSON_FILE_NAME>


#### PowerShell Example
```
PS C:\>.\Copy-Vlans.ps1' -inputs test.json

```


---
### Deploy Template

#### Available Scripts

- [deploy_template.py](../Python/deploy_template.py)

- [Deploy-Template.ps1](../PowerShell/Deploy-Template.ps1)


#### Synopsis
Script to perform template deployment with or without identity pools on the target devices.

#### Description:
This script performs template deployment with or without an associated identity pool. Limitations:

- Currently the script only supports servers. It does not support chassis or IO modules. If this is something you would like please let us known by leaving an issue at https://github.com/dell/OpenManage-Enterprise/issues.
- The script does not provide an interface for changing the values in the identity pool. If you want to change the default values see the variable `identity_pool_payload`. You may update the values there
- The script allows you to either templatize all values from a target or only one value. Possible values are listed below. We did not add the ability to include arrays. If this is something you would like feel free to open an issue and let us know at https://github.com/dell/OpenManage-Enterprise/issues
    - iDRAC
    - BIOS
    - System
    - NIC
    - Lifecycle Controller
    - RAID
    - EventFilters
    - Fiber Channel
    - All

*WARNING*: To use identity pools the template must include NICs.

Note: The PowerShell version of this code has not been tested in some time. We suggest using the Python version. If an
update to the PowerShell version is a high priority to you please leave an issue at
https://github.com/dell/OpenManage-Enterprise/issues

#### Python Example
    python deploy_template.py --ip 192.168.1.93 --password PASSWORD --source-idrac-ip 192.168.1.10 --idrac-ips 192.168.1.45 --use-identity-pool


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Deploy-Template.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -SourceId 25527 -TargetId 10782 -Component iDRAC
     In this instance you will be prompted for credentials.
    

    PS C:\>$cred = Get-Credential
    .\Deploy-Template.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -SourceId 25527 -GroupId 1010 -Component iDRAC
     In this instance you will be prompted for credentials.

```


---
### Edit Discovery Job

#### Available Scripts

- [edit_discovery_job.py](../Python/edit_discovery_job.py)

- [Edit-DiscoveryJob.ps1](../PowerShell/Edit-DiscoveryJob.ps1)


#### Synopsis
Script to update an existing discovery job in OME

#### Description
This script uses the OME REST API to update an existing discovery job(if found) with the credentials and also
it updates networkaddress if user passs iprange.
For authentication X-Auth is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

#### Python Example
```bash
python edit_discovery_job.py --ip <ip addr> --user admin
--password <passwd> --jobNamePattern <Existing Discovery Job name>
--targetUserName <user name> --targetPassword <password>
--targetIpAddresses <10.xx.xx.x,10.xx.xx.xx-10.yy.yy.yy,10.xx.xx.xx>
```
where {jobNamePattern} can be existing discovery job name(Discovery_Essentials_10.xx.xx.xx)
or the job name pattern(Discovery_Essentials)


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Edit-DiscoveryJob --IpAddress "10.xx.xx.xx" -Credentials $cred -JobNamePattern "Discovery_Essentials_IP" -DeviceU
    serName "root" -DevicePassword "test12" -IpArray 10.xx.xx.xx,10.xx.xx.xx

```


---
### Invoke Discover Device

#### Available Scripts

- [invoke_discover_device.py](../Python/invoke_discover_device.py)

- [Invoke-DiscoverDevice.ps1](../PowerShell/Invoke-DiscoverDevice.ps1)


#### Synopsis
Script to discover devices managed by OME Enterprise

#### Description

Currently the PowerShell version of this script offers substantially more capability. See:
https://github.com/dell/OpenManage-Enterprise/issues/119

**Python**
This script uses the OME REST API to discover devices.
For authentication X-Auth is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

**PowerShell**
This script currently allows the discovery of servers, chassis, and network devices. Storage devices are not
currently supported. If it would be helpful to you leave a comment on
https://github.com/dell/OpenManage-Enterprise/issues/114 to let us know this is a priority for you. Currently only
SNMPv2c is supported for network devices. It does not support SNMPv1 and OME does not currently support SNMPv3. If
SNMPv1 is a priority for you please open an issue at https://github.com/dell/OpenManage-Enterprise/issues.

#### Python Example
```bash
python invoke_discover_device.py --ip <ip addr> --user admin
--password <passwd> --targetUserName <user name>
--targetPassword <password> --deviceType <{Device_Type}>
--targetIpAddresses <10.xx.xx.x,10.xx.xx.xx-10.yy.yy.yy,10.xx.xx.xx> or --targetIpAddrCsvFile xyz.csv
```
where {Device_Type} can be server,chassis


#### PowerShell Example
```
PS C:\>$creds = Get-Credential # Your OME credentials
    $servcreds = Get-Credential # Your OME credentials
    .\Invoke-DiscoverDevice -IpAddress 192.168.1.93 -Credentials $creds -ServerIps 192.168.1.63-192.168.1.65 -ServerCre
    dentials $servcreds -GroupName TestGroup -JobCheckSleepInterval 10 -ServerCsv Book1.csv,'IP address' -ChassisCsv Bo
    ok1.csv,'ChassisIp' -ChassisCredentials $chassiscreds
    

    PS C:\>.\Invoke-DiscoverDevice -IpAddress 192.168.1.93 -Credentials $creds -NetworkDeviceIps 192.168.1.24,192.168.1
    .34 -SnmpCommunityString 'SomeString'

```


---
### Invoke Manage Query Groups

#### Available Scripts

- [invoke_manage_query_groups.py](../Python/invoke_manage_query_groups.py)


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



---
### New Mcm Group

#### Available Scripts

- [new_mcm_group.py](../Python/new_mcm_group.py)

- [New-McmGroup.ps1](../PowerShell/New-McmGroup.ps1)


#### Synopsis
Script to create MCM group, add all members to the created group,
and assign a backup lead

#### Description:
This script creates a MCM group, adds all standalone domains to the
created group and assigns a member as backup lead.

Note:
1. Credentials entered are not stored to disk.
2. The value passed in by the user for the argument 'ip'
is set as the lead in the created MCM group

#### API Workflow
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
    for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
    user name and password entered by user
4. Create MCM group with given group name
    with PUT on /ManagementDomainService
5. Parse returned job id and monitor it to completion
6. Add all standalone members to the created group
    with POST on /ManagementDomainService/Actions/ManagementDomainService.Domains
7. Parse returned job id and monitor it to completion
8. Assign a random member as backup lead
    with POST on /ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead
9. Parse returned job id and monitor it to completion

#### Python Example
`python new_mcm_group.py --ip <ip addr> --user root --password <passwd> --groupname testgroup`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\New-McmGroup.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -GroupName TestGroup
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### New Network

#### Available Scripts

- [new_network.py](../Python/new_network.py)

- [New-Network.ps1](../PowerShell/New-Network.ps1)


#### Synopsis
Script to create a new network with VLAN

#### Description
This script uses the OME REST API to create a new network
A network consists of a Minimum and Maximum VLAN ID to create a range
Set Minimum and Maximum to the same value to a single VLAN

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

*Must include header row with at least the rows in the example below
*NetworkType must be an integer value. Use get_network.py --list-networktypes
*For a single VLAN set VlanMinimum=VlanMaximum
For example:
Name,Description,VlanMaximum,VlanMinimum,NetworkType
VLAN 800,Description for VLAN 800,800,800,1

#### Example
`python new_network.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group"`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\New-Network.ps1 -IpAddress 100.79.6.11 -Credentials $cred -ListNetworkTypes
    

    PS C:\>.\New-Network.ps1 -IpAddress 100.79.6.11 -Credentials root -ListNetworkTypes
    

    PS C:\>.\New-Network.ps1 -IpAddress 100.79.6.11 -ListNetworks
    

    PS C:\>.\New-Network.ps1 -IpAddress 100.79.6.11 -ExportExample
    

    PS C:\>.\New-Network.ps1 -IpAddress 100.79.6.11 -InFile "New-NetworkExample.csv"

```


---
### New Ome User

#### Available Scripts

- [New-OmeUser.ps1](../PowerShell/New-OmeUser.ps1)


#### Synopsis
Script to add users to OpenManage Enterprise
#### Description
This script uses the OME REST API to add users to OpenManage Enterprise. 
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.



#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    $newusercred = Get-Credential
    .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -NewUserCredentials $newusercred -NewUserRole ADMIN
    ISTRATOR
    .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -NewUserCredentials $newusercred -NewUserRole ADMIN
    ISTRATOR -NewUserDescription 'This is a description of the user'
    .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -NewUserCredentials $newusercred -NewUserRole ADMIN
    ISTRATOR -NewUserLocked

```


---
### New Static Group

#### Available Scripts

- [new_static_group.py](../Python/new_static_group.py)

- [New-StaticGroup.ps1](../PowerShell/New-StaticGroup.ps1)


#### Synopsis
Script to create a new static group

#### Description
This script uses the OME REST API to create a new static
group. The user is responsible for adding devices to the
group once the group has been successfully created.
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python new_static_group.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group"`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\New-StaticGroup.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -GroupName "Test_OME_Group"
    

    PS C:\>.\New-StaticGroup.ps1 -IpAddress "10.xx.xx.xx" -GroupName "Test_OME" -GroupDescription "This is my group"
    In this instance you will be prompted for credentials to use

```


---
### New Template

#### Available Scripts

- [new_template.py](../Python/new_template.py)


#### Synopsis
Script to manage templates in OpenManage Enterprise

#### Description
This script uses the OME REST API to create a template from file

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
    python new_template.py --ip 192.168.1.93 --password password --template-file gelante.xml
    python new_template.py --ip 192.168.1.93 --password password --template-file gelante.xml --template-name 格蘭特是最好的



---
### Set Power State

#### Available Scripts

- [set_power_state.py](../Python/set_power_state.py)

- [Set-PowerState.ps1](../PowerShell/Set-PowerState.ps1)


#### Synopsis
Script to change the power state of a device, set of devices, and/or group in OME.

#### Description
This script employs the OME REST API to perform power control operations. It accepts idrac IPs, group names, device
names, service tags, or device ids as arguments. It can optionally write the output of the operation to a CSV file.
For authentication X-Auth is used over Basic Authentication. Note that the credentials entered are not stored to disk.

#### Python Example

    python set_power_state.py --ip 192.168.1.93 --password somepass --groupname Test --idrac-ips 192.168.1.45 --state {state} --csv-file test.csv
    python set_power_state.py --ip 192.168.1.93 --password somepass --groupname Test --device-names 格蘭特,192.168.1.63 --state {state}

    where {state} can be "POWER_ON", "POWER_OFF_GRACEFUL", "POWER_CYCLE", "POWER_OFF_NON_GRACEFUL", "MASTER_BUS_RESET"


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Set-PowerState.ps1 -IpAddress 192.168.1.93 -Credentials $creds -IdracIps 192.168.1.63 -State POWER_ON -CsvFile te
    st.csv

```



## Update Scripts
Update scripts include those things for BIOS, firmware, and driver updates.

---
### Invoke Refresh Inventory

#### Available Scripts

- [invoke_refresh_inventory.py](../Python/invoke_refresh_inventory.py)

- [Invoke-RefreshInventory.ps1](../PowerShell/Invoke-RefreshInventory.ps1)


#### Synopsis
Refreshes the inventory on a set of target devices. This includes the configuration inventory tab.

#### Description
This script uses the OME REST API to refresh the inventory of a targeted server. It performs X-Auth
with basic authentication. Note: Credentials are not stored on disk.

#### Python Example
`python invoke_refresh_inventory.py -i 192.168.1.93 -u admin -p somepass --idrac-ips 192.168.1.63,192.168.1.45`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    Invoke-RefreshInventory.ps1 -IpAddress 192.168.1.93 -Credentials $creds -GroupName Test -ServiceTags AAAAAAA

```


---
### Update Firmware Using Catalog

#### Available Scripts

- [update_firmware_using_catalog.py](../Python/update_firmware_using_catalog.py)

- [Update-FirmwareUsingCatalog.ps1](../PowerShell/Update-FirmwareUsingCatalog.ps1)


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


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Update-FirmwareUsingCatalog -IpAddress "10.xx.xx.xx" -Credentials $cred -DeviceId 25234
    .\Update-FirmwareUsingCatalog -IpAddress 192.168.1.93 -Credentials $creds -UpdateActions upgrade -RepoType DELL_ONL
    INE -IdracIps 192.168.1.45
    

    PS C:\>.\Update-FirmwareUsingCatalog -IpAddress "10.xx.xx.xx" -Credentials $cred -GroupName Test
    In this instance you will be prompted for credentials to use to connect to the appliance

```


---
### Update Installed Firmware With Dup

#### Available Scripts

- [update_installed_firmware_with_dup.py](../Python/update_installed_firmware_with_dup.py)

- [Update-InstalledFirmwareWithDup.ps1](../PowerShell/Update-InstalledFirmwareWithDup.ps1)


#### Synopsis
 Script to update firmware for a device or applicable devices
 within a group using a DUP

#### Description
 This script uses the OME REST API to allow updating a device
 or a group of devices by using a single DUP file.

 Note that the credentials entered are not stored to disk.

#### Python Example

    python update_installed_firmware_with_dup.py --ip <ip addr> --user admin
        --password <passwd> --groupid 25315
        --dupfile iDRAC-with-Lifecycle-Controller_Firmware_387FW_WN64_3.21.21.21_A00.EXE

#### API workflow:

1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
   for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
   user name and password entered by user
4. Upload the DUP file to OME and retrieve a file
   token to use in subsequent requests
   POST on UpdateService.UploadFile
5. Determine device or groups that DUP file applies to
   using a POST on UpdateService.GetSingleDupReport
6. Create a firmware update task with the required targets
   using a POST on /api/JobService/Jobs
7. Parse returned job id and monitor it to completion
8. If job fails then GET Job Execution History Details
   and print info to screen


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Update-InstalledFirmware.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -DupFile .\BIOSxxxx.EXE -DeviceId 25234
    

    PS C:\>.\Update-InstalledFirmwareWithDup.ps1 -IpAddress "10.xx.xx.xx" -DupFile .\BIOSxxxx.EXE
    -GroupId 1010
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```



## Monitor Scripts
Monitor scripts include those things for checking alerts, health, performance, power status, and other pre-existing status data.

---
### Get Alerts

#### Available Scripts

- [get_alerts.py](../Python/get_alerts.py)

- [Get-Alerts.ps1](../PowerShell/Get-Alerts.ps1)


#### Synopsis
Retrieves alerts from a target OME Instance.

#### Description
This script provides a large number of ways to get alerts with various filters. With no arguments it will pull all
alerts from the OME instance. The below filters are available:

- top - Pull top records
- skip - Skip N number of records
- orderby - Order by a specific column
- id - Filter by the OME internal event ID
- Alert device ID - Filter by the OME internal ID for the device
- Alert Device Identifier / Service Tag - Filter by the device identifier or service tag of a device
- Device type - Filter by device type (server, chassis, etc)
- Severity type - The severity of the alert - warning, critical, info, etc
- Status type - The status of the device - normal, warning, critical, etc
- Category Name - The type of alert generated. Audit, configuration, storage, system health, etc
- Subcategory ID - Filter by a specific subcategory. The list is long - see the --get-subcategories option for details
- Subcategory name - Same as above except the name of the category instead of the ID
- Message - Filter by the message generated with the alert
- TimeStampBegin - Filter by starting time of alerts with format YYYY-MM-DD HH:MM:SS.SS
- TimeStampEnd - Filter by ending time of alerts with format YYYY-MM-DD HH:MM:SS.SS
- Device name - Filter by a specific device name
- Group name - Filter alerts by a group name
- Group description - Filter alerts by a group description

Authentication is done over x-auth with basic authentication. Note: Credentials are not stored on disk.

#### Python Examples
```
python get_alerts --ip 192.168.1.93 --password somepass --top 1 --skip 5
python get_alerts --ip 192.168.1.93 --password somepass --alerts-by-group-name "Test" --severity-type CRITICAL --top 5
python get_alerts --ip 192.168.1.93 --password somepass --orderby Message --category-name AUDIT --alert-device-type STORAGE
python get_alerts --ip 192.168.1.85 --user admin --password somepass --top 10 --time-stamp-begin "2015-09-07 19:01:28.46"
```


#### PowerShell Example
```
PS C:\>$creds = Get-Credential
    Get-Alerts.ps1 -IpAddress 192.168.1.93 -Credentials $creds -CategoryName SYSTEM_HEALTH -Top 10
    Get-Alerts.ps1 -IpAddress 192.168.1.93 -Credentials $creds -Top 5 -Skip 3 -Orderby TimeStampAscending -StatusType C
    RITICAL
    Get-Alerts.ps1 -IpAddress 192.168.1.85 -Credentials $creds -TimeStampEnd '2021-09-07 19:01:28.46' -TimeStampBegin '
    2015-09-07 19:01:28.46' -CategoryName SYSTEM_HEALTH -Top 10

```


---
### Get Audit Logs

#### Available Scripts

- [get_audit_logs.py](../Python/get_audit_logs.py)

- [Get-AuditLogs.ps1](../PowerShell/Get-AuditLogs.ps1)


#### Synopsis
Retrieves the audit logs from a target OME instance and can either save them in an CSV on a fileshare or
print them to screen.

#### Description
It performs X-Auth with basic authentication. Note: Credentials are not stored on disk.

#### Python Example
`python get_audit_logs.py -i 192.168.1.93 -u admin -p somepass
--share \192.168.1.7\gelante    est.csv --smbuser someuser --smbpass somepass`


#### PowerShell Example
```
PS C:\>$cred1 = Get-Credentials
    $cred2 = Get-Credentials
    python get_audit_logs.py -IpAddress 192.168.1.5 -Credentials $cred1 -Share \\192.168.1.7\gelante -SmbCreds $cred2

```


---
### Get Chassis Inventory

#### Available Scripts

- [get_chassis_inventory.py](../Python/get_chassis_inventory.py)

- [Get-ChassisInventory.ps1](../PowerShell/Get-ChassisInventory.ps1)


#### Synopsis
Script to get chassis inventory details in CSV format

#### Description
This script uses the OME REST API to get chassis inventory
in a CSV format for external consumption
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_chassis_inventory.py -i <ip addr> -u admin -p <password>`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-ChassisInventory.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    

    PS C:\>.\Get-ChassisInventory.ps1 -IpAddress "10.xx.xx.xx"
    In this instance you will be prompted for credentials to use

```


---
### Get Device Inventory

#### Available Scripts

- [get_device_inventory.py](../Python/get_device_inventory.py)

- [Get-DeviceInventory.ps1](../PowerShell/Get-DeviceInventory.ps1)


#### Synopsis
Script to get the device inventory details

#### Description
This script uses the OME REST API to get detailed inventory
for a device given ID/Name/Service Tag
and Inventory type (os,cpus,disks,memory,controllers) of the device
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_device_inventory.py -i <ip addr> -u admin
    -p <password> -fby Name -f "iDRAC-abcdef" -invtype os`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-DeviceInventory.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -InventoryType {InventoryType} -FilterBy Name -DeviceInfo idrac-BZ0M630
     where {InventoryType} can be cpus or memory or controllers or disks or os
    

    PS C:\>.\Get-DeviceInventory.ps1 -IpAddress "10.xx.xx.xx" -InventoryType {InventoryType} -FilterBy SvcTag -DeviceIn
    fo BZ0M630
    where {InventoryType} can be cpus or memory or controllers or disks or os
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### Get Device List

#### Available Scripts

- [get_device_list.py](../Python/get_device_list.py)

- [Get-DeviceList.ps1](../PowerShell/Get-DeviceList.ps1)


#### Synopsis
Script to get the list of devices managed by OM Enterprise

#### Description
This script uses the OME REST API to get a list of devices
currently being managed by that instance. For authentication X-Auth
is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_device_list.py --ip <xx> --user <username> --password <pwd>`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-DeviceList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    .\Get-DeviceList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -OutFormat json
    .\Get-DeviceList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -OutFormat CSV -OutFilePath .\\test.csv

```


---
### Get Firmware Baselines

#### Available Scripts

- [get_firmware_baselines.py](../Python/get_firmware_baselines.py)

- [Get-FirmwareBaselines.ps1](../PowerShell/Get-FirmwareBaselines.ps1)


#### Synopsis
Gets a list of all firmware baselines available from an OME server or baselines associated
with a specific device.

#### Description
This script uses the OME REST API to find baselines associated
with a given server. For authentication X-Auth is used over Basic
Authentication. Note: The credentials entered are not stored to disk.

#### Python Example
`python get_firmware_baseline.py -i 192.168.1.93 -u admin -p somepass -r 192.168.1.45`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    Get-FirmwareBaselines.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -IdracIp 192.168.1.45

```


---
### Get Group By Device

#### Available Scripts

- [get_group_by_device.py](../Python/get_group_by_device.py)


#### Synopsis
Takes as input a device(s) and returns all groups to which that device belongs.

#### Description
This script uses the OME REST API to find all groups to which a device belongs. Note: The credentials entered are not
 stored to disk. Multiple devices can be specified. It will produce output in the following format:

```
-----------------------------
Device 192.168.1.120 belongs to groups:
-----------------------------
Group Name: All Devices        Group ID: 1031
Group Name: Dell iDRAC Servers        Group ID: 1010
Group Name: Servers        Group ID: 1009
Group Name: Some group        Group ID: 14382
Group Name: System Groups        Group ID: 500
Group Name: fx2cmc        Group ID: 14377
```

#### Python Example
    python get_group_by_device.py --ip 192.168.1.85 --user admin --password password --idrac-ip 192.168.1.120
    python get_group_by_device.py --ip 192.168.1.85 --user admin --password password --service-tags AAAAA,BBBBB



---
### Get Group Details

#### Available Scripts

- [get_group_details.py](../Python/get_group_details.py)

- [Get-GroupDetails.ps1](../PowerShell/Get-GroupDetails.ps1)


#### Synopsis
Script to get the details of groups managed by OM Enterprise

#### Description
This script uses the OME REST API to get a group and the
device details for all devices in that group. For authentication
X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_group_details.py --ip <xx> --user <username> --password <pwd>
--groupinfo "All Devices"`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-GroupDetails.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    -GroupInfo "Dell iDRAC server devices"
    

    PS C:\>.\Get-GroupDetails.ps1 -IpAddress "10.xx.xx.xx" -GroupInfo 1008
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### Get Group Details By Filter

#### Available Scripts

- [get_group_details_by_filter.py](../Python/get_group_details_by_filter.py)

- [Get-GroupDetailsByFilter.ps1](../PowerShell/Get-GroupDetailsByFilter.ps1)


#### Synopsis
Script to get the details of groups managed by OM Enterprise
This script uses OData filters for extracting information

#### Description
This script uses the OME REST API to get a group and the
device details for all devices in that group. For authentication
X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_group_details_by_filter.py --ip <xx> --user <username> --password <pwd>
    --filterby Name --field "All Devices"`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-GroupDetailsByFilter.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -FilterBy Description -GroupInfo "Dell iDRAC server devices"
    

    PS C:\>.\Get-GroupDetailsByFilter.ps1 -IpAddress "10.xx.xx.xx" -FilterBy
    Name -GroupInfo "Dell iDRAC Servers"
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### Get Group List

#### Available Scripts

- [get_group_list.py](../Python/get_group_list.py)

- [Get-GroupList.ps1](../PowerShell/Get-GroupList.ps1)


#### Synopsis
Script to get the list of groups managed by OM Enterprise

#### Description
This script uses the OME REST API to get a list of groups
currently being managed by that instance. For authentication X-Auth
is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_group_list.py --ip <xx> --user <username> --password <pwd>`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-GroupList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    

    PS C:\>.\Get-GroupList.ps1 -IpAddress "10.xx.xx.xx"
    In this instance you will be prompted for credentials to use

```


---
### Get Identitypool Usage

#### Available Scripts

- [Get-IdentityPoolUsage.ps1](../PowerShell/Get-IdentityPoolUsage.ps1)


#### Synopsis
Script to get the list of virtual addresses in an Identity Pool
#### Description
This script uses the OME REST API to get a list of virtual addresses in an Identity Pool.
Will export to a CSV file called Get-IdentityPoolUsage.csv in the current directory
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.



#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    

    PS C:\>.\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx"
    In this instance you will be prompted for credentials to use
    

    PS C:\>.\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx" -Id 3
    In this instance you will be prompted for credentials to use
    

    PS C:\>.\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx" -Id 3 -OutFile C:\Temp\export.csv
    In this instance you will be prompted for credentials to use

```


---
### Get Ome Users

#### Available Scripts

- [Get-OmeUsers.ps1](../PowerShell/Get-OmeUsers.ps1)


#### Synopsis
Retrieve a list of users from OME.
#### Description
This script uses the OME REST API to retrieve a list of users from OME.



#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-OmeUsers.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred

```


---
### Get Ome Vlans

#### Available Scripts

- [get_ome_vlans.py](../Python/get_ome_vlans.py)


#### Synopsis
Retrieves data regarding the VLANs on an OME instance.

#### Description
The --out-file argument is optional. If specified output will go to screen and a file. Otherwise it only prints to
screen.

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_ome_vlans.py --ip <xx> --user <username> --password <pwd> --out-file <exported csv file>`



---
### Get Report List

#### Available Scripts

- [get_report_list.py](../Python/get_report_list.py)

- [Get-ReportList.ps1](../PowerShell/Get-ReportList.ps1)


#### Synopsis
Script to get the list of reports defined in OM Enterprise

#### Description
This script uses the OME REST API to get a list of reports
currently defined in that instance. For authentication X-Auth
is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
`python get_report_list.py --ip <xx> --user <username> --password <pwd>`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-ReportList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    

    PS C:\>.\Get-ReportList.ps1 -IpAddress "10.xx.xx.xx"
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### Get Warranty Information

#### Available Scripts

- [get_warranty_information.py](../Python/get_warranty_information.py)

- [Get-WarrantyInformation.ps1](../PowerShell/Get-WarrantyInformation.ps1)


#### Synopsis
Retrieves the warranty information for all devices on an OME instance.

#### Description
You can provide a keyword argument to filter devices by the service description. For example you can specify 'pro'
and that would match a Service Level Description of 'Silver Support or ProSupport'

For authentication X-Auth is used over Basic Authentication Note that the credentials entered are not stored to disk.

#### Example
    python get_warranty_information.py --ip 192.168.1.93 --user admin --password password --warranty-keyword prosupport --out-file <csv_file>


#### PowerShell Example
```
PS C:\>.\Get-WarrantyInformation.ps1' -IpAddress 192.168.1.93 -credentials $creds -outfile test.csv -WarrantyKeywor
    d silver

```


---
### Invoke Report Execution

#### Available Scripts

- [invoke_report_execution.py](../Python/invoke_report_execution.py)

- [Invoke-ReportExecution.ps1](../PowerShell/Invoke-ReportExecution.ps1)


#### Synopsis
Allow execution of a pre-defined report in OME
and print out report results to screen

#### Description
Allow execution of a pre-defined report including custom
reports in OpenManage Enterprise.
Output results are presented in a csv format to collate
column names with the results

Note: The group id argument is optional and is unused
in the report execution API at this time.

#### API Workflow
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
user name and password entered by user
4. POST on ReportService.RunReport method
Parameters are the ID of the report to run
5. if method execution is successful returned
response presents a job id to track status
6. GET on JobService/Jobs(<jobid>) and poll
returned job status until completion
7. On success GET on ReportService/ReportDefs(ID)
to determine column names for the report
8. Extract report results (GET) at /ReportResults/ResultRows
and print out results

#### Python Example
`python .\invoke_report_execution.py  --ip <ip addr> --user <username>
    --password <password> --reportid 10051`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -ReportId 10043 -OutputFilePath test.csv
    

    PS C:\>.\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -ReportName SomeReport
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```



## Maintenance Scripts
Maintenance scripts include those things for reprovisioning, remediation, and general upkeep of devices.

---
### Invoke Retire Lead

#### Available Scripts

- [invoke_retire_lead.py](../Python/invoke_retire_lead.py)

- [Invoke-RetireLead.ps1](../PowerShell/Invoke-RetireLead.ps1)


#### Synopsis
Script to retire lead of MCM group and promote the exising backup lead as lead

#### Description:
This script retires the current lead and the backup lead gets promoted as the new lead

#### Python Example
`python invoke_retire_lead.py --ip <lead ip> --user <username> --password <password>`

Note:
1. Credentials entered are not stored to disk.

#### API Workflow
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers
    for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not
    user name and password entered by user
4. Retire lead and promote backup lead as the new lead
    with POST on /ManagementDomainService/Actions/ManagementDomainService.RetireLead
5. Parse returned job id and monitor it to completion


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Invoke-RetireLead.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### Set Scale Vlan Profile

#### Available Scripts

- [Set-ScaleVlanProfile.ps1](../PowerShell/Set-ScaleVlanProfile.ps1)


#### Synopsis
Script to set the ScaleVlanProfile property for a fabric
#### Description
Script allows enumeration of all fabrics on the given system and 
allows the user to select a fabric on which the ScaleVlanProfile
property can be changed to the input value (Enabled / Disabled)



#### PowerShell Example
```
PS C:\>$credentials = Get-Credentials
    Set-ScaleVlanProfile.ps1 -IpAddress 100.200.100.101 -Credentials $cred -ProfileState Enabled

```



## SupportAssist Enterprise OME Plugin Scripts
[SupportAssist Enterprise](https://www.delltechnologies.com/en-us/services/support-deployment-technologies/support-assist-enterprise.htm#accordion0) is a product for managing the lifecycle of your servers and any cases you open against them. Some features it includes:
- Configurable to automatically open cases when issues arise
- Case tracking from beginning to end
- Automatic creation of SupportAssist packages for cases so that you no longer have to manually retrieve logs on support's behalf.
- Automation of parts dispatch information
- SupportAssist site health monitoring

---
### Get Supportassist Cases

#### Available Scripts

- [get_supportassist_cases.py](../Python/get_supportassist_cases.py)

- [Get-SupportassistCases.ps1](../PowerShell/Get-SupportassistCases.ps1)


#### Synopsis
Retrieves the case data from the SupportAssist Enterprise (SAE) Plugin on OME

#### Description
The --out-file argument is optional. If specified the output will go to a CSV file. Otherwise it prints to screen.

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
    python get_supportassist_cases.py --ip <xx> --user <username> --password <pwd> --out-file <some csv file>


#### PowerShell Example
```
PS C:\>.\Get-SupportassistCases.ps1' -credentials $creds -outfile test.csv -ipaddress 192.168.1.93

```


---
### Invoke Manage Supportassist Groups

#### Available Scripts

- [invoke_manage_supportassist_groups.py](../Python/invoke_manage_supportassist_groups.py)

- [Invoke-ManageSupportAssistGroups.ps1](../PowerShell/Invoke-ManageSupportAssistGroups.ps1)


#### Synopsis
Performs management tasks of OME SupportAssist Enterprise (SAE) groups including creating new groups, adding devices,
removing devices, and deleting groups.

#### Description

**Python Version**

Creation of groups is managed from a YML file with the argument --add-group. You can create the YML file automatically
 using the --generate-yaml <FILENAME> argument following by --add-group <FILENAME>. You can also manually complete the
yaml file by copying and pasting the below into <YOURFILE>.yml:

    ---
    Id: 0
    Name: "Your Group"
    Description: "This is a test group for supportassist enterprise"
    ContactOptIn: True
    DispatchOptIn: True
    MyAccountId: 
    CustomerDetails:
      PrimaryContact:
        FirstName: "Gelante"
        LastName: "Woxihuanxueyuyan"
        Email: "gelante@dell.com"
        Phone: "8888888888"
        AlternatePhone:
        TimeFrame: "10:00 AM-4:00 PM" # The spacing and caps do matter.
        TimeZone: "TZ_ID_71"  # This is an ID for the timezone from OME. You have to use the /api/ApplicationService/Network/TimeZones API endpoint to get it.
        ContactMethod: "phone"
      SecondaryContact:
        FirstName: "Anjila"
        LastName: "Zheshiwotaitai"
        Email: "gelante@daier.com"
        Phone: "9999999999"
        AlternatePhone:
        TimeFrame: "10:00 AM-4:00 PM"
        TimeZone: "TZ_ID_71"
        ContactMethod: "phone"
      ShippingDetails:
        PrimaryContact:
          FirstName: "Wojiarbob"
          LastName: "Nolose"
          Email: "gengduojiademingze@judadaier.com"
          Phone: "1111111111"
          AlternatePhone:
        SecondaryContact:
          FirstName: "Wotaoyan"
          LastName: "Woxuyaozuodepeixun"
          Email: "wobuguanxipeixun@gmail.com"
          Phone: "9999999999"
          AlternatePhone:
        Country: "US"
        State: "Ohio"
        City: "Centerville"
        Zip: "44444"
        Cnpj:
        Ie:
        AddressLine1: 109 Español Way
        AddressLine2: San Antonio TX
        AddressLine3: 78211
        AddressLine4:
        PreferredContactTimeZone: "TZ_ID_71"
        PreferredContactTimeFrame: "10:00 AM-4:00 PM"
        TechnicianRequired: False
        DispatchNotes: "我现在写程序但是我需要做培训。我偏好写程序."

You will need to replace all the fields with your information. This is the same as the file generated by
--generate-yaml except you will have to account for making sure it is valid yourself. This is ultimately converted to
 JSON so you could also write your own input mechanism.

**PowerShell Version**

Creation of groups is managed from a JSON file with the argument -AddGroup. You can create the JSON file automatically using the
-GenerateJson <FILENAME> argument following by -AddGroup <FILENAME>. You can also manually complete the JSON file by copying
and pasting the below into <YOURFILE>.json:

    {
      "MyAccountId": 9999999,
      "Description": "Test group from me",
      "Name": "Test Group 2",
      "DispatchOptIn": true,
      "CustomerDetails": {
        "ShippingDetails": {
          "AddressLine1": "109 Gelante Way",
          "TechnicianRequired": true,
          "PrimaryContact": {
            "LastName": "Curell",
            "Phone": "1111111111",
            "AlternatePhone": "",
            "FirstName": "Grant",
            "Email": "grant_curell@meiguo.com"
          },
          "AddressLine4": "",
          "City": "Dayton",
          "Country": "US",
          "DispatchNotes": "No",
          "State": "Ohio",
          "SecondaryContact": {
            "LastName": "Curell",
            "Phone": "9999999999",
            "AlternatePhone": "",
            "FirstName": "Angela",
            "Email": "grantcurell@wojia.com"
          },
          "Cnpj": null,
          "AddressLine3": "78210",
          "PreferredContactTimeFrame": "10:00 AM-4:00 PM",
          "Zip": "45459",
          "Ie": null,
          "PreferredContactTimeZone": "TZ_ID_65",
          "AddressLine2": "San Antonio TX"
        },
        "PrimaryContact": {
          "LastName": "Curell",
          "TimeZone": "TZ_ID_10",
          "AlternatePhone": "",
          "ContactMethod": "phone",
          "TimeFrame": "10:00 AM-4:00 PM",
          "FirstName": "Grant",
          "Phone": "8888888888",
          "Email": "daiershizuihaode@dell.com"
        },
        "SecondaryContact": {
          "LastName": "Curell",
          "TimeZone": "TZ_ID_71",
          "AlternatePhone": "",
          "ContactMethod": "phone",
          "TimeFrame": "10:00 AM-4:00 PM",
          "FirstName": "Angela",
          "Phone": "9999999999",
          "Email": "grantcurell@zheshiwotaitai.com"
        }
      },
      "ContactOptIn": true
    }

You will need to replace all the fields with your information. This is the same as the file generated by -GenerateJSON except you will have to
account for making sure it is valid yourself. This is ultimately converted to JSON so you could also write your own input mechanism.

#### Python Example
    python invoke_manage_supportassist_groups.py --ip 192.168.1.93 --user admin --password <password> --add-group "Gelante Group"
    python invoke_manage_supportassist_groups.py --ip 192.168.1.93 --user admin --password <password> --add-devices "Test Group" --idrac-ips 192.168.1.63
    python invoke_manage_supportassist_groups.py --ip 192.168.1.93 --user admin --password <password> --remove-devices "Test Group" --idrac-ips 192.168.1.63
    python invoke_manage_supportassist_groups.py --ip 192.168.1.93 --user admin --password <password> --remove-group "Test Group 2"


#### PowerShell Example
```
PS C:\>$creds = Get-Credential # Your OME credentials
    $servcreds = Get-Credential # Your OME credentials
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -GenerateJson test.json
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -AddGroup test.json
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -AddDevices 'Test Group 2' -Serv
    iceTag CEAOEU
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -RemoveDevices 'Test Group 2' -S
    erviceTag CEAOEU
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -RemoveGroup 'Test Group 2'

```



## OME Power Manager Plugin Scripts
[Dell Power Manager](https://www.dell.com/support/manuals/en-us/openmanage-enterprise-power-manager/pmp_1.2_ug/introduction-to-power-manager)
 is a plugin for OME which allows fine grained tracking and control of device power consumption including
per device utilization and anomalous behavior. Power Manager alerts and reports about power and thermal events in servers,
 chassis, and custom groups consisting of servers and chassis.

**Script Use Cases**
- Alerts & Reports
	Scripts for Power Manager specific Alerts & Reports use cases
- Devices & Monitoring List
	Scripts for finding Power Manager capable devices & monitoring list action use cases
- Import Physical Hierarchy
	Script for importing Physical Group and Device Association from a CSV file
- Metrics & Monitoring
	Scripts for Power Manager specific metrics & monitoring use cases
- Misc Scripts
	Scripts for Power Manager specific some miscellaneous feature use cases
- Policy & EPR
	Scripts for Power Manager specific Policy & EPR use cases

---
### Find Non Pmp Capable Devices

#### Available Scripts

- [Find-NonPmpCapableDevices.ps1](../PowerShell/Find-NonPmpCapableDevices.ps1)

- [find_non_pmp_capable_devices.py](../Python/find_non_pmp_capable_devices.py)


#### Synopsis
Script to Find devices which are not capable for power policy, 
including servers which are not capable for power monitoring too.

#### Description
This script gets all devices where a power policy cannot be applied 
from power manager.

Note:
1. Credentials entered are not stored to disk.
2. For a large number of devices ,time taken for script to finish might increase ,also depending on network speed. (upto 6-7 minutes for 8000 devices at 100Mbps network )
3. This script doesn't need OMEnt-Power manager to be already installed on the OMEnt and works with or without OMEnt-Power manager
4: User executing the script should have privilege to cerate a new file in the path where script is located.

Finds all non-policy power capable devices

API workflow is below:
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not user name and password entered by user
4. From All devices list fetch for the servers not having 1006 (monitoring capability) devicecapability bit set.
5. For Chassis type devices do not check anything as chassis are always monitoring and do not have 1006 in device capabilities
5. Print all such devices(deviceId and ServiceTag) into a csv file Non_compatible_devices.csv

#### Python Example
    python find_non_pmp_capable_devices.py --ip <ip addr> --user root --password <passwd>


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Find-NonPmpCapableDevices.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    

    PS C:\>.\Find-NonPmpCapableDevices.ps1 -IpAddress "10.xx.xx.xx"
    In this instance you will be prompted for credentials to use
    

    PS C:\>To save the device Ids to a file(file_name.txt) give the command in following format
    .\Find-NonPmpCapableDevices.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred >file_name.txt

```


---
### Find Non Power Policy Capable Devices

#### Available Scripts

- [Find-NonPowerPolicyCapableDevices.ps1](../PowerShell/Find-NonPowerPolicyCapableDevices.ps1)

- [find_non_power_policy_capable_devices.py](../Python/find_non_power_policy_capable_devices.py)


#### Synopsis
Script to Find devices which are not capable for power policy, 
including servers which are not capable for power monitoring too.

#### Description
This script gets all devices where a power policy cannot be applied from power manager.

Note:
1. Credentials entered are not stored to disk.
2. For a large number of devices ,time taken for script to finish might increase ,also depending on network speed. (upto 6-7 minutes for 8000 devices at 100Mbps network )
3. This script doesn't need OMEnt-Power manager to be already installed on the OMEnt and works with or without OMEnt-Power manager
4:User executing the script should have privilege to cerate a new file in the path where script is located.

API workflow is below:
1. POST on SessionService/Sessions
2. If new session is created (201) parse headers for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not user name and password entered by user
4. From All devices list fetch for the servers not having both 1105(policy capability) and 1006 (monitoring capability)  devicecapability bit set.
5. For Chassis type devices check for only 1105 bit as chassis are always monitoring capable and do not have 1006 in devicecapabilities
5. Print all such devices(deviceId and ServiceTag) into a csv file Non_compatible_policy_devices.csv

#### Python Example
    Finds all non-policy power capable  devices
    python find_non_power_policy_capable_devices.py --ip <ip addr> --user root --password <passwd>


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Find-NonPowerPolicyCapableDevices.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    

    PS C:\>.\Find-NonPowerPolicyCapableDevices.ps1 -IpAddress "10.xx.xx.xx"
    In this instance you will be prompted for credentials to use
    

    PS C:\>To save the device Ids to a file(file_name.txt) give the command in following format
    .\Find-NonPowerPolicyCapableDevices.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred >file_name.txt

```


---
### Get Power Manager Alerts

#### Available Scripts

- [get_power_manager_alerts.py](../Python/get_power_manager_alerts.py)


#### Synopsis
Script to get the list of Power Manager Specific Alerts in OpenManage Enterprise

#### Description
This script exercises the OpenManage Enterprise REST API to get the list of Power Manager specific alerts
- For authentication, X-Auth is used over Basic Authentication
- Note that the credentials entered are not stored to disk.

#### Python Example
    python get_power_manager_alerts.py --ip <xx> --username <username> --password <pwd>

    Output:

    =======================================
      Power Manager - Metrics - Alerts
    =======================================

    SEVERITY  SOURCE_NAME      TIME                     CATEGORY       SUB_CATEGORY  MESSAGE_ID  MESSAGE

    Warning   linux-0j8n       2020-03-20 16:31:20.484  System Health  Metrics       CMET0004    POWER on Group_R740s has exceeded its threshold.
    Critical  linux-0j8n       2020-03-20 16:16:21.252  System Health  Metrics       CMET0008    TEMPERATURE on Group_R740s has exceeded its lower threshold.

    ========================================================
      Power Manager - Power Configuration - Alerts
    ========================================================

    SEVERITY  SOURCE_NAME      TIME                     CATEGORY       SUB_CATEGORY         MESSAGE_ID  MESSAGE

    Normal    linux-0j8n       2020-01-23 13:30:00.399  System Health  Power Configuration  CPWR0014    Violation of power policy Policy_on_R740s on group Group_R740s got rectified.
    Critical  linux-0j8n       2020-01-23 12:30:00.417  System Health  Power Configuration  CPWR0013    Power policy Policy_on_R740s on group Group_R740s got violated.



---
### Get Power Manager Capable Devices

#### Available Scripts

- [get_power_manager_capable_devices.py](../Python/get_power_manager_capable_devices.py)


#### Synopsis
   Script to get the list of devices from OpenManage Enterprise which are capable to be monitored/managed by Power Manager

#### Description
   This script exercises the OpenManage Enterprise REST API to get a list of devices currently being managed by OpenManage Enterprise & capable to be monitored/managed by Power Manager.
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

#### Python Example
    python Get_Power_Manager_Capable_Devices.py --ip <xx> --username <username> --password <pwd>
   
    Output:
    
       =====================================================
          Devices List with Power Manager capablilities
       =====================================================

      DEVICE_ID  SERVICE_TAG  MODEL            DEVICE_NAME              POWER_MANAGER_CAPABILITY

      10113      XXXXXXX      PowerEdge R640   WIN2K12356.BLR.net       Monitor + Management
      10106      XXXXXXX      PowerEdge R640   WINDOWS2019.BLR.net      Monitor only
      10105      XXXXXXX      PowerEdge R640   WINHIRTK12.BLR.net       Monitor + Management
      10111      XXXXXXX      PowerEdge R640   WINKKLLLL.BLR.net        Monitor only
      10109      XXXXXXX      PowerEdge R640   WIN2019SCALAB.BLR.net    Monitor + Management



---
### Get Power Manager Device Metrics

#### Available Scripts

- [get_power_manager_device_metrics.py](../Python/get_power_manager_device_metrics.py)


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



---
### Get Power Manager Epr

#### Available Scripts

- [get_power_manager_epr.py](../Python/get_power_manager_epr.py)


#### Synopsis
   Script to get Power Manager EPR applied for either Devices/Groups with optional filters

#### Descriptiontion
   This script exercises the Power Manager REST API to get Emergency Power Reductions policy enabled for devices or groups.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

#### Python Example

    python get_power_manager_epr.py --ip <xx> --username <username> --password <pwd> --filterBy <filter_name> --filterValue <filter_value>

    Output:

    ================================================
        Power Manager Emergency Reduction Policy
    ================================================

    EPR_POLICY_ID  EPR_TYPE  IS_EPR_POWERDOWN/THROTTLE?  EPR_ENABLED?  EPR_EXECUTION_STATE  IS_EPR_ON_GROUP/DEVICE?  GROUP/DEVICE_ASSIGNED_TO  CREATED_TIME

    13             MANUAL    Throttle                    True          SUCCESS              Device                   6W92WV2                   2020-03-22 15:14:15.111016



---
### Get Power Manager Group Metrics

#### Available Scripts

- [get_power_manager_group_metrics.py](../Python/get_power_manager_group_metrics.py)


#### Synopsis
   Script to get different Power Manager Metrics for groups which are being monitored by Power Manager

#### Description
   This script exercises the OpenManage Enterprise REST API to get different Power Manager Metrics for groups at different time duration which are being monitored by Power Manager.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.
    - Use "get_power_manager_monitoring_list.py" to get group ID

#### Python Example
    python get_power_manager_group_metrics.py --ip <xx> --username <username> --password <pwd> --groupID <ID of a Group> --metricType <Metric Supported> --duration <Duration> --sort <Sort Order>

    Output:

        ==========================================================================================
              Power Manager Metrics for group ID -> 10313 collected in Six_hours time window
        ==========================================================================================

            METRIC_TYPE                       METRIC_VALUE  COLLECTED_AT

            Maximum_system_power_consumption  136.0         2020-03-22 06:45:28.891437
            Minimum_system_power_consumption  133.0         2020-03-22 06:45:28.891437
            Average_system_power_consumption  133.0         2020-03-22 06:45:28.891437
            Maximum_system_power_consumption  136.0         2020-03-22 07:00:18.443143



---
### Get Power Manager Monitoring List

#### Available Scripts

- [get_power_manager_monitoring_list.py](../Python/get_power_manager_monitoring_list.py)


#### Synopsis
   Script to get devices or groups being monitored by Power Manager.

#### Description
   This script exercises the Power Manager REST API to get devices or groups that being monitored by Power Manager.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

#### Python Example
    python get_power_manager_monitoring_list.py --ip <xx> --username <username> --password <pwd>

    Output:

        ==============================================
            Devices being Monitored by Power Manager
        ==============================================

        DEVICE_ID  DEVICE_NAME              SERVICETAG  MODEL            IS_PART_OF_GROUP?  IS_POWER_POLICY_CAPABLE?

        10103      WINDOWS2012.BLR.net      XXXXXXX     PowerEdge R640   True               False
        10104      WINDWIW.BLR.net          YYYYYYY     PowerEdge R640   True               True

        ==============================================
            Groups being Monitored by Power Manager
        ==============================================

        GROUP_TYPE      GROUP_ID  GROUP_PARENT_ID  GROUP_NAME        DEVICES_IN_WORKING_SET

        PHYSICAL_GROUP  10489     10488            AISLE2            3
        STATIC_GROUP    10116     1021             G1_PMP1.0         5



---
### Get Power Manager Policies

#### Available Scripts

- [get_power_manager_policies.py](../Python/get_power_manager_policies.py)


#### Synopsis
   Script to get Power Manager policies created for either Devices/Groups with optional filters

#### Description
   This script exercises the Power Manager REST API to get different Power Manager Polcies created on devices or groups.
    - For authentication X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

#### Python Example
    python get_power_manager_policies.py --ip <xx> --username <username> --password <pwd> --filterBy <filter_name> --filterValue <filter_value>

    Output:

        ==================================
            Power Manager Policies
        ==================================

        POLICY_ID  POLICY_NAME                       POLICY_TYPE            POLICY_ENABLED  POLICY_EXECUTION_STATE  IS_POLICY_ON_GROUP/DEVICE?  GROUP/DEVICE_ASSIGNED_TO  CREATED_TIME

        9          Temperature Triggered for groups  TEMPERATURE-TRIGGERED  True            NOSTATE                 Group                       G1_PMP1.0                 2020-03-22 13:00:30.520681
        6          Policy3                           STATIC                 True            NOSTATE                 Device                      47XGH32                   2020-03-18 11:17:44.340717
        5          Policy2                           STATIC                 True            SUCCESS                 Device                      47XGH32                   2020-03-18 11:09:29.710303
        4          Policy1                           STATIC                 True            SUCCESS                 Device                      47XGH32                   2020-03-18 11:02:20.585298
    



---
### Get Power Manager Reports

#### Available Scripts

- [get_power_manager_reports.py](../Python/get_power_manager_reports.py)


#### Synopsis
   Script to get the list of Power Manager Specific Device and Group Reports (Pre-Canned & Custom) in OpenManage Enterprise

#### Description
This script exercises the OpenManage Enterprise REST API to get the list of Power Manager Device and Group Reports
- For authentication, X-Auth is used over Basic Authentication
- Note that the credentials entered are not stored to disk.

#### Python Example
    python get_power_manager_reports.py --ip <xx> --username <username> --password <pwd>

    Output:

        =====================================
            Power Manager Device Reports
        =====================================

        REPORT_ID  REPORT_NAME                                          IS_PRE-CANNED_OR_CUSTOM?  LAST_EDITED_BY  LAST_RUN_BY  LAST_RUN_DURATION  LAST_RUN_DATE

        10287      DeviceWSnNotWS                                       Custom                    None            admin        0.78               2020-03-18 09:49:14.739
        2000       Power Manager: Metric Thresholds Report for Device  Pre-Canned                None            admin        3.68               2020-03-18 08:03:34.282
        2002       Power Manager: Power and Thermal Report of Device   Pre-Canned                None            admin        5.39               2020-03-18 08:04:14.099


        =====================================
            Power Manager Group Reports
        =====================================

        REPORT_ID  REPORT_NAME                                               IS_PRE-CANNED_OR_CUSTOM?  LAST_EDITED_BY  LAST_RUN_BY  LAST_RUN_DURATION  LAST_RUN_DATE

        10281      GroupThermal                                              Custom                    None            admin        3.56               2020-03-18 08:02:12.003
        2001       Power Manager: Metric Thresholds Report for Group        Pre-Canned                None            None         None               None



---
### Get Power Manager Top Energy Consumers

#### Available Scripts

- [get_power_manager_top_energy_consumers.py](../Python/get_power_manager_top_energy_consumers.py)


#### Synopsis
   Script to get the list of top 5 energy consuming (KWH) Server/Chassis/Group being monitored by Power Manager

#### Description
   This script exercises the OpenManage Enterprise REST API to get the list of top 5 energy consuming Server/Chassis/Group (in KWH) being monitored by Power Manager
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

#### Python Example
    python get_power_manager_top_energy_consumers.py --ip <xx> --username <username> --password <pwd>



---
### Get Power Manager Top Offenders

#### Available Scripts

- [get_power_manager_top_offeners.py](../Python/get_power_manager_top_offeners.py)


#### Synopsis
   Script to get the list of top power and temperature offenders (Device or Group which violated the respective threshold)

#### Description
   This script exercises the OpenManage Enterprise REST API to get the list of top power and temperature offenders (Device or Group which violated the respective threshold)
    - For authentication, X-Auth is used over Basic Authentication
    - Note that the credentials entered are not stored to disk.

#### Python Example
    python get_power_manager_top_offenders.py --ip <xx> --username <username> --password <pwd>



---
### Get Set Power Manager Setting

#### Available Scripts

- [get_set_power_manager_setting.py](../Python/get_set_power_manager_setting.py)


#### Synopsis
   Script to get or set Power Manager Settings applied on OpenManage Enterprise 

#### Description
This script exercises the Power Manager REST API to get & set Power Manager Settings.
- For authentication X-Auth is used over Basic Authentication
- Note that the credentials entered are not stored to disk.

#### Python Example
    python get_set_power_manager_settings.py --ip <xx> --username <username> --password <pwd>



---
### Invoke Refresh Power Manager Inventory

#### Available Scripts

- [invoke_refresh_power_manager_inventory.py](../Python/invoke_refresh_power_manager_inventory.py)

- [Invoke-RefreshPowerManagerInventory.ps1](../PowerShell/Invoke-RefreshPowerManagerInventory.ps1)


#### Synopsis
Script to perform refresh inventory for all devices to detect power 
monitoring capability after Power manager Installation.

#### Description
This script fetches the jobID for default inventory refresh and runs
the job until completion, checking every 10 seconds.

Note:
1. Credentials entered are not stored to disk.

Fetches jobID for default inventory task from OMEnt , and runs the job

API workflow is below:

1. POST on SessionService/Sessions
2. If new session is created (201) parse headers for x-auth token and update headers with token
3. All subsequent requests use X-auth token and not user name and password entered by user
4. Find the jobID of default inventory task from all jobs with GET on /JobService/Jobs
5. Parse returned job id to /JobService/Actions/JobService.RunJobs and monitor it to completion, waiting every 10 seconds

#### Python Example
    python invoke_refresh_power_manager_inventory.py --ip <ip addr> --user root --password <passwd> --groupname testgroup


#### PowerShell Example
```
PS C:\>$creds = Get-Credentials
    .\Invoke-RefreshPowerManagerInventory.ps1 -IpAddress 192.168.1.93 -Credentials $creds

```


---
### New Power Manager Physical Group

#### Available Scripts

- [new_power_manager_physical_group.py](../Python/new_power_manager_physical_group.py)


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


