# API Documentation

This repository is composed of two principal portions - OpenManage Enterprise (OME) API usage examples and plugins.

API usage examples are stored in Core/PowerShell and Core/Python for PowerShell and Python examples respectively.
Parity is generally maintained between PowerShell and Python examples. Available scripts are listed for each functionality
shown below. 

You can find a current copy of the OME API documentation [here](https://dl.dell.com/topicspdf/dell-openmanage-enterprise_Reference-Guide2_en-us.pdf).

## Table of Contents
<div class="toc">
<ul>
<li><a href="#deploy-scripts">Deploy Scripts</a></li>
<ul>

<li><a href="#add-device-to-static-group">Add Device To Static Group</a></li>

<li><a href="#add-members">Add Members</a></li>

<li><a href="#edit-discovery-job">Edit Discovery Job</a></li>

<li><a href="#invoke-discover-device">Invoke Discover Device</a></li>

<li><a href="#invoke-manage-query-groups">Invoke Manage Query Groups</a></li>

<li><a href="#new-mcm-group">New Mcm Group</a></li>

<li><a href="#new-network">New Network</a></li>

<li><a href="#new-static-group">New Static Group</a></li>

<li><a href="#set-power-state">Set Power State</a></li>

<li><a href="#set-system-configuration">Set System Configuration</a></li>

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

<li><a href="#get-group-details">Get Group Details</a></li>

<li><a href="#get-group-details-by-filter">Get Group Details By Filter</a></li>

<li><a href="#get-group-list">Get Group List</a></li>

<li><a href="#get-identitypool-usage">Get Identitypool Usage</a></li>

<li><a href="#get-report-list">Get Report List</a></li>

<li><a href="#invoke-report-execution">Invoke Report Execution</a></li>

</ul>
<li><a href="#maintenance-scripts">Maintenance Scripts</a></li>
<ul>

<li><a href="#invoke-retire-lead">Invoke Retire Lead</a></li>

<li><a href="#set-scale-vlan-profile">Set Scale Vlan Profile</a></li>

</ul>
</ul>
</div>

## Deploy Scripts
Deploy scripts include those things for discovery and generating the initial inventory, configuration, and os deployment.

---
### Add Device To Static Group

#### Available Scripts

- [add_device_to_static_group.py](../Core/Python/add_device_to_static_group.py)

- [Add-DeviceToStaticGroup.ps1](../Core/PowerShell/Add-DeviceToStaticGroup.ps1)


#### Synopsis
Add one or more hosts to an existing static group.

#### Description
This script uses the OME REST API to add one or more hosts to an existing static group. You can provide specific
 devices or you can provide the job ID for a previous discovery job containing a set of servers. The script will pull
 from the discovery job and add those servers to a gorup. For authentication X-Auth is used over Basic Authentication.
Note: The credentials entered are not stored to disk.

#### Python Example
    ```
    python add_device_to_static_group.py --idrac-ips 192.168.1.45,192.168.1.63 --groupname 格蘭特 --password somepass --ip 192.168.1.93 --use-discovery-job-id 14028
    python add_device_to_static_group.py --service-tags servtag1,servtag2,servtag3 --groupname 格蘭特 --password somepass --ip 192.168.1.93
    ```


#### PowerShell Example
```
PS C:\>$creds = Get-Credentials
    .\Add-DeviceToStaticGroup.ps1' -IpAddress 192.168.1.93 -Credentials $creds -GroupName 'YourGroup' -IdracIps 
    '192.168.1.45,192.168.1.63' -UseDiscoveryJobId 14094

```


---
### Add Members

#### Available Scripts

- [add_members.py](../Core/Python/add_members.py)

- [Add-Members.ps1](../Core/PowerShell/Add-Members.ps1)


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
PS C:\>$cred = Get-Credential
    .\Create-McmGroup.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### Edit Discovery Job

#### Available Scripts

- [edit_discovery_job.py](../Core/Python/edit_discovery_job.py)

- [Edit-DiscoveryJob.ps1](../Core/PowerShell/Edit-DiscoveryJob.ps1)


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
    .\Edit-DiscoveryJob --IpAddress "10.xx.xx.xx" -Credentials $cred -JobNamePattern "Discovery_Essentials_IP" 
    -DeviceUserName "root" -DevicePassword "test12" -IpArray 10.xx.xx.xx,10.xx.xx.xx

```


---
### Invoke Discover Device

#### Available Scripts

- [invoke_discover_device.py](../Core/Python/invoke_discover_device.py)

- [Invoke-DiscoverDevice.ps1](../Core/PowerShell/Invoke-DiscoverDevice.ps1)


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
    .\Invoke-DiscoverDevice -IpAddress 192.168.1.93 -Credentials $creds -ServerIps 192.168.1.63-192.168.1.65 
    -ServerCredentials $servcreds -GroupName TestGroup -JobCheckSleepInterval 10 -ServerCsv Book1.csv,'IP address' 
    -ChassisCsv Book1.csv,'ChassisIp' -ChassisCredentials $chassiscreds
    

    PS C:\>.\Invoke-DiscoverDevice -IpAddress 192.168.1.93 -Credentials $creds -NetworkDeviceIps 
    192.168.1.24,192.168.1.34 -SnmpCommunityString 'SomeString'

```


---
### Invoke Manage Query Groups

#### Available Scripts

- [invoke_manage_query_groups.py](../Core/Python/invoke_manage_query_groups.py)


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

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --create y --groupname "Grant Group" --description "query created using python OME script" --fid 238 --comparison-values 151 --oid 1
Create a group called Grant Group which looks for devices equal to (1) sub-type (238) compellent storage (151)

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --fid 231,229 --oid 1,1 --comparison-fields AAAAAAA,1000 --loid 2,2 --create "Service Tag or Normal Status"
Create a group called "Service Tag or Normal Status" which looks for service tags (231) equal to (1) AAAAAAA or (2) device with status (229) equal to (1) normal status (1000)

invoke_manage_query_groups.py --ip 192.168.0.120 -u admin -p admin --delete "Some Group"
Deletes a group with the name "Some Group"
```



---
### New Mcm Group

#### Available Scripts

- [new_mcm_group.py](../Core/Python/new_mcm_group.py)

- [New-McmGroup.ps1](../Core/PowerShell/New-McmGroup.ps1)


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

- [new_network.py](../Core/Python/new_network.py)

- [New-Network.ps1](../Core/PowerShell/New-Network.ps1)


#### Synopsis
Script to create a new network with VLAN

#### Description
This script uses the OME REST API to create a new network
A network consists of a Minimum and Maximum VLAN ID to create a range
Set Minimum and Maximum to the same value to a single VLAN

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
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
### New Static Group

#### Available Scripts

- [new_static_group.py](../Core/Python/new_static_group.py)

- [New-StaticGroup.ps1](../Core/PowerShell/New-StaticGroup.ps1)


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
### Set Power State

#### Available Scripts

- [set_power_state.py](../Core/Python/set_power_state.py)

- [Set-PowerState.ps1](../Core/PowerShell/Set-PowerState.ps1)


#### Synopsis
Script to change the power state of a device, set of devices, and/or group in OME.

#### Description
This script employs the OME REST API to perform power control operations. It accepts idrac IPs, group names, device
names, service tags, or device ids as arguments. It can optionally write the output of the operation to a CSV file.
For authentication X-Auth is used over Basic Authentication. Note that the credentials entered are not stored to disk.

#### Python Example
'''
python set_power_state.py --ip 192.168.1.93 --password somepass --groupname Test --idrac-ips 192.168.1.45 --state {state} --csv-file test.csv
python set_power_state.py --ip 192.168.1.93 --password somepass --groupname Test --device-names 格蘭特,192.168.1.63 --state {state}
'''
where {state} can be "POWER_ON", "POWER_OFF_GRACEFUL", "POWER_CYCLE", "POWER_OFF_NON_GRACEFUL", "MASTER_BUS_RESET"


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Set-PowerState.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -DeviceId 25527  -State {state}
     where {state} can be on/off/warm boot/cold boot/shutdown

```


---
### Set System Configuration

#### Available Scripts

- [set_system_configuration.py](../Core/Python/set_system_configuration.py)

- [Set-SystemConfiguration.ps1](../Core/PowerShell/Set-SystemConfiguration.ps1)


#### Synopsis
Script to perform template deployment on the target devices.

#### Description:
This script performs template deployment. Note that the credentials entered are not stored to disk.

#### Python Example
`python set_system_configuration.py --ip <ip addr> --user admin
    --password <passwd> --sourceid <10089> --targetid/--groupid <10081>`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Get-Templates.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -SourceId 25527 -TargetId 10782 -Component iDRAC
     In this instance you will be prompted for credentials.
    

    PS C:\>$cred = Get-Credential
    .\Get-Templates.ps1 -IpAddress "10.xx.xx.xx" -Credentials
     $cred -SourceId 25527 -GroupId 1010 -Component iDRAC
     In this instance you will be prompted for credentials.

```



## Update Scripts
Update scripts include those things for BIOS, firmware, and driver updates.

---
### Invoke Refresh Inventory

#### Available Scripts

- [invoke_refresh_inventory.py](../Core/Python/invoke_refresh_inventory.py)

- [Invoke-RefreshInventory.ps1](../Core/PowerShell/Invoke-RefreshInventory.ps1)


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

- [update_firmware_using_catalog.py](../Core/Python/update_firmware_using_catalog.py)

- [Update-FirmwareUsingCatalog.ps1](../Core/PowerShell/Update-FirmwareUsingCatalog.ps1)


#### Synopsis
Script to update firmware using catalog

#### Description:
This script uses the OME REST API to allow updating a firmware using catalog.

Note that the credentials entered are not stored to disk.

#### Python Example
`python update_firmware_using_catalog_3.0.py --ip <ip addr> --user admin
--password <passwd> --groupid 25315`


#### PowerShell Example
```
PS C:\>$cred = Get-Credential
    .\Update-FirmwareUsingCatalog -IpAddress "10.xx.xx.xx" -Credentials $cred -DeviceId 25234
    .\Update-FirmwareUsingCatalog -IpAddress 192.168.1.93 -Credentials $creds -UpdateActions upgrade -RepoType 
    DELL_ONLINE -IdracIps 192.168.1.45
    

    PS C:\>.\Update-FirmwareUsingCatalog -IpAddress "10.xx.xx.xx" -Credentials $cred -GroupName Test
    In this instance you will be prompted for credentials to use to connect to the appliance

```


---
### Update Installed Firmware With Dup

#### Available Scripts

- [update_installed_firmware_with_dup.py](../Core/Python/update_installed_firmware_with_dup.py)

- [Update-InstalledFirmwareWithDup.ps1](../Core/PowerShell/Update-InstalledFirmwareWithDup.ps1)


#### Synopsis
 Script to update firmware for a device or applicable devices
 within a group using a DUP

#### Description
 This script uses the OME REST API to allow updating a device
 or a group of devices by using a single DUP file.

 Note that the credentials entered are not stored to disk.

#### Python Example
```bash
python update_installed_firmware_with_dup.py --ip <ip addr> --user admin
    --password <passwd> --groupid 25315
    --dupfile iDRAC-with-Lifecycle-Controller_Firmware_387FW_WN64_3.21.21.21_A00.EXE
```

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

- [get_alerts.py](../Core/Python/get_alerts.py)

- [Get-Alerts.ps1](../Core/PowerShell/Get-Alerts.ps1)


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
- TimeStampBegin - Not currently available. See https://github.com/dell/OpenManage-Enterprise/issues/101
- TimeStampEnd - Not currently available. See https://github.com/dell/OpenManage-Enterprise/issues/101
- Device name - Filter by a specific device name
- Group name - Filter alerts by a group name
- Group description - Filter alerts by a group description

Authentication is done over x-auth with basic authentication. Note: Credentials are not stored on disk.

#### Python Examples
```
python get_alerts --ip 192.168.1.93 --password somepass --top 1 --skip 5
python get_alerts --ip 192.168.1.93 --password somepass --alerts-by-group-name "Test" --severity-type CRITICAL --top 5
python get_alerts --ip 192.168.1.93 --password somepass --orderby Message --category-name AUDIT --alert-device-type STORAGE
```


#### PowerShell Example
```
PS C:\>$creds = Get-Credential
    Get-Alerts.ps1 -IpAddress 192.168.1.93 -Credentials $creds -CategoryName SYSTEM_HEALTH -Top 10
    Get-Alerts.ps1 -IpAddress 192.168.1.93 -Credentials $creds -Top 5 -Skip 3 -Orderby TimeStampAscending -StatusType 
    CRITICAL

```


---
### Get Audit Logs

#### Available Scripts

- [get_audit_logs.py](../Core/Python/get_audit_logs.py)

- [Get-AuditLogs.ps1](../Core/PowerShell/Get-AuditLogs.ps1)


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

- [get_chassis_inventory.py](../Core/Python/get_chassis_inventory.py)

- [Get-ChassisInventory.ps1](../Core/PowerShell/Get-ChassisInventory.ps1)


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

- [get_device_inventory.py](../Core/Python/get_device_inventory.py)

- [Get-DeviceInventory.ps1](../Core/PowerShell/Get-DeviceInventory.ps1)


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
    

    PS C:\>.\Get-DeviceInventory.ps1 -IpAddress "10.xx.xx.xx" -InventoryType {InventoryType} -FilterBy SvcTag 
    -DeviceInfo BZ0M630
    where {InventoryType} can be cpus or memory or controllers or disks or os
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```


---
### Get Device List

#### Available Scripts

- [get_device_list.py](../Core/Python/get_device_list.py)

- [Get-DeviceList.ps1](../Core/PowerShell/Get-DeviceList.ps1)


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

- [get_firmware_baselines.py](../Core/Python/get_firmware_baselines.py)

- [Get-FirmwareBaselines.ps1](../Core/PowerShell/Get-FirmwareBaselines.ps1)


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
### Get Group Details

#### Available Scripts

- [get_group_details.py](../Core/Python/get_group_details.py)

- [Get-GroupDetails.ps1](../Core/PowerShell/Get-GroupDetails.ps1)


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

- [get_group_details_by_filter.py](../Core/Python/get_group_details_by_filter.py)

- [Get-GroupDetailsByFilter.ps1](../Core/PowerShell/Get-GroupDetailsByFilter.ps1)


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

- [get_group_list.py](../Core/Python/get_group_list.py)

- [Get-GroupList.ps1](../Core/PowerShell/Get-GroupList.ps1)


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

- [get_identitypool_usage.py](../Core/Python/get_identitypool_usage.py)

- [Get-IdentityPoolUsage.ps1](../Core/PowerShell/Get-IdentityPoolUsage.ps1)


#### Synopsis
Script to get the list of virtual addresses in an Identity Pool

#### Description
This script uses the OME REST API to get a list of virtual addresses in an Identity Pool.
Will export to a CSV file called IdentityPoolUsage.csv in the current directory.
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Python Example
```bash
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd>
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd> --id 11
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd> --id 11 --outfile "/tmp/temp.csv"
```


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
### Get Report List

#### Available Scripts

- [get_report_list.py](../Core/Python/get_report_list.py)

- [Get-ReportList.ps1](../Core/PowerShell/Get-ReportList.ps1)


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
### Invoke Report Execution

#### Available Scripts

- [invoke_report_execution.py](../Core/Python/invoke_report_execution.py)

- [Invoke-ReportExecution.ps1](../Core/PowerShell/Invoke-ReportExecution.ps1)


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
    .\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -ReportId 10043
    

    PS C:\>.\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -ReportId 10043
    In this instance you will be prompted for credentials to use to
    connect to the appliance

```



## Maintenance Scripts
Maintenance scripts include those things for reprovisioning, remediation, and general upkeep of devices.

---
### Invoke Retire Lead

#### Available Scripts

- [invoke_retire_lead.py](../Core/Python/invoke_retire_lead.py)

- [Invoke-RetireLead.ps1](../Core/PowerShell/Invoke-RetireLead.ps1)


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

- [Set-ScaleVlanProfile.ps1](../Core/PowerShell/Set-ScaleVlanProfile.ps1)


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

