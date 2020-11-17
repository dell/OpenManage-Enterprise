# API Documentation

This repository is composed of two principal portions - OpenManage Enterprise (OME) API usage examples and plugins.

API usage examples are stored in Core/PowerShell and Core/Python for PowerShell and Python examples respectively.
Parity is generally maintained between PowerShell and Python examples. Available scripts are listed for each functionality
shown below. 

You can find a current copy of the OME API documentation [here](https://www.dell.com/support/manuals/en-us/dell-openmanage-enterprise/ome-3.3.1_omem-1.10.00_apiguide/about-this-document?guid=guid-e4740be0-2c49-443a-8f3d-1cb50cd4b7a3&lang=en-us). A PDF version is available [here](https://dl.dell.com/topicspdf/dell-openmanage-enterprise_api-guide2_en-us.pdf)

## Table of Contents
<div class="toc">
<ul>
<li><a href="#deploy-scripts">Deploy Scripts</a></li>
<ul>

<li><a href="#add-device-to-static-group">Add Device To Static Group</a></li>

<li><a href="#add-members">Add Members</a></li>

<li><a href="#edit-discovery-job">Edit Discovery Job</a></li>

<li><a href="#invoke-discover-device">Invoke Discover Device</a></li>

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

<li><a href="#get-alerts-by-device">Get Alerts By Device</a></li>

<li><a href="#get-alerts-by-group">Get Alerts By Group</a></li>

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

</ul>
</ul>
</div>

## Deploy Scripts
Deploy scripts include those things for discovery and generating the initial inventory, configuration, and os deployment.

---
### Add Device To Static Group

#### Available Scripts

- [add_device_to_static_group.py](../Core/Python/add_device_to_static_group.py)


#### Synopsis
Add one or more hosts to an existing static group.

#### Description
This script exercises the OME REST API to add one or more
hosts to an existing static group. For authentication X-Auth
is used over Basic Authentication. Note: The credentials entered
are not stored to disk.

#### Example
    `python add_device_to_static_group.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group" --devicenames "cmc1,host3,192.168.1.5"`

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

#### Example
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

---
### Edit Discovery Job

#### Available Scripts

- [edit_discovery_job.py](../Core/Python/edit_discovery_job.py)


#### Synopsis
Script to update an existing discovery job in OME

#### Description
This script exercises the OME REST API to update an existing discovery job(if found) with the credentials and also 
it updates networkaddress if user passs iprange.
For authentication X-Auth is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

#### Example
```bash
python edit_discovery_job.py --ip <ip addr> --user admin
--password <passwd> --jobNamePattern <Existing Discovery Job name>
--targetUserName <user name> --targetPassword <password>
--targetIpAddresses <10.xx.xx.x,10.xx.xx.xx-10.yy.yy.yy,10.xx.xx.xx>
```
where {jobNamePattern} can be existing discovery job name(Discovery_Essentials_10.xx.xx.xx)
or the job name pattern(Discovery_Essentials)

---
### Invoke Discover Device

#### Available Scripts

- [invoke_discover_device.py](../Core/Python/invoke_discover_device.py)

- [Invoke-DiscoverDevice.ps1](../Core/PowerShell/Invoke-DiscoverDevice.ps1)


#### Synopsis
Script to discover devices managed by OME Enterprise

#### Description
This script exercises the OME REST API to discover devices.
For authentication X-Auth is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

#### Example
```bash
python invoke_discover_device.py --ip <ip addr> --user admin
--password <passwd> --targetUserName <user name>
--targetPassword <password> --deviceType <{Device_Type}>
--targetIpAddresses <10.xx.xx.x,10.xx.xx.xx-10.yy.yy.yy,10.xx.xx.xx> or --targetIpAddrCsvFile xyz.csv
```
where {Device_Type} can be server,chassis

---
### New Mcm Group

#### Available Scripts

- [new_mcm_group.py](../Core/Python/new_mcm_group.py)

- [New-McmGroup.ps1](../Core/PowerShell/New-McmGroup.ps1)


#### Synopsis
Script to create MCM group, add all members to the created group,
and assign a backup lead

Description: 
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

#### Example
`python new_mcm_group.py --ip <ip addr> --user root --password <passwd> --groupname testgroup`

---
### New Network

#### Available Scripts

- [new_network.py](../Core/Python/new_network.py)

- [New-Network.ps1](../Core/PowerShell/New-Network.ps1)


#### Synopsis
Script to create a new network with VLAN

#### Description
This script exercises the OME REST API to create a new network
A network consists of a Minimum and Maximum VLAN ID to create a range
Set Minimum and Maximum to the same value to a single VLAN

For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python new_network.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group"`

---
### New Static Group

#### Available Scripts

- [new_static_group.py](../Core/Python/new_static_group.py)

- [New-StaticGroup.ps1](../Core/PowerShell/New-StaticGroup.ps1)


#### Synopsis
Script to create a new static group

#### Description
This script exercises the OME REST API to create a new static
group. The user is responsible for adding devices to the
group once the group has been successfully created.
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python new_static_group.py --ip <xx> --user <username> --password <pwd> --groupname "Random Test Group"`

---
### Set Power State

#### Available Scripts

- [set_power_state.py](../Core/Python/set_power_state.py)

- [Set-PowerState.ps1](../Core/PowerShell/Set-PowerState.ps1)


#### Synopsis
Script to perform power control on device managed by OM Enterprise

#### Description
This script exercises the OME REST API to perform power control operations.
For authentication X-Auth is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

#### Example
```bash
python set_power_state.py --ip <ip addr> --user admin
--password <passwd> --deviceId 25527  --state {state}
```
where {state} can be "On", "Off", "Cold Boot","Warm Boot", "ShutDown"

---
### Set System Configuration

#### Available Scripts

- [set_system_configuration.py](../Core/Python/set_system_configuration.py)

- [Set-SystemConfiguration.ps1](../Core/PowerShell/Set-SystemConfiguration.ps1)


#### Synopsis
Script to perform template deployment on the target devices.

Description: 
This script performs template deployment. Note that the credentials entered are not stored to disk.

#### Example
`python set_system_configuration.py --ip <ip addr> --user admin
    --password <passwd> --sourceid <10089> --targetid/--groupid <10081>`


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

#### Example
`python invoke_refresh_inventory.py -i 192.168.1.93 -u admin -p somepass --idrac-ips 192.168.1.63,192.168.1.45`

---
### Update Firmware Using Catalog

#### Available Scripts

- [update_firmware_using_catalog.py](../Core/Python/update_firmware_using_catalog.py)

- [Update-FirmwareUsingCatalog.ps1](../Core/PowerShell/Update-FirmwareUsingCatalog.ps1)


#### Synopsis
Script to update firmware using catalog

Description: 
This script uses the OME REST API to allow updating a firmware using catalog.

Note that the credentials entered are not stored to disk.

#### Example
`python update_firmware_using_catalog_3.0.py --ip <ip addr> --user admin
--password <passwd> --groupid 25315`

---
### Update Installed Firmware With Dup

#### Available Scripts

- [update_installed_firmware_with_dup.py](../Core/Python/update_installed_firmware_with_dup.py)

- [Update-InstalledFirmwareWithDup.ps1](../Core/PowerShell/Update-InstalledFirmwareWithDup.ps1)


#### Synopsis
 Script to update firmware for a device or applicable devices
 within a group using a DUP

#### Description
 This script exercises the OME REST API to allow updating a device
 or a group of devices by using a single DUP file.

 Note that the credentials entered are not stored to disk.

#### Example
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


## Monitor Scripts
Monitor scripts include those things for checking alerts, health, performance, power status, and other pre-existing status data.

---
### Get Alerts By Device

#### Available Scripts

- [get_alerts_by_device.py](../Core/Python/get_alerts_by_device.py)

- [Get-AlertsByDevice.ps1](../Core/PowerShell/Get-AlertsByDevice.ps1)


#### Synopsis
Script to get the alerts for a device given the name or
asset tag of the device

#### Description
This script exercises the OME REST API to get a list of alerts for
a specific device given the name or the asset tag of the device
Note that the credentials entered are not stored to disk.

#### Example
`python get_alerts_by_device.py --ip <xx> --user <username>
    --password <pwd> --filterby Name --field "idrac-abcdef"`

---
### Get Alerts By Group

#### Available Scripts

- [get_alerts_by_group.py](../Core/Python/get_alerts_by_group.py)

- [Get-AlertsByGroup.ps1](../Core/PowerShell/Get-AlertsByGroup.ps1)


#### Synopsis
Script to get the list of alerts for a group in OME

#### Description
This script exercises the OME REST API to get a list
of alerts for the given group. For authentication X-Auth
is used over Basic Authentication.
Note that the credentials entered are not stored to disk.

#### Example
    `python get_alerts_by_group.py --ip <ip addr> --user admin
        --password <password> --filterby Name
        --field "Dell iDRAC Servers"`

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

#### Example
`python get_audit_logs.py -i 192.168.1.93 -u admin -p somepass
--share \192.168.1.7\gelante    est.csv --smbuser someuser --smbpass somepass`

---
### Get Chassis Inventory

#### Available Scripts

- [get_chassis_inventory.py](../Core/Python/get_chassis_inventory.py)

- [Get-ChassisInventory.ps1](../Core/PowerShell/Get-ChassisInventory.ps1)


#### Synopsis
Script to get chassis inventory details in CSV format

#### Description
This script exercises the OME REST API to get chassis inventory
in a CSV format for external consumption
Note that the credentials entered are not stored to disk.

#### Example
`python get_chassis_inventory.py -i <ip addr> -u admin -p <password>`

---
### Get Device Inventory

#### Available Scripts

- [get_device_inventory.py](../Core/Python/get_device_inventory.py)

- [Get-DeviceInventory.ps1](../Core/PowerShell/Get-DeviceInventory.ps1)


#### Synopsis
Script to get the device inventory details

#### Description
This script exercises the OME REST API to get detailed inventory
for a device given ID/Name/Service Tag
and Inventory type (os,cpus,disks,memory,controllers) of the device
Note that the credentials entered are not stored to disk.

#### Example
`python get_device_inventory.py -i <ip addr> -u admin
    -p <password> -fby Name -f "iDRAC-abcdef" -invtype os`

---
### Get Device List

#### Available Scripts

- [get_device_list.py](../Core/Python/get_device_list.py)

- [Get-DeviceList.ps1](../Core/PowerShell/Get-DeviceList.ps1)


#### Synopsis
Script to get the list of devices managed by OM Enterprise

#### Description
This script exercises the OME REST API to get a list of devices
currently being managed by that instance. For authentication X-Auth
is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_device_list.py --ip <xx> --user <username> --password <pwd>`

---
### Get Firmware Baselines

#### Available Scripts

- [get_firmware_baselines.py](../Core/Python/get_firmware_baselines.py)

- [Get-FirmwareBaselines.ps1](../Core/PowerShell/Get-FirmwareBaselines.ps1)


#### Synopsis
Gets a list of all firmware baselines available from an OME server or baselines associated
with a specific device.

#### Description
This script exercises the OME REST API to find baselines associated
with a given server. For authentication X-Auth is used over Basic
Authentication. Note: The credentials entered are not stored to disk.

#### Example
`python get_firmware_baseline.py -i 192.168.1.93 -u admin -p somepass -r 192.168.1.45`

---
### Get Group Details

#### Available Scripts

- [get_group_details.py](../Core/Python/get_group_details.py)

- [Get-GroupDetails.ps1](../Core/PowerShell/Get-GroupDetails.ps1)


#### Synopsis
Script to get the details of groups managed by OM Enterprise

#### Description
This script exercises the OME REST API to get a group and the
device details for all devices in that group. For authentication
X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_group_details.py --ip <xx> --user <username> --password <pwd>
--groupinfo "All Devices"`

---
### Get Group Details By Filter

#### Available Scripts

- [get_group_details_by_filter.py](../Core/Python/get_group_details_by_filter.py)

- [Get-GroupDetailsByFilter.ps1](../Core/PowerShell/Get-GroupDetailsByFilter.ps1)


#### Synopsis
Script to get the details of groups managed by OM Enterprise
This script uses OData filters for extracting information

#### Description
This script exercises the OME REST API to get a group and the
device details for all devices in that group. For authentication
X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_group_details_by_filter.py --ip <xx> --user <username> --password <pwd>
    --filterby Name --field "All Devices"`

---
### Get Group List

#### Available Scripts

- [get_group_list.py](../Core/Python/get_group_list.py)

- [Get-GroupList.ps1](../Core/PowerShell/Get-GroupList.ps1)


#### Synopsis
Script to get the list of groups managed by OM Enterprise

#### Description
This script exercises the OME REST API to get a list of groups
currently being managed by that instance. For authentication X-Auth
is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_group_list.py --ip <xx> --user <username> --password <pwd>`

---
### Get Identitypool Usage

#### Available Scripts

- [get_identitypool_usage.py](../Core/Python/get_identitypool_usage.py)

- [Get-IdentityPoolUsage.ps1](../Core/PowerShell/Get-IdentityPoolUsage.ps1)


#### Synopsis
Script to get the list of virtual addresses in an Identity Pool

#### Description
This script exercises the OME REST API to get a list of virtual addresses in an Identity Pool.
Will export to a CSV file called IdentityPoolUsage.csv in the current directory. 
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
```bash
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd>
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd> --id 11
python get_identitypool_usage.py --ip <xx> --user <username> --password <pwd> --id 11 --outfile "/tmp/temp.csv"
```

---
### Get Report List

#### Available Scripts

- [get_report_list.py](../Core/Python/get_report_list.py)

- [Get-ReportList.ps1](../Core/PowerShell/Get-ReportList.ps1)


#### Synopsis
Script to get the list of reports defined in OM Enterprise

#### Description
This script exercises the OME REST API to get a list of reports
currently defined in that instance. For authentication X-Auth
is used over Basic Authentication
Note that the credentials entered are not stored to disk.

#### Example
`python get_report_list.py --ip <xx> --user <username> --password <pwd>`

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

#### Example
`python .\invoke_report_execution.py  --ip <ip addr> --user <username>
    --password <password> --reportid 10051`


## Maintenance Scripts
Maintenance scripts include those things for reprovisioning, remediation, and general upkeep of devices.

---
### Invoke Retire Lead

#### Available Scripts

- [invoke_retire_lead.py](../Core/Python/invoke_retire_lead.py)

- [Invoke-RetireLead.ps1](../Core/PowerShell/Invoke-RetireLead.ps1)


#### Synopsis
Script to retire lead of MCM group and promote the exising backup lead as lead

Description: 
This script retires the current lead and the backup lead gets promoted as the new lead

#### Example
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
