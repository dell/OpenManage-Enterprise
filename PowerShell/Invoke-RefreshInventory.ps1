#Requires -Version 7

<#
_author_ = Grant Curell <grant_curell@dell.com>

Copyright (c) 2021 Dell EMC Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>

<#
  .SYNOPSIS
    Refreshes the inventory on a set of target devices

  .DESCRIPTION

    This script uses the OME REST API to refresh the inventory of a targeted server. It performs X-Auth
    with basic authentication. Note: Credentials are not stored on disk.

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
  .PARAMETER GroupName
    The name of the group containing the devices whose inventory you want to refresh.
    Defaults to all devices. Due to the way the API functions, if you want to refresh the 
    configuration inventory, you must have all applicable devices in a group. The 
    configuration inventory is specific to the tab called Configuration Inventory under 
    a device's view. You can use the create_static_group and add_device_to_static group 
    modules to do this programmatically.
  .PARAMETER DeviceIds
    Optional
    A comma separated list of device-ids to refresh. Applies to 
    regular inventory only. This does not impact the configuration 
    inventory tab. That is controlled by the group name.
  .PARAMETER ServiceTags
    Optional
    A comma separated list of service tags to refresh. Applies to 
    regular inventory only. This does not impact the configuration 
    inventory tab. That is controlled by the group name.
  .PARAMETER IdracIps
    Optional
    A comma separated list of idrac IPs to refresh. Applies to regular 
    inventory only. This does not impact the configuration inventory 
    tab. That is controlled by the group name.
  .PARAMETER DeviceNames
    Optional
    A comma separated list of device names to refresh. Applies to 
    regular inventory only. This does not impact the configuration 
    inventory tab. That is controlled by the group name.
  .PARAMETER SkipConfigInventory
    The configuration inventory is the inventory you see specifically under the tab for a
     specific device. In order to obtain a config inventory that server must be part of a
     group or you have to run an inventory update against all devices which can be time 
    consuming. A regular inventory run will update things like firmware assuming that the
     version change is reflected in idrac. A config inventory is launched in the GUI by 
    clicking "Run inventory" on quick links on the devices page. A regular inventory is 
    the same as clicking "Run inventory" on a specific device's page.

  .EXAMPLE
    $cred = Get-Credential
    Invoke-RefreshInventory.ps1 -IpAddress 192.168.1.93 -Credentials $creds -GroupName Test -ServiceTags AAAAAAA
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory = $false)]
    [string] $GroupName = "All Devices",

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[int]] $DeviceIds,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $ServiceTags,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[System.Net.IPAddress]] $IdracIps,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $DeviceNames,

    [Parameter(Mandatory = $false)]
    [bool] $SkipConfigInventory = $false

)


function Get-Data {
  <#
  .SYNOPSIS
    Used to interact with API resources

  .DESCRIPTION
    This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
    handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
    pages to get a complete listing.

  .PARAMETER Url
    The API url against which you would like to make a request

  .PARAMETER OdataFilter
    An optional parameter for providing an odata filter to run against the API endpoint.

  .PARAMETER MaxPages
    The maximum number of pages you would like to return

  .INPUTS
    None. You cannot pipe objects to Get-Data.

  .OUTPUTS
    dict. A dictionary containing the results of the API call or an empty dictionary in the case of a failure

  #>

  [CmdletBinding()]
  param (

    [Parameter(Mandatory)]
    [string]
    $Url,

    [Parameter(Mandatory = $false)]
    [string]
    $OdataFilter,

    [Parameter(Mandatory = $false)]
    [int]
    $MaxPages = $null
  )

  $Data = @()
  $NextLinkUrl = $null
  try {

    if ($PSBoundParameters.ContainsKey('OdataFilter')) {
      $CountData = Invoke-RestMethod -Uri $Url"?`$filter=$($OdataFilter)" -Method Get -Credential $Credentials -SkipCertificateCheck

      if ($CountData.'@odata.count' -lt 1) {
        Write-Error "No results were found for filter $($OdataFilter)."
        return @{}
      } 
    }
    else {
      $CountData = Invoke-RestMethod -Uri $Url -Method Get -Credential $Credentials -ContentType $Type `
        -SkipCertificateCheck
    }

    if ($null -ne $CountData.'value') {
      $Data += $CountData.'value'
    }
    else {
      $Data += $CountData
    }
    
    if ($CountData.'@odata.nextLink') {
      $NextLinkUrl = "https://$($IpAddress)$($CountData.'@odata.nextLink')"
    }

    $i = 1
    while ($NextLinkUrl) {
      if ($MaxPages) {
        if ($i -ge $MaxPages) {
          break
        }
        $i = $i + 1
      }
      
      $NextLinkData = Invoke-RestMethod -Uri "$($NextLinkUrl)" -Method Get -Credential $Credentials `
      -ContentType $Type -SkipCertificateCheck
          
      if ($null -ne $NextLinkData.'value') {
        $Data += $NextLinkData.'value'
      }
      else {
        $Data += $NextLinkData
      }    
      
      if ($NextLinkData.'@odata.nextLink') {
        $NextLinkUrl = "https://$($IpAddress)$($NextLinkData.'@odata.nextLink')"
      }
      else {
        $NextLinkUrl = $null
      }
    }

    return $Data

  }
  catch [System.Net.Http.HttpRequestException] {
    Write-Error "There was a problem connecting to OME or the URL supplied is invalid. Did it become unavailable?"
    return @{}
  }

}


function Get-DeviceId {
    <#
    .SYNOPSIS
    Resolves a service tag, idrac IP or device name to a device ID

    .PARAMETER OmeIpAddress
    IP address of the OME server

    .PARAMETER ServiceTag
    (Optional) The service tag of a host

    .PARAMETER DeviceIdracIp
    (Optional) The idrac IP of a host

    .PARAMETER DeviceName
    (Optional) The name of a host

    .OUTPUTS
    int. The output is the ID of the device fed into the function or -1 if it couldn't be found.

    #>
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Net.IPAddress]$OmeIpAddress,

        [Parameter(Mandatory = $false)]
        [parameter(ParameterSetName = "ServiceTag")]
        [string]$ServiceTag,

        [Parameter(Mandatory = $false)]
        [parameter(ParameterSetName = "DeviceIdracIp")]
        [System.Net.IPAddress]$DeviceIdracIp,

        [Parameter(Mandatory = $false)]
        [parameter(ParameterSetName = "DeviceName")]
        [string]$Devicename
    )

    $DeviceId = -1
    
    if ($PSBoundParameters.ContainsKey('DeviceName')) {
        $DeviceId = Get-Data "https://$($OmeIpAddress)/api/DeviceService/Devices" "DeviceName eq `'$($DeviceName)`'"

        if ($null -eq $DeviceId) {
            Write-Output "Error: We were unable to find device name $($DeviceName) on this OME server. Exiting."
            Exit
        }
        else {
            $DeviceId = $DeviceId.'Id'
        }
    }

    if ($PSBoundParameters.ContainsKey('ServiceTag')) {
        $DeviceId = Get-Data "https://$($OmeIpAddress)/api/DeviceService/Devices" "DeviceServiceTag eq `'$($ServiceTag)`'"

        if ($null -eq $DeviceId) {
            Write-Output "Error: We were unable to find service tag $($ServiceTag) on this OME server. Exiting."
            Exit
        }
        else {
            $DeviceId = $DeviceId.'Id'
        }
    }

    if ($PSBoundParameters.ContainsKey('DeviceIdracIp')) {
        $DeviceList = Get-Data "https://$($OmeIpAddress)/api/DeviceService/Devices"
        foreach ($Device in $DeviceList) {
            if ($Device.'DeviceManagement'[0].'NetworkAddress' -eq $DeviceIdracIp) {
                $DeviceId = $Device."Id"
                break
            }
        }

        if ($DeviceId -eq 0) {
            throw "Error: We were unable to find idrac IP $($IdracIp) on this OME server. Exiting."
        }
    }

    return $DeviceId
}


function Invoke-TrackJobToCompletion {
    <#
    .SYNOPSIS
    Tracks a job to either completion or a failure within the job.

    .PARAMETER OmeIpAddress
    The IP address of the OME server

    .PARAMETER JobId
    The ID of the job which you would like to track

    .PARAMETER MaxRetries
    (Optional) The maximum number of times the function should contact the server to see if the job has completed

    .PARAMETER SleepInterval
    (Optional) The frequency with which the function should check the server for job completion

    .OUTPUTS
    True if the job completed successfully or completed with errors. Returns false if the job failed.

    #>

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [System.Net.IPAddress]
        $OmeIpAddress,

        [Parameter(Mandatory)]
        [int]
        $JobId,

        [Parameter(Mandatory = $false)]
        [int]
        $MaxRetries = 20,

        [Parameter(Mandatory = $false)]
        [int]
        $SleepInterval = 60
    )

    $FAILEDJOBSTATUSES = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')
    $Ctr = 0
    do {
        $Ctr++
        Start-Sleep -Seconds $SleepInterval
        $JOBSVCURL = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
        $JobData = Get-Data $JOBSVCURL

        if ($null -eq $JobData) {
            Write-Error "Something went wrong tracking the job data. 
            Try checking jobs in OME to see if the job is running."
            return $false
        }

        $JobStatus = $JobData.LastRunStatus.Name
        Write-Host "Iteration $($Ctr): Status of $($JobId) is $($JobStatus)"
        if ($JobStatus -eq 'Completed') {
            ## Completed successfully
            Write-Host "Job completed successfully!"
            break
        }
        elseif ($FAILEDJOBSTATUSES -contains $JobStatus) {
            Write-Warning "Job failed"
            $JOBEXECURL = "$($JOBSVCURL)/ExecutionHistories"
            $ExecRespInfo = Invoke-RestMethod -Uri $JOBEXECURL -Method Get -Credential $Credentials -SkipCertificateCheck
            $HistoryId = $ExecRespInfo.value[0].Id
            $HistoryResp = Invoke-RestMethod -Uri "$($JOBEXECURL)($($HistoryId))/ExecutionHistoryDetails" -Method Get `
                                             -ContentType $Type -Credential $Credentials -SkipCertificateCheck
            Write-Host "------------------- ERROR -------------------"
            Write-Host $HistoryResp.value
            Write-Host "------------------- ERROR -------------------"
            return $false
        }
        else { continue }
    } until ($Ctr -ge $MaxRetries)

    if ($Ctr -ge $MaxRetries) {
      Write-Warning "Job exceeded max retries! Check OME for details on what has hung."
      return $false
    }

    return $true
}

try {

    $BaseUri = "https://$($IpAddress)"
    $JobsUrl = "https://$($IpAddress)/api/JobService/Jobs"
    $Type = "application/json"
    $Targets = @()

    if ($null -eq $DeviceIds -and $null -eq $ServiceTags -and $null -eq $IdracIps -and $null -eq $DeviceNames) {
        Write-Error "You must provide at least one of the following: DeviceIds, ServiceTags, IdracIps, DeviceNames"
    }

    if ($PSBoundParameters.ContainsKey('ServiceTags')) {
        foreach ($ServiceTag in $ServiceTags -split ',') {
            $Target = Get-DeviceId -OmeIpAddress $IpAddress -ServiceTag $ServiceTag
            if ($Target -ne -1) {
                $Targets += $Target
            }
            else {
                Write-Error "Error - could not get ID for service tag $($ServiceTag)"
                Exit
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('IdracIps')) {
        foreach ($IdracIp in $IdracIps -split ',') {
            $Target = Get-DeviceId -OmeIpAddress $IpAddress -DeviceIdracIp $IdracIp
            if ($Target -ne -1) {
                $Targets += $Target
            }
            else {
                Write-Error "Error - could not get ID for idrac IP $($IdracIp)"
                Exit
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('DeviceNames')) {
        foreach ($DeviceName in $DeviceNames -split ',') {
            $Target = Get-DeviceId -OmeIpAddress $IpAddress -DeviceName $DeviceName
            if ($Target -ne -1) {
                $Targets += $Target
            }
            else {
                Write-Error "Error - could not get ID for device name $($DeviceName)"
                Exit
            }
        }
    }

    $GroupId = Get-Data "https://$($IpAddress)/api/GroupService/Groups" "Name eq `'$($GroupName)`'"

    if ($null -eq $GroupId) {
        Write-Error "We were unable to find the ID for group name $($GroupName)... exiting."
        Exit
    }

    $GroupId = $GroupId.'Id'

    $TargetsPayload = @()
    foreach ($IdToRefresh in $Targets) {
        $TargetsPayload += @{
            Id         = $IdToRefresh
            Data       = ""
            TargetType = @{
                Id   = 1000
                Name = "DEVICE"
            }
        }
    }

    $Payload = @{
        Id             = 0
        JobName        = "Inventory refresh via the API."
        JobDescription = "Refreshes the inventories for targeted hardware."
        Schedule       = "startnow"
        State          = "Enabled"
        JobType        = @{
            Name = "Inventory_Task"
        }
        Targets        = $TargetsPayload
    } | ConvertTo-Json -Depth 6

    Write-Output "Beginning standard inventory refresh..."
    $CreateResponse = Invoke-RestMethod -Method 'Post' -Uri $JobsUrl -Credential $Credentials -SkipCertificateCheck -Body $Payload -ContentType $Type

    if ($null -eq $CreateResponse) {
        Write-Error "Error: Failed to refresh inventory. We aren't sure what went wrong."
        Exit
    }

    $CreateResponse = $CreateResponse.value

    if (-not $SkipConfigInventory) {

        $Payload = @{
            JobDescription = "Run config inventory collection task on selected devices"
            JobName        = "Part 1 - API refresh config inventory"
            JobType        = @{
                Id   = 50 
                Name = "Device_Config_Task"
            }
            Params         = @(
                @{
                    Key   = "action"
                    Value = "CONFIG_INVENTORY" 
                })
            Schedule       = "startnow"
            StartTime      = ""
            State          = "Enabled"
            Targets        = @(
                @{
                    Data       = ""
                    Id         = $GroupId
                    JobId      = -1
                    TargetType = @{ 
                        Id   = 6000 
                        Name = "GROUP" 
                    }
                })
        } | ConvertTo-Json -Depth 6
    

        Write-Output "Beginning part 1 of 2 of the configuration inventory refresh."
        $CreateResponse = Invoke-RestMethod -Method 'Post' -Uri $JobsUrl -Credential $Credentials -SkipCertificateCheck -Body $Payload -ContentType $Type

        if ($null -eq $CreateResponse) {
            Write-Error "Error: Failed to refresh inventory."
        }

        Write-Output "Waiting for part 1 of configuration inventory refresh to finish. This could take a couple of minutes."
        if (Invoke-TrackJobToCompletion $IpAddress $CreateResponse.'Id' -SleepInterval 10) {
            Write-Output "Part 1 of configuration inventory refresh completed successfully."
        }
        else {
            Write-Error "Something went wrong. Tracking part 1 of the inventory refresh failed."
            Exit
        }

        $Payload = @{
            JobDescription = "Create Inventory"
            JobName        = "Part 2 - API refresh config inventory"
            JobType        = @{
                Id   = 8 
                Name = "Inventory_Task"
            }
            Params         = @(
                @{
                    Key   = "action"
                    Value = "CONFIG_INVENTORY" 
                },
                @{
                    Key   = "isCollectDriverInventory"
                    Value = "true"
                })
            Schedule       = "startnow"
            StartTime      = ""
            State          = "Enabled"
            Targets        = @(
                @{
                    Data       = ""
                    Id         = $GroupId
                    JobId      = -1
                    TargetType = @{ 
                        Id   = 6000 
                        Name = "GROUP" 
                    }
                })
        } | ConvertTo-Json -Depth 6

        Write-Output "Beginning part 2 of 2 of the configuration inventory refresh"
        $CreateResponse = Invoke-RestMethod -Method 'Post' -Uri $JobsUrl -Credential $Credentials -SkipCertificateCheck -Body $Payload -ContentType $Type

        if ($null -eq $CreateResponse) {
            Write-Error "Error: Failed to refresh inventory."
        }

        Write-Output "Waiting for part 2 of configuration inventory refresh to finish. This could take a couple of minutes."
        if (Invoke-TrackJobToCompletion $IpAddress $CreateResponse.'Id' -SleepInterval 10) {
            Write-Output "Part 2 of configuration inventory refresh completed successfully."
        }
        else {
            Write-Error "Something went wrong. Tracking part 2 of the inventory refresh failed."
            Exit
        }

    }

    Write-Output "Inventory refresh complete!"
}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
