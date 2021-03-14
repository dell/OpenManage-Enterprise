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
    Add one or more hosts to an existing static group.

  .DESCRIPTION
    This script uses the OME REST API to add one or more hosts to an existing static group. You can provide specific
    devices or you can provide the job ID for a previous discovery job containing a set of servers. The script will pull
    from the discovery job and add those servers to a gorup. For authentication X-Auth is used over Basic Authentication.

    Note: The credentials entered are not stored to disk.

  .PARAMETER IpAddress 
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
  .PARAMETER GroupName
    The name of the group to which you want to add servers.
  .PARAMETER DeviceIds
    A comma separated list of device-ids which you want to add to a group.
  .PARAMETER ServiceTags
    A comma separated list of service tags which you want to add to a group.
  .PARAMETER IdracIps
    A comma separated list of idrac IPs which you want to add to a group.
  .PARAMETER DeviceNames
    A comma separated list of device names which you want to add to a group.
  .PARAMETER UseDiscoveryJobId
    This option allows you to provide the job ID from a discovery job and will pull the servers from that job ID and
    assign them to the specified group. You can either retrieve the job ID programatically or you can get it manually
    from the UI by clicking on the job and pulling it from the URL.
    Ex: https://192.168.1.93/core/console/console.html#/core/monitor/monitor_portal/jobsDetails?jobsId=14026

  .EXAMPLE
    $creds = Get-Credentials
    .\Add-DeviceToStaticGroup.ps1' -IpAddress 192.168.1.93 -Credentials $creds -GroupName 'YourGroup' -IdracIps '192.168.1.45,192.168.1.63' -UseDiscoveryJobId 14094
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [String]$GroupName,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[int]] $DeviceIds,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $ServiceTags,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $IdracIps,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $DeviceNames,

    [Parameter(Mandatory = $false)]
    [String] $UseDiscoveryJobId = $false
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
        [Parameter(ParameterSetName = "ServiceTag")]
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


try {

    $Targets = @()

    if ($PSBoundParameters.ContainsKey('GroupName')) {

        $GroupData = Get-Data "https://$($IpAddress)/api/GroupService/Groups" "Name eq '$($GroupName)'"

        if ($null -eq $GroupData) {
            Write-Error "We were unable to retrieve the GroupId for group name $($GroupName). Is the name correct?"
            Exit
        }

        $GroupId = $GroupData.'Id'
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

    if ($PSBoundParameters.ContainsKey('UseDiscoveryJobId')) {
        $JobInfo = Get-Data "https://$($IpAddress)/api/JobService/Jobs($($UseDiscoveryJobId))"

        if ($JobInfo.PSobject.Properties.name -match 'ExecutionHistories@odata.navigationLink') {
            $JobInfo = Get-Data "https://$($IpAddress)$($JobInfo.'ExecutionHistories@odata.navigationLink')"
        }
        else {
            Write-Error "Error: Something went wrong getting the job with ID " + $UseDiscoveryJobId
            Exit
        }

        if ($JobInfo.PSobject.Properties.name -match 'ExecutionHistoryDetails@odata.navigationLink') {
            $JobInfo = Get-Data "https://$($IpAddress)$($JobInfo[0].'ExecutionHistoryDetails@odata.navigationLink')"
        }
        else {
            Write-Error "Error: Something went wrong getting the execution details"
            Exit
        }

        if ($JobInfo.length -gt 0) {
            foreach ($Node in $JobInfo) {
                $Target = Get-DeviceId -OmeIpAddress $IpAddress -DeviceIdracIp $Node.'Key'
                if ($Target -ne -1) {
                    $Targets += $Target
                }
                else {
                    Write-Warning "Could not resolve ID for $($Node.'Key')"
                }
            }
        }
        else {
            Write-Error "The job info array returned empty. Exiting."
            Exit
        }
    }

    # Eliminate any duplicate IDs in the list
    $Targets = @($Targets | Get-Unique)

    if ($Targets.length -lt 1) {
        Write-Error "No IDs found. Did you provide an argument?"
        Exit
    }

    # Add devices to the group
    Write-Host "Adding devices to the group..."
    $Payload = @{
        GroupId = $GroupId
        MemberDeviceIds = $Targets
    } | ConvertTo-Json

    $Type = "application/json"
    $GroupAddDeviceUrl = "https://$($IpAddress)/api/GroupService/Actions/GroupService.AddMemberDevices"

    try {
        Invoke-RestMethod -Uri $GroupAddDeviceUrl -Credential $Credentials -ContentType $Type -Method Post -Body $Payload -SkipCertificateCheck
    }
    catch [System.Net.Http.HttpRequestException] {
        Write-Error "Adding the devices to the group threw an error. This usually means one or more devices were
         already in the group. Devices that weren't already in the group will still be added."
        Exit
    }

    Write-Host "Devices successfully added to the group!"
}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
