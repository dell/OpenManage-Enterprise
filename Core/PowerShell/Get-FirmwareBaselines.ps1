<#
_author_ = Grant Curell <grant_curell@dell.com>

Copyright (c) 2020 Dell EMC Corporation

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
    Gets a list of all firmware baselines available from an OME server or baselines associated
    with a specific device.
  .DESCRIPTION

    This script exercises the OME REST API to find baselines associated
    with a given server. For authentication X-Auth is used over Basic
    Authentication. Note: The credentials entered are not stored to disk.

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance

  .EXAMPLE
    $cred = Get-Credential
    Get-FirmwareBaselines.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -IdracIp 192.168.1.45
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [System.Net.IPAddress] $IpAddress,

  [Parameter(Mandatory)]
  [pscredential] $Credentials,

  [int] $DeviceId = $null,

  [string] $ServiceTag = $null,

  [System.Net.IPAddress] $IdracIp = $null,

  [string] $DeviceName = $null

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

  .INPUTS
  None. You cannot pipe objects to Get-Data.

  .OUTPUTS
  list. The Get-Data function returns a list of hashtables with the headers resulting from authentication against the
  OME server

#>

  [CmdletBinding()]
  param (

    [Parameter(Mandatory)]
    [string] 
    # The API url against which you would like to make a request
    $Url,

    [Parameter(Mandatory = $false)]
    [string]
    # (Optional) A filter to run against the API endpoint
    $Filter
  )

  $Data = @()
  $NextLinkUrl = $null
  try {

    if ($PSBoundParameters.ContainsKey('Filter')) {
      $CountData = Invoke-RestMethod -Uri $Url"?`$filter=$($Filter)" -Method Get -Credential $Credentials -SkipCertificateCheck

      if ($CountData.'@odata.count' -lt 1) {
        Write-Error "No results were found for filter $($Filter)."
        return $null
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
      $NextLinkUrl = $BaseUri + $CountData.'@odata.nextLink'
    }
    while ($NextLinkUrl) {
      $NextLinkData = Invoke-RestMethod -Uri $NextLinkUrl -Method Get -Credential $Credentials `
        -ContentType $Type -SkipCertificateCheck
          
      if ($null -ne $NextLinkData.'value') {
        $Data += $NextLinkData.'value'
      }
      else {
        $Data += $NextLinkData
      }    
          
      if ($NextLinkData.'@odata.nextLink') {
        $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
      }
      else {
        $NextLinkUrl = $null
      }
    }
  
    return $Data

  }
  catch [System.Net.Http.HttpRequestException] {
    Write-Error "There was a problem connecting to OME or the URL supplied is invalid. Did it become unavailable?"
    return $null
  }

}


# Verify arguments are mutually exclusive
$MutuallyExclusiveError = "The Device ID, Service Tag, idrac IP, and Device Name arguments are mutually exclusive.
                           Please define only one."
if ($PSBoundParameters.ContainsKey('DeviceId') -and 
  ($PSBoundParameters.ContainsKey('ServiceTag') -or 
    $PSBoundParameters.ContainsKey('IdracIp') -or 
    $PSBoundParameters.ContainsKey('DeviceName'))) {
  Write-Error $MutuallyExclusiveError
  Exit
} 

if ($PSBoundParameters.ContainsKey('ServiceTag') -and 
  ($PSBoundParameters.ContainsKey('DeviceId') -or 
    $PSBoundParameters.ContainsKey('IdracIp') -or 
    $PSBoundParameters.ContainsKey('DeviceName'))) {
  Write-Error $MutuallyExclusiveError
  Exit
} 

if ($PSBoundParameters.ContainsKey('IdracIp') -and 
  ($PSBoundParameters.ContainsKey('ServiceTag') -or 
    $PSBoundParameters.ContainsKey('DeviceId') -or 
    $PSBoundParameters.ContainsKey('DeviceName'))) {
  Write-Error $MutuallyExclusiveError
  Exit
} 

if ($PSBoundParameters.ContainsKey('DeviceName') -and 
  ($PSBoundParameters.ContainsKey('ServiceTag') -or 
    $PSBoundParameters.ContainsKey('IdracIp') -or 
    $PSBoundParameters.ContainsKey('DeviceId'))) {
  Write-Error $MutuallyExclusiveError
  Exit
}



try {

  $BaseUri = "https://$($IpAddress)"
  $FirmwareBaselines = Get-Data "https://$($IpAddress)/api/UpdateService/Baselines"

  if ($null -eq $FirmwareBaselines) {
    Write-Error "Unable to get firmware baselines from $($IpAddress). This could happen for many reasons but the most
                 likely is a failure in the connection."
    Exit
  }

  if (0 -ge $FirmwareBaselines.Count) {
    Write-Error "No firmware baselines found on this OME server: $($IpAddress). Exiting."
    Exit
  }

  if ($PSBoundParameters.ContainsKey('IdracIp') -or $PSBoundParameters.ContainsKey('ServiceTag')) {
    Write-Output "Retrieving a list of all devices..."
    $DeviceList = Get-Data "https://$($IpAddress)/api/DeviceService/Devices"

    if ($null -eq $DeviceList) {
      Write-Error "Unable to get devices from $($IpAddress). This could happen for many reasons but the most likely is a"
      " failure in the connection."
      Exit
    }

    if (0 -ge $DeviceList.Count) {
      Write-Error "No devices found on this OME server: $($IpAddress). Exiting."
      Exit
    }
  }

  if ($PSBoundParameters.ContainsKey('DeviceName')) {
    $DeviceId = Get-Data "https://$($IpAddress)/api/DeviceService/Devices" "DeviceName eq `'$($DeviceName)`'"

    if ($null -eq $DeviceId) {
      Write-Output "Error: We were unable to find device name $($DeviceName) on this OME server. Exiting."
      Exit
    }
    else {
      $DeviceId = $DeviceId.'Id'
    }
  }

  if ($PSBoundParameters.ContainsKey('ServiceTag')) {
    $DeviceId = Get-Data "https://$($IpAddress)/api/DeviceService/Devices" "DeviceServiceTag eq `'$($ServiceTag)`'"

    if ($null -eq $DeviceId) {
      Write-Output "Error: We were unable to find service tag $($ServiceTag) on this OME server. Exiting."
      Exit
    }
    else {
      $DeviceId = $DeviceId.'Id'
    }
  }

  if ($PSBoundParameters.ContainsKey('IdracIp')) {
    foreach ($Device in $DeviceList) {
      if ($Device.'DeviceManagement'[0].'NetworkAddress' -eq $IdracIp) {
        $DeviceId = $Device."Id"
        break
      }
    }

    if ($DeviceId -eq 0) {
      Write-Output "Error: We were unable to find idrac IP $($IdracIp) on this OME server. Exiting."
      Exit
    }
  }

  $FirmwareBaselineNames = @()
  foreach ($FirmwareBaseline in $FirmwareBaselines) {
    if ($DeviceId) {
      if ($FirmwareBaseline.'Targets'.Count -gt 0) {
        foreach ($Target in $FirmwareBaseline.'Targets') {
          if ($Target.'Id' -eq $DeviceId) {
            $FirmwareBaselineNames = $FirmwareBaselineNames + $FirmwareBaseline.'Name'
          }
        }
      }
    }
  }

  if ($FirmwareBaselineNames.Count -gt 0) {
    Write-Output "Baselines are:"
    Write-Output $FirmwareBaselineNames
  }
  else {
    Write-Output "No firmware baselines found!"
  }

}
catch {
  Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
