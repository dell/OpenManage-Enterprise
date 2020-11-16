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
    Retrieves the audit logs from a target OME instance and can either save them in an CSV on a fileshare or 
    print them to screen.

  .DESCRIPTION

    It performs X-Auth with basic authentication. Note: Credentials are not stored on disk.

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
  .PARAMETER Share
    (optional) The name of the share you would like to mount
  .PARAMETER SmbCreds
    (optional) The name of the SMB credentials for the share

  .EXAMPLE
    $cred1 = Get-Credentials
    $cred2 = Get-Credentials
    python get_audit_logs.py -IpAddress 192.168.1.5 -Credentials $cred1 -Share \\192.168.1.7\gelante -SmbCreds $cred2
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [System.Net.IPAddress] $IpAddress,

  [Parameter(Mandatory)]
  [pscredential] $Credentials,

  [string] $Share = $null,

  [pscredential] $SmbCreds = $null

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
  dict. A dictionary containing the results of the API call

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

try {

  $AuditLogs = Get-Data "https://$($IpAddress)/api/ApplicationService/AuditLogs"
  
  if ($null -eq $AuditLogs) {
    Write-Output "Error: We were unable to fetch the audit logs... exiting."
    Exit
  }

  if ($PSBoundParameters.ContainsKey('Share')) {
    $Share = $Share.TrimEnd('\')
    New-SmbMapping -RemotePath $Share -Username $Credentials.UserName -Password $Credentials.Password
    $AuditLogs | Export-Csv -LiteralPath "$($Share)\$(get-date -f yyyy-MM-dd).csv"
  }
  else {
    Write-Output $AuditLogs
  }

}
catch {
  Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
