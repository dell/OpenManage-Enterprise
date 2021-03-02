#Requires -Version 7

<#
_author_ = Grant Curell <grant_curell@dell.com>
_author_ = Chris Steinbeisser <chris.steinbeisser@Dell.com>

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
   Retrieve a list of users from OME.
 .DESCRIPTION
   This script uses the OME REST API to retrieve a list of users from OME.
 .PARAMETER IpAddress
   IP Address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance

 .EXAMPLE
   $cred = Get-Credential
   .\Get-OmeUsers.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials
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


try {

    Write-Host "Retrieving user data..."
    $Users = Get-Data "https://$($IpAddress)/api/AccountService/Accounts"
    foreach ($User in $Users) {
        Write-Host $Users |  Format-Table | Out-String
    }
    
}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
