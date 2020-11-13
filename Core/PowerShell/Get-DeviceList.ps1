<#
PowerShell Script using OME API to get the device list.
_author_ = Raajeev Kalyanaraman <raajeev.kalyanaraman@Dell.com>

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
    Script to get the list of devices managed by OM Enterprise

  .DESCRIPTION

    This script exercises the OME REST API to get a list of devices
    currently being managed by that instance. For authentication X-Auth
    is used over Basic Authentication

    Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
    This is the IP address of the OME Appliance

 .PARAMETER Credentials
    Credentials used to talk to the OME Appliance

 .PARAMETER OutFormat
    Output format - one of csv / json. If no argument is provided to this and to OutFilePath it will print 
    a table to screen. If OutFilePath is provided it will print to a file. Note: using the argument CSV here
    without OutFilePath will also cause a table to print to screen. Without OutFilePath and with the json
    argument this will print the JSON to screen.

 .PARAMETER OutFilePath
    An optional file to dump output to in the specified
    output format  

  .EXAMPLE
    $cred = Get-Credential
    .\Get-DeviceList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
    .\Get-DeviceList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -OutFormat json
    .\Get-DeviceList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -OutFormat CSV -OutFilePath .\\test.csv
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [System.Net.IPAddress] $IPAddress,

  [Parameter(Mandatory = $False)]
  [ValidateSet('CSV', 'json')]
  [String] $OutFormat = "CSV",

  [Parameter(Mandatory = $false)]
  [AllowEmptyString()]
  [String] $OutFilePath = "",

  [Parameter(Mandatory)]
  [pscredential] $Credentials
)

function Get-UniqueFileName {
  <#
      .SYNOPSIS
        Get a unique file name for the provided file

      .DESCRIPTION
        Resolves any relative paths to a full path and if the file already exists adds (#) to the filename and
        returns it.

      .PARAMETER FilePath
        A file path to a target location. Ex: '.\test.csv'

      .OUTPUTS
        The output of the function is in the variable FilePath and contains the full file path to the provided
        file. For example if .\test.csv were provided, this could resolve to 
        "C:\Users\grant\Documents\code\OpenManage-Enterprise\test.csv"
    #>

  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [System.IO.FileInfo] $FilePath,
    
    [Parameter(Mandatory)]
    [String] $formatextension
  )

  if (Test-Path -LiteralPath $FilePath -PathType Container) {
    Write-Error "Unable to get the file name, please provide the filename"
    throw
  }
  else {
    $folder = Split-Path -Path ([io.path]::GetFullPath($FilePath)) -Parent
    $formatfilename = $FilePath.BaseName
    $i = 1
    while (Test-Path $FilePath) {
      $filename = $formatfilename + "($i)"
      $newfilename = $filename + "." + $formatextension
      $FilePath = Join-Path $folder $newfilename
      $i++
    }
  }
  return $FilePath
}


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
    Write-Error "There was a problem connecting to OME. Did it become unavailable?"
    return $null
  }

}


try {

  $BaseUri = "https://$($IpAddress)"
  $DeviceCountUrl = $BaseUri + "/api/DeviceService/Devices"
  $NextLinkUrl = $null

  $DeviceData = Get-Data $DeviceCountUrl
    
  if ($OutFormat -eq "json") {    
    if (-not $PSBoundParameters.ContainsKey('OutFilePath') -or $OutFilePath -eq "") {
      $DeviceData | ConvertTo-Json -Depth 100
    }
    else {
      $FilePath = Get-UniqueFileName -FilePath $OutFilePath -formatextension "json"
      $jsondata | Out-File -FilePath $OutFilePath
    } 
  }
  else {
    $Devicearray = @()
    foreach ($device in $DeviceData) {
      $DirPermissions = New-Object -TypeName PSObject -Property @{
        ID                = $Device.Id
        Identifier        = $Device.Identifier
        DeviceServiceTag  = $Device.DeviceServiceTag
        ChassisServiceTag = $Device.ChassisServiceTag
        Model             = $Device.Model
        DeviceName        = $Device.DeviceName
      }
      $Devicearray += $DirPermissions
    } if ($null -eq $OutFilePath -or $OutFilePath -eq "") {
      $Devicearray | Format-Table
    }
    else {
      $FilePath = Get-UniqueFileName -FilePath $OutFilePath -formatextension "csv"
      $Devicearray | Export-Csv -Path $FilePath -NoTypeInformation
    } 
  }

}
catch {
  Write-Error "Exception occured - $($_.Exception.Message)"
}