#Requires -Version 7

<#
_author_ = Grant Curell <grant_curell@dell.com>
_contributor_ = Raajeev Kalyanaraman wrote the method for getting alerts by group

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
    Retrieves alerts from a target OME Instance.

  .DESCRIPTION

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

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance

  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance

  .PARAMETER Top
    Top records to return.

  .PARAMETER Pages
    You will generally not need to change this unless you are using a large value for top
    - typically more than 50 devices. In the UI the results come in pages. Even when
    not using the UI the results are still delivered in 'pages'. The 'top' argument
    effectively sets the page size to the value you select and will return *everything*
    , albeit much slower, by iterating over all pages in OME. To prevent this we tell it
    to only return a certain number of pages. By default this value is 1. If you want
    more than one page of results you can set this.

  .PARAMETER Skip
    The number of records, starting at the top, to skip.

  .PARAMETER Orderby
    Order to apply to the output.

  .PARAMETER Id
    Filter by the OME internal event ID.

  .PARAMETER AlertDeviceId
    Filter by OME internal device ID.

  .PARAMETER AlertDeviceIdentifier
    Filter by the device identifier. For servers this is the service tag.

  .PARAMETER AlertDeviceType
    Filter by device type.

  .PARAMETER SeverityType
    Filter by the severity type of the alert.

  .PARAMETER StatusType
    Filter by status type of the device.

  .PARAMETER CategoryName
    Filter by category name.

  .PARAMETER GetSubcategories
    Grabs a list of subcategories from the OME instance.

  .PARAMETER SubcategoryId
    Filter by subcategory ID. To get a list of subcategory IDs available run this program 
    with the --get-subcategories option.

  .PARAMETER SubcategoryName
    Filter by subcategory name. To get a list of subcategory names available run this 
    program with the --get-subcategories option.

  .PARAMETER Message
    Filter by message.

  .PARAMETER TimeStampBegin
    Filter by starting time of alerts. Use format YYYY-MM-DD HH:MM:SS.SS. Ex: 2021-09-07 19:01:28.46
    You must surround it with quotes '

  .PARAMETER TimeStampEnd
    Filter by ending time of alerts. Use format YYYY-MM-DD HH:MM:SS.SS. Ex: 2021-09-07 19:01:28.46
    You must surround it with quotes '

  .PARAMETER AlertDeviceName
    Filter by the OME device name.

  .PARAMETER AlertsByGroupName
    The name of the group on which you want to filter.

  .PARAMETER AlertsByGroupDescription
    The description of the group on which you want to filter.

  .EXAMPLE
    $creds = Get-Credential
    Get-Alerts.ps1 -IpAddress 192.168.1.93 -Credentials $creds -CategoryName SYSTEM_HEALTH -Top 10
    Get-Alerts.ps1 -IpAddress 192.168.1.93 -Credentials $creds -Top 5 -Skip 3 -Orderby TimeStampAscending -StatusType CRITICAL
    Get-Alerts.ps1 -IpAddress 192.168.1.85 -Credentials $creds -TimeStampEnd '2021-09-07 19:01:28.46' -TimeStampBegin '2015-09-07 19:01:28.46' -CategoryName SYSTEM_HEALTH -Top 10
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory = $false)]
    [string] $Top,

    [Parameter(Mandatory = $false)]
    [int] $Pages,

    [Parameter(Mandatory = $false)]
    [string] $Skip,

    [Parameter(Mandatory = $False)]
    [ValidateSet('AlertDeviceIdentifier', 'AlertDeviceType', 'SeverityType',
        'StatusType', 'SubCategoryName', 'Message', 'TimeStampDescending', 
        'TimeStampAscending')]
    [String] $Orderby,

    [Parameter(Mandatory = $false)]
    [string] $Id,

    [Parameter(Mandatory = $false)]
    [string] $AlertDeviceId,

    [Parameter(Mandatory = $false)]
    [string] $AlertDeviceIdentifier,

    [Parameter(Mandatory = $false)]
    [ValidateSet('SERVER', 'CHASSIS', 'NETWORK_CONTROLLER', 'NETWORK_IOM', 'STORAGE', 'STORAGE_IOM')]
    [string] $AlertDeviceType,

    [Parameter(Mandatory = $false)]
    [ValidateSet('WARNING', 'CRITICAL', 'INFO', 'NORMAL', 'UNKNOWN')]
    [string] $SeverityType,

    [Parameter(Mandatory = $false)]
    [ValidateSet('NORMAL', 'UNKNOWN', 'WARNING', 'CRITICAL', 'NOSTATUS')]
    [string] $StatusType,

    [Parameter(Mandatory = $false)]
    [ValidateSet('AUDIT', 'CONFIGURATION', 'MISCELLANEOUS', 'STORAGE', 'SYSTEM_HEALTH', 'UPDATES',
        'WORK_NOTES')]
    [string] $CategoryName,

    [Parameter(Mandatory = $false)]
    [Switch] $GetSubcategories,

    [Parameter(Mandatory = $false)]
    [string] $SubcategoryId,

    [Parameter(Mandatory = $false)]
    [string] $SubcategoryName,

    [Parameter(Mandatory = $false)]
    [string] $Message,

    [Parameter(Mandatory = $false)]
    [string] $TimeStampBegin,

    [Parameter(Mandatory = $false)]
    [string] $TimeStampEnd,

    [Parameter(Mandatory = $false)]
    [string] $AlertDeviceName,

    [Parameter(Mandatory = $false)]
    [string] $AlertsByGroupName,

    [Parameter(Mandatory = $false)]
    [string] $AlertsByGroupDescription
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

$SEVERITYTYPEMAP = 
@{
    WARNING  = '8'
    CRITICAL = '16'
    INFO     = '2'
    NORMAL   = '4'
    UNKNOWN  = '1'
}

$STATUSTYPEMAP =   
@{
    NORMAL   = '1000'
    UNKNOWN  = '2000'
    WARNING  = '3000'
    CRITICAL = '4000'
    NOSTATUS = '5000'
}

$ALERTDEVICETYPEMAP = 
@{
    SERVER             = '1000'
    CHASSIS            = '2000'
    NETWORK_CONTROLLER = '9000'
    NETWORK_IOM        = '4000'
    STORAGE            = '3000'
    STORAGE_IOM        = '8000'
}

$CATEGORYIDMAP = 
@{
    AUDIT         = 4
    MISCELLANEOUS = 7
    STORAGE       = 2
    SYSTEM_HEALTH = 1
    UPDATES       = 3
    WORK_NOTES    = 6
    CONFIGURATION = 5
}

try {
  
    if ($PSBoundParameters.ContainsKey('GetSubcategories')) {
        Write-Output Get-Data "https://$($IpAddress)/api/AlertService/AlertCategories"
    }

    if ($PSBoundParameters.ContainsKey('Pages') -and -not $PSBoundParameters.ContainsKey('Top')) {
        Write-Error "You cannot provide the pages argument without the top argument."
        Exit
    }

    if ($PSBoundParameters.ContainsKey('Top') -and -not $PSBoundParameters.ContainsKey('Pages')) {
        $Pages = 1
    }

    $AuditLogsUrl = "https://$($IpAddress)/api/AlertService/Alerts"

    $UserOdataFilter = @()

    if ($PSBoundParameters.ContainsKey('Id')) {
        $UserOdataFilter += "Id eq $($Id)"
    }

    if ($PSBoundParameters.ContainsKey('AlertDeviceId')) {
        $UserOdataFilter += "AlertDeviceId eq %$($AlertDeviceId)"
    }
  
    if ($PSBoundParameters.ContainsKey('AlertDeviceIdentifier')) {
        $UserOdataFilter += "AlertDeviceIdentifier eq '$($AlertDeviceIdentifier)'"
    }
  
    if ($PSBoundParameters.ContainsKey('AlertDeviceType')) {
        $UserOdataFilter += "AlertDeviceType eq $($ALERTDEVICETYPEMAP[$AlertDeviceType])"
    }

    if ($PSBoundParameters.ContainsKey('StatusType')) {
        $UserOdataFilter += "StatusType eq $($STATUSTYPEMAP[$StatusType])"
    }

    if ($PSBoundParameters.ContainsKey('SeverityType')) {
        $UserOdataFilter += "SeverityType eq $($SEVERITYTYPEMAP[$SeverityType])"
    }

    if ($PSBoundParameters.ContainsKey('CategoryName')) {
        $UserOdataFilter += "CategoryId eq $($CATEGORYIDMAP[$CategoryName])"
    }
  
    if ($PSBoundParameters.ContainsKey('SubcategoryId')) {
        $UserOdataFilter += "SubCategoryId eq $($SubcategoryId)"
    }
  
    if ($PSBoundParameters.ContainsKey('SubcategoryName')) {
        $UserOdataFilter += "SubCategoryName eq '$($SubcategoryName)'"
    }

    if ($PSBoundParameters.ContainsKey('AlertDeviceName')) {
        $UserOdataFilter += "AlertDeviceName eq '$($AlertDeviceName)'"
    }

    if ($PSBoundParameters.ContainsKey('Message')) {
        $UserOdataFilter += "Message eq '$($Message)'"
    }

    if ($PSBoundParameters.ContainsKey('TimeStampBegin')) {
        $UserOdataFilter += "TimeStamp ge '$($TimeStampBegin)'"
    }

    if ($PSBoundParameters.ContainsKey('TimeStampEnd')) {
        $UserOdataFilter += "TimeStamp le '$($TimeStampEnd)'"
    }


    $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups"
    $Groups = $null
    $GroupId = ""

    if ($PSBoundParameters.ContainsKey('AlertsByGroupName')) {

        $Groups = Get-Data $GroupUrl "Name eq '$($AlertsByGroupName)'"

        if ($Groups.Length -lt 1) {
            Write-Error "Error: We were unable to find a group matching the name $($AlertsByGroupName)."
            Exit
        }

        $GroupId = $Groups[0].'Id'

    }
    elseif ($PSBoundParameters.ContainsKey('AlertsByGroupDescription')) {
        $Groups = Get-Data $GroupUrl "Description eq '$($AlertsByGroupDescription)'"

        if ($Groups.Length -lt 1) {
            Write-Error "Error: We were unable to find a group matching the description $($AlertsByGroupDescription)."
            Exit
        }

        $GroupId = $Groups[0].'Id'
    }

    if ($PSBoundParameters.ContainsKey('AlertsByGroupDescription') -or $PSBoundParameters.ContainsKey('AlertsByGroupName')) {
        $UserOdataFilter += "AlertDeviceGroup eq $($GroupId)"
    }

    $UrlFilter = $null
    if ($UserOdataFilter.Length -gt 0) {
        $UrlFilter = ''
        ForEach ($Index in (0..($UserOdataFilter.Count - 1))) {
            # Do not append and on the last element of the filter
            if ($Index -eq $UserOdataFilter.Count - 1) {
                $UrlFilter += $UserOdataFilter[$Index]
            }
            else {
                $UrlFilter += "$($UserOdataFilter[$Index]) and "
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('Orderby')) {
        if ($Orderby -eq "TimeStampAscending") {
            $Orderby = "TimeStamp asc"
        }
        if ($Orderby -eq "TimeStampDescending") {
            $Orderby = "TimeStamp desc"
        }
    }

    # These are arguments which aren't filters: top, skip, and orderby
    $NonfilterArgs = @()
    if ($null -eq $UrlFilter) {
        if ($PSBoundParameters.ContainsKey('Top')) {
            $NonfilterArgs += "top=$($Top)"
        }
        if ($PSBoundParameters.ContainsKey('Skip')) {
            $NonfilterArgs += "skip=$($Skip)"
        }
        if ($PSBoundParameters.ContainsKey('Orderby')) {
            $NonfilterArgs += "orderby=$($Orderby)"
        }

        # Create the URL if there is no filter argument
        $NonFilterUrl = $null
        if ($NonfilterArgs.Length -gt 0) {
            $NonFilterUrl = ''
            ForEach ($Index in (0..($NonfilterArgs.Count - 1))) {
                # Do not append &$ on the last element of the filter
                if ($Index -eq 0) {
                    $NonFilterUrl += "?`$$($NonfilterArgs[$Index])"
                }
                else {
                    $NonFilterUrl += "&`$$($NonfilterArgs[$Index])"
                }
            }
            $AuditLogsUrl = $AuditLogsUrl + $NonFilterUrl
        }
    }
    else {
        if ($PSBoundParameters.ContainsKey('Top')) {
            $UrlFilter += "&`$top=$($Top)"
        }
        if ($PSBoundParameters.ContainsKey('Skip')) {
            $UrlFilter += "&`$skip=$($Skip)"
        }
        if ($PSBoundParameters.ContainsKey('Orderby')) {
            $UrlFilter += "&`$orderby=$($Orderby)"
        }
    }

    if ($null -ne $UrlFilter) {
        Write-Output "The URL is $($AuditLogsUrl)?`$filter=$($UrlFilter)"
        Write-Output "You can modify this URL in accordance with the odata 4 standard. See http://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part2-url-conventions.html for details."
        $Output = Get-Data $AuditLogsUrl $UrlFilter $Pages
        Write-Output $Output
    }
    else {
        Write-Output "The URL is $($AuditLogsUrl)"
        $Output = Get-Data -Url $AuditLogsUrl -MaxPages $Pages
        Write-Output $Output
    }
}
catch {
    Write-Error "Exception occurred at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}

# https://192.168.1.85/api/AlertService/Alerts?$filter=TimeStamp%20ge%20%272021-09-07%2019:01:22.483%27 - working