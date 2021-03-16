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
    Performs management tasks of OME SupportAssist Enterprise (SAE) groups including creating new groups, adding devices,
    removing devices, and deleting groups.

  .DESCRIPTION
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

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
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
  .PARAMETER UseDiscoveryJobId
    This option allows you to provide the job ID from a discovery job and will pull the servers from that job ID and
    assign them to the specified group. You can either retrieve the job ID programatically or you can get it manually
    from the UI by clicking on the job and pulling it from the URL.
    Ex: https://192.168.1.93/core/console/console.html#/core/monitor/monitor_portal/jobsDetails?jobsId=14026
  .PARAMETER GenerateJson
    Generate a JSON file which can be used as input to create the SupportAssist Enterprise group. Provide the name 
    of the output JSON as an argument.
  .PARAMETER AddGroup
    Create a new SupportAssist Enterprise group. You must provide the name of the JSON file with your input settings as an argument.
  .PARAMETER RemoveGroup
    Remove a SupportAssist Enterprise group. Provide the name of the group which you would like to remove with this option.
  .PARAMETER AddDevices
    Add the specified devices to the SupportAssist Enterprise group. Specify the device IDs with -DeviceIds, -ServiceTags, 
    -IdracIps, -DeviceNames, or -UseDiscoveryJobId. The -AddDevices option accepts the name of the group to which you 
    want to add devices as an argument.
  .PARAMETER RemoveDevices
    Removes the specified devices to the SupportAssist Enterprise group. Specify the device IDs with -DeviceIds, -ServiceTags, 
    -IdracIps, -DeviceNames, or -UseDiscoveryJobId. The -RemoveDevices option accepts the name of the group to which you 
    want to remove devices as an argument.

  .EXAMPLE
    $creds = Get-Credential # Your OME credentials
    $servcreds = Get-Credential # Your OME credentials
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -GenerateJson test.json
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -AddGroup test.json
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -AddDevices 'Test Group 2' -ServiceTag CEAOEU
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -RemoveDevices 'Test Group 2' -ServiceTag CEAOEU
    .\Invoke-ManageSupportAssistGroups.ps1 -IpAddress 192.168.1.93 -Credentials $creds -RemoveGroup 'Test Group 2'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[int]] $DeviceIds,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $ServiceTags,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[System.Net.IPAddress]] $IdracIps,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $DeviceNames,

    [Parameter(Mandatory = $false)]
    [String] $UseDiscoveryJobId,

    [Parameter(Mandatory = $false, ParameterSetName = 'Action')]
    [string]$GenerateJson,

    [Parameter(Mandatory = $false, ParameterSetName = 'Action')]
    [string]$AddGroup,

    [Parameter(Mandatory = $false, ParameterSetName = 'Action')]
    [string]$RemoveGroup,

    [Parameter(Mandatory = $false, ParameterSetName = 'Action')]
    [string]$AddDevices,

    [Parameter(Mandatory = $false, ParameterSetName = 'Action')]
    [string]$RemoveDevices
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


function Get-Timezone {
  <#
    .SYNOPSIS
      Gets a list of the available timezones on the OME instance
  
    .OUTPUTS
      Returns a dictionary containing the timezones on the OME server or an empty dictionary if there
      was a problem.
  #>

  $Timezones = Get-Data -Url "https://$($IpAddress)/api/ApplicationService/Network/TimeZones"

  if ($Timezones.length -lt 1) {
    Write-Host "There was a problem retreiving the time zones! Exiting."
    return @{}
  }

  return $Timezones
}


function CreateGroupCreationPayload {
<#
  .SYNOPSIS
    Prompts the user for each field required to create the group

  .DESCRIPTION
    Prompts for each field required to create a new SupportAssist Enterprise user group and then
    generates a correctly formatted HashTable based on it.

  .OUTPUTS
    A HashTable containing all the data required to generate the group
  #>
  [CmdletBinding()]
  param (

    [Parameter(Mandatory = $false)]
    [string]
    $OutputFilePath,

    [Parameter(Mandatory = $false)]
    [string]
    $InputFilePath
  )

  $UserDataDictionary = @{
    Name = Read-Host "Group Name "
    Description = Read-Host "Description "
    ContactOptIn = Read-Confirmation "Do you want to be contacted regarding this group? This will also opt you into dispatches. (y/n)"
    MyAccountId = [int]$(Read-Host "Account ID (only numbers) ")
    CustomerDetails = $null
  }

  if ($UserDataDictionary.ContactOptIn) {

    $UserDataDictionary['DispatchOptIn'] = $true

    $CustomerDetails = @{}

    $Timezones = Get-Timezone

    if ($Timezones.length -lt 1) {
      return @{}
    }

    function _PromptForContactDetails {
      param (
        [Parameter(Mandatory = $true)]
        [string] $PromptText
      )

      $DataDictionary = @{
        FirstName = Read-Host "$($PromptText) Contact First Name"
        LastName = Read-Host "$($PromptText) Contact Last Name"
        Email = Read-Host "$($PromptText) Contact Email"
        Phone = Read-Host "$($PromptText) Contact Phone"
        AlternatePhone = Read-Host "$($PromptText) Contact Alternate Phone"
      }

      return $DataDictionary
    }

    # Primary Contact
    $CustomerDetails['PrimaryContact'] = _PromptForContactDetails 'Primary'
    $CustomerDetails['PrimaryContact']['ContactMethod'] = 'phone'
    $CustomerDetails['PrimaryContact']['TimeFrame'] = Read-Host "Primary Contact time frame in the format: 10:00 AM-4:00 PM.  WARNING: There is no input validation on this. You must match caps and spacing"

    foreach ($Timezone in $Timezones) {
      Write-Host "Name: $($Timezone.Name) Id: $($Timezone.Id)"
    }
    $CustomerDetails['PrimaryContact']['TimeZone'] = Read-Host "Primary contact timezone. Input timezone ID. (Make sure to match exactly)"

    # Secondary Contact
    $CustomerDetails['SecondaryContact'] = _PromptForContactDetails 'Secondary'
    $CustomerDetails['SecondaryContact']['ContactMethod'] = 'phone'
    $CustomerDetails['SecondaryContact']['TimeFrame'] = Read-Host "Secondary Contact time frame in the format: 10:00 AM-4:00 PM.  WARNING: There is no input validation on this. You must match caps and spacing"

    foreach ($Timezone in $Timezones) {
      Write-Host "Name: $($Timezone.Name) Id: $($Timezone.Id)"
    }
    $CustomerDetails['SecondaryContact']['TimeZone'] = Read-Host "Secondary contact timezone. Input timezone ID. (Make sure to match exactly)"

    # Shipping Details Primary Contact
    $CustomerDetails['ShippingDetails'] = @{
      PrimaryContact = _PromptForContactDetails 'Shipping Primary Contact'
      SecondaryContact = _PromptForContactDetails 'Shipping Secondary Contact'
      Country = "US"  # TODO - need to add support for other countries
      State = Read-Host 'State'
      City = Read-Host 'City'
      Zip = Read-Host 'Zip'
      Cnpj = $null
      Ie = $null
      AddressLine1 = Read-Host 'Address Line 1'
      AddressLine2 = Read-Host 'Address Line 2'
      AddressLine3 = Read-Host 'Address Line 3'
      AddressLine4 = Read-Host 'Address Line 4'
      PreferredContactTimeFrame = Read-Host "Shipping contact time frame in the format: 10:00 AM-4:00 PM.  WARNING: There is no input validation on this. You must match caps and spacing"
      TechnicianRequired = Read-Confirmation 'Is a technician required for dispatches? (y/n): '
      DispatchNotes = Read-Host 'Any dispatch notes you want to add to devices in this group'
    }

    foreach ($Timezone in $Timezones) {
      Write-Host "Name: $($Timezone.Name) Id: $($Timezone.Id)"
    }
    $CustomerDetails['ShippingDetails']['PreferredContactTimeZone'] = Read-Host "Shipping contact timezone. Input timezone ID. (Make sure to match exactly)"

    $UserDataDictionary.CustomerDetails = $CustomerDetails
  }
  else {
    $CustomerDetails.DispatchOptIn = $false
  }

  return $UserDataDictionary
}


function Confirm-IsValid {
  <#
  .SYNOPSIS
    Tests whether a filepath is valid or not.

  .DESCRIPTION
    Performs different tests depending on whether you are testing a file for the ability to read
    (InputFilePath) or write (OutputFilePath)

  .PARAMETER OutputFilePath
    The path to an output file you want to test

  .PARAMETER InputFilePath
    The path to an input file you want to test

  .OUTPUTS
    Returns true if the path is valid and false if it is not
  #>
  [CmdletBinding()]
  param (

    [Parameter(Mandatory = $false)]
    [string]
    $OutputFilePath,

    [Parameter(Mandatory = $false)]
    [string]
    $InputFilePath
  )

  if ($PSBoundParameters.ContainsKey('InputFilePath') -and $PSBoundParameters.ContainsKey('OutputFilePath')) {
    Write-Error "You can only provide either an InputFilePath or an OutputFilePath."
    Exit
  }

  # Some of the tests are the same - we can use the same variable name
  if ($PSBoundParameters.ContainsKey('InputFilePath')) {
    $OutputFilePath = $InputFilePath
  }

  if ($PSBoundParameters.ContainsKey('InputFilePath')) {
    if (-not $(Test-Path -Path $InputFilePath -PathType Leaf)) {
      Write-Error "The file $($InputFilePath) does not exist."
      return $false
    }
  }
  else {
    if (Test-Path -Path $OutputFilePath -PathType Leaf) {
      if (-not $(Read-Confirmation "$($OutputFilePath) already exists. Do you want to continue? (Y/N)")) {
        return $false
      } 
    }
  }

  $ParentPath = $(Split-Path -Path $OutputFilePath -Parent)
  if ($ParentPath -ne "") {
    if (-not $(Test-Path -PathType Container $ParentPath)) {
      Write-Error "The path '$($OutputFilePath)' does not appear to be valid."
      return $false
    }
  }

  if (Test-Path $(Split-Path -Path $OutputFilePath -Leaf) -PathType Container) {
    Write-Error "You must provide a filename as part of the path. It looks like you only provided a folder in $($OutputFilePath)!"
    return $false
  }

  return $true
}


function Read-Confirmation() {
  <#
  .SYNOPSIS
    Prompts a user with a yes or no question

  .DESCRIPTION
    Prompts a user with a yes or no question. The question text should include something telling the user
    to type y/Y/Yes/yes or N/n/No/no

  .PARAMETER QuestionText
    The text which you want to display to the user

  .OUTPUTS
    Returns true if the user enters yes and false if the user enters no
  #>
  [CmdletBinding()]
  param (

      [Parameter(Mandatory)]
      [string]
      $QuestionText
  )
  do {
      $Confirmation = (Read-Host $QuestionText).ToUpper()
  } while ($Confirmation -ne 'YES' -and $Confirmation -ne 'Y' -and $Confirmation -ne 'N' -and $Confirmation -ne 'NO')

  if ($Confirmation -ne 'YES' -and $Confirmation -ne 'Y') {
      return $false
  }

  return $true
}


function GetGroupIdByName {
  <#
  .SYNOPSIS
    Resolves the name of a group to an ID

  .PARAMETER GroupName
    The name of the group to be resolved

  .OUTPUTS
    The ID of the group or -1 if it couldn't be found
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]
    $GroupName
  )

  Write-Host "Resolving group name $($GroupName) to a group ID..."

  $GroupData = Get-Data "https://$($IpAddress)/api/GroupService/Groups" "Name eq '$($GroupName)'"

  if ($GroupData.count -lt 1) {
    Write-Error "We were unable to retrieve the GroupId for group name $($GroupName). Is the name correct?"
    return -1
  }

  Write-Host "$($GroupName)'s ID is $($GroupData.'Id')"
  return $GroupData.'Id'
  
}


Try {
  $Type = "application/json"

  $Targets = @()

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

  if (($PSBoundParameters.ContainsKey('AddDevices') -or $PSBoundParameters.ContainsKey('RemoveDevices')) -and $Targets.length -lt 1) {
      Write-Error "Error: No IDs found. Did you provide a device to add or remove?"
      Exit
  }

  if ($PSBoundParameters.ContainsKey('GenerateJson')) {

    Write-Host "Running generate JSON..."
    
    if (-not $(Confirm-IsValid -OutputFilePath $GenerateJson)) {
      Exit
    }

    CreateGroupCreationPayload | ConvertTo-Json -Depth 10 | Out-File $GenerateJson
  }
  elseif ($PSBoundParameters.ContainsKey('AddGroup')) {
    Write-Host "Creating new group..."

    $AddGroupUrl = "https://$($IpAddress)/api/SupportAssistService/Actions/SupportAssistService.CreateOrUpdateGroup"

    if (-not $(Confirm-IsValid -InputFilePath $AddGroup)) {
      Exit
    }

    try {
      Invoke-RestMethod -Method 'Post' -Uri $AddGroupUrl -Credential $Credentials -SkipCertificateCheck -Body $(Get-Content -Path $AddGroup) -ContentType $Type
    }
    catch [System.Net.Http.HttpRequestException] {
      Write-Error "There was a problem with the group creation request. This usually means there is a problem with one of the fields."
      Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
      Write-Error $_.ErrorDetails
      Exit
    }

    Write-Host "Group creation completed successfully!"
  }
  elseif ($PSBoundParameters.ContainsKey('AddDevices')) {
    Write-Host "Adding devices to the group $($AddDevices)"

    $AddDevicesUrl = "https://$($IpAddress)/api/SupportAssistService/Actions/SupportAssistService.AddMemberDevices"

    $GroupId = GetGroupIdByName $AddDevices

    if (-1 -eq $GroupId) {
      Exit
    } 

    $Payload = @{
      GroupId = $GroupId
      MemberDeviceIds = $Targets
    } | ConvertTo-Json -Depth 10

    try {
      Invoke-RestMethod -Method 'Post' -Uri $AddDevicesUrl -Credential $Credentials -SkipCertificateCheck -Body $Payload -ContentType $Type
      Write-Host "Devices added successfully!"
    }
    catch [System.Net.Http.HttpRequestException] {
      Write-Error "There was a problem adding the devices to the group."
      Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
      Write-Error $_.ErrorDetails
      Exit
    }

  }
  elseif ($PSBoundParameters.ContainsKey('RemoveDevices')) {
    Write-Host "Removing devices from the group $($RemoveDevices)"

    $RemoveDevicesUrl = "https://$($IpAddress)/api/SupportAssistService/Actions/SupportAssistService.RemoveMemberDevices"

    $GroupId = GetGroupIdByName $RemoveDevices

    if (-1 -eq $GroupId) {
      Exit
    } 

    $Payload = @{
      GroupId = $GroupId
      MemberDeviceIds = $Targets
    } | ConvertTo-Json -Depth 10

    try {
      Invoke-RestMethod -Method 'Post' -Uri $RemoveDevicesUrl -Credential $Credentials -SkipCertificateCheck -Body $Payload -ContentType $Type
      Write-Host "Devices removed successfully!"
    }
    catch [System.Net.Http.HttpRequestException] {
      Write-Error "There was a problem removing the devices from the group."
      Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
      Write-Error $_.ErrorDetails
      Exit
    }
  }
  elseif ($PSBoundParameters.ContainsKey('RemoveGroup')) {
    Write-Host "Removing the group $($RemoveGroup)..."

    $AddGroupUrl = "https://$($IpAddress)/api/SupportAssistService/Actions/SupportAssistService.DeleteGroup"

    $GroupId = GetGroupIdByName $RemoveGroup

    if (-1 -eq $GroupId) {
      Exit
    } 

    $Payload = @{
      GroupId = $GroupId
    } | ConvertTo-Json -Depth 10

    try {
      Invoke-RestMethod -Method 'Post' -Uri $AddGroupUrl -Credential $Credentials -SkipCertificateCheck -Body $Payload -ContentType $Type
    }
    catch [System.Net.Http.HttpRequestException] {
      Write-Error "There was a problem with the group deletion request. This usually means there is a problem with one of the fields."
      Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
      Write-Error $_.ErrorDetails
      Exit
    }

    Write-Host "Group deletion completed successfully!"
  }

}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
