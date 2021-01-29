<#
_author_ = Chris Steinbeisser <chris.steinbeisser@Dell.com>
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
   Script to add users to OpenManage Enterprise
 .DESCRIPTION
   This script uses the OME REST API to add users to OpenManage Enterprise. 
   For authentication X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.
 .PARAMETER IpAddress
   IP Address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER NewUserCredentials
   Credentials for the new user
 .PARAMETER NewUserRole
   The role you would like to assign the user. The default roles in OME include "VIEWER", "DEVICE_MANAGER", and "ADMINISTRATOR". You may add your own.
 .PARAMETER NewUserDescription
   Description of the new user in the form of 'a string like this'. The default is "User created via the OME API."
 .PARAMETER NewUserLocked
   Add this switch to lock the user after creation. False by default.
 .PARAMETER NewUserEnabled
   Add this switch to enable the user after creation. True by default.

 .EXAMPLE
   $cred = Get-Credential
   $newusercred = Get-Credential
   .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -NewUserCredentials $newusercred -NewUserRole ADMINISTRATOR
   .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -NewUserCredentials $newusercred -NewUserRole ADMINISTRATOR -NewUserDescription 'This is a description of the user'
   .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -NewUserCredentials $newusercred -NewUserRole ADMINISTRATOR -NewUserLocked
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [pscredential] $NewUserCredentials,

    [Parameter(Mandatory)]
    [string] $NewUserRole,

    [Parameter(Mandatory=$false)]
    [string] $NewUserDescription = "User created via the OME API.",

    [Parameter(Mandatory=$false)]
    [boolean] $NewUserLocked = $false,

    [Parameter(Mandatory=$false)]
    [boolean]  $NewUserEnabled = $true
)

function Get-Data {
    <#
    .SYNOPSIS
        Used to interact with API resources

    .DESCRIPTION
        This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
        handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
        pages to get a complete listing. Assumes there is a variable called Credentials with OME's credentials.

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
        $NextLinkUrl = $BaseUri + $CountData.'@odata.nextLink'
        }

        $i = 1
        while ($NextLinkUrl) {
        if ($MaxPages) {
            if ($i -ge $MaxPages) {
            break
            }
            $i = $i + 1
        }
        $NextLinkData = Invoke-RestMethod -Uri "https://$($IpAddress)$($NextLinkUrl)" -Method Get -Credential $Credentials `
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
        return @{}
    }

}


try {

    $Roles = Get-Data "https://$($IpAddress)/api/AccountService/Roles"
    $FoundRole = $false

    Write-Host "Searching OME for the requested role..."
    foreach ($Role in $Roles) {
        if ($NewUserRole -eq $Role.Name) {
            $RoleId = $Role.Id
            $FoundRole = $True
            Write-Host "Found role $($NewUserRole)!"
            break
        }
    }

    if (-not $FoundRole) {
        Write-Error "We did not find the role $($NewUserRole). The possible roles on this OME server are:"
        foreach($Role in $Roles) {
            Write-Host $Role.Name
        }
        Exit
    }

    $AccountInfo = @{
        UserName = $NewUserCredentials.GetNetworkCredential().UserName
        Password = $NewUserCredentials.GetNetworkCredential().Password
        RoleId = $RoleId
        Locked = $NewUserLocked
        Enabled = $NewUserEnabled
        Description = $NewUserDescription
        UserTypeId = 1
        DirectoryServiceId = 0      
        } | ConvertTo-Json
    Write-Host "Creating new user..."
    try {
        $AccountsUrlResp = Invoke-RestMethod -Uri "https://$($IpAddress)/api/AccountService/Accounts" -Method Post -Headers $Headers -ContentType "application/json" -Body $AccountInfo -SkipCertificateCheck -Credential $Credentials
    }
    catch [System.Net.Http.HttpRequestException] {
        Write-Error "Creating the new user failed. Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
        Write-Error "Error details are $($_.ErrorDetails)"
        Exit
    }

    Write-Host "URLStatusCode ->  $($AccountsUrlResp.StatusCode) Success"
    Write-Host "Successfully created user $($NewUserCredentials.GetNetworkCredential().UserName)!"
}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
