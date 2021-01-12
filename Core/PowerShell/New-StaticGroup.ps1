<#
_author_ = Raajeev Kalyanaraman <raajeev.kalyanaraman@Dell.com>

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
    Script to create a static group in OME
  .DESCRIPTION

    This script uses the OME REST API to create a new 
    static group in OME. The user will need to manually add
    devices to this newly created group. For authentication
    X-Auth is used over Basic Authentication

    Note that the credentials entered are not stored to disk.

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
  .PARAMETER GroupName
    Name for the static group to be created
  .PARAMETER GroupDescription
    An optional description for your group
  .EXAMPLE
    $cred = Get-Credential
    .\New-StaticGroup.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -GroupName "Test_OME_Group"

  .EXAMPLE
    .\New-StaticGroup.ps1 -IpAddress "10.xx.xx.xx" -GroupName "Test_OME" -GroupDescription "This is my group"
    In this instance you will be prompted for credentials to use
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [string] $GroupName,

    [Parameter(Mandatory=$false)]
    [string] $GroupDescription = ""
)


Try {
    Write-Host "Getting the ID for Static Groups..."
    $Type = "application/json"
    $StaticGrpResp = Invoke-RestMethod -Uri "https://$($IpAddress)/api/GroupService/Groups?`$filter=Name eq 'Static Groups'" `
                                       -Method Get -Credential $Credentials -SkipCertificateCheck
                                          
    $StaticGrpId = $StaticGrpResp.value[0].Id
    $GrpPayload = @{
        GroupModel = @{
            Name             = $GroupName;
            Description      = $GroupDescription;
            MembershipTypeId = 12;
            ParentId         = [uint32]$StaticGrpId
        }
    } | ConvertTo-Json -Depth 6

    Write-Host "Creating new group..."
    $CreateResp = Invoke-RestMethod -Uri "https://$($IpAddress)/api/GroupService/Actions/GroupService.CreateGroup" `
                                    -Method POST -ContentType $Type -Body $GrpPayload -Credential $Credentials -SkipCertificateCheck
    Write-Host "New group created - ID: $($CreateResp)"
}
catch {
    Write-Error "Check if the group name already exists in OME and retry... Exception was: $($_.Exception.Message)"
}
