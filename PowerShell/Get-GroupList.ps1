<#
_author_ = Raajeev Kalyanaraman <raajeev.kalyanaraman@Dell.com>

Copyright (c) 2022 Dell EMC Corporation

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
   Script to get the list of groups managed by OM Enterprise
 .DESCRIPTION

   This script uses the OME REST API to get a list of groups
   currently being managed by that instance. For authentication X-Auth
   is used over Basic Authentication

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance

 .EXAMPLE
   $cred = Get-Credential
   .\Get-GroupList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred

 .EXAMPLE
   .\Get-GroupList.ps1 -IpAddress "10.xx.xx.xx"
   In this instance you will be prompted for credentials to use
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [System.Net.IPAddress] $IpAddress,

  [Parameter(Mandatory)]
  [pscredential] $Credentials
)

Try {

  $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups"
  $Type = "application/json"
  $Headers = @{}

  $GroupInfo = Invoke-RestMethod -SkipCertificateCheck -Uri $GroupUrl -Method Get -Headers $Headers -ContentType $Type -Credential $Credentials
  $GroupInfo.'value' |  Sort-Object Id |  Format-Table -Property Id, Name, Description, CreationTime, UpdatedTime

}
catch {
  Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}