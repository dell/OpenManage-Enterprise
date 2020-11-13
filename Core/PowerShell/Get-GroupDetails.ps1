<#
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
   Script to retrieve the details for a group including
   all devices contained by that group
 .DESCRIPTION

   This script exercises the OME REST API to get the details
   for a group and for devices in that group. The group can
   be filtered using the Group ID or Name or Description.
   This example does not use ODATA queries with filter
   constructs.

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER GroupInfo
   Group ID or Name or Description

   .EXAMPLE
   $cred = Get-Credential
   .\Get-GroupDetails.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
   -GroupInfo "Dell iDRAC server devices"

 .EXAMPLE
   .\Get-GroupDetails.ps1 -IpAddress "10.xx.xx.xx" -GroupInfo 1008
   In this instance you will be prompted for credentials to use to
   connect to the appliance
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [String] $GroupInfo
)

function Set-CertPolicy() {
    ## Trust all certs - for sample usage only
    Try {
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Error "Unable to add type for cert policy"
    }
}





Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups"
    $Type = "application/json"
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName" = $UserName; "Password" = $Password; "SessionType" = "API" } | ConvertTo-Json
    $Headers = @{}
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        ## Successfully created a session - extract the auth token from the response
        ## header and update our headers for subsequent requests
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        $GrpResp = Invoke-WebRequest -Uri $GroupUrl -Method Get -Headers $Headers -ContentType $Type
        if ($GrpResp.StatusCode -eq 200) {
            ## Iterate over groups and see if a match is found for given criteria
            $GrpInfo = $GrpResp.Content | ConvertFrom-Json
            $groupList = $GrpInfo.value
            $groupCount = $GrpInfo.'@odata.count'
            if ($groupCount -gt 0) {
                $FoundGroup = $FALSE
                $currGroupCount = ($groupList.value).Length
                if ($groupCount -gt $currGroupCount) {
                    $delta = $groupCount - $currGroupCount
                    $RemainingGroupUrl = $GroupUrl + "?`$skip=$($currGroupCount)&`$top=$($delta)"
                    $remainingGroupResp = Invoke-WebRequest -Uri $RemainingGroupUrl -Method Get -Headers $Headers -ContentType $Type
                    if ($remainingGroupResp.StatusCode -eq 200) {
                        $remGroupInfo = $remainingGroupResp.Content | ConvertFrom-Json
                        $groupList += $remGroupInfo.value
                    }
                }
                foreach ($Group in $GrpInfo.'value') {
                    if ($Group.Id -eq $GroupInfo -or
                        ([String]($Group.Name)).ToLower() -eq $GroupInfo.ToLower() -or
                        ([String]($Group.Description)).ToLower() -eq $GroupInfo.ToLower()) {
                        $FoundGroup = $TRUE
                        Write-Output "*** Group Details ***"
                        $Group | Format-List
                        $DevUrl = $GroupUrl + "(" + [String]($Group.Id) + ")/Devices"
                        $DevResp = Invoke-WebRequest -Uri $DevUrl -Method Get -Headers $Headers -ContentType $Type
                        if ($DevResp.StatusCode -eq 200) {
                            $DevInfo = $DevResp.Content | ConvertFrom-Json
                            $DevList = $DevInfo.value
                            $deviceCount = $DevInfo.'@odata.count'
                            if ($deviceCount -gt 0) {
                                $currDeviceCount = ($DevInfo.value).Length
                                if ($deviceCount -gt $currDeviceCount) {
                                    $delta = $deviceCount - $currDeviceCount 
                                    $RemainingDeviceurl = $DevUrl + "?`$skip=$($currDeviceCount)&`$top=$($delta)"
                                    $RemainingDeviceResp = Invoke-WebRequest -Uri $RemainingDeviceurl -Method Get -Headers $Headers -ContentType $Type
                                    if ($RemainingDeviceResp.StatusCode -eq 200) {
                                        $RemainingDeviceInfo = $RemainingDeviceResp.Content | ConvertFrom-Json
                                        $DevList += $RemainingDeviceInfo.value
                                    }
                                    else {
                                        Write-Error "Unable to get full set of devices ... "
                                    }
                                }

                                Write-Output "*** Group Device Details ***"
                                #$Devices = $DevResp.Content | ConvertFrom-Json
                                $DevList | Format-List
                            }
                            else {
                                Write-Warning "No devices found in group ($($GroupInfo))"
                            }
                        }
                        else {
                            Write-Warning "Unable to retrieve devices for group ($($GroupInfo)) from $($IpAddress)"
                        }
                    }
                }
                if (-not $FoundGroup) {
                    Write-Warning "No group matching ($($GroupInfo)) found"
                }
            }
            else {
                Write-Warning "No group data retrieved from $($IpAddress)"
            }
            #$GrpResp.Content | ConvertFrom-Json | ConvertTo-Json -Depth 4
        }
        else {
            Write-Error "Unable to retrieve group list from $($IpAddress)"
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}