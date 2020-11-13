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
   Script to retrieve the alerts for a group 

 .DESCRIPTION

   This script exercises the OME REST API to get the alerts
   for a group. The group can be filtered using the Group Name
   or Description.
   This example uses ODATA queries with filter constructs.

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER FilterBy
   Express filter criteria - name or description of group
 .PARAMETER GroupInfo
   The actual group name or description to search against
   Note that this is a case sensitive search.

 .EXAMPLE
   $cred = Get-Credential
   .\Get-AlertsByGroup.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -FilterBy Description -GroupInfo "Dell iDRAC server devices"

 .EXAMPLE
   .\Get-AlertsByGroup.ps1 -IpAddress "10.xx.xx.xx" -FilterBy Name -GroupInfo "Dell iDRAC Servers"
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
    [ValidateSet("Name", "Description")]
    [String] $FilterBy,

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
    $BaseUri = "https://$($IpAddress)"
    $SessionUrl = $BaseUri + "/api/SessionService/Sessions"
    $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups?`$filter=$($FilterBy) eq '$($GroupInfo)'"
    $NextLinkUrl = $null
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
            $GrpInfo = $GrpResp.Content | ConvertFrom-Json
            if ($GrpInfo.'@odata.count' -gt 0) {
                $GroupId = $GrpInfo.value[0].Id
                $AlertUrl = "https://$($IpAddress)/api/AlertService/Alerts?`$filter=AlertDeviceGroup eq $($GroupId)"
                $AlertResp = Invoke-WebRequest -Uri $AlertUrl -Method Get -Headers $Headers -ContentType $Type
                if ($AlertResp.StatusCode -eq 200) {
                    $AlertInfo = $AlertResp.Content | ConvertFrom-Json
                    $AlertList = $AlertInfo.value
                    $TotalCount = $AlertInfo.'@odata.count'
                    if ($TotalCount -gt 0) {
                        if ($AlertInfo.'@odata.nextLink') {
                            $NextLinkUrl = $BaseUri + $AlertInfo.'@odata.nextLink'
                        }
                        while ($NextLinkUrl) {
                            $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -Method Get -Headers $Headers -ContentType $Type
                            if ($NextLinkResponse.StatusCode -eq 200) {
                                $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                                $AlertList += $NextLinkData.'value'
                                if ($NextLinkData.'@odata.nextLink') {
                                    $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                                }
                                else {
                                    $NextLinkUrl = $null
                                }
                            }
                            else {
                                Write-Error "Unable to get full set of Alerts ... "
                                $NextLinkUrl = $null
                            }
                        }
                        Write-Output "*** Alerts for group ($($GroupInfo))***"
                        $AlertList | Format-List
                    }
                    else {
                        Write-Warning "No alerts found for group ($($GroupInfo))"
                    }
                }
                else {
                    Write-Warning "Unable to retrieve alerts for group ($($GroupInfo)) from $($IpAddress)"
                }
            }
            else {
                Write-Warning "No group matching field ($($GroupInfo)) retrieved from $($IpAddress)"
            }
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