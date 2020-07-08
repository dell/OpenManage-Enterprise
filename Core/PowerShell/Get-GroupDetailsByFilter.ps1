<#
_author_ = Raajeev Kalyanaraman <raajeev.kalyanaraman@Dell.com>
_version_ = 0.1

Copyright (c) 2018 Dell EMC Corporation

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
   be filtered using the Group Name or Description.
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
   .\Get-GroupDetailsByFilter.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -FilterBy Description -GroupInfo "Dell iDRAC server devices"

 .EXAMPLE
   .\Get-GroupDetailsByFilter.ps1 -IpAddress "10.xx.xx.xx" -FilterBy
    Name -GroupInfo "Dell iDRAC Servers"
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
    [ValidateSet("Name","Description")]
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
    Catch {
        Write-Error "Unable to add type for cert policy"
    }
}

Try {
    Set-CertPolicy
    $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions"
    $GroupUrl    = "https://$($IpAddress)/api/GroupService/Groups?`$filter=$($FilterBy) eq '$($GroupInfo)'"
    $Type        = "application/json"
    $UserName    = $Credentials.username
    $Password    = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName"=$UserName;"Password"=$Password;"SessionType"="API"} | ConvertTo-Json
    $Headers     = @{}

    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        ## Successfully created a session - extract the auth token from the response
        ## header and update our headers for subsequent requests
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        $GrpResp = Invoke-WebRequest -Uri $GroupUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($GrpResp.StatusCode -eq 200) {
            $GrpInfo = $GrpResp.Content | ConvertFrom-Json
            if ($GrpInfo.'@odata.count' -gt 0) {
                ## Only one group matching criteria should be found
                $GroupId = $GrpInfo.value[0].Id
                Write-Output "*** Group Details ***"
                $GrpInfo.value | Format-List

                $DevUrl = "https://$($IpAddress)/api/GroupService/Groups($($GroupId))/Devices"
                $DevResp = Invoke-WebRequest -Uri $DevUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                if ($DevResp.StatusCode -eq 200) {
                    $DevInfo = $DevResp.Content | ConvertFrom-Json
                    if ($DevInfo.'@odata.count' -gt 0) {
                        Write-Output "*** Group Device Details ***"
                        $Devices = $DevResp.Content | ConvertFrom-Json
                        $Devices.'value' | Format-List
                    }
                    else {
                        Write-Warning "No devices found in group ($($GroupInfo))"
                    }
                }
                else {
                    Write-Warning "Unable to retrieve devices for group ($($GroupInfo)) from $($IpAddress)"
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
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}