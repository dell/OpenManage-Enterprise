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
   Script to create a static group in OME
 .DESCRIPTION

   This script exercises the OME REST API to create a new 
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


 .EXAMPLE
   $cred = Get-Credential
   .\New-StaticGroup.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
        -GroupName "Test_OME_Group"

 .EXAMPLE
   .\New-StaticGroup.ps1 -IpAddress "10.xx.xx.xx" -GroupName "Test_OME"
   In this instance you will be prompted for credentials to use
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [string] $GroupName    
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
    $StaticGrp   = "https://$($IpAddress)/api/GroupService/Groups?`$filter=Name eq 'Static Groups'"
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
        $StaticGrpResp = Invoke-WebRequest -Uri $StaticGrp -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($StaticGrpResp.StatusCode -eq 200) {
            $StaticGrpInfo = $StaticGrpResp.Content | ConvertFrom-Json
            $StaticGrpId = $StaticGrpInfo.Value[0].Id
            $GrpInfo = @{
                "Name"=$GroupName;
                "Description"="";
                "MembershipTypeId"=12;
                "ParentId"=[uint32]$StaticGrpId
                }
            $GrpPayload = @{"GroupModel"=$GrpInfo} | ConvertTo-Json
            $GrpCreateUrl = "https://$($IpAddress)/api/GroupService/Actions/GroupService.CreateGroup"

            $CreateResp = Invoke-WebRequest -Uri $GrpCreateUrl -UseBasicParsing -Me Post -H $Headers -Con $Type -Body $GrpPayload
            if ($CreateResp.StatusCode -eq 200) {
                Write-Host "new group created - ID:$($CreateResp)"
            }
            else {
                ## going to throw an exception if the group name already exists
            }

        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Check if the group name already exists in OME and retry...Exception: $($_.Exception.Message)"
}