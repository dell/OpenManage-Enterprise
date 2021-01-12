<#
_author_ = Chris Steinbeisser <chris.steinbeisser@Dell.com>
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
   Script to add users to OpenManage Enterprise
 .DESCRIPTION
   This script exercises the OME REST API to add users to OpenManage Enterprise. 
   For authentication X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.
 .PARAMETER IpAddress
   IP Address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER new_UserName
   New OME local user to add to OME Appliance
 .PARAMETER new_UserPassword
   New OME local user password to add to OME Appliance
 .PARAMETER new_UserRole
   Assign new basic OME local user role [viewer(16)||adminastrator(10)] 
 .PARAMETER new_UserLocked
   New OME local user locked [1(true) || 0(false)] 
 .PARAMETER new_UserEnabled
   New OME local user enabled [1(true)|| 0(false)] 

 .EXAMPLE
  .\New-OMEntUser.ps1
  In this instance the script prompts for all parameters including login credentials for the OME Appliance
 .EXAMPLE
   $cred = Get-Credential
   .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -new_UserName "Buddy" -new_UserPassword "Test123!" -new_UserRole 10 -new_UserLocked 0 -new_UserEnabled 1
 .EXAMPLE
   .\New-OMEntUser.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -new_UserName "Buddy" -new_UserPassword "Test123!" -new_UserRole 10
  In this instance you will be prompted just for the OME Appliance credentials

 .LINK
   Dell OME 3.3.1 RESTful API Accounts PUT Method: https://www.dell.com/support/manuals/us/en/04/dell-openmanage-enterprise/ome-3.3.1_omem-1.10.00_apiguide/put-method-for-accountsid?guid=guid-4edc1d5b-1119-4590-a0d9-8b497ac0553b&lang=en-us


#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [string] $new_UserName,

    [Parameter(Mandatory)]
    [string] $new_UserPassword,

    [Parameter(Mandatory)]
    [string] $new_UserRole,

    [Parameter(Mandatory)]
    [boolean] $new_UserLocked,

    [Parameter(Mandatory)]
    [boolean]  $new_UserEnabled


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
    $AccountsUrl   = "https://$($IpAddress)/api/AccountService/Accounts"
    $Type        = "application/json"
    $UserName    = $Credentials.username
    $Password    = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName"=$UserName;"Password"=$Password;"SessionType"="API"} | ConvertTo-Json
    $Headers     = @{}
    $AccountInfo = @{}

    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        ## Successfully created a session - extract the auth token from the response
        ## header and update our headers for subsequent requests
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
               $AccountInfo = @{
                "UserName"=$new_UserName;
                "Password"=$new_UserPassword;
                "RoleId"=$new_UserRole;
                "Locked"=$new_UserLocked;
                "Enabled"=$new_UserEnabled;
                "UserTypeId"=1;
                "DirectoryServiceId"=0      
                
                } | ConvertTo-Json
        
        $AccountsUrlResp = Invoke-WebRequest -Uri $AccountsUrl -UseBasicParsing -Method Post -Headers $Headers -ContentType $Type -Body $AccountInfo
        if ($AccountsUrlResp.StatusCode -eq 200 -or $AccountsUrlResp.StatusCode -eq 201) {

            Write-Host "URLStatusCode ->  $($AccountsUrlResp.StatusCode) Success"
            Write-Host "New User created - $($AccountInfo)"
        }
        else {
            Write-Host "URLStatusCode ->  $($AccountsUrlResp.StatusCode)"
            Write-Error "Unable to create New User - $($AccountsURlResp)"
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}