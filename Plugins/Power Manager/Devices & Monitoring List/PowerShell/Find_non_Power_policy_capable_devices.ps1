<#
_author_ = Ashish Singh <ashish_singh11@Dell.com>
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
   Script to get the list of devices which are not capable of power policy capping with OMEnt-Power Manager
 .DESCRIPTION
   This script exercises the OME REST API to get a list of devices which are 
   not capable of power monitoring with OMEnt-Power Manager
   currently being managed by that instance. For authentication X-Auth
   is used over Basic Authentication
   Note :
        1)The credentials entered are not stored to disk.
        2)This script doesn't take into account devices with iDRAC Firmware version 4.0.0.0
 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
   Credentials used to talk to the OME Appliance
   
 .EXAMPLE
   $cred = Get-Credential
   .\Find_non_Power_policy_capable_devices.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred
 .EXAMPLE
   .\Find_non_Power_policy_capable_devices.ps1 -IpAddress "10.xx.xx.xx"
   In this instance you will be prompted for credentials to use
 .EXAMPLE 
  To save the device Ids to a file(file_name.txt) give the command in following format 
  .\Find_non_Power_policy_capable_devices.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred >file_name.txt

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials
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
    $BaseUri = "https://$($IpAddress)"
    $DeviceCountUrl   = $BaseUri + "/api/DeviceService/Devices"
    $NextLinkUrl = $null
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
        $DeviceData = @()
        $Total=@()
        $DevCountResp = Invoke-WebRequest -Uri $DeviceCountUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($DevCountResp.StatusCode -eq 200) 
        {
            $DeviceCountData = $DevCountResp.Content | ConvertFrom-Json
            $DeviceData += $DeviceCountData.'value'
            $Total=$DeviceCountData.'@odata.count'
            $toskip=50

            $NextLinkUrl = $DeviceCountUrl+"?`$skip=$($toskip)&`$top=$($Total)"
            $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                if ($NextLinkResponse.StatusCode -eq 200) 
                {
                $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                $DeviceData += $NextLinkData.'value'  
                }
            else{
                    Write-Warning "Unable to fetch nextlink data"
                }
        
            for ($i=0;$i -ne $Total ; $i++){
            
                $capability=$DeviceData[$i].DeviceCapabilities
                <#if device type is chassis, check only for power capping bit 1105#>
                if ($DeviceData[$i].'Type' -eq 2000)
                {
                    if($capability -notcontains 1105 )
                    {
                        <#print Id of the devices which aren't power policy capping capable#>
                        $DeviceData[$i].'Id' |Format-List
                    }
                }
                else
                {
                    <#if device type is server, check for both power monitoring bit 1006 and power capping bit 1105#>
                    if($capability -notcontains 1105 -or $capability -notcontains 1006 )
                    {
                        <#print Id of the devices which aren't power policy capping capable#>
                        $DeviceData[$i].'Id' |Format-List
                    }
                }
            }
        }
    else{
            Write-Error "Unable to get count of managed devices .. Exiting"
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}