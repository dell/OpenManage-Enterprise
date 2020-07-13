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
   Script to retrieve the list of pre-defined reports 

 .DESCRIPTION

   This script exercises the OME REST API to get the list of
   pre-defined reports 
   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance

 .EXAMPLE
   $cred = Get-Credential
   .\Get-ReportList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred 

 .EXAMPLE
   .\Get-ReportList.ps1 -IpAddress "10.xx.xx.xx"
   In this instance you will be prompted for credentials to use to
   connect to the appliance
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
    $BaseUri = "https://$($IpAddress)"
    $SessionUrl  = $BaseUri + "/api/SessionService/Sessions"
    $ReportUrl   = $BaseUri + "/api/ReportService/ReportDefs"
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
        $ReportResp = Invoke-WebRequest -Uri $ReportUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($ReportResp.StatusCode -eq 200) {
            $ReportInfo = $ReportResp.Content | ConvertFrom-Json
            $ReportList = $ReportInfo.value
            $totalReports = $ReportInfo.'@odata.count'
            if ($totalReports -gt 0) {
              if ($ReportInfo.'@odata.nextLink'){
                $NextLinkUrl = $BaseUri + $ReportInfo.'@odata.nextLink'
              }
              while ($NextLinkUrl){
                  $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                  if ($NextLinkResponse.StatusCode -eq 200) {
                      $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                      $ReportList += $NextLinkData.'value'
                      if ($NextLinkData.'@odata.nextLink'){
                          $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                      }else{
                          $NextLinkUrl = $null
                      }
                  }else {
                    Write-Warning "Unable to get nextlink response for $($NextLinkUrl)"
                    $NextLinkUrl = $null
                  }
              }
              Write-Output "*** List of pre-defined reports ***"
              $ReportList | Format-List
            }
            else {
                    Write-Warning "No pre-defined reports found on $($IpAddress)"
            }
        }
        else {
            Write-Warning "Unable to retrieve reports from $($IpAddress)"
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}