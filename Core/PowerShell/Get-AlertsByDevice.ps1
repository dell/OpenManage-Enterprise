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
   Script to retrieve the alerts for a device 

 .DESCRIPTION

   This script exercises the OME REST API to get the alerts
   for a device. The device can be filtered using the Device Name
   or Asset Tag
   This example uses ODATA queries with filter constructs.

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER FilterBy
   Express filter criteria - Name or Deviceidentifier
 .PARAMETER DeviceInfo
   The actual device name or device identifier to search against
   The device name maps to the Device Identifier if you are
   enumerating the list of devices. This same field is 
   represented as AlertDeviceName in the Alert data.

   Note that this is a case sensitive search.

 .EXAMPLE
   $cred = Get-Credential
   .\Get-AlertsByDevice.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -FilterBy name -DeviceInfo ""

 .EXAMPLE
   .\Get-AlertsByDevice.ps1 -IpAddress "10.xx.xx.xx" -FilterBy DeviceIdentifier -DeviceInfo ""
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
  [ValidateSet("Name", "DeviceIdentifier")]
  [String] $FilterBy,

  [Parameter(Mandatory)]
  [String] $DeviceInfo 
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
  $FilterMap = @{'Name' = 'AlertDeviceName'; 'DeviceIdentifier' = 'AlertDeviceIdentifier' }
  $BaseUri = "https://$($IpAddress)"
  $SessionUrl = $BaseUri + "/api/SessionService/Sessions"
  $FilterExpr = $FilterMap[$FilterBy]
  $AlertUrl = "https://$($IpAddress)/api/AlertService/Alerts?`$filter=$($FilterExpr) eq '$($DeviceInfo)'"
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
    $AlertResp = Invoke-WebRequest -Uri $AlertUrl -Method Get -Headers $Headers -ContentType $Type
    if ($AlertResp.StatusCode -eq 200) {
      $AlertInfo = $AlertResp.Content | ConvertFrom-Json
      $AlertList = $AlertInfo.value
      $TotalAlerts = $AlertInfo.'@odata.count' 
      if ($TotalAlerts -gt 0) {
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
        Write-Output "*** Alerts for device ($($DeviceInfo)) ***"
        $AlertList | Format-List
      }
      else {
        Write-Warning "No alerts found for device $($DeviceInfo)"
      }
    }
    else {
      Write-Warning "Unable to retrieve alerts for ($($DeviceInfo)) from $($IpAddress)"
    }
  }
  else {
    Write-Error "Unable to create a session with appliance $($IpAddress)"
  }
}
catch {
  Write-Error "Exception occured - $($_.Exception.Message)"
}