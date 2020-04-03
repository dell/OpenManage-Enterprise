<#
_author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
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
   Script to get the list of virtual addresses in an Identity Pool
 .DESCRIPTION

   This script exercises the OME REST API to get a list of virtual addresses in an Identity Pool.
   Will export to a CSV file called Get-IdentityPoolUsage.csv in the current directory
   For authentication X-Auth is used over Basic Authentication
   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER Id
   This is the Identity Pool Id
 .PARAMETER OutFile
   This is the full path to output the CSV file

 .EXAMPLE
   $cred = Get-Credential
   .\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred

 .EXAMPLE
   .\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx"
   In this instance you will be prompted for credentials to use

 .EXAMPLE
   .\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx" -Id 3
   In this instance you will be prompted for credentials to use

 .EXAMPLE
   .\Get-IdentityPoolUsage.ps1 -IpAddress "10.xx.xx.xx" -Id 3 -OutFile C:\Temp\export.csv
   In this instance you will be prompted for credentials to use
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory=$false)]
    [String] $Id,

    [Parameter(Mandatory=$false)]
    [String] $OutFile
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

$SessionAuthToken = @{}

function Get-Session($IpAddress, $Credentials) {
    $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions"
    $Type        = "application/json"
    $UserName    = $Credentials.username
    $Password    = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName"=$UserName;"Password"=$Password;"SessionType"="API"} | ConvertTo-Json

    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        $SessResponseData = $SessResponse.Content | ConvertFrom-Json
        $SessionAuthToken = @{
        "token"= $SessResponse.Headers["X-Auth-Token"];
        "id"= $SessResponseData.Id
        }
    }
    return $SessionAuthToken
}

function Remove-Session($IpAddress, $Headers, $Id) {
    $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions('$($Id)')"
    $Type        = "application/json"
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Delete -Headers $Headers -ContentType $Type
}

Try {
    Set-CertPolicy
    $BaseUri = "https://$($IpAddress)"
    $NextLinkUrl = $null
    $Type        = "application/json"
    $Headers     = @{}

    # Request authentication session token
    $AuthToken = Get-Session $IpAddress $Credentials
    if ($AuthToken) {
        # Successfully created a session, extract token
        $Headers."X-Auth-Token" = $AuthToken["token"]
        
        # Display Identity Pools
        $IdentityPoolUrl = $BaseUri + "/api/IdentityPoolService/IdentityPools"
        $IdentityPoolResp = Invoke-WebRequest -Uri $IdentityPoolUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($IdentityPoolResp.StatusCode -eq 200) {
            $IdentityPoolRespData = $IdentityPoolResp.Content | ConvertFrom-Json
            $IdentityPoolRespData = $IdentityPoolRespData.'value'

            if ($Id -eq "") {
                $IdentityPoolRespData | Select Id, Name | Out-String
                $Id = Read-Host "Please Enter Identity Pool Id"
            }
        }

        # Get Identity Pool Usage Sets
        $IdentityPoolUsageSetUrl = $BaseUri + "/api/IdentityPoolService/IdentityPools($($Id))/UsageIdentitySets"
        $IdentityPoolUsageSetResp = Invoke-WebRequest -Uri $IdentityPoolUsageSetUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($IdentityPoolUsageSetResp.StatusCode -eq 200) {
            $IdentityPoolUsageSetRespData = $IdentityPoolUsageSetResp.Content | ConvertFrom-Json
            $IdentityPoolUsageSetRespData = $IdentityPoolUsageSetRespData.'value'

            $DeviceData = @()
            # Loop through Usage Sets using Id to get Details
            foreach ($IdentitySet in $IdentityPoolUsageSetRespData) {    
                $IdentitySetId = $IdentitySet.IdentitySetId
                $IdentitySetName = $IdentitySet.Name

                $IdentityPoolUsageDetailUrl = $BaseUri + "/api/IdentityPoolService/IdentityPools($($Id))/UsageIdentitySets($($IdentitySetId))/Details"
                $IdentityPoolUsageDetailResp = Invoke-WebRequest -Uri $IdentityPoolUsageDetailUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                if ($IdentityPoolUsageDetailResp.StatusCode -eq 200) {
                    $IdentityPoolUsageDetailData = $IdentityPoolUsageDetailResp.Content | ConvertFrom-Json
                    # Loop through Details appending to object array
                    foreach($DeviceEntry in $IdentityPoolUsageDetailData.'value')
                    {
                        $DeviceDetails =@{
                            IdentityType = $IdentitySetName
                            ChassisName = $DeviceEntry.DeviceInfo.ChassisName
                            ServerName = $DeviceEntry.DeviceInfo.ServerName
                            ManagementIp = $DeviceEntry.DeviceInfo.ManagementIp
                            NicIdentifier = $DeviceEntry.NicIdentifier
                            MacAddress = $DeviceEntry.MacAddress
                        }
                        $DeviceData += New-Object PSObject -Property $DeviceDetails 
                    }

                    # Check if there are multiple pages in response
                    if ($IdentityPoolUsageDetailData.'@odata.nextLink'){
                        $NextLinkUrl = $BaseUri + $IdentityPoolUsageDetailData.'@odata.nextLink'
                    }
                    # Loop through pages until end
                    while ($NextLinkUrl) {
                        $IdentityPoolUsageDetailNextLinkResp = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                        if ($IdentityPoolUsageDetailNextLinkResp.StatusCode -eq 200) {
                            $IdentityPoolUsageDetailNextLinkData = $IdentityPoolUsageDetailNextLinkResp.Content | ConvertFrom-Json
                            # Loop through Details appending to object array
                            foreach($DeviceEntry in $IdentityPoolUsageDetailNextLinkData.'value')
                            {
                                $DeviceDetails =@{
                                    IdentityType = $IdentitySetName
                                    ChassisName = $DeviceEntry.DeviceInfo.ChassisName
                                    ServerName = $DeviceEntry.DeviceInfo.ServerName
                                    ManagementIp = $DeviceEntry.DeviceInfo.ManagementIp
                                    NicIdentifier = $DeviceEntry.NicIdentifier
                                    MacAddress = $DeviceEntry.MacAddress
                                }
                                $DeviceData += New-Object PSObject -Property $DeviceDetails 
                            }
                            # Set for nextLink for next iteration
                            if ($IdentityPoolUsageDetailNextLinkData.'@odata.nextLink'){
                                $NextLinkUrl = $BaseUri + $IdentityPoolUsageDetailNextLinkData.'@odata.nextLink'
                            } else { 
                                $NextLinkUrl = $null
                            }
                        } else {
                            $NextLinkUrl = $null
                            Write-Error "Unable to retrieve items from nextLink... Exiting"
                        }
                    }
                }
                else {
                    Write-Error "Unable to get identity pools... Exiting"
                }
            }

            # Print table to console
            $DeviceData | Format-Table | Out-String

            # Export to CSV
            if ($DeviceData.Count -gt 0) {
                if ($OutFile -eq "") {
                    $DeviceData | Export-Csv -Path "Get-IdentityPoolUsage.csv" -NoTypeInformation
                    Write-Host "Exported data to $(Get-Location)\Get-IdentityPoolUsage.csv"
                } else {
                    $DeviceData | Export-Csv -Path $OutFile -NoTypeInformation
                    Write-Host "Exported data to $($OutFile)"
                }
            } else {
                Write-Host "No data to display"
            }
        }
    
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception: $($_)"
}
Finally {
    if ($AuthToken) {
      Remove-Session $IpAddress $Headers $AuthToken["id"]
    }
}