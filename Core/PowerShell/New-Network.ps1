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
   Script to create a static group in OME
 .DESCRIPTION

   This script exercises the OME REST API to create a new network
   A network consists of a Minimum and Maximum VLAN ID to create a range
   Set Minimum and Maximum to the same value to a single VLAN
   
   For authentication X-Auth is used over Basic Authentication

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
    This is the IP address of the OME Appliance
 .PARAMETER Credentials
    Credentials used to talk to the OME Appliance. Will be prompted if not supplied.
 .PARAMETER ListNetworkTypes
    List available Network Types
 .PARAMETER ListNetworks
    List existing Networks 
 .PARAMETER ExportExample
    Creates a file called New-NetworkExample.csv in the current directory. 
    Use this file as an example to import.
 .PARAMETER InFile
    Path to CSV file in format. 

    *Must include header row with at least the rows in the example below
    *Use -ExportExample to create an example CSV file for import
    *NetworkType must be an integer value. Use --list-networktypes
    *For a single VLAN set VlanMinimum=VlanMaximum
    Example:
    Name,Description,VlanMaximum,VlanMinimum,NetworkType
    VLAN 800,Description for VLAN 800,800,800,1

 .EXAMPLE
   $cred = Get-Credential
   .\New-Network.ps1 -IpAddress 100.79.6.11 -Credentials $cred -ListNetworkTypes

 .EXAMPLE
   .\New-Network.ps1 -IpAddress 100.79.6.11 -Credentials root -ListNetworkTypes

 .EXAMPLE
   .\New-Network.ps1 -IpAddress 100.79.6.11 -ListNetworks

 .EXAMPLE
   .\New-Network.ps1 -IpAddress 100.79.6.11 -ExportExample

 .EXAMPLE
   .\New-Network.ps1 -IpAddress 100.79.6.11 -InFile "New-NetworkExample.csv"

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory=$false)]
    [switch] $ExportExample,

    [Parameter(Mandatory=$false)]
    [switch] $ListNetworks,

    [Parameter(Mandatory=$false)]
    [switch] $ListNetworkTypes,

    [Parameter(Mandatory=$false)]
    [string] $InFile
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

function Get-Networks($BaseUri, $Headers) {
    # Display Networks
    $Type        = "application/json"
    $NetworkUrl = $BaseUri + "/api/NetworkConfigurationService/Networks"
    $NetworkResp = Invoke-WebRequest -Uri $NetworkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($NetworkResp.StatusCode -eq 200) {
        $NetworkRespData = $NetworkResp.Content | ConvertFrom-Json
        $NetworkRespData = $NetworkRespData.'value'

        $NetworkRespData | Select Id, Name, Description, VlanMinimum, VlanMaximum, CreatedBy | Format-Table | Out-String
    }
}

function Get-NetworkTypes($BaseUri, $Headers) {
    # Display Network Types
    $Type        = "application/json"
    $NetworkTypeUrl = $BaseUri + "/api/NetworkConfigurationService/NetworkTypes"
    $NetworkTypeResp = Invoke-WebRequest -Uri $NetworkTypeUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($NetworkTypeResp.StatusCode -eq 200) {
        $NetworkTypeRespData = $NetworkTypeResp.Content | ConvertFrom-Json
        $NetworkTypeRespData = $NetworkTypeRespData.'value'

        $NetworkTypeRespData | Select Id, Name | Format-Table | Out-String
    }
}

function Export-ExampleCSV() {
    $Example = [pscustomobject]@{
        "Name"= "VLAN 800";
        "Description"= "Description for VLAN 800";
        "VlanMinimum"= 800;
        "VlanMaximum"= 800;
        "NetworkType"= 1;
    }
    $Example | Export-Csv -Path .\New-NetworkExample.csv -NoTypeInformation
    Write-Host "Exported example data to $(Get-Location)\New-NetworkExample.csv"
}

Try {
    Set-CertPolicy
    $BaseUri = "https://$($IpAddress)"
    $Type        = "application/json"
    $Headers     = @{}

    # Export example CSV file
    if ($ExportExample) {
        Export-ExampleCSV
        exit
    }

    # Request authentication session token
    $AuthToken = Get-Session $IpAddress $Credentials
    if ($AuthToken) {
        # Successfully created a session, extract token
        $Headers."X-Auth-Token" = $AuthToken["token"]
        
        if ($ListNetworks) {
            Get-Networks $BaseUri $Headers
            exit
        }

        if ($ListNetworkTypes) {
            Get-NetworkTypes $BaseUri $Headers
            exit
        }

        # Check if we want to import from CSV file
        if ($InFile -ne "" -and (Test-Path $InFile)) {
            Import-CSV $InFile | Foreach-Object {
                $Payload = @{
                    "Name"= $_.Name;
                    "Description"= $_.Description;
                    "VlanMaximum"= $_.VlanMinimum -as [int];
                    "VlanMinimum"= $_.VlanMaximum -as [int];
                    "Type"= $_.NetworkType -as [int];
                }
                $PayloadJson = $Payload | ConvertTo-Json
                Write-Host "Creating Network from data: $($PayloadJson)"
                # Create Network
                Try {
                    $CreateNetworkUrl = $BaseUri + "/api/NetworkConfigurationService/Networks"
                    $CreateResp = Invoke-WebRequest -Uri $CreateNetworkUrl -UseBasicParsing -Me Post -H $Headers -Con $Type -Body $PayloadJson
                    if ($CreateResp.StatusCode -eq 201) {
                        Write-Host "New Network created $($_)"
                    }
                    else {
                        Write-Host $CreateResp.Content
                    }
                } Catch {
                    Write-Host "Exception: $($_)"
                }
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