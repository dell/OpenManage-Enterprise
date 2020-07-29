<#
PowerShell Script using OME API to get the device list.
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
   Script to get the list of devices managed by OM Enterprise

 .DESCRIPTION

   This script exercises the OME REST API to get a list of devices
   currently being managed by that instance. For authentication X-Auth
   is used over Basic Authentication

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance

 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance

 .PARAMETER OutFormat
   Output format - one of csv / json
   Default is JSON

 .PARAMETER Outfilepath
   An optional file to dump output to in the specified
   output format  


   .EXAMPLE
   $cred = Get-Credential
   .\Get-DeviceList.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred

 .EXAMPLE
   Get-DeviceList -IPAddress "10.xx.xx.xx" -UserName admin
   Get-DeviceList -IPAddress "10.xx.xx.xx" -OutFormat json -UserName admin
   Get-DeviceList -IpAddress 100.96.20.132 -OutFormat CSV -UserName admin -Outfilepath C:\Users\Desktop\test.csv
   Get-DeviceList -IpAddress 100.96.20.132 -OutFormat json -UserName admin -Outfilepath C:\Users\Desktop\test.json
   In this instance you will be prompted for credentials to use
#>

function Set-CertPolicy() 
{
    ## Trust all certs - for sample usage only
    Try 
    {
        add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy 
        {
            public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem)
            {
                return true;
            }
        }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    Catch 
    {
        Write-Error "Unable to add type for cert policy"
    }
}

function Json-Format
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $data,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [String] $path
    )

    if($path -eq $null -or $path -eq "")
    {
        $DeviceData | ConvertTo-Json -Depth 100
    }
    else
    {
        $filepath = Get-uniquefilename -filepath $path -formatextension "json"
        $jsondata | Out-File -FilePath $path
    } 
}

function CSV-Format
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $data,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [String] $path
    )
    $Devicearray = @()
    foreach($device in $DeviceData)
    {
        $DirPermissions = New-Object -TypeName PSObject -Property @{
        ID = $Device.Id
        Identifier = $Device.Identifier
        DeviceServiceTag = $Device.DeviceServiceTag
        ChassisServiceTag = $Device.ChassisServiceTag
        Model = $Device.Model
        DeviceName = $Device.DeviceName
        }
        $Devicearray += $DirPermissions
    }
    if($path -eq $null -or $path -eq "")
    {
        $Devicearray | Format-Table
    }
    else
    {
        $filepath = Get-uniquefilename -filepath $path -formatextension "csv"
        $Devicearray | Export-Csv -Path $filepath -NoTypeInformation
    } 
}

function Get-uniquefilename
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo] $filepath,
    
        [Parameter(Mandatory)]
        [String] $formatextension
    )

    if(Test-Path -LiteralPath $filepath -PathType Container)
    {
        Write-Error "Unable to get the file name, please provide the filename"
    }
    else
    {
        $folder = Split-Path -Path ([io.path]::GetFullPath($filepath)) -Parent
        $formatfilename = $filepath.BaseName
        $i = 1
        while(Test-Path $filepath)
        {
            $filename = $formatfilename+"($i)"
            $newfilename = $filename+"."+$formatextension
            $filepath = Join-Path $folder $newfilename
            $i++
        }
    }
    return $filepath
}

function Get-DeviceList
{

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.IPAddress] $IPAddress,
    
        [Parameter(Mandatory=$False)]
        [ValidateSet('CSV','Json')]
        [String] $OutFormat = "json",

        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [String] $Outfilepath = "",

        [Parameter(Mandatory = $true)]
        $UserName = "admin",

        [Parameter(Mandatory=$True)]
        [SecureString]$Password
     )
     try
     {
        Set-CertPolicy
        $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions"
        $BaseUri = "https://$($IpAddress)"
        $DeviceCountUrl   = $BaseUri + "/api/DeviceService/Devices"
        $NextLinkUrl = $null
        $Type        = "application/json"
        #$UserName    = $Credentials.username
        $PlainPassword = [System.Net.NetworkCredential]::new("", $Password).Password
        #$password = ConvertFrom-SecureString -SecureString $Password
        #$Password    = $Credentials.GetNetworkCredential().password
        $UserDetails = @{"UserName"=$UserName;"Password"=$PlainPassword;"SessionType"="API"} | ConvertTo-Json
        $Headers     = @{}

        $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
        if($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201)
        {
            ## Successfully created a session - extract the auth token from the response
            ## header and update our headers for subsequent requests
            $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
            $DeviceData = @()
            $DevCountResp = Invoke-WebRequest -Uri $DeviceCountUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
            if ($DevCountResp.StatusCode -eq 200)
            {
                $DeviceCountData = $DevCountResp.Content | ConvertFrom-Json
                $DeviceData += $DeviceCountData.'value'
                if($DeviceCountData.'@odata.nextLink')
                {
                    $NextLinkUrl = $BaseUri + $DeviceCountData.'@odata.nextLink'
                }
                while($NextLinkUrl)
                {
                    $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                    if($NextLinkResponse.StatusCode -eq 200)
                    {
                        $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                        $DeviceData += $NextLinkData.'value'
                        if($NextLinkData.'@odata.nextLink')
                        {
                            $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                        }
                        else
                        {
                            $NextLinkUrl = $null
                        }
                    }
                    else
                    {
                        Write-Warning "Unable to get nextlink response for $($NextLinkUrl)"
                        $NextLinkUrl = $null
                    }
                }
                
                if($OutFormat -eq "json")
                {
                    Json-Format -data $DeviceData -path $Outfilepath
                }
                elseif($OutFormat -eq "csv")
                {
                    CSV-Format -data $DeviceData -path $Outfilepath
                }       
            }
            else
            {
                Write-Error "Unable to get count of managed devices .. Exiting"
            }
        }
        else
        {
            Write-Error "Unable to create a session with appliance $($IpAddress)"
        }
     }
     catch
     {
         Write-Error "Exception occured - $($_.Exception.Message)"
     }
}
