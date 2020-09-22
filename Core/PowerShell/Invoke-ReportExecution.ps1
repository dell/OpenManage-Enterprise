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
   Script to invoke execution of a report in OME 

 .DESCRIPTION

   This script exercises the OME REST API to execute a pre-canned
   report (this can include custom reports defined by the user)
   and tracks completion of the report. On completion the report
   result is printed to screen.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER ReportId
   ID of the report to be run
   
 .EXAMPLE
   $cred = Get-Credential
   .\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -ReportId 10043

 .EXAMPLE
   .\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -ReportId 10043
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
    [uint64] $ReportId,

    [Parameter(Mandatory=$false)]
    [uint64] $GroupId = 0,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("csv", "table")]
    [string]$OutputFormat="csv",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFilePath=""    
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

function Format-OutputInfo($IpAddress,$Headers,$Type,$ReportId) {
    $BaseUri = "https://$($IpAddress)"
    $ReportDeets = $BaseUri + "/api/ReportService/ReportDefs($($ReportId))"
    $NextLinkUrl = $null
    $OutputArray = @()
    $ColumnNames = @()
    [psobject[]]$objlist = @()
    $DeetsResp = Invoke-WebRequest -Uri $ReportDeets -UseBasicParsing -Headers $Headers -Method Get -ContentType $Type
    if ($DeetsResp.StatusCode -eq 200){
        $DeetsInfo = $DeetsResp.Content | ConvertFrom-Json
        $ColumnNames = $DeetsInfo.ColumnNames.Name
        Write-Verbose "Extracting results for report ($($ReportId))"
        $ResultUrl = $BaseUri + "/api/ReportService/ReportDefs($($ReportId))/ReportResults/ResultRows"
        
        $RepResult = Invoke-WebRequest -Uri $ResultUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($RepResult.StatusCode -eq 200) {
            $RepInfo = $RepResult.Content | ConvertFrom-Json
            $totalRepResults = [int]($RepInfo.'@odata.count')
            if ($totalRepResults -gt 0) {
                $ReportResultList = $RepInfo.Value
                if ($RepInfo.'@odata.nextLink'){
                    $NextLinkUrl = $BaseUri + $RepInfo.'@odata.nextLink'
                }
                while ($NextLinkUrl){
                    $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                    if ($NextLinkResponse.StatusCode -eq 200) {
                        $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                        $ReportResultList += $NextLinkData.'value'
                        if ($NextLinkData.'@odata.nextLink'){
                            $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                        }else{
                            $NextLinkUrl = $null
                        }
                    }else {
                        Write-Error "Unable to get full set of report results"
                        $NextLinkUrl = $null
                    }
                }
                foreach ($value in $ReportResultList) {
                    $resultVals = $value.Values

                    $tempHash = @{}
                    for ($i =0; $i -lt $ColumnNames.Count; $i++) {
                        $tempHash[$ColumnNames[$i]] = $resultVals[$i]
                    }
                    $outputArray += , $tempHash
                    if($outputformat -eq "csv")
                    {
                        $objlist += New-Object -TypeName psobject -Property $tempHash
                    }
                }
                if($outputformat -eq "csv")
                {
                    $filepath = Get-uniquefilename -filepath $outputfilepath -formatextension "csv"
                    $objlist | Export-Csv -Path $filepath
                }
                else
                {
                    $outputArray.Foreach({[PSCustomObject]$_}) | Format-Table -AutoSize
                }
            }
            else {
                Write-Warning "No result data retrieved from $($IpAddress) for report ($($ReportId))"
            }
        }
        else {
            Write-Warning "Unable to get report results for $($ReportId) from $($IpAddress)"
        }
    }
    else {
        Write-Warning "Unable to create mapping for report data columns"
    }
}

Try {
    if(($outputformat -like "csv") -and ($outputfilepath -eq ""))
    {
        Write-Error "CSV Filepath is not provided." -ErrorAction Stop
    }

    Set-CertPolicy
    $SessionUrl    = "https://$($IpAddress)/api/SessionService/Sessions"
    $ExecRepUrl    = "https://$($IpAddress)/api/ReportService/Actions/ReportService.RunReport"
    $Type          = "application/json"
    $UserName      = $Credentials.username
    $Password      = $Credentials.GetNetworkCredential().password
    $UserDetails   = @{"UserName"=$UserName;"Password"=$Password;"SessionType"="API"} | ConvertTo-Json
    $RepPayload    = @{"ReportDefId"=$ReportId; "FilterGroupId"=$GroupId} | ConvertTo-Json
    $Headers       = @{}
    $JobDoneStatus = @("completed","failed","warning","aborted","canceled")
    $RetryCount    = 90 

    
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        ## Successfully created a session - extract the auth token from the response
        ## header and update our headers for subsequent requests
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        $ReportResp = Invoke-WebRequest -Uri $ExecRepUrl -UseBasicParsing -Method Post -Headers $Headers -ContentType $Type -Body $RepPayload
        if ($ReportResp.StatusCode -eq 200) {
            $JobId = $ReportResp.Content
            $JobUrl = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
            $CurrJobStatus = ""
            $Counter = 0
            do {
                $Counter++
                Write-Host "Polling report status ... "
                Start-Sleep -Seconds 10                
                $JobResp = Invoke-WebRequest -Uri $JobUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                if ($JobResp.StatusCode -eq 200) {
                    $JobInfo = $JobResp.Content | ConvertFrom-Json
                    $CurrJobStatus = [string]($JobInfo.LastRunStatus.Name).ToLower()
                    Write-Verbose "Job status is $($CurrJobStatus)"
                }
                else {
                    Write-Warning "Unable to determine job status - Iteration $($Counter)"
                }

            } until ( ($JobDoneStatus -contains $CurrJobStatus) -or ($Counter -gt $RetryCount))
            if ($CurrJobStatus -eq 'completed') {
                Format-OutputInfo $IpAddress $Headers $Type $ReportId
            }
            else {
                Write-Warning "Job $($JobId) failed ... Unable to run report"
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