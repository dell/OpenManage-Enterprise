  
<#
_author_ = Ashish Singh <ashish_singh11@Dell.com>
_version_ = 0.1
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
   Script to run default inventory task to determine power management capabilities of devices post OMEnt-Power Manager Installation
 .DESCRIPTION
   This script fetches Job id of Default Inventory Task and rns the job, post which it iterates till job is completed.
 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
  .PARAMETER JobNamePattern

   .EXAMPLE

  .\Refresh_Inventory.ps1 
   Enter the IPaddress when prompted
   Enter the Credentials when prompted
#>
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
function Get-JobId($Headers) {
    $Jobname= 'Default Inventory Task'
    $JobId = -1
    $JobUrl = "https://$($IpAddress)/api/JobService/Jobs"
    $JobResponse = Invoke-WebRequest -UseBasicParsing -Uri $JobUrl -Headers $Headers -Method Get
    if ($JobResponse.StatusCode -eq 200) {
        Write-Host "Job fetched"
        $JobInfo = $JobResponse.Content | ConvertFrom-Json
       <# Write-Host "$($JobInfo)"#>
        $JobList = $JobInfo.value
        $totalJobs = $JobInfo.'@odata.count'
        if ($totalJobs -gt 0) {
            if ($JobInfo.'@odata.nextLink'){
                $NextLinkUrl = $BaseUri + $JobInfo.'@odata.nextLink'
            }
            while ($NextLinkUrl){
                $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                if ($NextLinkResponse.StatusCode -eq 200) {
                    $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                    $JobList += $NextLinkData.'value'
                    if ($NextLinkData.'@odata.nextLink'){
                        $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                    }
                    else{
                        $NextLinkUrl = $null
                    }
                }
                else {
                    Write-Warning "Unable to get nextlink response for $($NextLinkUrl)"
                }
            }
        }
        else{
            Write-Warning "Job results are empty"
        }
        
        foreach ($jobinfo in $JobList){
            if ($jobinfo.'JobName' -match $JobName){
                $Jobid=$jobinfo.Id
                <#Write-Host "$($jobinfo.Id)"#>
                $job_match_found=1
                }
            }
        }
        if (!$job_match_found){
            Write-Host "Unable to track running discovery config job"
        }
    return $JobId
    }
function Get-JobStatus($JobId) {
    $FailedJobStatuses = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')
    $SLEEP_INTERVAL = 30
    $JobSvcUrl = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
    $Type = "application/json"
    $Headers = @{ }
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{ "UserName" = $UserName; "Password" = $Password; "SessionType" = "API" } | ConvertTo-Json
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) 
    {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        do {
        $Ctr++
        
        $JobResp = Invoke-WebRequest -UseBasicParsing -Uri $JobSvcUrl -Headers $Headers -ContentType $Type -Method Get
        $jobresp.Content
        if ($JobResp.StatusCode -eq 200) {
            $JobData = $JobResp.Content | ConvertFrom-Json
            $JobStatus = $JobData.LastRunStatus.Name
            Write-Host "Iteration $($Ctr): Status of Default Inventory Task $($JobId) is $($JobStatus)"
        }
        Start-Sleep -Seconds $SLEEP_INTERVAL
    } until ($JobStatus -ne 'Running')
    return $JobStatus
}
}


Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $RunJobUrl= "https://$($IpAddress)/api/JobService/Actions/JobService.RunJobs"
    $Type = "application/json"
    $Headers = @{ }
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{ "UserName" = $UserName; "Password" = $Password; "SessionType" = "API" } | ConvertTo-Json
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        $InventoryJobId=Get-JobId($Headers)
        $jpl= '[' + $InventoryJobId +']'
       $JobCreationpayload= @{ "JobIds" =  $($jpl)} |ConvertTo-Json
       $JobCreationpayload=$JobCreationpayload.Replace("`"[","[").Replace("]`"","]")
       $RunInventoryResponse = Invoke-WebRequest -Uri $RunJobUrl -UseBasicParsing -Method Post  -Body $JobCreationpayload -Headers $Headers -ContentType $Type
        if ( $RunInventoryResponse.StatusCode -eq 204){
            Write-Host "Performing Inventory ..."
            <#Start-Sleep Seconds 10#>
            $JobStatus= Get-JobStatus($InventoryJobId)
        }
        else{
            Write-Host "Inventory Job creation Failed..."

        }
    }
    else{
            Write-Host "Session creation Failed...."
    }
}

Catch{
    Write-Error "Exception occured - $($_.Exception.Message)"
}    
        