<#
_author_ = Vittalareddy Nanjareddy <vittalareddy_nanjare@Dell.com>

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
   Script to retire lead of MCM group and promote the exising backup lead as lead.

 .DESCRIPTION

   This script retires the current lead and the backup lead gets promoted as the new lead.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance

 .EXAMPLE
   $cred = Get-Credential
   .\Invoke-RetireLead.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred

   In this instance you will be prompted for credentials to use to
   connect to the appliance
#>
[CmdletBinding(DefaultParameterSetName = 'Group_Name')]
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
    catch {
        Write-Error "Unable to add type for cert policy"
    }
}


function Retire-Lead($IpAddress, $Headers) {
    $BackupLead = $null
    Write-Host "Checking for Backup Lead"
    $BackupLead = Get-BackupLead $IpAddress $Headers
    $JobId = 0
    $AssignBackupLeadRequired = 0
    if ($null -eq $BackupLead) {
        $AssignBackupLeadRequired = 1
        Write-Host "No backup lead found. Assigning backup lead"
        $JobId = Assign-BackupLead $IpAddress $Headers
        if ($JobId) {
            Write-Host "Polling backup lead assignment ..."
            Wait-OnJobStatus $IpAddress $Headers $Type $JobId
        }
        else {
            Write-Warning "Unable to track backup lead assignment ..."
        }
    }

    if ($AssignBackupLeadRequired) {
        Write-Host "Waiting for sync operation to complete for assign backup lead"
        Start-Sleep -Seconds 900
    }
    $BackupLead = Get-BackupLead $IpAddress $Headers
    Write-Host "Checking Backup lead health"
    $BackupLeadHealth = $BackupLead.'BackupLeadHealth'
    if ($BackupLeadHealth -ne 1000) {
        Write-Host "Backup lead health is CRITICAL or WARNING."
        Write-Host "Please ensure backup lead is healty before retiring the lead"
        return $null
    }

    $URL = "https://$($IpAddress)/api/ManagementDomainService/Actions/ManagementDomainService.RetireLead"
    $Payload = '{
        "PostRetirementRoleType" : "Member"
    }' | ConvertFrom-Json

    $Body = $Payload | ConvertTo-Json -Depth 6
    $Response = Invoke-WebRequest -Uri $URL -Headers $Headers -ContentType $Type -Method POST -Body $Body 
    if ($Response.StatusCode -eq 200) {
        $RetireLeadResp = $Response | ConvertFrom-Json
        $JobId = $RetireLeadResp.'JobId'
        if ($JobId) {
            Write-Host "Created job to retire lead with job id $($JobId)"
        }
    }
    else {
        Write-Warning "Failed to retire lead"
    }

    return $JobId
}


function Assign-BackupLead($IpAddress, $Headers) {
    $URL = "https://$($IpAddress)/api/ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead"
    $DomainInfo = Get-Domains $IpAddress $Headers
    $ListOfMembers = $DomainInfo.'members'
    $JobId = 0
    if ($ListOfMembers.Length -gt 0) {
        $Member = Get-Random -InputObject $ListOfMembers -Count 1
        $MemberId = $Member."Id"
        $TargetArray = @()
        $TargetTempHash = @{}
        $TargetTempHash."Id" = $MemberId
        $TargetArray += $TargetTempHash
        $Body = ConvertTo-Json $TargetArray
        $Response = Invoke-WebRequest -Uri $URL -Headers $Headers -ContentType $Type -Method POST -Body $Body 
        if ($Response.StatusCode -eq 200) {
            $BackupLeadData = $Response | ConvertFrom-Json
            $JobId = $BackupLeadData.'JobId'
            Write-Host "Successfully assigned backup lead"
        }
        else {
            Write-Warning "Failed to assign backup lead"
        }
    }

    return $JobId
}

function Get-Domains($IpAddress, $Headers) {
    $Members = @()
    $TargetHash = @{} 
    $Lead = $null
    $BackupLead = $null
    $URL = "https://$($IpAddress)/api/ManagementDomainService/Domains"
    $Response = Invoke-WebRequest -Uri $URL -Headers $Headers -ContentType $Type -Method GET
    if ($Response.StatusCode -eq 200) {
        $DomainResp = $Response.Content | ConvertFrom-Json
        if ($DomainResp."value".Length -gt 0) {
            $MemberDevices = $DomainResp."value"
            foreach ($Member in $MemberDevices) {
                $Role = $Member.'DomainRoleTypeValue'
                $BackupLeadFlag = $Member.'BackupLead'
                if ($Role -eq "LEAD") {
                    if ($null -eq $Lead) {
                        $Lead = $Member
                    }
                }
                elseif ($BackupLeadFlag) {
                    if ($null -eq $BackupLead) {
                        $BackupLead = $Member
                    }
                }
                elseif ($Role -eq "MEMBER") {
                    $Members += $Member
                }
            }
        }
        else {
            Write-Warning "No domains discovered"
        }
        $TargetHash."lead" = $Lead
        $TargetHash."backup_lead" = $BackupLead
        $TargetHash."members" = $Members
        return $TargetHash
    }
    else {
        Write-Warning "Failed to get domains and status code returned is $($Response.StatusCode)"
    }
}


function Get-BackupLead($IpAddress, $Headers) {
    $Domains = Get-Domains $IpAddress $Headers
    return $Domains.'backup_lead'
}


function Wait-OnJobStatus($IpAddress, $Headers, $Type, $JobId) {
    $JOB_STATUS_MAP = @{
        "2020" = "Scheduled";
        "2030" = "Queued";
        "2040" = "Starting";
        "2050" = "Running";
        "2060" = "Completed";
        "2070" = "Failed";
        "2090" = "Warning";
        "2080" = "New";
        "2100" = "Aborted";
        "2101" = "Paused";
        "2102" = "Stopped";
        "2103" = "Canceled"
    }

    $FailedJobStatuses = @(2070, 2090, 2100, 2101, 2102, 2103)

    $MAX_RETRIES = 20
    $SLEEP_INTERVAL = 60

    $JobSvcUrl = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
    $Ctr = 0
    do {
        $Ctr++
        Start-Sleep -Seconds $SLEEP_INTERVAL
        $JobResp = Invoke-WebRequest -Uri $JobSvcUrl -Headers $Headers -ContentType $Type -Method Get
        if ($JobResp.StatusCode -eq 200) {
            $JobData = $JobResp.Content | ConvertFrom-Json
            $JobStatus = [string]$JobData.LastRunStatus.Id
            Write-Host "Iteration $($Ctr): Status of $($JobId) is $($JOB_STATUS_MAP.$JobStatus)"
            if ($JobStatus -eq 2060) {
                ## Completed successfully
                Write-Host "Completed job successfully ..."
                break
            }
            elseif ($FailedJobStatuses -contains $JobStatus) {
                Write-Warning "Job failed .... "
                $JobExecUrl = "$($JobSvcUrl)/ExecutionHistories"
                $ExecResp = Invoke-WebRequest -Uri $JobExecUrl -Method Get -Headers $Headers -ContentType $Type
                if ($ExecResp.StatusCode -eq 200) {
                    $ExecRespInfo = $ExecResp.Content | ConvertFrom-Json
                    $HistoryId = $ExecRespInfo.value[0].Id
                    $ExecHistoryUrl = "$($JobExecUrl)($($HistoryId))/ExecutionHistoryDetails"
                    $HistoryResp = Invoke-WebRequest -Uri $ExecHistoryUrl -Method Get -Headers $Headers -ContentType $Type
                    if ($HistoryResp.StatusCode -eq 200) {
                        Write-Host ($HistoryResp.Content | ConvertFrom-Json | ConvertTo-Json -Depth 4)
                    }
                    else {
                        Write-Warning "Unable to get job execution history details"
                    }
                }
                else {
                    Write-Warning "Unable to get job execution history info"
                }
                break
            }
            else { continue }
        }
        else { Write-Warning "Unable to get status for $($JobId) .. Iteration $($Ctr)" }
    } until ($Ctr -ge $MAX_RETRIES)
}


## Script that does the work
Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $Type = "application/json"
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName" = $UserName; "Password" = $Password; "SessionType" = "API" } | ConvertTo-Json
    $Headers = @{}


    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 201) {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        Write-Host "Successfully created session with $($IpAddress)"
        ## Sending in non-existent targets throws an exception with a "bad request"
        ## error. Doing some pre-req error checking as a result to validate input
        ## This is a Powershell quirk on Invoke-WebRequest failing with an error
        # Create mcm group
        $JobId = 0
        $JobId = Retire-Lead $IpAddress $Headers
        if ($JobId) {
            Write-Host "Polling for retire lead job status ..."
            Wait-OnJobStatus $IpAddress $Headers $Type $JobId
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}
