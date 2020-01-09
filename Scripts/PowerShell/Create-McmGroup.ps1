<#
_author_ = Vittalareddy Nanjareddy <vittalareddy_nanjare@Dell.com>
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
   script to create an MCM group and add all possible members to the created group

 .DESCRIPTION

   This script exercises the OME REST API to create mcm group, find memebers and add the members to the group.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER GroupName
   The Name of the MCM Group.

 .EXAMPLE
   $cred = Get-Credential
   .\Create-McmGroup.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -GroupName TestGroup

   In this instance you will be prompted for credentials to use to
   connect to the appliance
#>
[CmdletBinding(DefaultParameterSetName = 'Group_Name')]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(ParameterSetName = 'Group_Name', Mandatory)]
    [String] $GroupName
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


function Get-DiscoveredDomains($IpAddress, $Headers, $Role) {
    $DiscoveredDomains = @()
    $FilteredDiscoveredDomains = @()
    $TargetArray = @()
    $URL = "https://$($IpAddress)/api/ManagementDomainService/DiscoveredDomains"
    $Response = Invoke-WebRequest -Uri $URL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
    if ($Response.StatusCode -eq 200) {
        $DomainResp = $Response.Content | ConvertFrom-Json
        if ($DomainResp."value".Length -gt 0) {
            $DiscoveredDomains = $DomainResp."value"
        }
        else {
            Write-Warning "No domains discovered"
        }
    }
    else {
        Write-Warning "Unable to fetch discovered domain info...skipping"
    }
    if ($Role) {
        foreach ($Domain in $DiscoveredDomains) {
            if ($Domain.'DomainRoleTypeValue' -eq $Role) {
                #$FilteredDiscoveredDomains += $Domain.'DomainRoleTypeValue'
                $FilteredDiscoveredDomains += $Domain
            }
        }
    }

    if ($FilteredDiscoveredDomains.Length -gt 0){
        foreach ($Domain in $FilteredDiscoveredDomains){
            $TargetTempHash = @{}
            $TargetTempHash."GroupId" = $Domain."GroupId"
            $TargetArray += $TargetTempHash
        }
    }
    $TargetArrayList = @()
    $TargetArrayList = ConvertTo-Json $TargetArray
    return $TargetArrayList
}


function Create-McmGroup($IpAddress, $Headers, $GroupName) {
    $CreateGroupURL = "https://$($IpAddress)/api/ManagementDomainService"
    $payload = '{
        "GroupName": "",
        "GroupDescription": "",
        "JoinApproval": "AUTOMATIC",
        "ConfigReplication": [{
            "ConfigType": "Power",
            "Enabled": "false"
        }, {
            "ConfigType": "UserAuthentication",
            "Enabled": "false"
        }, {
            "ConfigType": "AlertDestinations",
            "Enabled": "false"
        }, {
            "ConfigType": "TimeSettings",
            "Enabled": "false"
        }, {
            "ConfigType": "ProxySettings",
            "Enabled": "false"
        }, {
            "ConfigType": "SecuritySettings",
            "Enabled": "false"
        }, {
            "ConfigType": "NetworkServices",
            "Enabled": "false"
        }, {
            "ConfigType": "LocalAccessConfiguration",
            "Enabled": "false"
        }]
    }' | ConvertFrom-Json

    $JobId = 0
    $Payload."GroupName" = $GroupName
    $Body = $payload | ConvertTo-Json -Depth 6
    $Response = Invoke-WebRequest -Uri $CreateGroupURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method PUT -Body $Body 
    if ($Response.StatusCode -eq 200) {
        $GroupData = $Response | ConvertFrom-Json
        $JobId = $GroupData.'JobId'
        Write-Host "MCM group created successfully...JobId is $($JobId)"
    }
    else {
        Write-Warning "Failed to create MCM group"
    }

    return $JobId
}


function Add-AllMembersViaLead($IpAddress, $Headers) {
    # Add standalone domains to the group
    $Role = "STANDALONE"
    $StandaloneDomains = @()
    $StandaloneDomains = Get-DiscoveredDomains $IpAddress $Headers $Role
    $JobId = 0
    $Payload = @()
    if ($StandaloneDomains.Length -gt 0){
        $Payload = $StandaloneDomains
        $ManagementDomainURL = "https://$($IpAddress)/api/ManagementDomainService/Actions/ManagementDomainService.Domains"
        $Body = $Payload 
        Write-Host "Adding members to the group..."
        Write-Host "Invoking URL $($ManagementDomainURL)"
        $Response = Invoke-WebRequest -Uri $ManagementDomainURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method POST -Body $Body 
        if ($Response.StatusCode -eq 200) {
            $ManagementData = $Response | ConvertFrom-Json
            $JobId = $ManagementData.'JobId'
            Write-Host "Added members to the created group...Job ID is $($JobId)"
        }
        else {
            Write-Warning "Failed to add members to the group"
        }
    } else {
        Write-Warning "No standalone chassis found to add as member to the created group"
    }
    return $JobId
}

function Assign-BackupLead($IpAddress, $Headers) {
    $URL = "https://$($IpAddress)/api/ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead"
    $ListOfMembers = @()
    $ListOfMembers = Get-Domains $IpAddress $Headers
    $JobId = 0
    if ($ListOfMembers.Length -gt 0) {
        $Member = Get-Random -InputObject $ListOfMembers -Count 1
        $MemberId = $Member."Id"
        $TargetArray = @()
        $TargetTempHash = @{}
        $TargetTempHash."Id" = $MemberId
        $TargetArray += $TargetTempHash
        $Body = ConvertTo-Json $TargetArray
        Write-Host "Assigning backup lead..."
        Write-Host "Invoking URL $($URL)"
        Write-Host "Payload $($Body)"
        $Response = Invoke-WebRequest -Uri $URL -UseBasicParsing -Headers $Headers -ContentType $Type -Method POST -Body $Body 
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
    $ListOfMembers = @()
    $URL = "https://$($IpAddress)/api/ManagementDomainService/Domains"
    $Response = Invoke-WebRequest -Uri $URL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
    if ($Response.StatusCode -eq 200) {
        $DomainResp = $Response.Content | ConvertFrom-Json
        if ($DomainResp."value".Length -gt 0) {
            $MemberDevices = $DomainResp."value"
            foreach ($Member in $MemberDevices) {
                if ($Member.'DomainRoleTypeValue' -eq "MEMBER") {
                    $Members += $Member
                }
            }
        }
        else {
            Write-Warning "No domains discovered"
        }
        $ListOfMembers = $Members
        return $ListOfMembers
    }
    else {
        Write-Warning "Failed to get domains and status code returned is $($Response.StatusCode)"
    }
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
    $SLEEP_INTERVAL = 10

    $JobSvcUrl = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
    $Ctr = 0
    do {
        $Ctr++
        Start-Sleep -Seconds $SLEEP_INTERVAL
        $JobResp = Invoke-WebRequest -UseBasicParsing -Uri $JobSvcUrl -Headers $Headers -ContentType $Type -Method Get
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
                $ExecResp = Invoke-WebRequest -UseBasicParsing -Uri $JobExecUrl -Method Get -Headers $Headers -ContentType $Type
                if ($ExecResp.StatusCode -eq 200) {
                    $ExecRespInfo = $ExecResp.Content | ConvertFrom-Json
                    $HistoryId = $ExecRespInfo.value[0].Id
                    $ExecHistoryUrl = "$($JobExecUrl)($($HistoryId))/ExecutionHistoryDetails"
                    $HistoryResp = Invoke-WebRequest -UseBasicParsing -Uri $ExecHistoryUrl -Method Get -Headers $Headers -ContentType $Type
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
        else {Write-Warning "Unable to get status for $($JobId) .. Iteration $($Ctr)"}
    } until ($Ctr -ge $MAX_RETRIES)
}




## Script that does the work
Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $Type = "application/json"
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName" = $UserName; "Password" = $Password; "SessionType" = "API"} | ConvertTo-Json
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
        Write-Host "Creating mcm group"
        $JobId = Create-McmGroup $IpAddress $Headers $GroupName
        if ($JobId) {
            Write-Host "Created job $($JobId) to create mcm group ... Polling status now"
            Wait-OnJobStatus $IpAddress $Headers $Type $JobId
            $JobId = Add-AllMembersViaLead $IpAddress $Headers
            if ($JobId) {
                Write-Host "Polling addition of members to group ..."
                Wait-OnJobStatus $IpAddress $Headers $Type $JobId
                $JobId = Assign-BackupLead $IpAddress $Headers
                if ($JobId) {
                    Write-Host "Polling backup lead assignment ..."
                    Wait-OnJobStatus $IpAddress $Headers $Type $JobId
                }else {
                    Write-Warning "Unable to track backup lead assignment ..."
                }
            }
        }
        else {
            Write-Error "Unable to track group creation .. Exiting" 
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}