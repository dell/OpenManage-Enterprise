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
   Script to update firmware for a device or applicable devices
   within a group 
 .DESCRIPTION
   This script exercises the OME REST API to allow updating 
   a device or a group of devices by using a single DUP file.
 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER DupFile
   Path to the Dell Update package file to be used for the
   update
 .PARAMETER GroupId
   The Id of the Group to be updated using the DUP.
 .PARAMETER DeviceId
   The Id of the device to be updated using the DUP.
 .EXAMPLE
   $cred = Get-Credential
   .\Update-InstalledFirmware.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -DupFile .\BIOSxxxx.EXE -DeviceId 25234
 .EXAMPLE
   .\Update-InstalledFirmware.ps1 -IpAddress "10.xx.xx.xx" -DupFile .\BIOSxxxx.EXE
    -GroupId 1010
   In this instance you will be prompted for credentials to use to
   connect to the appliance
#>
[CmdletBinding(DefaultParameterSetName='Group_Update')]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [ValidateScript({
        if(-Not ($_ | Test-Path) ){
            throw "File or folder does not exist" 
        }
        if(-Not ($_ | Test-Path -PathType Leaf) ){
            throw "The Path argument must be a file. Folder paths are not allowed."
        }
        return $true
    })]
    [System.IO.FileInfo]$DupFile,

    [Parameter(ParameterSetName='Group_Update',Mandatory)]
    [System.UInt32]$GroupId,

    [Parameter(ParameterSetName='Device_Update')]
    [System.UInt32]$DeviceId
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

function Get-GroupList($IpAddress,$Headers,$Type){
    $GroupList = @()
    $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups"
    $GrpResp = Invoke-WebRequest -Uri $GroupUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($GrpResp.StatusCode -eq 200) {
        $GroupInfo = $GrpResp.Content | ConvertFrom-Json
        $GroupInfo.'value' |  Sort-Object Id | ForEach-Object {$GroupList += , $_.Id}
    }
    return $GroupList
}

function Get-DeviceList($IpAddress,$Headers,$Type){
    $NextLinkUrl = $null
    $BaseUri = "https://$($IpAddress)"
    $DeviceList = @()
    $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices"
    $DevResp = Invoke-WebRequest -Uri $DeviceUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($DevResp.StatusCode -eq 200) {
        $DevInfo = $DevResp.Content | ConvertFrom-Json
        $DevInfo.'value' |  Sort-Object Id | ForEach-Object {$DeviceList += , $_.Id}

        if($DevInfo.'@odata.nextLink'){
             $NextLinkUrl = $BaseUri + $DevInfo.'@odata.nextLink'
        }
        while($NextLinkUrl){
                    $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                    if($NextLinkResponse.StatusCode -eq 200)
                    {
                        $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                        $NextLinkData.'value' | Sort-Object Id | ForEach-Object {$DeviceList += , $_.Id}
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
    }
    return $DeviceList
}
function Push-DupToOME($IpAddress,$Headers, $DupFile) {
    $FileToken = $null
    $UploadActionUri = "https://$($IpAddress)/api/UpdateService/Actions/UpdateService.UploadFile"
    Write-Host "Uploading $($DupFile) to $($IpAddress). This action may take some time to complete."
    $UploadResponse = Invoke-WebRequest -Uri $UploadActionUri -UseBasicParsing -Method Post -InFile $DupFile -ContentType "application/octet-stream" -Headers $Headers
    if ($UploadResponse.StatusCode -eq 200) {
        ## Successfully uploaded the DUP file . Get the file token
        ## returned by OME on upload of the DUP file
        ## The file token is returned as an array of decimals that maps to ascii text values
        $FileToken = [System.Text.Encoding]::ASCII.GetString($UploadResponse.Content)
        Write-Host "Successfully uploaded $($DupFile)"
    }
    else {
        Write-Warning "Unable to upload $($DupFile) to $($IpAddress)..."
    }
    return $FileToken
}

function Set-DupApplicabilityPayload($FileTokenInfo, $ParamHash)
{
    $BlankArray  = @()
    $DupReportPayload = @{"SingleUpdateReportBaseline"=$BlankArray;
                          "SingleUpdateReportGroup"=$BlankArray;
                          "SingleUpdateReportTargets"=$BlankArray;
                          "SingleUpdateReportFileToken"="";
                        }
    $DupReportPayload.SingleUpdateReportFileToken = $FileTokenInfo
    if ($ParamHash.GroupId) {
        $DupReportPayload.SingleUpdateReportGroup += $ParamHash.GroupId
        $DupReportPayload.SingleUpdateReportTargets = $BlankArray
    }
    else {
        $DupReportPayload.SingleUpdateReportGroup = $BlankArray
        $DupReportPayload.SingleUpdateReportTargets += $ParamHash.DeviceId
    }
    return $DupReportPayload | ConvertTo-Json
}

function Get-ApplicableComponents($IpAddress, $Headers, $Type, $DupReportPayload)
{
    $componentMap = @{"ComponentCurrentVersion"="Current Ver";
                      "ComponentUpdateAction"="Action";
                      "ComponentVersion"="Avail Ver";
                      "ComponentCriticality"="Criticality";
                      "ComponentRebootRequired"="Reboot Req";
                      "ComponentName"="Name"}

    $RetDupPayload = $null

    $DupUpdatePayload =  '{
        "Id": 0,
        "JobName": "Firmware Update Task",
        "JobDescription": "dup test",
        "Schedule": "startnow",
        "State": "Enabled",
        "CreatedBy": "admin",
        "JobType": {
            "Id": 5,
            "Name": "Update_Task"
        },
        "Targets" : [],
        "Params": [
            {
                "JobId": 0,
                "Key": "operationName",
                "Value": "INSTALL_FIRMWARE"
            },
            {
                "JobId": 0,
                "Key": "complianceUpdate",
                "Value": "false"
            },
            {"JobId": 0,
             "Key": "stagingValue",
             "Value": "false"
             },
            {
                "JobId": 0,
                "Key": "signVerify",
                "Value": "true"
            }
        ]
    }' | ConvertFrom-Json

    $FileToken = ($DupReportPayload | ConvertFrom-Json).SingleUpdateReportFileToken


    $DupReportUrl = "https://$($IpAddress)/api/UpdateService/Actions/UpdateService.GetSingleDupReport"
    try {
        $DupResponse = Invoke-WebRequest -UseBasicParsing -Uri $DupReportUrl -Headers $Headers -ContentType $Type -Body $DupReportPayload -Method Post -ErrorAction SilentlyContinue       
        if ($DupResponse.StatusCode -eq 200) {
            $DupResponseInfo = $DupResponse.Content | ConvertFrom-Json
            if ($DupResponse.Length -gt 0) {
                $RetVal = $true
                if ($DupResponseInfo.Length -gt 0) {
                    $TargetArray = @()                    
                    foreach ($Device in $DupResponseInfo) {
                        $outputArray = @()
                        foreach ($Component in $Device.DeviceReport.Components) {
                            $tempHash = @{}
                            $tempHash."Device" = $Device.DeviceReport.DeviceServiceTag
                            $tempHash."IpAddress" = $Device.DeviceReport.DeviceIpAddress
                            ## This is a custom object - convert to a hash
                            $dupHash = @{}
                            $Component | Get-Member -MemberType NoteProperty | ForEach-Object {$dupHash.Add($_.Name, $Component.($_.Name))}
                            foreach ($key in $dupHash.keys) {
                                if ($componentMap.Keys -Contains $key) {
                                    $tempHash[$ComponentMap.$key] = $dupHash.$key                            
                                }
                            }

                            ## For the current component if the available version is > current version
                            ## then add it to the list of targets
                            if ($tempHash."Avail Ver" -gt $tempHash."Current Ver") {
                                $TargetTempHash = @{}
                                $TargetTempHash."Id" = $Device.DeviceId
                                $TargetTempHash."Data" = [string]($Component.ComponentSourceName) + "=" + [string]($FileToken)
                                $TargetTempHash."TargetType" = @{}
                                $TargetTempHash."TargetType"."Id" = [uint64]$Device.DeviceReport.DeviceTypeId
                                $TargetTempHash."TargetType"."Name" = $Device.DeviceReport.DeviceTypeName
                                $outputArray += , $tempHash
                                $TargetArray += , $TargetTempHash
                            }
                            else {
                                Write-Host "Skipping component $($tempHash."Name") - No upgrade available"
                            }
                        }
                        $outputArray.Foreach({[PSCustomObject]$_}) | Format-Table -AutoSize -Property "IpAddress", "Device", "Current Ver", "Avail Ver", "Action", "Reboot Req", "Criticality", "Name" -Wrap | Out-String | % {Write-Host $_}
                   }
                   $DupUpdatePayload."Targets" = $TargetArray                   
                   $RetDupPayload = $DupUpdatePayload 
                }
                else {
                    Write-Warning "No applicable devices found for updating...Exiting"
                }
            }
            else {
                Write-Warning "No applicable devices or components found"
            }
        }
    }
    catch {
        Write-Warning "DUP file may not apply to device/group id. Please validate parameters and retry"
        #Write-Host $_.Exception.Response.StatusCode.Value__
    }
    $RetDupPayload
}

function Wait-OnUpdateJobs($IpAddress, $Headers, $Type, $JobId)
{
    $JOB_STATUS_MAP = @{
        "2020"="Scheduled";
        "2030"="Queued";
        "2040"="Starting";
        "2050"="Running";
        "2060"="Completed";
        "2070"="Failed";
        "2090"="Warning";
        "2080"="New";
        "2100"="Aborted";
        "2101"="Paused";
        "2102"="Stopped";
        "2103"="Canceled"
    }

    $FailedJobStatuses = @(2070,2090,2100,2101,2102,2103)

    $MAX_RETRIES = 20
    $SLEEP_INTERVAL = 60

    $JobSvcUrl = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
    $Ctr = 0
    do {        
        $Ctr++
        Start-Sleep -Seconds $SLEEP_INTERVAL
        $JobResp = Invoke-WebRequest -UseBasicParsing -Uri $JobSvcUrl -Headers $Headers -ContentType $Type -Method Get
        if ($JobResp.StatusCode -eq 200) {
            $JobData = $JobResp.Content | ConvertFrom-Json
            $JobStatus = $JobData.LastRunStatus.Id
            Write-Host "Iteration $($Ctr): Status of $($JobId) is $(($JOB_STATUS_MAP.$JobStatus))"
            if ($JobStatus -eq 2060) {
                ## Completed successfully
                Write-Host "Completed updating firmware successfully ..."
                break
            }
            elseif ($FailedJobStatuses -contains $JobStatus) {
                Write-Warning "Update job failed .... "
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
    $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions"
    $Type        = "application/json"
    $UserName    = $Credentials.username
    $Password    = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName"=$UserName;"Password"=$Password;"SessionType"="API"} | ConvertTo-Json
    $Headers     = @{}


    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 201) {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        Write-Host "Successfully created session with $($IpAddress)`nParsing $($DupFile)"
        
        ## Sending in non-existent targets throws an exception with a "bad request"
        ## error. Doing some pre-req error checking as a result to validate input
        ## This is a Powershell quirk on Invoke-WebRequest failing with an error
        if ($GroupId) {
            $GroupList = Get-GroupList $IpAddress $Headers $Type
            if ($GroupList -contains $GroupId) {}
            else {throw "Group $($GroupId) not present on $($IpAddress) ... Exiting"}
        }
        else {
            $DeviceList = Get-DeviceList $IpAddress $Headers $Type
            if ($DeviceList -contains $DeviceId) {}
            else {throw "Device $($DeviceId) not present on $($IpAddress) ... Exiting"}
        }


        ## Validate that the DUP is non empty and upload to OME
        $DupFileLength = (Get-Item $DupFile).Length 
        Write-Host "Successfully parsed $($DupFile) - Size: $($DupFileLength) bytes"
        if ($DupFileLength -gt 0) {
            ## Upload the DUP file and get the file token for it from OME
            $FileTokenInfo = Push-DupToOME $IpAddress $Headers $DupFile
            if ($FileTokenInfo){
                if ($GroupId) {
                    $DupReportPayload = Set-DupApplicabilityPayload $FileTokenInfo @{"GroupId"=$GroupId}
                }
                else {
                    $DupReportPayload = Set-DupApplicabilityPayload $FileTokenInfo @{"DeviceId"=$DeviceId}
                }
                Write-Host "Determining if any devices and components are applicable for $($DupFile)"
                $DupUpdatePayload = Get-ApplicableComponents $IpAddress $Headers $Type $DupReportPayload
                if ($DupUpdatePayload -and ($DupUpdatePayload."Targets".Length -gt 0)){
                    Write-Host $DupUpdatePayload."Targets".Length
                    $JobBody = $DupUpdatePayload | ConvertTo-Json -Depth 6
                    $JobSvcUrl = "https://$($IpAddress)/api/JobService/Jobs"
                    $JobResp = Invoke-WebRequest -Uri $JobSvcUrl -UseBasicParsing -Method Post -Body $JobBody -Headers $Headers -ContentType $Type
                    if ($JobResp.StatusCode -eq 201) {
                        $JobInfo = $JobResp.Content | ConvertFrom-Json
                        $JobId = $JobInfo.Id
                        Write-Host "Created job $($JobId) to flash firmware ... Polling status now"
                        Wait-OnUpdateJobs $IpAddress $Headers $Type $JobId
                    }
                    else {
                        Write-Warning "Unable to create job for firmware update .. Exiting"
                    }
                }
                else {
                    Write-Warning "No updateable components found ... Skipping update"
                }
            }
            else {
                Write-Warning "No file token returned ... "
            }
        }
        else {
            Write-Warning "Dup file $($DupFile) is an empty file ... "
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}