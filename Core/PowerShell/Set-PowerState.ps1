<#
 .SYNOPSIS
   Script to perform power control on device
 .DESCRIPTION
    This script exercises the OME REST API to power on
    /power off/reset(warm boot)/power cycle (cold boot)/shutdown
    devices managed by OME.
    Note that the credentials entered are not stored to disk.
 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER DeviceId
    The Id of the device to perform the operation on
 .PARAMETER State
   The desired power state for the device - One of
   off/on/warm boot/cold boot/shutdown
 .EXAMPLE
   $cred = Get-Credential
   .\Set-PowerState.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -DeviceId 25527  -State {state}
    where {state} can be on/off/warm boot/cold boot/shutdown
#>



[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [parameter(Mandatory)]
    [System.UInt32]$DeviceId,
    [Parameter(Mandatory)]
    [ValidateSet("On", "Off", "Cold Boot", "Warm Boot","ShutDown")]
    [String] $State
)

$PowerControlStateMap = @{
    "On"        = "2";
    "Off"       = "12";
    "Cold Boot" = "5";
    "Warm Boot" ="10";
    "ShutDown" = "8"
}

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

function Get-DeviceIdList($IpAddress, $Headers, $Type) {
    $DeviceIdList = @()
    $NextLinkUrl = $null
    $BaseUri = "https://$($IpAddress)"
    $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices"
    $DevResp = Invoke-WebRequest -Uri $DeviceUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($DevResp.StatusCode -eq 200) {
        $DevInfo = $DevResp.Content | ConvertFrom-Json
        if ($DevInfo.'@odata.count' -gt 0 ) {
            $DevInfo.'value' |  Sort-Object Id | ForEach-Object { $DeviceIdList += , $_.Id}
            if($DevInfo.'@odata.nextLink'){
               $NextLinkUrl = $BaseUri + $DevInfo.'@odata.nextLink'
            }
            while($NextLinkUrl){
                    $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                    if($NextLinkResponse.StatusCode -eq 200)
                    {
                        $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                        $NextLinkData.'value' | Sort-Object Id | ForEach-Object {$DeviceIdList += , $_.Id}
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
    }
    return $DeviceIdList
}




function Get-DevicepowerState($IpAddress, $Headers, $Type, $DeviceId) {
    $DeviceUrl = $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices($($DeviceId))"
    $DevResp = Invoke-WebRequest -Uri $DeviceUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    $PowerState = $null
    if ($DevResp.StatusCode -eq 200){
        $DevInfo = $DevResp.Content | ConvertFrom-Json
        $PowerState = $DevInfo.PowerState
    }
    return $PowerState
}


function Get-JobServicePayload() {
    $POWER_CONTROL = '{
    "power_control_details": {
            "Id": 0,
            "JobName": "System Reset",
            "JobDescription": "DeviceAction_Task",
            "Schedule": "startnow",
            "State": "Enabled",
            "JobType": {
                "Id": 3,
                "Name": "DeviceAction_Task"
            },
            "Params": [
                {
                    "Key": "operationName",
                    "Value": "VIRTUAL_RESEAT"
                },
                {
                    "Key": "connectionProfile",
                    "Value": "0"
                }
            ],
            "Targets": [
                {
                    "Id": 26593,
                    "Data": "",
                    "TargetType":
                    {
                        "Id": 1000,
                        "Name": "DEVICE"
                    }
                }
            ]
        }
    }' |ConvertFrom-Json
    return $POWER_CONTROL

}

function Get-UpdatedJobServicePayload ($JobServicePayload, $DeviceId, $State) {
    $JobName = @{
        "On"        = "Power On";
        "Off"       = "Power Off";
        "Cold Boot" = "Power Cycle"
        "Warm Boot" = "System Reset (Warm Boot)"
        "ShutDown" = "Graceful Shutdown"
    }
    $PowerControlDetails = $JobServicePayload."power_control_details"
    $PowerControlDetails."JobName" = $JobName[$State]
    $PowerControlDetails."JobDescription"="Power Control Task:"+$JobName[$State]
    $PowerControlDetails."Params"[0]."Value" = "POWER_CONTROL"
    $PowerControlDetails."Params"[1]."Key" = "powerState"
    $PowerControlDetails."Params"[1]."Value" = $PowerControlStateMap[$State]
    $PowerControlDetails."Targets"[0]."Id" = $DeviceId
    return $PowerControlDetails
}



function Get-JobStatus($IpAddress, $Headers, $Type, $JobId, $State) {
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
    $SLEEP_INTERVAL = 30
    $StatusName=@{ "On"= "Powered On";
    "Off" = "Powered Off";
    "Cold Boot" = "Power Cycle"
    "Warm Boot" = " Reset "
    "ShutDown" = "Shutdown"}
    $JobSvcUrl = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
    $Ctr = 0
    do {
        $Ctr++
        Start-Sleep -Seconds $SLEEP_INTERVAL
        $JobResp = Invoke-WebRequest -UseBasicParsing -Uri $JobSvcUrl -Headers $Headers -ContentType $Type -Method Get
        if ($JobResp.StatusCode -eq 200) {
            $JobData = $JobResp.Content | ConvertFrom-Json
            $JobStatus = [string]$JobData.LastRunStatus.Id
            Write-Host "Iteration $($Ctr): Status of $($JobId) is  $($JOB_STATUS_MAP.$JobStatus)"
            if ($JobStatus -eq 2060) {
                ## Completed successfully
                Write-Host " $($StatusName[$State]) completed successfully..."
                break
            }
            elseif ($FailedJobStatuses -contains $JobStatus) {
                Write-Warning " $($StatusName[$State]) operation failed .... "
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


Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $JobUrl = "https://$($IpAddress)/api/JobService/Jobs"
    $Type = "application/json"
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName" = $UserName; "Password" = $Password; "SessionType" = "API"} | ConvertTo-Json
    $Headers = @{}
    $DeviceIdList = @()
    $PowerStateMap=@{ "On"="17";"Off"="18";"PoweringOn"="20";"PoweringOff"="21"}
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        Write-Host "Successfully created session"
        ## Successfully created a session - extract the auth token from the response
        ## header and update our headers for subsequent requests
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        $DeviceIdList = Get-DeviceIdList $IpAddress $Headers $Type
        if($DeviceIdList){
       if($DeviceIdList -Contains $DeviceId){
          $PowerState = Get-DevicepowerState $IpAddress $Headers $Type $DeviceId
          if($PowerState){
            if($PowerControlStateMap[$State] -eq $PowerState ){
                Write-Host "Device is already in the desired state."
            }elseif(($State -eq "On") -and ($PowerState -eq $PowerStateMap["PoweringOn"])){
                Write-Host "Device is already in the desired state."
            }
            elseif(($State -eq "Off") -and ($PowerState -eq $PowerStateMap["PoweringOff"])){
                Write-Host "Device is already in the desired state. "
            }
            else{
                $JobServicePayload = Get-JobServicePayload
                $UpdatedJobServicePayload = Get-UpdatedJobServicePayload $JobServicePayload $DeviceId $State
                $UpdatedJobServicePayload = $UpdatedJobServicePayload |ConvertTo-Json -Depth 6
                $JobResponse = Invoke-WebRequest -Uri $JobUrl -Method Post -Body $UpdatedJobServicePayload -ContentType $Type -Headers $Headers
                if ($JobResponse.StatusCode -eq 201) {
                    $JobInfo = $JobResponse.Content | ConvertFrom-Json
                    $JobId = $JobInfo.Id
                    Get-JobStatus $IpAddress $Headers $Type $JObId $State
                }
                else {
                    Write-Error "unable to  $($State) device..."
                    Write-Host $JobResponse
                }
            }
          }else{
              Write-Host "Unable to fetch powerstate for device with id $($DeviceId))"
          }
       }else{
        Write-Warning "Device with Id $($DeviceId) not found on $($IPAddress) .....Existing "
       }
    }else{
        Write-Error "Device not found on $($IpAddress) ... Exiting"
    }
}else {
    Write-Error "Unable to create a session with appliance $($IpAddress)"
}
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}