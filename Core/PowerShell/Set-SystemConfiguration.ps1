<#
 .SYNOPSIS
   Script to deploy template
 .DESCRIPTION
    This script exercises the OME REST API to depoy template.
    Note that the credentials entered are not stored to disk.
 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER SourceId
     Source device id to clone the elements from the device.
 .PARAMETER TargetId
    Target device id to deploy template on the target device 
 .Parameter GroupId
     Id of the group to deploy template on the devices belong to the group. 
 .Parameter Component
      Component to clone from source device. 
 .EXAMPLE
   $cred = Get-Credential
   .\Get-Templates.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -SourceId 25527 -TargetId 10782 -Component iDRAC
    In this instance you will be prompted for credentials.
    .EXAMPLE
   $cred = Get-Credential
   .\Get-Templates.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -SourceId 25527 -GroupId 1010 -Component iDRAC
    In this instance you will be prompted for credentials.
#>



[CmdletBinding(DefaultParameterSetName = 'Group_Id')]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [System.UInt32]$SourceId,

    [Parameter(ParameterSetName = 'Device_Id')]
    [System.UInt32]$TargetId,

    [Parameter(ParameterSetName = 'Group_Id', Mandatory)]
    [System.UInt32]$GroupId,

    [Parameter(Mandatory = $false)]
    [ValidateSet("iDRAC", "BIOS", "System", "NIC", "LifecycleController", "RAID", "EventFilters", "All")]
    [String]$Component

)

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
$FailedJobStatus = @(2070, 2090, 2100, 2101, 2102, 2103)
$MAX_RETRIES = 20
$SLEEP_INTERVAL = 30


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


function Get-TemplatePayload($SourceId, $Component) {
    $template_payload = '{
        "Name" : "Test Templates",
        "Description":"aBVT Test Templates",
        "TypeId" : 2,
        "ViewTypeId":2,
        "SourceDeviceId" : 25014,
        "Fqdds" : "EventFilters"
    }'
    $template_payload = $template_payload|ConvertFrom-Json
    $template_payload.SourceDeviceId = $SourceId
    if ($Component) {
        $template_payload.Fqdds = $Component  
    }
    else {
        $template_payload.Fqdds = "All"
    }
    return $template_payload
}

function Get-IdentityPoolPayload() {
    $IdentityPoolPayload = '{
        "Name": "aBVT Test IO",
        "Description": "Fully populated IO pool.",
        "EthernetSettings":{
            "Mac":{
                "IdentityCount":55,
                "StartingMacAddress": "UFBQUFAA"
            }
          },
          "IscsiSettings":{
            "Mac":{
                "IdentityCount":65,
                "StartingMacAddress": "YGBgYGAA"
            },
            "InitiatorConfig":{
                "IqnPrefix":"iqn.dell.com"
            }
          },
          "FcoeSettings":{
            "Mac":{
                "IdentityCount":75,
                "StartingMacAddress": "cHBwcHAA"
            }
          },
          "FcSettings":{
            "Wwnn":{
                "IdentityCount":85,
                "StartingAddress": "IACAgICAgAA="
            },
            "Wwpn":{
                "IdentityCount":85,
                "StartingAddress": "IAGAgICAgAA="
                }
          }
    }'
    return  $IdentityPoolPayload
}


function Get-TemplateStatus($IpAddress, $Headers, $Type, $TemplateId) {
    $TemplateUrl = "https://$($IpAddress)/api/TemplateService/Templates?`$filter=Id eq $($TemplateId)"
    $Ctr = 0
    $Status = $null
    $TemplateIncomplete = $true
    do {
        $Ctr++
        Start-Sleep -Seconds $SLEEP_INTERVAL
        $TemplateResponse = Invoke-WebRequest -Uri $TemplateUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
        if ($TemplateResponse.StatusCode -eq 200) {
            $TemplateInfo = $TemplateResponse.Content | ConvertFrom-Json
            $Status = [string]$TemplateInfo.value[0].Status
            Write-Host "Iteration $($Ctr): Status of $($TemplateId) is $($JOB_STATUS_MAP.$Status)"
            if ($Status -eq "2060") {
                Write-Host "Template created successfully ..."
                $TemplateIncomplete = $false
                break
            }
            elseif ($FailedJobStatus -contains $Status) {
                $TemplateIncomplete = $false
                break
            }
            else { continue }
        }
        else {Write-Warning "Unable to get status for $($TemplateId) .. Iteration $($Ctr)"}
    } until ($Ctr -ge $MAX_RETRIES)
    if ($TemplateIncomplete) {
        Write-Warning "Template creation $($JOB_STATUS_MAP.$Status) after polling $($MAX_RETRIES) times...Check status"
    }
    return $JOB_STATUS_MAP.$Status
}


function New-IdentityPool($IpAddress, $Headers, $Type) {
    $IdentityUrl = "https://$($IpAddress)/api/IdentityPoolService/IdentityPools"
    $IdentityPoolId = $null
    $IdentityPoolPayload = Get-IdentityPoolPayload |ConvertFrom-Json
    $IdentityPoolPayload = $IdentityPoolPayload |ConvertTo-Json -Depth 6
    $IdentityResponse = Invoke-WebRequest -Uri $IdentityUrl -Method Post -Body $IdentityPoolPayload  -ContentType $Type -Headers $Headers
    if ( $IdentityResponse.StatusCode -eq 201) {
        $IdentityInfo = $IdentityResponse.Content |ConvertFrom-Json
        $IsSuccessful = $IdentityInfo.IsSuccessful
        if ($IsSuccessful) {
            Write-Host "Identity pool created successfully"
            $IdentityPoolId = $IdentityInfo.Id
        }
        else {
            throw "Identity pool creation is unsuccessful"
        }
    }
    else {
        throw "unable to create identity pool ..Exiting"
    }
    return $IdentityPoolId
}

function Set-IdentitiesToTarget ($IpAddress, $Type, $Headers, $IdentityId, $TemplateId) {
    $payload = '{
        "TemplateId": 27,
        "IdentityPoolId":14
    }'
    $TemplateUrl = "https://$($IpAddress)/api/TemplateService/Actions/TemplateService.UpdateNetworkConfig"
    $payload = $payload |ConvertFrom-Json
    $payload.TemplateId = $TemplateId
    $payload.IdentityPoolId = $IdentityId
    $AssignIdentityPayload = $payload |ConvertTo-Json -Depth 6
    $AssignIdentityResponse = Invoke-WebRequest -Uri $TemplateUrl -Method Post -Body $AssignIdentityPayload -ContentType $Type -Headers $Headers
    return $AssignIdentityResponse
}

function Set-Configuration($IpAddress, $Type, $Headers, $TemplateId, $IdList) {
    $payload = '{
        "Id":27,
        "TargetIds":[
           25014
        ]
     }'
    $TemplateDeployUrl = "https://$($IpAddress)/api/TemplateService/Actions/TemplateService.Deploy"
    $payload = $payload |ConvertFrom-Json
    $payload.Id = $TemplateId
    $payload.TargetIds = $null
    $payload.TargetIds = @($IdList)
    $DeployTemplatePayload = $payload |ConvertTo-Json -Depth 6
    $DeployResponse = Invoke-WebRequest -Uri $TemplateDeployUrl -Method Post -Body $DeployTemplatePayload -ContentType $Type -Headers $Headers
    return $DeployResponse
}


function Get-DeployTemplateStatus($IpAddress, $Type, $Headers, $JobId) {
    $Completed = $false
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
                Write-Host " Template deployed successfully..."
                $Completed = $true
                break
            }
            elseif ($FailedJobStatus -contains $JobStatus) {
                if ($JobStatus -eq 2090) {
                    Write-Warning "Completed with errors.........."
                }
                else {
                    Write-Warning " Failed to deploy template.... "
                }
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
    return $Completed
}


function Get-AssignedIdentities($IpAddress, $Type, $Headers, $TemplateId, $TargetId) {
    $payload = '{
        "TemplateId" : 27,
        "BaseEntityId" : 25014
      }'
    $TemplateUrl = "https://$($IpAddress)/api/TemplateService/Actions/TemplateService.GetAssignedIdentities"
    $payload = $payload|ConvertFrom-Json
    $payload.TemplateId = $TemplateId
    $payload.BaseEntityId = $TargetId
    $AssignedIdentitiesPayload = $payload|ConvertTo-Json -Depth 6
    $AssignedIdentitiesResponse = Invoke-WebRequest -Uri $TemplateUrl -Method Post -Body $AssignedIdentitiesPayload -ContentType $Type -Headers $Headers
    if ( $AssignedIdentitiesResponse.StatusCode -eq 200) {
        $AssignIdentitiesInfo = $AssignedIdentitiesResponse.Content | ConvertFrom-Json
        $AssignIdentitiesInfo = $AssignIdentitiesInfo |ConvertTo-Json -Depth 6
        write-Host $AssignIdentitiesInfo
    }
    else {
        Write-Warning "unable to get assigned identities"
    }
}


function Get-DeviceIdList($IpAddress, $Headers, $Type, $Url) {
    $DeviceIdList = @()
    $NextLinkUrl = $null
    $BaseUri = "https://$($IpAddress)"
    $DevResp = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
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


function New-Template($IpAddress, $Headers, $Type, $SourceId, $Component ) {
    $TemplateUrl = "https://$($IpAddress)/api/TemplateService/Templates"
    $TemplatePayload = Get-TemplatePayload $SourceId $Component
    $TemplatePayload = $TemplatePayload |ConvertTo-Json -Depth 6
    $TemplateId = $null
    $TemplateResponse = Invoke-WebRequest -Uri $TemplateUrl -Method Post -Body $TemplatePayload -ContentType $Type -Headers $Headers
    Write-Host "Creating Template..."
    if ($TemplateResponse.StatusCode -eq 201) {
        $TemplateId = $TemplateResponse.Content | ConvertFrom-Json
        $TemplateStatus = Get-TemplateStatus $IpAddress $Headers $Type $TemplateId
        if ($TemplateStatus) {
            if ($TemplateStatus -ne "Completed") {
                throw "Template creation $($TemplateStatus)"
            }
        }
        else {
            throw "unable to create template ..Exiting"
        }
    }
    return $TemplateId
}
function Get-GroupIdList ($IpAddress, $Headers, $Type) {
    $GroupIdList = @()
    $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups"
    $GroupResp = Invoke-WebRequest -Uri $GroupUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($GroupResp.StatusCode -eq 200) {
        $GroupInfo = $GroupResp.Content | ConvertFrom-Json
        if ($GroupInfo.'@odata.count' -gt 0 ) {
            $GroupInfo.'value' |  Sort-Object Id | ForEach-Object { $GroupIdList += , $_.Id}
        }
    }
    return $GroupIdList
}

Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices"
    $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups($($GroupId))/Devices"
    $Type = "application/json"
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName" = $UserName; "Password" = $Password; "SessionType" = "API"} | ConvertTo-Json
    $Headers = @{}
    $IdList = @()
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        ## Successfully created a session - extract the auth token from the response
        ## header and update our headers for subsequent requests
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        Write-Host "Session created successfully"
        $DeviceIdList = Get-DeviceIdList $IpAddress $Headers $Type  $DeviceUrl
        if ($null -eq $DeviceIdList  ) {
            throw  "Device not found on $($IpAddress) ... Exiting"
        }
        if ($GroupId) {
            $GroupIdList = Get-GroupIdList $IpAddress $Headers $Type
            if ($GroupIdList -contains $GroupId) {
                $IdList = Get-DeviceIdList $IpAddress $Headers $Type $GroupUrl
            }
            else {
                throw "Group with Id $($GroupId) not found on $($IPAddress) .....Existing "
            }
        }
        if ($TargetId) {
            if ($DeviceIdList -contains $TargetId) {
                $IdList = $TargetId
            }
            else {
                throw "Device with Id $($TargetId) not found on $($IPAddress) .....Existing "
            }
        }
        if ($DeviceIdList -contains $SourceId) {
            $TemplateId = New-Template $IpAddress $Headers $Type $SourceId $Component
            if ($TemplateId) {
                Write-Host "Creating Identity pool ........"
                $IdentityPoolId = New-IdentityPool $IpAddress $Headers $Type
                if ($IdentityPoolId) {
                    Write-Host "Assigning identities to target ........."
                    Start-Sleep -Seconds 30
                    $AssignIdentityResponse = Set-IdentitiesToTarget $IpAddress $Type $Headers $IdentityPoolId $TemplateId
                    if ($AssignIdentityResponse.StatusCode -eq 200 ) {
                        Write-Host "Assigned identities to target successfully"
                        Start-Sleep -Seconds 30
                        Write-Host "Deploying template............."
                        $DeployTemplateResponse = Set-Configuration $IpAddress $Type $Headers  $TemplateId $IdList
                        if ( $DeployTemplateResponse.StatusCode -eq 200) {
                            $DeployTemplateContent = $DeployTemplateResponse.Content|ConvertFrom-Json
                            $JobId = $DeployTemplateContent
                            $Status = Get-DeployTemplateStatus $IpAddress $Type $Headers $JobId
                            if ($Status) {
                                Write-Host "Checking assigned identities........."
                                Start-Sleep -Seconds 30
                                Get-AssignedIdentities  $IpAddress $Type $Headers $TemplateId $TargetId
                            }
                        }
                        else {
                            Write-Warning "Failed to deploy template"
                        }
                    }
                    else {
                        Write-Warning "Unable to assign identities  ..Exiting"
                    }
                }
                else {
                    Write-Warning "Unable to get identitypool id"
                }
            }
            else {
                Write-Warning "Unable to get template id"
            }
        }
        else {
            Write-Warning "Device with Id $($SourceId) not found on $($IPAddress) .....Existing "
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}