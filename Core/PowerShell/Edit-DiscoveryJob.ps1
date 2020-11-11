<#
 .SYNOPSIS
   Script to update an existing discovery job in OME

 .DESCRIPTION

   This script exercises the OME REST API to update an existing discovery job(if found) with the credentials and networkaddress if user passses the iparray.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
  .PARAMETER JobNamePattern
  It is an existing discovery job name/job name pattern
  .PARAMETER DeviceUserName
  user name of the device that needs to be updated in connection profile
  .PARAMETER DevicePassword
  password of the device that needs to be updated in connection profile
  .PARAMETER IpArray
  Array of Ip addresses
  
   .EXAMPLE
  $cred = Get-Credential
  .\Edit-DiscoveryJob --IpAddress "10.xx.xx.xx" -Credentials $cred -JobNamePattern "Discovery_Essentials_IP" -DeviceUserName "root" -DevicePassword "test12" -IpArray 10.xx.xx.xx,10.xx.xx.xx
   
   In this instance you will be prompted for credentials
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [String] $JobNamePattern,

    [Parameter(Mandatory)]
    [String] $DeviceUserName,

    [Parameter(Mandatory)]
    [String] $DevicePassword,

    [parameter(ParameterSetName = 'Discover_Ip')]
    [String[]]$IpArray
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

function Get-DiscoverConfigPayload() {
    $DiscoveryConfigDetails = '{
        "DiscoveryConfigGroupId": 22,
        "DiscoveryConfigGroupName": "Discovery_Essentials_IP_foo.194",
        "DiscoveryConfigModels": [
            {
                "DiscoveryConfigId": 2,
                "DiscoveryConfigStatus": null,
                "DiscoveryConfigTargets": [
                    {
                        "DiscoveryConfigTargetId": 2,
                        "NetworkAddressDetail": null,
                        "SubnetMask": null,
                        "AddressType": 3,
                        "Disabled": false,
                        "Exclude": false
                    }
                ],
                "ConnectionProfileId": 10079,
                "ConnectionProfile": "{\n  \"profileId\" : 10079,\n  \"profileName\" : \"\",\n  \"profileDescription\" : \"\",\n  \"type\" : \"DISCOVERY\",\n  \"updatedBy\" : null,\n  \"updateTime\" : 1580413699634,\n  \"credentials\" : [ {\n    \"type\" : \"WSMAN\",\n    \"authType\" : \"Basic\",\n    \"modified\" : false,\n    \"id\" : 3,\n    \"credentials\" : {\n      \"username\" : \"root\",\n      \"password\" : null,\n      \"domain\" : null,\n      \"caCheck\" : false,\n      \"cnCheck\" : false,\n      \"certificateData\" : null,\n      \"certificateDetail\" : null,\n      \"port\" : 443,\n      \"retries\" : 3,\n      \"timeout\" : 60,\n      \"isHttp\" : false,\n      \"keepAlive\" : false\n    }\n  }, {\n    \"type\" : \"REDFISH\",\n    \"authType\" : \"Basic\",\n    \"modified\" : false,\n    \"id\" : 4,\n    \"credentials\" : {\n      \"username\" : \"root\",\n      \"password\" : null,\n      \"domain\" : null,\n      \"caCheck\" : false,\n      \"cnCheck\" : false,\n      \"certificateData\" : null,\n      \"certificateDetail\" : null,\n      \"port\" : 443,\n      \"retries\" : 3,\n      \"timeout\" : 60,\n      \"isHttp\" : false,\n      \"keepAlive\" : true,\n      \"version\" : null\n    }\n  } ]\n}",
                "DeviceType": [
                    1000
                ]
            }
        ],
        "Schedule": {
            "RunNow": true,
            "RunLater": false,
            "Recurring": null,
            "Cron": "startnow",
            "StartTime": null,
            "EndTime": null
        },
        "CreateGroup": true,
        "TrapDestination": false,
        "CommunityString": false
    }' | ConvertFrom-Json
    return $DiscoveryConfigDetails
}


function Test-IpAddress($ipAddrs) {
    $ipAddrs = $ipAddrs | Where-Object { $_ }
    $ipAddressList = [System.Collections.ArrayList][String[]]$ipAddrs
    foreach ($ip in $ipAddrs) {
        if ($ip -Match '-') {
            $ips = $ip -split "-"
            if (([System.Net.IPAddress]::TryParse($ips[0], [ref]$null) -eq $false) -or ([System.Net.IPAddress]::TryParse($ips[1], [ref]$null) -eq $false) ) {
                Write-Warning "Removing invalid ip address $($ip)"
                $ipAddressList.Remove($ip)
            }
        }
        else {
            if ([System.Net.IPAddress]::TryParse($ip, [ref]$null) -eq $false) {
                Write-Warning "Removing invalid ip address $($ip)"
                $ipAddressList.Remove($ip)
            }
        }
    }
    return $ipAddressList
}

function Get-JobStatus($IpAddress, $Headers, $Type, $JobName) {
    $FailedJobStatuses = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')
    $BaseUri = "https://$($IpAddress)"
    $JobSvcUrl = $BaseUri + "/api/JobService/Jobs"
    $NextLinkUrl = $null
    $job_match_found = $null
    Write-Host "Polling job status"
    $SLEEP_INTERVAL = 3
    Start-Sleep -Seconds $SLEEP_INTERVAL
    $JobResp = Invoke-WebRequest -Uri $JobSvcUrl -Method Get -Headers $Headers -ContentType $Type
    if ($JobResp.StatusCode -eq 200) {
        $JobInfo = $JobResp.Content | ConvertFrom-Json
        $JobList = $JobInfo.value
        $totalJobs = $JobInfo.'@odata.count'
        if ($totalJobs -gt 0) {
            if ($JobInfo.'@odata.nextLink') {
                $NextLinkUrl = $BaseUri + $JobInfo.'@odata.nextLink'
            }
            while ($NextLinkUrl) {
                $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -Method Get -Headers $Headers -ContentType $Type
                if ($NextLinkResponse.StatusCode -eq 200) {
                    $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                    $JobList += $NextLinkData.'value'
                    if ($NextLinkData.'@odata.nextLink') {
                        $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                    }
                    else {
                        $NextLinkUrl = $null
                    }
                }
                else {
                    Write-Warning "Unable to get nextlink response for $($NextLinkUrl)"
                }
            }
        }
        else {
            Write-Warning "Job results are empty"
        }
        
        foreach ($jobinfo in $JobList) {
            if ($jobinfo.'JobName' -match $JobName) {
                if ($jobinfo.'LastRunStatus'.'Name' -eq "Running") {
                    Write-Host "Discovery config job status is $($jobinfo.'LastRunStatus'.'Name')"
                    $job_match_found = 1
                }
            }
        }

        if (!$job_match_found) {
            Write-Host "Unable to track running discovery config job"
        }
    }
    else {
        Write-Warning "Unable to fetch jobs"
    }
}



function Update-Config-Payload($IpAddress, $DeviceUserName, $DevicePassword, $JobNamePattern, $ipAddressList) {
    $DiscoveryConfigModels = @()
    $CredentialsList = @()
    $DiscoveryConfigUrl = "https://$($IpAddress)/api/DiscoveryConfigService/DiscoveryConfigGroups"
    $DiscoveryResp = Invoke-WebRequest -Uri $DiscoveryConfigUrl -Method Get -Headers $Headers -ContentType $Type
    $Payload = Get-DiscoverConfigPayload
    $ConfigGrpId = $null
    $DiscoveryConfigTargets = @()
    if ($DiscoveryResp.StatusCode -eq 200) {
        $ResponseData = $DiscoveryResp | ConvertFrom-Json

        $ConfigValueList = $ResponseData.'value'
        if ($ConfigValueList.Length -gt 0) {
            foreach ($value in $ConfigValueList) {
                if ($value.DiscoveryConfigGroupName -match $JobNamePattern) {
                    $ConfigGrpId = $value.DiscoveryConfigGroupId
                    $DiscoveryConfigTargets = $value.DiscoveryConfigModels[0].DiscoveryConfigTargets
                    $value.DiscoveryConfigModels[0].PSObject.Properties.Remove("DiscoveryConfigTargets")
                    $value.DiscoveryConfigModels[0] | Add-Member -MemberType NoteProperty -Name 'DiscoveryConfigTargets' -Value @()
                    if ($ipAddressList.Length -gt 0) {
                        foreach ($ip in $ipAddressList) {
                            $jsonContent = [PSCustomObject]@{
                                'NetworkAddressDetail' = $ip
                            }
                            $value.DiscoveryConfigModels[0].DiscoveryConfigTargets += $jsonContent
                        }
                    }
                    else {
                        $value.DiscoveryConfigModels[0].DiscoveryConfigTargets = $DiscoveryConfigTargets
                    }
                    $connectionProfile = $value.'DiscoveryConfigModels'.'ConnectionProfile' | ConvertFrom-Json
                    $connectionProfile.'credentials'[0].'credentials'.'username' = $DeviceUserName
                    $connectionProfile.'credentials'[0].'credentials'.'password' = $DevicePassword
                    $connectionProfile.'credentials'[1].'credentials'.'username' = $DeviceUserName
                    $connectionProfile.'credentials'[1].'credentials'.'password' = $DevicePassword
                    $value.'DiscoveryConfigModels'[0].'ConnectionProfile' = $connectionProfile | ConvertTo-Json -Depth 6
                    $Payload.'DiscoveryConfigGroupId' = $value.DiscoveryConfigGroupId
                    $Payload.'DiscoveryConfigGroupName' = $value.DiscoveryConfigGroupName
                    $Payload.'DiscoveryConfigModels' = $value.'DiscoveryConfigModels'
                    break;
                }
            }
        }
        else {
            Write-Warning "Unable to get device config data"
        }
		
        if ($ConfigGrpId) {
            # Modify an existing discovery job
            $ModifyConfigGrpURL = "https://$($IpAddress)/api/DiscoveryConfigService/DiscoveryConfigGroups($($ConfigGrpId))"
            Write-Host "URL = $($ModifyConfigGrpURL)"
            $Body = $Payload | ConvertTo-Json -Depth 6
            $Response = Invoke-WebRequest -Uri $ModifyConfigGrpURL -Headers $Headers -ContentType $Type -Method PUT -Body $Body
            if ($Response.StatusCode -eq 200) {
                Write-Host "Successfully modified the discovery config group"
                Get-JobStatus $IpAddress $Headers $Type $JobNamePattern
            }
            else {
                Write-Warning "Failed to modify discovery config group"
            }
        }
        else {
            Write-Warning "Unable to find discovery config groupname corresponding to the discovery job name pattern passed"
        }
    }
    else {
        Write-Warning "Unable to get device config data"
    }
}


Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $DiscoverUrl = "https://$($IPAddress)/api/DiscoveryConfigService/DiscoveryConfigGroups"
    $Type = "application/json"
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $UserDetails = @{ "UserName" = $UserName; "Password" = $Password; "SessionType" = "API" } | ConvertTo-Json
    $Headers = @{ }
    $ipAddressList = Test-IpAddress $IpArray
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        Update-Config-Payload $IpAddress $DeviceUserName $DevicePassword $JobNamePattern $ipAddressList
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}