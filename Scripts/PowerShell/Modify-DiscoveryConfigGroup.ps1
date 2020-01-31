<#
 .SYNOPSIS
   Script to discover devices in OME

 .DESCRIPTION

   This script exercises the OME REST API to discover devices.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
  .PARAMETER JobNamePattern
  It is discovery job name pattern
  .PARAMETER DeviceUserName
  user name of the device that needs to be updated in connection profile
  .PARAMETER DevicePassword
  password of the device that needs to be updated in connection profile
  .PARAMETER $nodeCredentials
  Credentials used to talk to the server ,chassis
 .EXAMPLE
  $cred = Get-Credential
  $disccred = Get-Credential
  .\Modify-DiscoveryConfig.ps1.ps1 --IpAddress "10.xx.xx.xx" -JobNamePattern "Discovery_Essentials_IP" -DeviceUserName "root" -DevicePassword "test12"
   In this instance you will be prompted for credentials to use to
   connect to the appliance
   .EXAMPLE
  $cred = Get-Credential
  .\Modify-DiscoveryConfig.ps1.ps1 --IpAddress "10.xx.xx.xx" -JobNamePattern "Discovery_Essentials_IP" -DeviceUserName "root" -DevicePassword "test12"
   
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
    [String] $DevicePassword
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
                        "NetworkAddressDetail": "10.255.2.174",
                        "SubnetMask": null,
                        "AddressType": 3,
                        "Disabled": false,
                        "Exclude": false
                    }
                ],
                "ConnectionProfileId": 10079,
                "ConnectionProfile": "{\n  \"profileId\" : 10079,\n  \"profileName\" : \"\",\n  \"profileDescription\" : \"\",\n  \"type\" : \"DISCOVERY\",\n  \"updatedBy\" : null,\n  \"updateTime\" : 1580413699634,\n  \"credentials\" : [ {\n    \"type\" : \"WSMAN\",\n    \"authType\" : \"Basic\",\n    \"modified\" : false,\n    \"id\" : 3,\n    \"credentials\" : {\n      \"username\" : \"root\",\n      \"password\" : \"sebastian\",\n      \"domain\" : null,\n      \"caCheck\" : false,\n      \"cnCheck\" : false,\n      \"certificateData\" : null,\n      \"certificateDetail\" : null,\n      \"port\" : 443,\n      \"retries\" : 3,\n      \"timeout\" : 60,\n      \"isHttp\" : false,\n      \"keepAlive\" : false\n    }\n  }, {\n    \"type\" : \"REDFISH\",\n    \"authType\" : \"Basic\",\n    \"modified\" : false,\n    \"id\" : 4,\n    \"credentials\" : {\n      \"username\" : \"root\",\n      \"password\" : null,\n      \"domain\" : null,\n      \"caCheck\" : false,\n      \"cnCheck\" : false,\n      \"certificateData\" : null,\n      \"certificateDetail\" : null,\n      \"port\" : 443,\n      \"retries\" : 3,\n      \"timeout\" : 60,\n      \"isHttp\" : false,\n      \"keepAlive\" : true,\n      \"version\" : null\n    }\n  } ]\n}",
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
    }' |ConvertFrom-Json
    return $DiscoveryConfigDetails
}

function Get-JobId($IpAddress, $Headers, $DiscoverConfigGroupId) {
    $JobId = -1
    $JobUrl = "https://$($IpAddress)/api/DiscoveryConfigService/Jobs"
    $JobResponse = Invoke-WebRequest -UseBasicParsing -Uri $JobUrl -Headers $Headers -Method Get
    if ($JobResponse.StatusCode -eq 200) {
        $JobInfo = $JobResponse.Content | ConvertFrom-Json
        $JobValues = $JobInfo.value
        foreach ($value in $JobValues) {
            if ($value.DiscoveryConfigGroupId -eq $DiscoverConfigGroupId) {
                $JobId = $value.JobId
                break;
            }
        }
    }
    else {
        Write-Warning "Unable to get jobid"
    }
    return $JobId
}


function Get-JobStatus($IpAddress, $Headers, $Type, $JobName) {
    $FailedJobStatuses = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')
	$BaseUri = "https://$($IpAddress)"
    $JobSvcUrl = $BaseUri + "/api/JobService/Jobs"
	$NextLinkUrl = $null
	Write-Host "Polling job status"
	$SLEEP_INTERVAL = 3
	Start-Sleep -Seconds $SLEEP_INTERVAL
	$JobResp = Invoke-WebRequest -UseBasicParsing -Uri $JobSvcUrl -Method Get -Headers $Headers -ContentType $Type
	#Write-Host "Polling job status"
	#Start-Sleep -Seconds $SLEEP_INTERVAL
	if ($JobResp.StatusCode -eq 200) {
		$JobInfo = $JobResp.Content | ConvertFrom-Json
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
				  }else{
					  $NextLinkUrl = $null
				  }
			  }else {
				Write-Warning "Unable to get nextlink response for $($NextLinkUrl)"
			  }
			}
		}else{
			Write-Warning "Job results are empty"
		}
		$match = $null
		foreach ($jobinfo in $JobList){
			if ($jobinfo.'JobName' -match $JobName){
				if ($jobinfo.'LastRunStatus'.'Name' -eq "Running"){
					Write-Host "Discovery config job status is $($jobinfo.'LastRunStatus'.'Name')"
					$match = 1
				}
			}
		}
		
		if (!$match){
			Write-Host "Unable to track discovery config job status "
		}
	}else{
		Write-Warning "Unable to fetch jobs"
	}
}



function Update-Config-Payload($IpAddress,$DeviceUserName,$DevicePassword,$JobNamePattern) {
    $DiscoveryConfigModels = @()
    $CredentialsList = @()
    $DiscoveryConfigUrl = "https://$($IpAddress)/api/DiscoveryConfigService/DiscoveryConfigGroups"
    $DiscoveryResp = Invoke-WebRequest -UseBasicParsing -Uri $DiscoveryConfigUrl -Method Get -Headers $Headers -ContentType $Type
	$Payload = Get-DiscoverConfigPayload
	$ConfigGrpId = $null
    if ($DiscoveryResp.StatusCode -eq 200) {
        $ResponseData = $DiscoveryResp | ConvertFrom-Json
		
        $ConfigValueList = $ResponseData.'value'
		if ($ConfigValueList.Length -gt 0) {
			foreach ($value in $ConfigValueList) {
				if ($value.DiscoveryConfigGroupName -match $JobNamePattern) {
					$ConfigGrpId = $value.DiscoveryConfigGroupId
					#$DiscoveryConfigModels = $value.'DiscoveryConfigModels'
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
			#Write-Host $Payload.'DiscoveryConfigModels' | ConvertFrom-Json
			#Write-Host $Payload
		}else{
			Write-Warning "Unable to get device config data"
		}
		
		if ($ConfigGrpId){
			# Run discovery config job
			$ModifyConfigGrpURL = "https://$($IpAddress)/api/DiscoveryConfigService/DiscoveryConfigGroups($($ConfigGrpId))"
			Write-Host "URL = $($ModifyConfigGrpURL)"
			$Body = $Payload | ConvertTo-Json -Depth 6
			#Write-Host " Body $($Body)"
			$Response = Invoke-WebRequest -Uri $ModifyConfigGrpURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method PUT -Body $Body
			if ($Response.StatusCode -eq 200) {
				Write-Host "Successfully modified the discovery config group"
				Get-JobStatus $IpAddress $Headers $Type $JobNamePattern
			}
			else {
				Write-Warning "Failed to modify discovery config group"
			}
		}else{
			Write-Warning "Unable to find discovery config groupjname corresponding to the discovery job name pattern passed"
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
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
		Update-Config-Payload $IpAddress $DeviceUserName $DevicePassword $JobNamePattern
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}