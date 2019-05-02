<#
 .SYNOPSIS
   Script to discover devices in OME

 .DESCRIPTION

   This script exercises the OME REST API to discover devices.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
  .PARAMETER DeviceType
  It can be server,network switch chassis, dell storage
  .PARAMETER IPAddressCsvFile
  Path to the Csv file which contains ip addresses
  .PARAMETER IpArray
  Array of Ip addresses
  .PARAMETER $nodeCredentials
  Credentials used to talk to the server ,chassis
 .EXAMPLE
  $cred = Get-Credential
  $disccred = Get-Credential
  .\Find-DeviceForManagement.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -DeviceType {device_type}  -IPAddressCsvFile .\xxxx.csv  -nodeCredentials $disccred
   where {device_type} can be server/chassis
   In this instance you will be prompted for credentials to use to
   connect to the appliance
   .EXAMPLE
  $cred = Get-Credential
  .\Find-DeviceForManagement.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -DeviceType {device_type} -IpArray 10.xx.xx.xx,10.xx.xx.xx-10.yy.yy.yy,...
   where {device_type} can be server/chassis
   In this instance you will be prompted for credentials
#>
[CmdletBinding(DefaultParameterSetName = 'File_path')]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
	[ValidateSet('server', 'chassis')]
    [String] $DeviceType,
    [Parameter(ParameterSetName = 'File_path', Mandatory)]
    [ValidateScript( {
            if (-Not ($_ | Test-Path) ) {
                throw "File or folder does not exist"
            }
            if (-Not ($_ | Test-Path -PathType Leaf) ) {
                throw "The Path argument must be a file. Folder paths are not allowed."
            }
            return $true
        })]
    [System.IO.FileInfo]$IPAddressCsvFile,
    [parameter(ParameterSetName = 'Discover_Ip', Mandatory)]
    [String[]]$IpArray,
    [Parameter(Mandatory)]
    [pscredential] $nodeCredentials
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

function Get-DiscoverDevicePayload() {
    $DiscoveryConfigDetails = '{
         "server":{
            "DiscoveryConfigGroupName":"Server Discovery",
            "DiscoveryConfigModels":[
                {
                 "DiscoveryConfigTargets":[
				 {
						  "NetworkAddressDetail":""
                     }
                 ],
              "ConnectionProfile":"{\"profileName\":\"\",\"profileDescription\":
			 \"\",\"type\":\"DISCOVERY\",\"credentials\" :[{\"type\":
			 \"WSMAN\",\"authType\":\"Basic\",\"modified\":false,\"credentials\":
			 {\"username\":\"\",\"password\":\"\",\"port\":443,\"retries\":3,\"timeout\":
			 60}}]}",
                 "DeviceType":[1000]}],
            "Schedule":{
							"RunNow":true,
							"Cron":"startnow"
                       }
        },
		"network_switch":{
               "DiscoveryConfigGroupName": "Network switch Discovery ",
               "DiscoveryConfigModels": [{
					  "DiscoveryConfigTargets": [{
									 "NetworkAddressDetail": ""
					  }],
					  "ConnectionProfile":  "{\"profileName\" : \"\",\"profileDescription\" :
					  \"\",  \"type\" : \"DISCOVERY\",\"credentials\" : [ {\"type\" :
					  \"SNMP\",\"authType\" : \"Basic\",\"modified\" : false,\"credentials\" :
					  {\"community\" : \"public\",\"port\" : 161,\"enableV3\" :
					  false,\"enableV1V2\" : true,\"retries\" : 3,\"timeout\" : 60}} ]}",
					  "DeviceType": [7000]
               }],
               "Schedule": {
					  "RunNow": true,
					  "Cron": "startnow"
               }
		},
		"dell_storage":{
               "DiscoveryConfigGroupName": "Storage Discovery",
               "DiscoveryConfigModels": [{
					  "DiscoveryConfigTargets": [{
									 "NetworkAddressDetail": ""
					  }],
					  "ConnectionProfile":  "{\"profileName\" : \"\",\"profileDescription\" :
					  \"\",  \"type\" : \"DISCOVERY\",\"credentials\" : [ {\"type\" :
					  \"SNMP\",\"authType\" : \"Basic\",\"modified\" : false,\"credentials\" :
					  {\"community\" : \"public\",\"port\" : 161,\"enableV3\" :
					  false,\"enableV1V2\" : true,\"retries\" : 3,\"timeout\" : 60}} ]}",
					  "DeviceType": [5000]
               }],
               "Schedule": {
					  "RunNow": true,
					  "Cron": "startnow"
               }
		},
		"chassis":{
            "DiscoveryConfigGroupName":"Chassis Discovery",
            "DiscoveryConfigModels":[{
                 "DiscoveryConfigTargets":[
                     {
						  "NetworkAddressDetail":""
                     }
                 ],
               "ConnectionProfile":"{\"profileName\":\"\",\"profileDescription\":
			 \"\",\"type\":\"DISCOVERY\",\"credentials\" :[{\"type\":
			 \"WSMAN\",\"authType\":\"Basic\",\"modified\":false,\"credentials\":
			 {\"username\":\"\",\"password\":\"\",\"port\":443,\"retries\":3,\"timeout\":
			 60}}]}",
                 "DeviceType":[2000]}],
            "Schedule":{
							"RunNow":true,
							"Cron":"startnow"
                       }
        }
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
function Test-IpAddress($ipAddrs) {
    $ipAddrs = $ipAddrs | Where-Object {$_}
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



function Get-JobStatus($IpAddress, $Headers, $Type, $JobId) {
    $FailedJobStatuses = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')
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
            $JobStatus = $JobData.LastRunStatus.Name
            Write-Host "Iteration $($Ctr): Status of $($JobId) is $($JobStatus)"
            if ($JobStatus -eq 'Completed') {
                ## Completed successfully
                Write-Host "Completed Discovering Devices ..."
                break
            }
            elseif ($FailedJobStatuses -contains $JobStatus) {
                Write-Warning "Update job failed .... "
                $JobExecUrl = "$($JobSvcUrl)/ExecutionHistories"
                $ExecResp = Invoke-WebRequest -UseBasicParsing -Uri $JobExecUrl -Method Get -Headers $Headers -ContentType $Type
                if ($ExecResp.StatusCode -eq 200) {
                    Get-ExecutionHistoryDetail $ExecResp $ExecHistoryUrl $Headers $Type $JobExecUrl
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

function Get-ExecutionHistoryDetail($ExecResp, $ExecHistoryUrl, $Headers, $Type, $JobExecUrl) {
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

function Update-Payload($ipAddressList, $DeviceType, $nodeCredentials) {
    $DiscoverUserName = $nodeCredentials.username
    $DiscoverPassword = $nodeCredentials.GetNetworkCredential().password
    $inputs = Get-DiscoverDevicePayload
    $input = $inputs.$DeviceType
    $input.DiscoveryConfigModels[0].PSObject.Properties.Remove("DiscoveryConfigTargets")
    $input.DiscoveryConfigModels[0]| Add-Member -MemberType NoteProperty -Name 'DiscoveryConfigTargets' -Value @()
    foreach ($ip in $ipAddressList) {
        $jsonContent = [PSCustomObject]@{
            'NetworkAddressDetail' = $ip
        }
        $input.DiscoveryConfigModels[0].DiscoveryConfigTargets += $jsonContent
    }
    if ($DeviceType -eq 'server' -or $DeviceType -eq 'chassis') {
        $connectionProfile = $input.'DiscoveryConfigModels'.'ConnectionProfile' | ConvertFrom-Json
        $connectionProfile.'credentials'.'credentials'.'username' = $DiscoverUserName
        $connectionProfile.'credentials'.'credentials'.'password' = $DiscoverPassword
        $input.'DiscoveryConfigModels'[0].'ConnectionProfile' = $connectionProfile | ConvertTo-Json -Depth 6
    }
    return $input
}


Try {
    Set-CertPolicy
    $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
    $DiscoverUrl = "https://$($IPAddress)/api/DiscoveryConfigService/DiscoveryConfigGroups"
    $Type = "application/json"
    $UserName = $Credentials.username
    $Password = $Credentials.GetNetworkCredential().password
    $ipAddrs = @()
    if ($IPAddressCsvFile) {
        Get-Content -path  $IPAddressCsvFile | ForEach-Object {
            $split = $_ -split ","
            foreach ($ip in $split) {
                $ipAddrs += $ip
            }}
    }
    else {
        $ipAddrs = $IpArray
    }
    $ipAddressList = Test-IpAddress $ipAddrs
	if($ipAddressList){
    $input = Update-Payload $ipAddressList $DeviceType $nodeCredentials
    $input = $input | ConvertTo-Json -Depth 6
    $UserDetails = @{ "UserName" = $UserName; "Password" = $Password; "SessionType" = "API" } | ConvertTo-Json
    $Headers = @{ }
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
		Write-Host $input
        $DiscoverResponse = Invoke-WebRequest -Uri $DiscoverUrl -UseBasicParsing -Method Post  -Body $input -Headers $Headers -ContentType $Type
        if ($DiscoverResponse.StatusCode -eq 201) {
            write-Host "Discovering devices...."
            Start-Sleep -Seconds 10
            $DiscoverInfo = $DiscoverResponse.Content | ConvertFrom-Json
            $DiscoverConfigGroupId = $DiscoverInfo.DiscoveryConfigGroupId
            $JobId = Get-JobId $IpAddress $Headers $DiscoverConfigGroupId
            if ($JobId -gt 0) {
                Write-Host "Polling job to completion....."
                Get-JobStatus $IpAddress $Headers $Type $JobId
            }
            else {
                Write-Warning "Unable to get JobID"
            }
        }
        else {
            Write-Error "Unable to discover device  with appliance $($IpAddress) $($DiscoverResponse)"
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
	}else{
	write-Host "Enter a valid Ip Address"
	}
}
Catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}