﻿<#
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
   Script to update firmware using catalog for a device or applicable devices
   within a group
 .DESCRIPTION
   This script exercises the OME REST API to allow updating
   a device or a group of devices by using a single DUP file.
 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER GroupId
   The Id of the Group to be updated using the Catalog.
 .PARAMETER DeviceId
   The Id of the device to be updated using the Catalog.
 .EXAMPLE
   $cred = Get-Credential
   .\Update-InstalledFirmware.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -DeviceId 25234
 .EXAMPLE
   .\Update-InstalledFirmware.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -GroupId 1010
   In this instance you will be prompted for credentials to use to
   connect to the appliance
#>
[CmdletBinding(DefaultParameterSetName = 'Group_Update')]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(ParameterSetName = 'Group_Update', Mandatory)]
    [System.UInt32]$GroupId,

    [Parameter(ParameterSetName = 'Device_Update')]
    [System.UInt32]$DeviceId,
	
    [Parameter(ParameterSetName = 'servicetags')]
    [string]$servicetags,

    [Parameter(Mandatory=$false)]
    [ValidateSet('upgrade', 'downgrade', 'flash-all')]
    [String]$updateActions = 'upgrade',


    [Parameter(Mandatory)]
    [ValidateSet('DELL_ONLINE', 'NFS', 'CIFS')]
    [String]$repotype,

    [Parameter(Mandatory = $false)]
    [System.Net.IPAddress] $reposourceip,

    [Parameter(Mandatory = $false)]
    [String] $catalogpath,

    [Parameter(Mandatory = $false)]
    [String] $repouser,

    [Parameter(Mandatory = $false)]
    [String] $repodomain,

    [Parameter(Mandatory = $false)]
    [String] $repopassword,

    [Parameter(Mandatory = $false)]
    [String] $force

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

function Get-GroupList($IpAddress, $Headers, $Type) {
    $GroupList = @()
    $GroupUrl = "https://$($IpAddress)/api/GroupService/Groups"
    $GrpResp = Invoke-WebRequest -Uri $GroupUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($GrpResp.StatusCode -eq 200) {
        $GroupInfo = $GrpResp.Content | ConvertFrom-Json
        $GroupInfo.'value' |  Sort-Object Id | ForEach-Object {$GroupList += , $_.Id}
    }
    return $GroupList
}

function Get-ServiceTags($IpAddress,$Headers,$Type){
    $NextLinkUrl = $null
    $BaseUri = "https://$($IpAddress)"
    $ServieTagDictionary = @{}
    $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices"
    $DevResp = Invoke-WebRequest -Uri $DeviceUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($DevResp.StatusCode -eq 200) {
        $DevInfo = $DevResp.Content | ConvertFrom-Json
        $DevInfo.'value' |  Sort-Object Id | ForEach-Object {$ServieTagDictionary.Add($_.DeviceServiceTag, $_.Id)} #Add($_.DeviceServiceTag, $_.Id)}
     }
     return $ServieTagDictionary
}


function Get-DeviceList($IpAddress, $Headers, $Type) {
    $NextLinkUrl = $null
    $BaseUri = "https://$($IpAddress)"
    $DeviceList = @()
    $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices"
    $DevResp = Invoke-WebRequest -Uri $DeviceUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($DevResp.StatusCode -eq 200) {
        $DevInfo = $DevResp.Content | ConvertFrom-Json
        $DevInfo.'value' |  Sort-Object Id | ForEach-Object {$DeviceList += , $_.Id}

        if ($DevInfo.'@odata.nextLink') {
            $NextLinkUrl = $BaseUri + $DevInfo.'@odata.nextLink'
        }

        while($NextLinkUrl){
            $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
            if($NextLinkResponse.StatusCode -eq 200) {
                $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                $NextLinkData.'value' | Sort-Object Id | ForEach-Object {$DeviceList += , $_.Id}
                if($NextLinkData.'@odata.nextLink') {
                    $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                }
                else {
                    $NextLinkUrl = $null
                }
            }
            else {
                Write-Warning "Unable to get nextlink response for $($NextLinkUrl)"
                $NextLinkUrl = $null
            }
        }
    }
    return $DeviceList
}

function Check-ExistingCatalogAndBaseline($IpAddress, $Headers, $Type) {
    $CatalogList = @()
    $BaselineList = @()
    $CatalogInfo = @{}
    $CatalogURL = "https://$($IpAddress)/api/UpdateService/Catalogs"
    $Response = Invoke-WebRequest -Uri $CatalogURL -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($Response.StatusCode -eq 200) {
        $DevInfo = $Response.Content | ConvertFrom-Json
        $values = $DevInfo.'value'
        foreach ($data in $values) {
            if ($data.'Repository'.'Source' -eq "downloads.dell.com") {
                $CatalogList += $data.'Id'
                if ($data.'AssociatedBaselines'.Length -gt 0) {
                    foreach ($baseline in $data.'AssociatedBaselines') {
                        $BaselineList += $baseline.'BaselineId'
                    }
                }
                else {
                    Write-Host "There are no baselines associated for the Catalog $($CatalogList)"
                }
            }
            else {
                Write-Host "Skipping for other sources"
            }
        }
        $CatalogInfo."CatalogList" = $CatalogList
        $CatalogInfo."BaselineList" = $BaselineList
    }
    return $CatalogInfo
}

function Delete-CatalogAndBaseline($IpAddress, $Headers, $Type, $CatalogInfo) {
    $DeleteCatalogURL = "https://$($IpAddress)/api/UpdateService/Actions/UpdateService.RemoveCatalogs"
    $DeleteBaselineURL = "https://$($IpAddress)/api/UpdateService/Actions/UpdateService.RemoveBaselines"
    if ($CatalogInfo."BaselineList".Length -gt 0) {
        $BaselineDeletePayload = @{}
        $BaselineDeletePayload."BaselineIds" = $CatalogInfo."BaselineList"
        $payload = $BaselineDeletePayload | ConvertTo-Json
        $Response = Invoke-WebRequest -Uri $DeleteBaselineURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method POST -Body $payload
        if ($Response.StatusCode -eq 204) {
            Write-Host "Existing baselines deleted successfully"
        }
        else {
            Write-Error "Unable to delete baselines"
        }
    }
    else {
        Write-Host "There are no baselines associated..skipping"
    }

    if ($CatalogInfo."CatalogList".Length -gt 0) {
        $CatalogDeletePayload = @{}
        $CatalogDeletePayload."CatalogIds" = $CatalogInfo."CatalogList"
        $payload = $CatalogDeletePayload | ConvertTo-Json
        $Response = Invoke-WebRequest -Uri $DeleteCatalogURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method POST -Body $payload
        if ($Response.StatusCode -eq 204) {
            Write-Host "Existing catalogs deleted successfully"
        }
        else {
            Write-Error "Unable to delete catalogs"
        }
    }
    else {
        Write-Host "There are no existing catalogs..skipping"
    }
}

function Get-BaselineId($IpAddress, $Headers, $Type, $CatalogId) {
    $BaselineURL = "https://$($IpAddress)/api/UpdateService/Baselines"
    $BaselineId = $null
    $Response = Invoke-WebRequest -Uri $BaselineURL -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    if ($Response.StatusCode -eq 200) {
        $BaselineInfo = $Response.Content | ConvertFrom-Json
        $values = $BaselineInfo.'value'
        foreach ($data in $values) {
            if ($data.'CatalogId' -eq $CatalogId) {
                $BaselineId = $data.'Id'
                Break
            }
        }
    }
    return $BaselineId
}

function Create-Baseline($IpAddress, $Headers, $Type, $catalog_id, $repoId, $TargetTypeHash) {
    $BaselinePayload = Get-BaselinePayload $IpAddress $Headers $Type $catalog_id $repoId $TargetTypeHash
    $BaselineURL = "https://$($IpAddress)/api/UpdateService/Baselines"
    $Body = $BaselinePayload | ConvertTo-Json -Depth 6
    $Response = Invoke-WebRequest -Uri $BaselineURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method POST -Body $Body
    if ($Response.StatusCode -eq 201) {
        Write-Host "Baseline creation successful..waiting for completion"
    }
    else {
        Write-Warning "Baseline creation failed"
    }
}

function Create-Catalog($IpAddress, $Headers, $Type, $repo_type,  $repo_source_ip, $catalog_path, $repo_user, $repo_password, $repo_domain) {
    $CatalogPayload = Get-CatalogPayload -repotype $repo_type  -reposourceip $repo_source_ip -catalogpath $catalog_path -repouser $repo_user -repopassword $repo_password -repodomain $repo_domain    
    $CatalogURL = "https://$($IpAddress)/api/UpdateService/Catalogs"
    $Body = $CatalogPayload #| ConvertTo-Json -Depth 6
    $catalog_id = $null
    $repoId = $null
    $CatalogRepositorySource = $null
    if($repo_type -eq 'DELL_ONLINE'){
       $CatalogRepositorySource = "downloads.dell.com"
    }else{
       $CatalogRepositorySource = $repo_source_ip
    }
    $Response = Invoke-WebRequest -Uri $CatalogURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method POST -Body $Body
    if ($Response.StatusCode -eq 201) {
        Write-Host "Catalog creation successful..waiting for completion"
        Start-Sleep -s 80
        $Response = Invoke-WebRequest -Uri $CatalogURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
        $CatalogInfo = $Response | ConvertFrom-Json
        foreach ($catalog in $CatalogInfo.'value') {
            if ($catalog.'Repository'.'Source' -eq $CatalogRepositorySource) {
                $repoId = [uint64]$catalog.'Repository'.'Id'
                $catalog_id = [uint64]$catalog.'Id'
            }
        }
    }
    else {
        Write-Warning "Catalog creation failed...skipping update"
    }
    return $catalog_id, $repoId
}

function Get-CatalogPayload($repotype, $reposourceip, $catalogpath, $repouser, $repopassword, $repodomain) {
   $catalog_type = $repotype
    $source = $null
    $source_path = ""
    $filename = ""
    $user = ""
    $domain = ""
    $password = ""
    if($catalog_type -eq 'DELL_ONLINE'){
        $source = "downloads.dell.com"
    }
    else{
        $source = $reposourceip
        $path_tuple = $catalogpath #os.path.split(kwargs['catalog_path'])
        $source_path = $path_tuple.Replace([System.IO.Path]::GetFileName($path_tuple), '')  #path_tuple[0]
        $filename = [System.IO.Path]::GetFileName($path_tuple)  #path_tuple[1]
        if ($catalog_type -eq 'CIFS'){
            $user = $repouser
            $domain = $repodomain #kwargs['repo_domain'] if 'repo_domain' in kwargs.keys() else ""
            $password = $repopassword
            if ($user -ne "" -and $user -contains '\\'){
                $domain = $repouser.split('\\')[0]
                $user = $user.split('\\')[1]
                }

        }

    }
    $Time = Get-Date -Format 'dd:MM:yy-hh:mm:ss'
    $payload = @"
    {
     "Filename":"$filename",
      "SourcePath":"$source_path",      
      "Repository":
        {
          "Name":"Dell $catalog_type based Catalog + $Time",
          "Description":"$catalog_type dec",
          "RepositoryType":"$catalog_type",
          "Source":"$source",
          "DomainName":"$domain",
          "Username":"$user",
          "Password":"$password",
          "CheckCertificate":false
        }
    }
"@ 
     return $payload

}


function Get-BaselinePayload($IpAddress, $Headers, $Type, $CatalogId, $repoId, $TargetTypeHash) {
    $payload = '{
					"Name": "Factory Baseline1",
					"Description": "Factory test1",
					"CatalogId": 1104,
					"RepositoryId": 604,
					"DowngradeEnabled": true,
					"Is64Bit": true,
					"Targets": [
						{
							"Id":"target_id",
							 "Type": {
								"Id": "target_type",
								"Name": "target_name"
						  }
						}
					]
				}' | ConvertFrom-Json

    $TargetArray = @()
    $TargetArray += $TargetTypeHash
    $payload."Targets" = $TargetArray
    #$payload."Targets" = $TargetTypeHash
    $payload."Name" = "Test Baseline"
    $payload."Description" = "Test Baseline"
    $payload."CatalogId" = $CatalogId
    $payload."RepositoryId" = $repoId
    return $payload
}

function Get-GroupDetail($IpAddress, $Headers, $Type, $GroupId) {
    $GroupServiceURL = "https://$($IpAddress)/api/GroupService/Groups($($GroupId))"
    $Response = Invoke-WebRequest -Uri $GroupServiceURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
    $groupInfo = @{}
    $groupType = @{}
    if ($Response.StatusCode -eq 200) {
        $GroupResp = $Response.Content | ConvertFrom-Json
        if ($GroupResp."Id" -eq $GroupId) {
            $groupType."Id" = $GroupResp."TypeId"
            $groupType."Name" = "Group"
            $groupInfo."Id" =  $GroupId
            $groupInfo."Type" = $groupType
        }
        else {
            Write-Warning "Unable to find group id"
        }
    }
    else {
        Write-Warning "Unable to fetch group info...skipping"
    }
    return $groupInfo
}


function Get-DeviceDetail($IpAddress, $Headers, $Type, $DeviceIds) {
    $DeviceServiceURL = "https://$($IpAddress)/api/DeviceService/Devices"
    $Response = Invoke-WebRequest -Uri $DeviceServiceURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
    $TargetHash = @()
    if ($Response.StatusCode -eq 200) {
        $DevResp = $Response.Content | ConvertFrom-Json
        foreach($object in $DevResp.value){
           $DevInfo = @{}
           $CurrentDevId = $object."Id"
           if ($DeviceIds -contains $CurrentDevId) {
            $DevInfo."Id" = $object."Type"
            $DevInfo."Name" = $object."DeviceName"
            $temp = @{
                      "Id" = $CurrentDevId;
                      "Type" = $DevInfo 
                    }
            $TargetHash +=$temp
            }
            else {
                #Write-Warning "Unable to find device id $CurrentDevId"
            }

        }
        
    }
    else {
        Write-Warning "Unable to fetch device info...skipping"
    }
    return $TargetHash # | ConvertTo-Json

}


function Check-ResponseType($complValList) {
    $flag = "false"
    $complVal = $complValList[0]
	$ComponentCompliance= $complVal.ComponentComplianceReports
		if ($ComponentCompliance){
			$flag = "true"
		}
    return $flag
}

function Check-DeviceComplianceReport($IpAddress, $Headers, $Type, $BaselineId, $updateAction) {
    $ComplURL = "https://$($IpAddress)/api/UpdateService/Baselines($($BaselineId))/DeviceComplianceReports"
    $Response = Invoke-WebRequest -Uri $ComplURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
    $DeviceComplianceReportTargetList = @()
    $DeviceComplianceReportHash = @{}

    if ($Response.StatusCode -eq 200) {
        $ComplData = $Response | ConvertFrom-Json
        $complValList = $ComplData.'value'
		
        if ($complValList.Length -gt 0) {
            $responseType = Check-ResponseType $complValList
            if ($responseType -eq "true") {
                foreach ($complianceHash in $complValList) { 
                    $sourcesString = $null
                    $CompList = $complianceHash.'ComponentComplianceReports'
                    if ($CompList.Length -gt 0) {
                        foreach ($component in $CompList) {
                            $version, $currentVersion = Verify-Version $component.'Version' $component.'CurrentVersion'
                            if ($version -gt $currentVersion) {
                                if($updateAction -contains $component.'UpdateAction'){
                                $sourceName = $component.'SourceName'
                                     if ($sourcesString.Length -eq 0) {
                                         $sourcesString += $sourceName
                                     }
                                     else {
                                         $sourcesString += ';' + $sourceName
                                     }
                                }
                            }
                        }
                    }
                    if ( $null -ne $sourcesString) {
                        $DeviceComplianceReportHash.'Data' = $sourcesString
                        $DeviceComplianceReportHash.'Id' = $complianceHash.'DeviceId'
                        $DeviceComplianceReportTargetList += $DeviceComplianceReportHash
                    }
                }
            }
            elseif ($complValList.Length -gt 0){
                foreach ($complianceHash in $complValList) {
                    $sourcesString = $null
                    $navigationUrlLink = $complianceHash.'ComponentComplianceReports@odata.navigationLink'
                    $navigationURL = "https://$($IpAddress)" + "$navigationUrlLink"
                    $ComponentComplianceReportsResponse = Invoke-WebRequest -Uri $navigationURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
                    if ($ComponentComplianceReportsResponse.StatusCode -eq 200) {
                        $ComponentComplianceData = $ComponentComplianceReportsResponse.Content | ConvertFrom-Json
                        if ($ComponentComplianceData.'@odata.count' -gt 0) {
                            $ComponentComplianceValue = $ComponentComplianceData.'value' 
                            $version, $currentVersion = Verify-Version $ComponentComplianceValue.'Version' $ComponentComplianceValue.'CurrentVersion'
                            if ($version -gt $currentVersion) {
                                $sourceName = $ComponentComplianceValue.'SourceName'
                                if($updateAction -contains $component.'UpdateAction'){
                                    if ($sourcesString.Length -eq 0) {
                                        $sourcesString += $sourceName
                                    }
                                    else {
                                        $sourcesString += ';' + $sourceName
                                    }
                                }
                            }
                            if ( $null -ne $sourcesString) {
                                $DeviceComplianceReportHash.'Data' = $sourcesString
                                $DeviceComplianceReportHash.'Id' = $complianceHash.'DeviceId'
                                $DeviceComplianceReportTargetList += $DeviceComplianceReportHash
                            }
							
				
                        }
                    }
					else {
						Write-Warning "Compliance reports api call did not succeed...status code returned is not 200"
					}
                }
            }
			#>
			
        }
        else {
            Write-Warning "Compliance value list is empty"
        }
    }
    else {
        Write-Warning "Unable to fetch device compliance info...skipping"
    }
    return $DeviceComplianceReportTargetList

}

function Create-TargetPayload($ComplianceReportList) {
    $TargetTypeHash = @{}
    $TargetTypeHash.'Id' = 1000
    $TargetTypeHash.'Name' = "DEVICE"
    $ComplianceReportTargetList = @()
    foreach ($reportHash in $ComplianceReportList) {
        $reportHash.'TargetType' = $TargetTypeHash
        $ComplianceReportTargetList += $reportHash
    }
    return $ComplianceReportTargetList
}

function Wait-OnUpdateJob($IpAddress, $Headers, $Type, $JobId) {
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
        $JobResp = Invoke-WebRequest -UseBasicParsing -Uri $JobSvcUrl -Headers $Headers -ContentType $Type -Method Get
        if ($JobResp.StatusCode -eq 200) {
            $JobData = $JobResp.Content | ConvertFrom-Json
            $JobStatus = [string]$JobData.LastRunStatus.Id
            Write-Host "Iteration $($Ctr): Status of $($JobId) is $($JOB_STATUS_MAP.$JobStatus)"
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

function Get-FirmwareApplicablePayload($catalog_id, $repoId, $baselineId, $TargetPayload) {
    $Payload = '{
        "JobName": "Update Firmware-Test",
        "JobDescription": "Firmware Update Job",
        "Schedule": "startNow",
        "State": "Enabled",
        "JobType": {
            "Id": 5,
            "Name": "Update_Task"
        },
        "Params": [{
            "Key": "complianceReportId",
            "Value": "12"
        },
		{
            "Key": "repositoryId",
            "Value": "1104"
        },
		{
            "Key": "catalogId",
            "Value": "604"
        },
		{
            "Key": "operationName",
            "Value": "INSTALL_FIRMWARE"
        },
		{
            "Key": "complianceUpdate",
            "Value": "true"
        },
		{
            "Key": "signVerify",
            "Value": "true"
        },
		{
            "Key": "stagingValue",
            "Value": "false"
        }],
        "Targets": []
    }' | ConvertFrom-Json

    $ParamsHashValMap = @{
        "complianceReportId" = [string]$baselineId;
        "repositoryId"       = [string]$repoId;
        "catalogId"          = [string]$catalog_id
				}

    for ($i = 0; $i -le $Payload.'Params'.Length; $i++) {
        if ($ParamsHashValMap.Keys -Contains ($Payload.'Params'[$i].'Key')) {
            $value = $Payload.'Params'[$i].'Key'
            $Payload.'Params'[$i].'Value' = $ParamsHashValMap.$value
        }
    }
    $Payload."Targets" += $TargetPayload
    return $payload
}

function Verify-Version($version, $currentVersion) {
    if (($version -match "^[\d\.]+$") -and ($currentVersion -match "^[\d\.]+$") ) {
        if ($version.length -eq 1) {
            # append .0 to the single digit version since powershell [Version] requires [\d.\d] format.
            $version = $version + '.' + '0'
        }
        if ($currentVersion.length -eq 1) {
            $currentVersion = $currentVersion + '.' + '0'
        }
        $version = [Version]$version
        $currentVersion = [Version]$currentVersion
    }
    return $version, $currentVersion
}


function Check-CatalogStatus($IpAddress, $Headers, $Type, $catalog_id) {
    $Count = 1
    $MAX_RETRIES = 20
    $SLEEP_INTERVAL = 15
    $FailedJobstatus = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')
    do {
        $CatalogUrl = "https://$($IpAddress)/api/UpdateService/Catalogs($($catalog_id))"
        $Response = Invoke-WebRequest -Uri $CatalogUrl  -Method GET -Headers $Headers -ContentType $Type
        if ($Response.StatusCode -eq 200) {
            $CatalogData = $Response.Content | ConvertFrom-Json
            $Status = $CatalogData.'Status'
            Write-Host "Catalog Status is $($Status)"
            if ($Status -eq 'Completed') {
                Write-Host "Catalog created successfully"
                break
            }
            if ($FailedJobstatus -Contains ('$Status')) {
                Write-Host "unable to create catalog"
                break
            }
            $Count++
            Start-Sleep -Seconds $SLEEP_INTERVAL
        }
    }Until($Count -eq $MAX_RETRIES)
    if ($Count -eq $MAX_RETRIES) {
        Write-Warning "Trys $($MAX_RETRIES) times. Failed to get Catalog details."
        sys.exit(1)
    }
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
    $DeviceIds = @()

    $updateAction = @()

    if ($repotype -eq "CIFS"){
         if(($reposourceip -eq "") -or ($catalogpath -eq "") -or ($repouser -eq "") -or ($repopassword -eq "")){
               throw "CIFS repository requires --reposourceip, --catalogpath, --repouser and --repopassword."
         }
    }
    if($repotype -eq "NFS"){
        if(($reposourceip -eq "") -or ($catalogpath -eq "")){
            throw "NFS repository requires --reposourceip, --catalogpath."
         }
    }

    foreach( $action in $updateActions){
       if($action -eq "flash-all"){
       $updateAction += 'UPGRADE'
       $updateAction += 'DOWNGRADE'
       break
       }
       $updateAction += $action.ToUpper()
    }

    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 201) {
        $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
        Write-Host "Successfully created session with $($IpAddress)`nParsing $($DupFile)"
        ## Sending in non-existent targets throws an exception with a "bad request"
        ## error. Doing some pre-req error checking as a result to validate input
        ## This is a Powershell quirk on Invoke-WebRequest failing with an error
        if ($GroupId) {
            $GroupList = Get-GroupList $IpAddress $Headers $Type
            if ($GroupList -contains $GroupId) {
				#check if there are any devices associated with this group
				$GroupServiceURL = "https://$($IpAddress)/api/GroupService/Groups($($GroupId))/Devices"
				$Response = Invoke-WebRequest -Uri $GroupServiceURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method GET
				$groupInfo = @{}
				if ($Response.StatusCode -eq 200) {
					$GroupResp = $Response.Content | ConvertFrom-Json
					if ($GroupResp."@odata.count" -eq 0) {
						throw "Unable to fetch group info for group id $($GroupId)"
					}
				}
				else {throw "Unable to fetch group info for the device ... Exiting"}
			}
            else {throw "Group $($GroupId) not present on $($IpAddress) ... Exiting"}
        }
        elseif ($DeviceId) {
            $DeviceList = Get-DeviceList $IpAddress $Headers $Type
            if ($DeviceList -contains $DeviceId) {}
            else {throw "Device $($DeviceId) not present on $($IpAddress) ... Exiting"}
        }
        else {
            $ServiceTagDictionary = Get-ServiceTags $IpAddress $Headers $Type
            Foreach($serviceTag in $ServiceTags){
                if ($ServiceTagDictionary.keys -contains $serviceTag){
                        #write-host $serviceTag + "is present"
                        $DeviceIds += $ServiceTagDictionary.$serviceTag
                }else{
                     throw "ServiceTag $($serviceTag) not present on $($IpAddress) ... Exiting"
                }
            }            
        }
        #check if there are any existing catalogs,baselines and delete them before creating new catalog.
        $CatalogInfo = Check-ExistingCatalogAndBaseline $IpAddress $Headers $Type
        Delete-CatalogAndBaseline $IpAddress $Headers $Type $CatalogInfo
        #Create catalog
        #$catalog_id, $repoId = Create-Catalog $IpAddress $Headers $Type
        $catalog_id, $repoId = Create-Catalog  -IpAddress $IpAddress -Headers $Headers -Type $Type -repo_type $repotype -repo_source_ip $reposourceip -catalog_path $catalogpath -repo_user $repouser -repo_password $repopassword -repo_domain $repodomain
        #catalog_creation(ip_address=IP_ADDRESS, headers=HEADERS, repo_type=ARGS.repotype,
        #                     repo_source_ip=ARGS.reposourceip, catalog_path=ARGS.catalogpath,
        #                     repo_user=ARGS.repouser, repo_password=ARGS.repopassword,
        #                     repo_domain=ARGS.repodomain)
        Check-CatalogStatus $IpAddress $Headers $Type $catalog_id

        #create baseline
        $BaselinePayload = $null
        $baselineId = $null
        #$TargetTypeHash = ""
        if ($GroupId) {
            $TargetTypeHash = Get-GroupDetail $IpAddress $Headers $Type $GroupId
            $TargetTypeHash."Name" = "GROUP"
            Create-Baseline $IpAddress $Headers $Type $catalog_id $repoId $TargetTypeHash
        }
        elseif($DeviceId) {
            $TargetTypeHash = Get-DeviceDetail $IpAddress $Headers $Type $DeviceId
            #Write-Host $TargetTypeHash | ConvertTo-Json -Depth 6
            #Create-Baseline $IpAddress $Headers $Type $catalog_id $repoId $DeviceId $TargetTypeHash
            Create-Baseline $IpAddress $Headers $Type $catalog_id $repoId $TargetTypeHash
        
        }else{
            ##serviceTags base line catalog
            $TargetTypeHash = Get-DeviceDetail $IpAddress $Headers $Type $DeviceIds
            Create-Baseline $IpAddress $Headers $Type $catalog_id $repoId $TargetTypeHash
        
        }
        #Create-Baseline $IpAddress $Headers $Type $catalog_id $repoId $TargetTypeHash
        #Wait for baseline job to complete
        Start-Sleep 120
        $baselineId = Get-BaselineId $IpAddress $Headers $Type $catalog_id
        # Create compliance report
        $ComplianceReportList = Check-DeviceComplianceReport $IpAddress $Headers $Type $baselineId $updateAction
        if ($ComplianceReportList.Length -gt 0) {
            $TargetPayload = Create-TargetPayload $ComplianceReportList
            if ($TargetPayload.Length -gt 0) {
                $UpdatePayload = Get-FirmwareApplicablePayload $catalog_id $repoId $baselineId $TargetPayload
                # Update firmware
                $UpdateJobURL = "https://$($IpAddress)/api/JobService/Jobs"
                $Body = $UpdatePayload | ConvertTo-Json -Depth 6
                $JobResp = Invoke-WebRequest -Uri $UpdateJobURL -UseBasicParsing -Headers $Headers -ContentType $Type -Method POST -Body $Body
                if ($JobResp.StatusCode -eq 201) {
                    Write-Host "Update job creation successful"
                    $JobInfo = $JobResp.Content | ConvertFrom-Json
                    $JobId = $JobInfo.Id
                    Write-Host "Created job $($JobId) to flash firmware ... Polling status now"
                    Wait-OnUpdateJob $IpAddress $Headers $Type $JobId
                }
                else {
                    Write-Warning "Update job creation failed"
                }
            }
        }
        else {
            Write-Warning "Compliance report is null"
        }
    }
    else {
        Write-Error "Unable to create a session with appliance $($IpAddress)"
    }
}
catch {
    Write-Error "Exception occured - $($_.Exception.Message)"
}