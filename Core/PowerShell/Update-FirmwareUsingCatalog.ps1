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
    Script to update firmware using Dell's online catalog or a custom NFS/CIFs repository.
  .PARAMETER IpAddress
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
  .PARAMETER GroupName
    The ID of the Group to be updated using the catalog.
  .PARAMETER DeviceIds
    A list of IDs to be updated using the catalog
  .PARAMETER ServiceTags
    A list of service tags to be updated using the catalog
  .PARAMETER IdracIps
    A list of host idrac IPs belonging to hosts you would like to update
  .PARAMETER DeviceNames
    A list of device names belonging to hosts you would like to update
  .PARAMETER UpdateActions
    The type of action you would like to perform. This can be upgrade, downgrade, or flashall
    Currently only upgrade is implemented.
  .PARAMETER RepoType
    (Not yet implemented)The type of resitory from which you would like to pull from. This can be CIFS or NFS.
  .PARAMETER ResourceIp
    The IP address of the CIFs or NFS share from which you would like to pull.
  .PARAMETER CatalogPath
    The fully qualified path to a CFS or NFS repository
  .PARAMETER RepoUser
    The username for the CIFS or NFS repository
  .PARAMETER RepoDomain
    The domain of the CIFS or NFS repository from which you would like to update
  .PARAMETER RepoPassword
    The password for the CIFS or NFS repository
  .PARAMETER Force
    Not yet implemented

  .EXAMPLE
    $cred = Get-Credential
    .\Update-FirmwareUsingCatalog -IpAddress "10.xx.xx.xx" -Credentials $cred -DeviceId 25234
    .\Update-FirmwareUsingCatalog -IpAddress 192.168.1.93 -Credentials $creds -UpdateActions upgrade -RepoType DELL_ONLINE -IdracIps 192.168.1.45

  .EXAMPLE
    .\Update-FirmwareUsingCatalog -IpAddress "10.xx.xx.xx" -Credentials $cred -GroupName Test
     In this instance you will be prompted for credentials to use to connect to the appliance
#>
[CmdletBinding(DefaultParameterSetName = 'Group_Update')]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(ParameterSetName = 'Group_Update', Mandatory = $false)]
    [String]$GroupName,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[int]] $DeviceIds,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $ServiceTags,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[System.Net.IPAddress]] $IdracIps,

    [Parameter(Mandatory = $false)]
    [Collections.Generic.List[string]] $DeviceNames,

    [Parameter(Mandatory = $false)]
    [ValidateSet('upgrade', 'downgrade', 'flash-all')]
    [String]$UpdateActions = 'upgrade',

    [Parameter(Mandatory)]
    [ValidateSet('DELL_ONLINE', 'NFS', 'CIFS')]
    [String]$RepoType,

    [Parameter(Mandatory = $false)]
    [System.Net.IPAddress] $ResourceIp,

    [Parameter(Mandatory = $false)]
    [String] $CatalogPath,

    [Parameter(Mandatory = $false)]
    [String] $RepoUser,

    [Parameter(Mandatory = $false)]
    [String] $RepoDomain,

    [Parameter(Mandatory = $false)]
    [securestring] $RepoPassword,

    [Parameter(Mandatory = $false)]
    [String] $Force

)


function Get-DeviceId {
    <#
    .SYNOPSIS
    Resolves a service tag, idrac IP or device name to a device ID

    .PARAMETER OmeIpAddress
    IP address of the OME server

    .PARAMETER ServiceTag
    (Optional) The service tag of a host

    .PARAMETER DeviceIdracIp
    (Optional) The idrac IP of a host

    .PARAMETER DeviceName
    (Optional) The name of a host

    .OUTPUTS
    int. The output is the ID of the device fed into the function or -1 if it couldn't be found.

    #>

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [System.Net.IPAddress]
        $OmeIpAddress,

        [Parameter(Mandatory = $false)]
        [parameter(ParameterSetName = "ServiceTag")]
        [string]
        $ServiceTag,

        [Parameter(Mandatory = $false)]
        [parameter(ParameterSetName = "DeviceIdracIp")]

        [System.Net.IPAddress]
        $DeviceIdracIp,

        [Parameter(Mandatory = $false)]
        [parameter(ParameterSetName = "DeviceName")]
        [System.Net.IPAddress]
        $DeviceName
    )

    $DeviceId = -1
    
    if ($PSBoundParameters.ContainsKey('DeviceName')) {
        $DeviceId = Get-Data "https://$($OmeIpAddress)/api/DeviceService/Devices" "DeviceName eq `'$($DeviceName)`'"

        if ($null -eq $DeviceId) {
            Write-Output "Error: We were unable to find device name $($DeviceName) on this OME server. Exiting."
            Exit
        }
        else {
            $DeviceId = $DeviceId.'Id'
        }
    }

    if ($PSBoundParameters.ContainsKey('ServiceTag')) {
        $DeviceId = Get-Data "https://$($OmeIpAddress)/api/DeviceService/Devices" "DeviceServiceTag eq `'$($ServiceTag)`'"

        if ($null -eq $DeviceId) {
            Write-Output "Error: We were unable to find service tag $($ServiceTag) on this OME server. Exiting."
            Exit
        }
        else {
            $DeviceId = $DeviceId.'Id'
        }
    }

    if ($PSBoundParameters.ContainsKey('DeviceIdracIp')) {
        $DeviceList = Get-Data "https://$($OmeIpAddress)/api/DeviceService/Devices"
        foreach ($Device in $DeviceList) {
            if ($Device.'DeviceManagement'[0].'NetworkAddress' -eq $IdracIp) {
                $DeviceId = $Device."Id"
                break
            }
        }

        if ($DeviceId -eq 0) {
            throw "Error: We were unable to find idrac IP $($IdracIp) on this OME server. Exiting."
        }
    }

    return $DeviceId
}


function Get-Data {
    <#
    .SYNOPSIS
      Used to interact with API resources
  
    .DESCRIPTION
      This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
      handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
      pages to get a complete listing.
  
    .PARAMETER Url
      The API url against which you would like to make a request
  
    .PARAMETER OdataFilter
      An optional parameter for providing an odata filter to run against the API endpoint.
  
    .PARAMETER MaxPages
      The maximum number of pages you would like to return
  
    .INPUTS
      None. You cannot pipe objects to Get-Data.
  
    .OUTPUTS
      dict. A dictionary containing the results of the API call
  
  #>
  
    [CmdletBinding()]
    param (
  
      [Parameter(Mandatory)]
      [string]
      $Url,
  
      [Parameter(Mandatory = $false)]
      [string]
      $OdataFilter,
  
      [Parameter(Mandatory = $false)]
      [int]
      $MaxPages = $null
    )
  
    $Data = @()
    $NextLinkUrl = $null
    try {
  
      if ($PSBoundParameters.ContainsKey('OdataFilter')) {
        $CountData = Invoke-RestMethod -Uri $Url"?`$filter=$($OdataFilter)" -Method Get -Credential $Credentials -SkipCertificateCheck
  
        if ($CountData.'@odata.count' -lt 1) {
          Write-Error "No results were found for filter $($OdataFilter)."
          return $null
        } 
      }
      else {
        $CountData = Invoke-RestMethod -Uri $Url -Method Get -Credential $Credentials -ContentType $Type `
          -SkipCertificateCheck
      }
  
      if ($null -ne $CountData.'value') {
        $Data += $CountData.'value'
      }
      else {
        $Data += $CountData
      }
        
      if ($CountData.'@odata.nextLink') {
        $NextLinkUrl = $BaseUri + $CountData.'@odata.nextLink'
      }
  
      $i = 1
      while ($NextLinkUrl) {
        if ($MaxPages) {
          if ($i -ge $MaxPages) {
            break
          }
          $i = $i + 1
        }
        $NextLinkData = Invoke-RestMethod -Uri "https://$($IpAddress)$($NextLinkUrl)" -Method Get -Credential $Credentials `
          -ContentType $Type -SkipCertificateCheck
            
        if ($null -ne $NextLinkData.'value') {
          $Data += $NextLinkData.'value'
        }
        else {
          $Data += $NextLinkData
        }    
            
        if ($NextLinkData.'@odata.nextLink') {
          $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
        }
        else {
          $NextLinkUrl = $null
        }
      }
    
      return $Data
  
    }
    catch [System.Net.Http.HttpRequestException] {
      Write-Error "There was a problem connecting to OME or the URL supplied is invalid. Did it become unavailable?"
      return $null
    }
  
  }


function Test-Version($Version, $CurrentVersion) {
    <#
      .SYNOPSIS
        This is a helper function used to normalize version info so that PowerShell can compare

      .PARAMETER Version
        The version that is on the host

      .PARAMETER CurrentVersion
        The current up-to-date version

      .OUTPUTS
        A tuple containing the normalized versions
    #>
    if (($Version -match "^[\d\.]+$") -and ($CurrentVersion -match "^[\d\.]+$") ) {
        if ($Version.length -eq 1) {
            # append .0 to the single digit version since powershell [Version] requires [\d.\d] format.
            $Version = $Version + '.' + '0'
        }
        if ($CurrentVersion.length -eq 1) {
            $CurrentVersion = $CurrentVersion + '.' + '0'
        }
        $Version = [Version]$Version
        $CurrentVersion = [Version]$CurrentVersion
    }
    return $Version, $CurrentVersion
}


function Invoke-CheckDeviceComplianceReport($IpAddress, $Type, $BaselineId, $UpdateAction) {
    <#
    .SYNOPSIS
      Checks all devices in the compliance reports and generates a list of devices to update

    .DESCRIPTION
      This function reaches out to the baselines API and retrieves the compliance report associated with it. It then loops
      over each finding for each device and creates a payload for it.

    .PARAMETER IpAddress
      The IP address of the OME instance

    .PARAMETER Type
      The type of request to use for post methods. This will always be application/json here

    .PARAMETER BaselineId
      The identifier for the baseline containing the compliance reports

    .PARAMETER UpdateAction
      The type of action you would like to perform. This can be upgrade, downgrade, or flashall

    .OUTPUTS
      list. The output of this function are all the different devices which need to be updated. This is later fed into the
      payload sent to the update task.

    #>
    Write-Host "Checking compliance report..."
    $DeviceComplianceReportTargetList = @()
    $DeviceComplianceReportHash = @{}
    $TimeSpan = New-TimeSpan -Minutes 20
    $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host "Waiting for compliance report to finish. Timeout is $($TimeSpan)."
    do {
        Start-Sleep 5
        $ComplData = Invoke-RestMethod `
                                       -Uri "https://$($IpAddress)/api/UpdateService/Baselines($($BaselineId))/DeviceComplianceReports" `
                                       -Method GET -SkipCertificateCheck -Credential $Credentials
        Write-Host "Checking if baseline compliance report has finished. $($StopWatch.elapsed) has passed."
    } while ($StopWatch.elapsed -lt $TimeSpan -and $null -eq $ComplData)
    
    $ComplValList = $ComplData.'value'
    
    Write-Host "Checking compliance report versions for each device to determine what needs to be updated..."
    if ($ComplValList.Length -gt 0) {
        if ($ComplValList[0].ComponentComplianceReports) {
            foreach ($ComplianceHash in $ComplValList) { 
                $SourcesString = $null
                $CompList = $ComplianceHash.'ComponentComplianceReports'
                if ($CompList.Length -gt 0) {
                    foreach ($Component in $CompList) {
                        $Version, $CurrentVersion = Test-Version $Component.'Version' $Component.'CurrentVersion'
                        if ($Version -gt $CurrentVersion) {
                            if ($UpdateAction -contains $Component.'UpdateAction') {
                                $SourceName = $Component.'SourceName'
                                if ($SourcesString.Length -eq 0) {
                                    $SourcesString += $SourceName
                                }
                                else {
                                    $SourcesString += ';' + $SourceName
                                }
                            }
                        }
                    }
                }
                if ( $null -ne $SourcesString) {
                    $DeviceComplianceReportHash.'Data' = $SourcesString
                    $DeviceComplianceReportHash.'Id' = $ComplianceHash.'DeviceId'
                    $DeviceComplianceReportTargetList += $DeviceComplianceReportHash
                }
            }
        }
        elseif ($ComplValList.Length -gt 0) {
            foreach ($ComplianceHash in $ComplValList) {
                $SourcesString = $null
                $NavigationUrlLink = $ComplianceHash.'ComponentComplianceReports@odata.navigationLink'
                $NavigationURL = "https://$($IpAddress)" + "$NavigationUrlLink"
                $ComponentComplianceReportsResponse = Invoke-WebRequest -Uri $NavigationURL -ContentType $Type `
                -Method GET -SkipCertificateCheck -Credential $Credentials
                if ($ComponentComplianceReportsResponse.StatusCode -eq 200) {
                    $ComponentComplianceData = $ComponentComplianceReportsResponse.Content | ConvertFrom-Json
                    if ($ComponentComplianceData.'@odata.count' -gt 0) {
                        $ComponentComplianceValue = $ComponentComplianceData.'value' 
                        $Version, $CurrentVersion = Test-Version $ComponentComplianceValue.'Version' `
                        $ComponentComplianceValue.'CurrentVersion'
                        if ($Version -gt $CurrentVersion) {
                            $SourceName = $ComponentComplianceValue.'SourceName'
                            if ($UpdateAction -contains $Component.'UpdateAction') {
                                if ($SourcesString.Length -eq 0) {
                                    $SourcesString += $SourceName
                                }
                                else {
                                    $SourcesString += ';' + $SourceName
                                }
                            }
                        }
                        if ( $null -ne $SourcesString) {
                            $DeviceComplianceReportHash.'Data' = $SourcesString
                            $DeviceComplianceReportHash.'Id' = $ComplianceHash.'DeviceId'
                            $DeviceComplianceReportTargetList += $DeviceComplianceReportHash
                        }
                    }
                }
                else {
                    Write-Warning "Compliance reports api call did not succeed...status code returned is not 200"
                }
            }
        }
    }
    else {
        Write-Warning "Compliance value list is empty"
    }
    return $DeviceComplianceReportTargetList
}


function Invoke-TrackJobToCompletion {
    <#
    .SYNOPSIS
    Tracks a job to either completion or a failure within the job.

    .PARAMETER OmeIpAddress
    The IP address of the OME server

    .PARAMETER JobId
    The ID of the job which you would like to track

    .PARAMETER MaxRetries
    (Optional) The maximum number of times the function should contact the server to see if the job has completed

    .PARAMETER SleepInterval
    (Optional) The frequency with which the function should check the server for job completion

    .OUTPUTS
    True if the job completed successfully or completed with errors. Returns false if the job failed.

    #>

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [System.Net.IPAddress]
        $OmeIpAddress,

        [Parameter(Mandatory)]
        [int]
        $JobId,

        [Parameter(Mandatory = $false)]
        [int]
        $MaxRetries = 20,

        [Parameter(Mandatory = $false)]
        [int]
        $SleepInterval = 60
    )

    $FAILEDJOBSTATUSES = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')
    $Ctr = 0
    do {
        $Ctr++
        Start-Sleep -Seconds $SleepInterval
        $JOBSVCURL = "https://$($IpAddress)/api/JobService/Jobs($($JobId))"
        $JobData = Get-Data $JOBSVCURL

        if ($null -eq $JobData) {
            Write-Error "Something went wrong tracking the job data. 
            Try checking jobs in OME to see if the job is running."
            return $false
        }

        $JobStatus = $JobData.LastRunStatus.Name
        Write-Host "Iteration $($Ctr): Status of $($JobId) is $($JobStatus)"
        if ($JobStatus -eq 'Completed') {
            ## Completed successfully
            Write-Host "Job completed successfully!"
            break
        }
        elseif ($FAILEDJOBSTATUSES -contains $JobStatus) {
            Write-Warning "Job failed"
            $JOBEXECURL = "$($JOBSVCURL)/ExecutionHistories"
            $ExecRespInfo = Invoke-RestMethod -Uri $JOBEXECURL -Method Get -Credential $Credentials -SkipCertificateCheck
            $HistoryId = $ExecRespInfo.value[0].Id
            $HistoryResp = Invoke-RestMethod -Uri "$($JOBEXECURL)($($HistoryId))/ExecutionHistoryDetails" -Method Get `
                                             -ContentType $Type -Credential $Credentials -SkipCertificateCheck
            Write-Host ($HistoryResp.value)
            return $false
        }
        else { continue }
    } until ($Ctr -ge $MaxRetries)

    return $true
}


# -- Main script - beginning of execution is here --
try {
    $UpdateAction = @()
    $Type = "application/json"
    $CATALOGURL = "https://$($IpAddress)/api/UpdateService/Catalogs"
    $FAILEDJOBSTATUS = @('Failed', 'Warning', 'Aborted', 'Paused', 'Stopped', 'Canceled')

    # TODO - This is not yet implemented
    foreach ( $Action in $UpdateActions) {
        if ($Action -eq "flash-all" -or $Action -eq "downgrade") {
            Write-Error "The flash-all and downgrade actions are not yet implemented."
            Exit
        }
    }

    foreach ( $Action in $UpdateActions) {
        if ($Action -eq "flash-all") {
            $UpdateAction += 'UPGRADE'
            $UpdateAction += 'DOWNGRADE'
            break
        }
        $UpdateAction += $Action.ToUpper()
    }

    if ($RepoType -eq "CIFS") {
        Write-Error "Using CIFs functionality has not yet been implemented."
        Exit
        if (($ResourceIp -eq "") -or ($CatalogPath -eq "") -or ($RepoUser -eq "") -or ($RepoPassword -eq "")) {
            throw "CIFS repository requires --ResourceIp, --CatalogPath, --RepoUser and --RepoPassword."
        }
    }
    if ($RepoType -eq "NFS") {
        Write-Error "Using NFS functionality has not yet been implemented."
        Exit
        if (($ResourceIp -eq "") -or ($CatalogPath -eq "")) {
            throw "NFS repository requires --ResourceIp, --CatalogPath."
        }
    }

    $Targets = @()


    # -- Create a list of targets for firmware update --

    if ($PSBoundParameters.ContainsKey('GroupName') -and ($PSBoundParameters.ContainsKey('ServiceTags') `
        -or $PSBoundParameters.ContainsKey('IdracIps') -or $PSBoundParameters.ContainsKey('DeviceNames'))) {
        $Confirmation = Read-Host "WARNING: You have provided both a group and individual devices. The script will let you do this but if devices you provided indivudally are also in the specified group the behavior is unknown. You probably shouldn't do this, but we won't stop you. Do you want to continue? (Y/N)"
        if ($Confirmation -ne 'y' -and $Confirmation -ne 'Y') {
            Exit
        }
    }

    if ($PSBoundParameters.ContainsKey('DeviceIds')) {
        $Targets += $DeviceIds
    }

    if ($PSBoundParameters.ContainsKey('GroupName')) {

        $GroupData = Get-Data "https://$($IpAddress)/api/GroupService/Groups" "Name eq '$($GroupName)'"

        if ($null -eq $GroupData) {
            Write-Error "We were unable to retrieve the GroupId for group name $($GroupName). Is the name correct?"
            Exit
        }

        $GroupId = $GroupData.'Id'
        $GroupType = $GroupData.'TypeId'
    }
    
    if ($PSBoundParameters.ContainsKey('ServiceTags')) {
        foreach ($ServiceTag in $ServiceTags) {
            $Target = Get-DeviceId -OmeIpAddress $IpAddress -ServiceTag $ServiceTag
            if ($Target -ne -1) {
                $Targets += $Target
            }
            else {
                Write-Error "Error - could not get ID for service tag $($ServiceTag)"
                Exit
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('IdracIps')) {
        foreach ($IdracIp in $IdracIps) {
            $Target = Get-DeviceId -OmeIpAddress $IpAddress -DeviceIdracIp $IdracIp
            if ($Target -ne -1) {
                $Targets += $Target
            }
            else {
                Write-Error "Error - could not get ID for idrac IP $($IdracIp)"
                Exit
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('DeviceNames')) {
        foreach ($DeviceName in $DeviceNames) {
            $Target = Get-DeviceId $IpAddress -DeviceName $DeviceName
            if ($Target -ne -1) {
                $Targets += $Target
            }
            else {
                Write-Error "Error - could not get ID for device name $($DeviceName)"
                Exit
            }
        }
    }


    # -- Check if there are any existing catalogs or baselines and delete them before creating new catalog. --

    $CatalogList = @()
    $BaselineList = @()
    $CatalogInfo = @{}
    $DevInfo = Invoke-RestMethod -Uri $CATALOGURL -Method Get -Credential $Credentials -SkipCertificateCheck
    foreach ($Catalog in $DevInfo.'value') {
        if ($Catalog.'Repository'.'Source' -eq "downloads.dell.com") {
            $CatalogList += $Catalog.'Id'
            if ($Catalog.'AssociatedBaselines'.Length -gt 0) {
                foreach ($Baseline in $Catalog.'AssociatedBaselines') {
                    $BaselineList += $Baseline.'BaselineId'
                }
            }
            else {
                Write-Output "There are no baselines associated with the catalog $($Catalog.Name)"
            }
        }
        else {
            Write-Debug "Catalog $($Catalog.Name) has source other then download.dell.com selected. Skipping it for now."
        }
    }
    $CatalogInfo."CatalogList" = $CatalogList
    $CatalogInfo."BaselineList" = $BaselineList


    # -- Delete any catalogs or baselines which would conflict with this operation --
    # TODO - this should be updated to prompt before deleting or deconflict the naming of the catalog
    # TODO - see https://github.com/dell/OpenManage-Enterprise/issues/86
    Write-Output "Deleting any catalogs that are already associated with the target repository."
    if ($CatalogInfo."BaselineList".Length -gt 0) {
        $Payload = @{
            BaselineIds = $CatalogInfo."BaselineList"
        } | ConvertTo-Json
        $Response = Invoke-RestMethod -Uri "https://$($IpAddress)/api/UpdateService/Actions/UpdateService.RemoveBaselines" `
                                      -Credential $Credentials -ContentType $Type -Method POST -Body $Payload -SkipCertificateCheck
        Write-Output "Deleted all baselines associated with the target repository."
    }
    else {
        Write-Output "There are no baselines associated with the catalog... skipping"
    }

    if ($CatalogInfo."CatalogList".Length -gt 0) {
        $Payload = @{
            CatalogIds = $CatalogInfo."CatalogList"
        } | ConvertTo-Json
        $Response = Invoke-RestMethod -Uri "https://$($IpAddress)/api/UpdateService/Actions/UpdateService.RemoveCatalogs" `
                                      -Credential $Credentials -ContentType $Type -Method POST -Body $Payload -SkipCertificateCheck
        Write-Output "Deleted all catalogs associated with the target repository."
    }
    else {
        Write-Host "There are no catalogs on this OME instance... skipping."
    }

    
    # -- Get the catalog payload --

    $CatalogType = $RepoType
    $Source = $null
    $SourcePath = ""
    $FileName = ""
    $User = ""
    $Domain = ""
    $Password = ""
    if ($CatalogType -eq 'DELL_ONLINE') {
        $Source = "downloads.dell.com"
    }
    else {
        $Source = $RepoSourceIp
        $PathTuple = $CatalogPath
        $SourcePath = $PathTuple.Replace([System.IO.Path]::GetFileName($PathTuple), '')
        $FileName = [System.IO.Path]::GetFileName($PathTuple)
        if ($CatalogType -eq 'CIFS') {
            $User = $RepoUser
            $Domain = $RepoDomain
            $Password = $RepoPassword
            if ($User -ne "" -and $User -contains '\\') {
                $Domain = $RepoUser.split('\\')[0]
                $User = $User.split('\\')[1]
            }

        }

    }
    $Time = Get-Date -Format 'dd:MM:yy-hh:mm:ss'
    $Payload = @"
    {
     "Filename":"$FileName",
      "SourcePath":"$SourcePath",      
      "Repository":
        {
          "Name":"Dell $CatalogType based Catalog + $Time",
          "Description":"$CatalogType dec",
          "RepositoryType":"$CatalogType",
          "Source":"$Source",
          "DomainName":"$Domain",
          "Username":"$User",
          "Password":"$Password",
          "CheckCertificate":false
        }
    }
"@ 


    # -- Create catalog --

    $CatalogId = $null
    $RepoId = $null
    $CatalogRepositorySource = $null
    if ($RepoType -eq 'DELL_ONLINE') {
        $CatalogRepositorySource = "downloads.dell.com"
    }
    else {
        $CatalogRepositorySource = $RepoSourceIp
    }

    $Response = Invoke-RestMethod -Uri $CATALOGURL -Credential $Credentials -ContentType $Type -Method POST `
                                  -Body $Payload -SkipCertificateCheck

    if (-not $Response.TaskId) {
        Write-Error "There was a problem creating the catalog. Check the OME logs for details. Exiting."
        Exit
    }

    Write-Host "Catalog creation job submitted... waiting for completion"
    $CatalogInfo = Invoke-RestMethod -Uri $CATALOGURL -Method GET -SkipCertificateCheck -Credential $Credentials
    
    
    # -- Check catalog status --

    $TimeSpan = New-TimeSpan -Minutes 10
    $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host "Waiting for catalog creation to finish. Timeout is $($TimeSpan)."
    do {
        # Sometimes this needs a pause to work, other times it doesn't. If the ID doesn't exist from the
        # above this will throw an exception caught below.
        $RepoId = $null
        try {
            $CatalogData = Invoke-RestMethod -Uri $CATALOGURL"($($CatalogId))" -Method GET `
                                             -Credential $Credentials -SkipCertificateCheck
            break
        }
        catch [System.Net.Http.HttpRequestException] {
            Write-Output "Catalog not yet created. Waiting for $($SLEEPINTERVAL) seconds and then checking again."
            Start-Sleep $SLEEPINTERVAL
            # TODO This assumes that every other catalog with this source was deleted. This should be updated
            # TODO See https://github.com/dell/OpenManage-Enterprise/issues/86
            $CatalogInfo = Invoke-RestMethod -Uri $CATALOGURL -Method GET -SkipCertificateCheck -Credential $Credentials
            foreach ($Catalog in $CatalogInfo.'value') {
                if ($Catalog.'Repository'.'Source' -eq $CatalogRepositorySource) {
                    $RepoId = [uint64]$Catalog.'Repository'.'Id'
                    $CatalogId = [uint64]$Catalog.'Id'
                }
            }
        }

        $Status = $CatalogData.'Status'

        Write-Host "Catalog status is $($Status)"
        if ($Status -eq 'Completed') {
            Write-Host "Catalog created successfully"
            break
        }

        if ($FAILEDJOBSTATUS -Contains ('$Status')) {
            Write-Host "unable to create catalog"
            break
        }
    } while ($StopWatch.elapsed -lt $TimeSpan -and $null -eq $RepoId)

    if ($StopWatch.elapsed -gt $TimeSpan) {
        Write-Warning "Exceeded the timeout of $($TimeSpan) while waiting for catalog creation to complete. 
        Check the job log for catalog creation. Did something go wring?"
        sys.exit(1)
    }

    Write-Output "Catalog creation successful."


    # -- Create baseline --

    Write-Output "Creating baseline..."
    $BaselineId = $null
    $TargetsPayload = @()
    
    if ($PSBoundParameters.ContainsKey('GroupName')) {
        $TargetsPayload += @{
            Id         = $GroupId
            Type = @{
                Id   = $GroupType
                Name = "GROUP"
            }
        }
    }
    
    if ($PSBoundParameters.ContainsKey('ServiceTags') -or $PSBoundParameters.ContainsKey('IdracIps') -or `
        $PSBoundParameters.ContainsKey('DeviceNames')) {
        foreach ($DeviceToUpdate in $Targets) {
            $TargetsPayload += @{
                Id         = $DeviceToUpdate
                Type = @{
                    Id   = 1000
                    Name = "DEVICE"
                }
            }
        }
    }

    $Payload =  @{
        Name = "Dell baseline update $($Time)"
        Description = "Baseline update job launched via the OME API"
        CatalogId = $CatalogId
        RepositoryId = $RepoId
        DowngradeEnabled = $true
        Is64Bit = $true
        Targets = $TargetsPayload
    } | ConvertTo-Json -Depth 6

    $BASELINEURL = "https://$($IpAddress)/api/UpdateService/Baselines"
    $Response = Invoke-RestMethod -Uri $BASELINEURL -Credential $Credentials -Method POST -Body $Payload `
                                  -ContentType $Type -SkipCertificateCheck
    if (Invoke-TrackJobToCompletion -OmeIpAddress $IpAddress -JobId $Response.'TaskId' -SleepInterval 5) {
        Write-Output "Baseline creation task completed successfully."
    }
    $BaselineInfo = Invoke-RestMethod -Uri $BASELINEURL -Method Get -Credential $Credentials -SkipCertificateCheck
    foreach ($Baseline in $BaselineInfo.'value') {
        if ($Baseline.'CatalogId' -eq $CatalogId) {
            $BaselineId = $Baseline.'Id'
            Break
        }
    }

    if ($null -eq $BaselineId) {
        Write-Error "An error occurred while creating the baseline. Exiting."
        Exit
    }

    Write-Host "Baseline creation successful."


    # -- Create compliance report --

    $ComplianceReportList = Invoke-CheckDeviceComplianceReport $IpAddress $Type $BaselineId $UpdateAction
    if ($ComplianceReportList.Length -gt 0) {
        
        $TargetPayload = @()
        foreach ($ReportHash in $ComplianceReportList) {
            $ReportHash.'TargetType' = @{
                Id = 1000
                Name = "DEVICE"
            }
            $TargetPayload += $ReportHash
        }

        if ($TargetPayload.Length -gt 0) {

            # TODO - See https://github.com/dell/OpenManage-Enterprise/issues/88
            $Payload = @{
                JobName = "OME API Update Firmware Job"
                JobDescription = "Firmware update job triggered by the OME API"
                Schedule = "startNow"
                State = "Enabled"
                JobType = @{
                    Id = 5
                    Name = "Update_Task"
                }
                Params = @(
                    @{
                        Key = "complianceReportId"
                        Value = [string]$BaselineId
                    }
                    @{
                        Key = "repositoryId"
                        Value = [string]$RepoId
                    }
                    @{
                        Key = "catalogId"
                        Value = [string]$CatalogId
                    }
                    @{
                        Key = "operationName"
                        Value = "INSTALL_FIRMWARE"
                    }
                    @{
                        Key = "complianceUpdate"
                        Value = "true"
                    }
                    @{
                        Key = "signVerify"
                        Value = "true"
                    }
                    @{
                        Key = "stagingValue"
                        Value = "false"
                    }
                )
                Targets = $TargetPayload
            } | ConvertTo-Json -Depth 6
            
            # -- Update firmware --
            $Response = Invoke-RestMethod -Uri "https://$($IpAddress)/api/JobService/Jobs" -ContentType $Type `
                                          -Method POST -Body $Payload -SkipCertificateCheck -Credential $Credentials
            
            if ($null -eq $Response.Id) {
                Write-Host "Something went wrong submitting the update job. Check logs for details. Exiting."
                Exit
            }
            
            Write-Host "Device update job submitted!"
            Write-Host "Created job $($Response.Id) to flash firmware... polling status now. Maximum time set at 2 hours"
            if (Invoke-TrackJobToCompletion -OmeIpAddress $IpAddress -JobId $Response.Id -MaxRetries 240 -SleepInterval 30) {
                Write-Host "Firmware update completed successfully!"
            }
            else {
                Write-Error "Firmware update job failed. Check the OME logs for details."
                Exit
            }
        }
    }
    else {
        Write-Warning "The baseline doesn't seem to have any compliance reports associated with it. Check that the baseline was created correctly."
    }
}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
