<#
_author_ = Grant Curell <grant_curell@dell.com>

Copyright (c) 2021 Dell EMC Corporation

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
    Discovers devices and adds them to an OME instance.

  .DESCRIPTION
    This script currently allows the discovery of servers, chassis, and network devices. Storage devices are not
    currently supported. If it would be helpful to you leave a comment on
    https://github.com/dell/OpenManage-Enterprise/issues/114 to let us know this is a priority for you. Currently only
    SNMPv2c is supported for network devices. It does not support SNMPv1 and OME does not currently support SNMPv3. If
    SNMPv1 is a priority for you please open an issue at https://github.com/dell/OpenManage-Enterprise/issues.

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance
  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
  .PARAMETER ServersIps
    A comma separated list of server IPs which you want to discover in the form 'IP1,IP2,IP3'. It will also accept
    the `-` for a range. Ex: 'IP1-IP2,IP3'
  .PARAMETER ChassisIps
    A comma separated list of chassis IPs which you want to discover in the form 'IP1,IP2,IP3'. It will also accept
    the `-` for a range. Ex: 'IP1-IP2,IP3'
  .PARAMETER NetworkDeviceIps
    A comma separated list of network device IPs which you want to discover in the form 'IP1,IP2,IP3'. It will also
    accept the `-` for a range. Ex: 'IP1-IP2,IP3'. WARNING: When discovering network devices, if an IP is not responsive
  .PARAMETER ServerCsv
    A tuple containing a CSV file and column name with a list of IP addresses in the form `CSVFILENAME,"IP Addresses".
     This code will read the CSV file and then look for a column
    with the specified header. It expects one IP address per row.
  .PARAMETER ChassisCsv
    A tuple containing a CSV file and column name with a list of IP addresses in the form `CSVFILENAME,"IP Addresses".
     This code will read the CSV file and then look for a column
    with the specified header. It expects one IP address per row.
  .PARAMETER NetworkDeviceCsv
    A tuple containing a CSV file and column name with a list of IP addresses in the form `CSVFILENAME,"IP Addresses".
     This code will read the CSV file and then look for a column
    with the specified header. It expects one IP address per row.
  .PARAMETER ServerCredentials
    Credentials used to communicate with any servers
  .PARAMETER ChassisCredentials
    Credentials used to communicate with chassis
  .PARAMETER SnmpCommunityString
    The community string for the network devices to which you want to connect.
  .PARAMETER SnmpPort
    (Optional) The SNMP port you want to use for discovery. Defaults to 161.
  .PARAMETER GroupName
    (Optional) The name of a static group in which you want the discovered devices to be added. If the group already
    exists then they will be added there otherwise
    the group will be created and then added.
  .PARAMETER JobCheckSleepInterval
    (Optional) Allows you to adjust the amount of time between checks to see if the discovery job has completed. If
    you are discovering a large number of devices you may want to adjust this to a couple of minutes. Testing has been
     done with 6 devices and 10 seconds was more than sufficient. The default is 30 seconds.

  .EXAMPLE
    $creds = Get-Credential # Your OME credentials
    $servcreds = Get-Credential # Your OME credentials
    .\Invoke-DiscoverDevice -IpAddress 192.168.1.93 -Credentials $creds -ServerIps 192.168.1.63-192.168.1.65 -ServerCredentials $servcreds -GroupName TestGroup -JobCheckSleepInterval 10 -ServerCsv Book1.csv,'IP address' -ChassisCsv Book1.csv,'ChassisIp' -ChassisCredentials $chassiscreds

  .EXAMPLE
    .\Invoke-DiscoverDevice -IpAddress 192.168.1.93 -Credentials $creds -NetworkDeviceIps 192.168.1.24,192.168.1.34 -SnmpCommunityString 'SomeString'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory = $false)]
    [String] $ServerIps,

    [Parameter(Mandatory = $false)]
    [String] $ChassisIps,

    [Parameter(Mandatory = $false)]
    [String] $NetworkDeviceIps,

    [Parameter(Mandatory = $false)]
    [System.Object[]]$ServerCsv,

    [Parameter(Mandatory = $false)]
    [System.Object[]]$ChassisCsv,

    [Parameter(Mandatory = $false)]
    [System.Object[]]$NetworkDeviceCsv,

    [Parameter(Mandatory = $false)]
    [pscredential] $ServerCredentials,

    [Parameter(Mandatory = $false)]
    [pscredential] $ChassisCredentials,

    [Parameter(Mandatory = $false)]
    [string] $SnmpCommunityString,

    [Parameter(Mandatory = $false)]
    [string] $GroupName,

    [Parameter(Mandatory = $false)]
    [UInt32] $SnmpPort = 161,

    [Parameter(Mandatory = $false)]
    [int] $JobCheckSleepInterval = 30
)


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
    dict. A dictionary containing the results of the API call or an empty dictionary in the case of a failure

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
        return @{}
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
      $NextLinkUrl = "https://$($IpAddress)$($CountData.'@odata.nextLink')"
    }

    $i = 1
    while ($NextLinkUrl) {
      if ($MaxPages) {
        if ($i -ge $MaxPages) {
          break
        }
        $i = $i + 1
      }
      
      $NextLinkData = Invoke-RestMethod -Uri "$($NextLinkUrl)" -Method Get -Credential $Credentials `
      -ContentType $Type -SkipCertificateCheck
          
      if ($null -ne $NextLinkData.'value') {
        $Data += $NextLinkData.'value'
      }
      else {
        $Data += $NextLinkData
      }    
      
      if ($NextLinkData.'@odata.nextLink') {
        $NextLinkUrl = "https://$($IpAddress)$($NextLinkData.'@odata.nextLink')"
      }
      else {
        $NextLinkUrl = $null
      }
    }

    return $Data

  }
  catch [System.Net.Http.HttpRequestException] {
    Write-Error "There was a problem connecting to OME or the URL supplied is invalid. Did it become unavailable?"
    return @{}
  }

}


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
            if ($Device.'DeviceManagement'[0].'NetworkAddress' -eq $DeviceIdracIp) {
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
            Write-Host "------------------- ERROR -------------------"
            Write-Host $HistoryResp.value
            Write-Host "------------------- ERROR -------------------"
            return $false
        }
        else { continue }
    } until ($Ctr -ge $MaxRetries)

    if ($Ctr -ge $MaxRetries) {
        Write-Warning "Job exceeded max retries! Check OME for details on what has hung."
        return $false
    }

    return $true
}


function Read-Confirmation() {
    <#
    .SYNOPSIS
      Prompts a user with a yes or no question

    .DESCRIPTION
      Prompts a user with a yes or no question. The question text should include something telling the user
      to type y/Y/Yes/yes or N/n/No/no

    .PARAMETER QuestionText
      The text which you want to display to the user

    .OUTPUTS
      Returns true if the user enters yes and false if the user enters no
    #>
    [CmdletBinding()]
    param (
  
        [Parameter(Mandatory)]
        [string]
        $QuestionText
    )
    do {
        $Confirmation = (Read-Host $QuestionText).ToUpper()
    } while ($Confirmation -ne 'YES' -and $Confirmation -ne 'Y' -and $Confirmation -ne 'N' -and $Confirmation -ne 'NO')

    if ($Confirmation -ne 'YES' -and $Confirmation -ne 'Y') {
        return $false
    }

    return $true
}


function Confirm-Ips() {
    <#
    .SYNOPSIS
      Validates an IP address range

    .DESCRIPTION
      Accepts IP addresses in the formate IP1,IP2,IP3-IP4 or a variation thereof. It separates the addresses into an
      array of individual IP addresses and returns it. If an IP address is not valid it will prompt the user if they
      want to continue. If the user selects no the program will exit.

    .PARAMETER IpRange
      A string containing IP addresses formated as described in the description.

    .OUTPUTS
      An array of System.Net.IPAddress containing individual IP addresses 
    #> 
    [CmdletBinding()]
    param (
  
        [Parameter(Mandatory)]
        [string]
        $IpRange
    )

    $ValidatedIps = @()
    
    $IpRange = [System.Collections.ArrayList][String[]]($IpRange | Where-Object { $_ })
    foreach ($Ip in $IpRange) {
        if ($Ip -Match '-') {
            $Ips = $Ip -Split "-"
            if (([System.Net.IPAddress]::TryParse($Ips[0], [ref]$null) -eq $false) `
                    -or ([System.Net.IPAddress]::TryParse($Ips[1], [ref]$null) -eq $false) ) {
                if (-not (Read-Confirmation "IP address $($Ip) is not valid. Do you want to continue? (Y/N)")) {
                    Exit
                }
            }
            else {
                $ValidatedIps += $Ips
            }
        }
        elseif (($Ip -Match ',')) {
            $Ips = $Ip -split ','
            foreach ($Ip in $Ips) {
                if ([System.Net.IPAddress]::TryParse($Ip, [ref]$null) -eq $false) {
                    if (-not (Read-Confirmation "IP address $($Ip) is not valid. Do you want to continue? (Y/N)")) {
                        Exit
                    }
                }
                else {
                    $ValidatedIps += $Ip
                }
            }
        }
        else {
            if ([System.Net.IPAddress]::TryParse($Ip, [ref]$null) -eq $false) {
                if (-not (Read-Confirmation "IP address $($Ip) is not valid. Do you want to continue? (Y/N)")) {
                    Exit
                }
            }
            else {
                $ValidatedIps += $Ip
            }
        }
    }

    return $ValidatedIps
}


Try {
    $Type = "application/json"
    $ServerIpAddresses = @()
    $ChassisIpAddresses = @()
    $NetworkDeviceIpAddresses = @()

    # -- Validate arguments --
    Write-Host "Validating arguments..."
    if ('' -eq $ServerIps -and $null -eq $ServerCsv `
            -and '' -eq $ChassisIps -and $null -eq $ChassisCsv `
            -and '' -eq $NetworkDeviceIps -and $null -eq $NetworkDeviceCsv) {
        Write-Error "You must provide an IP source for discovery!"
        Exit
    }

    if (($PSBoundParameters.ContainsKey('ServerCsv') -or $PSBoundParameters.ContainsKey('ServerIps')) `
            -and $null -eq $ServerCredentials) {
        Write-Error "You provided IP addresses for servers but did not provide server credentials."
        Exit
    }

    if (($PSBoundParameters.ContainsKey('ChassisCsv') -or $PSBoundParameters.ContainsKey('ChassisIps')) `
            -and $null -eq $ChassisCredentials) {
        Write-Error "You provided IP addresses for chassis but did not provide chassis credentials."
        Exit
    }

    if (($PSBoundParameters.ContainsKey('NetworkDeviceCsv') -or $PSBoundParameters.ContainsKey('NetworkDeviceIps')) `
            -and $null -eq $SnmpCommunityString) {
        Write-Error "You provided IP addresses for network devices but did not provide an SNMP community string."
        Exit
    }

    # -- Validate the list of IP addresses --
    Write-Host "Validating IP addresses..."
    if ($PSBoundParameters.ContainsKey('ServerCsv')) {
        ForEach ($Server in Import-Csv -Path $ServerCsv[0]) {
            if ($Server.PSobject.Properties.name -match $ServerCsv[1]) {
                if ($Server.$($ServerCsv[1]) -eq '') {
                    continue
                }
                if ([System.Net.IPAddress]::TryParse($Server.$($ServerCsv[1]), [ref]$null) -eq $false) {
                    if (-not (Read-Confirmation "The IP address '$($Server.$($ServerCsv[1]))' in your server CSV is not valid. Do you want to continue? (Y/N)")) {
                        Exit
                    }
                }
                $ServerIpAddresses += $Server.$($ServerCsv[1])
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('ChassisCsv')) {
        ForEach ($Chassis in Import-Csv -Path $ChassisCsv[0]) {
            if ($Chassis.PSobject.Properties.name -match $ChassisCsv[1]) {
                if ($Chassis.$($ChassisCsv[1]) -eq '') {
                    continue
                }
                if ([System.Net.IPAddress]::TryParse($Chassis.$($ChassisCsv[1]), [ref]$null) -eq $false) {
                    if (-not (Read-Confirmation "The IP address '$($Chassis.$($ChassisCsv[1]))' in your chassis CSV is not valid. Do you want to continue? (Y/N)")) {
                        Exit
                    }
                }
                $ChassisIpAddresses += $Chassis.$($ChassisCsv[1])
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('NetworkDeviceCsv')) {
        ForEach ($NetworkDevice in Import-Csv -Path $NetworkDeviceCsv[0]) {
            if ($NetworkDevice.PSobject.Properties.name -match $NetworkDeviceCsv[1]) {
                if ($NetworkDevice.$($NetworkDeviceCsv[1]) -eq '') {
                    continue
                }
                if ([System.Net.IPAddress]::TryParse($NetworkDevice.$($NetworkDeviceCsv[1]), [ref]$null) -eq $false) {
                    if (-not (Read-Confirmation "The IP address '$($NetworkDevice.$($NetworkDeviceCsv[1]))' in your network device CSV is not valid. Do you want to continue? (Y/N)")) {
                        Exit
                    }
                }
                $NetworkDeviceIpAddresses += $NetworkDevice.$($NetworkDeviceCsv[1])
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('ServerIps')) {
        $ServerIpAddresses += Confirm-Ips $ServerIps
    }

    if ($PSBoundParameters.ContainsKey('ChassisIps')) {
        $ChassisIpAddresses += Confirm-Ips $ChassisIps
    }

    if ($PSBoundParameters.ContainsKey('NetworkDeviceIps')) {
        $NetworkDeviceIpAddresses += Confirm-Ips $NetworkDeviceIps
    }

    $Payload = @{
        DiscoveryConfigGroupName        = "API Initiated Discovery Task"
        DiscoveryConfigGroupDescription = "This discovery was initiated from a PowerShell script against the OME API"
        TrapDestination                 = $false
        DiscoveryConfigModels           = @()
        Schedule                        = @{
            RunNow   = $true
            RunLater = $false
            Cron     = "startnow"
        }
        CreateGroup                     = $false  # TODO: See https://github.com/dell/OpenManage-Enterprise/issues/116
    }

    # -- Create the discovery payload --
    Write-Host "Creating the discovery payload..."
    if ($PSBoundParameters.ContainsKey('ServerIps') -or $PSBoundParameters.ContainsKey('ServerCsv')) {

        if ($ServerIpAddresses.Length -lt 1) {
            Write-Error "You provided the argument ServerCsv or ServerIps but there are no server IPs to process. Did you have invalid IPs? Exiting."
            Exit
        }

        $DiscoveryConfigTargets = @()
        foreach ($Ip in $ServerIpAddresses) {
            $DiscoveryConfigTargets += @{
                NetworkAddressDetail = $Ip
            }
        }
        
        $Payload.DiscoveryConfigModels += @{
            DiscoveryConfigTargets = $DiscoveryConfigTargets
            ConnectionProfile      = ([String](@{
                        profileName        = ""
                        profileDescription = ""
                        type               = "DISCOVERY"
                        credentials        = @(
                            @{
                                type        = "WSMAN"
                                authType    = "Basic"
                                modified    = $false
                                credentials = @{
                                    username = $ServerCredentials.UserName
                                    password = $ServerCredentials.GetNetworkCredential().Password
                                    port     = 443
                                    retries  = 3
                                    timeout  = 60
                                }
                            }
                        )
                    } | ConvertTo-Json -Depth 6 -Compress))
            DeviceType             = @(1000)
        }
    }

    if ($PSBoundParameters.ContainsKey('NetworkDeviceIps') -or $PSBoundParameters.ContainsKey('NetworkDeviceCsv')) {
        
        if ($NetworkDeviceIpAddresses.Length -lt 1) {
            Write-Error "You provided the argument NetworkDeviceIps or NetworkDeviceCsv but there are no network device IPs to process. Did you have invalid IPs? Exiting."
            Exit
        }

        $DiscoveryConfigTargets = @()
        foreach ($Ip in $NetworkDeviceIpAddresses) {
            $DiscoveryConfigTargets += @{
                'NetworkAddressDetail' = $Ip
            }
        }
        
        $Payload.DiscoveryConfigModels += @{
            DiscoveryConfigTargets = $DiscoveryConfigTargets
            ConnectionProfile      = ([String](@{
                        profileName        = ""
                        profileDescription = ""
                        type               = "DISCOVERY"
                        credentials        = @(
                            @{
                                type        = "SNMP"
                                authType    = "Basic"
                                modified    = $false
                                credentials = @{
                                    # This converts the secure string to a plaintext string
                                    community  = $SnmpCommunityString
                                    port       = $SnmpPort
                                    enableV3   = $false
                                    enableV1V2 = $true
                                    retries    = 3
                                    timeout    = 3
                                }
                            }
                        )
                    } | ConvertTo-Json -Depth 6 -Compress))
            DeviceType             = @(7000)
        }
    }

    $DellStorage = @{}  # TODO - Not yet implemented. See https://github.com/dell/OpenManage-Enterprise/issues/114

    if ($PSBoundParameters.ContainsKey('ChassisIps') -or $PSBoundParameters.ContainsKey('ChassisCsv')) {

        Write-Warning "Warning: Some older CMC versions may have issues with WSMAN authentication. If your CMC/chassis discovery fails with a message related to WSMAN authentication try upgraded to the latest firmware."

        if ($ChassisIpAddresses.Length -lt 1) {
            Write-Error "You provided the argument ChassisCsv or ChassisIps but there are no chassis IPs to process. Did you have invalid IPs? Exiting."
            Exit
        }

        $DiscoveryConfigTargets = @()
        foreach ($Ip in $ChassisIpAddresses) {
            $DiscoveryConfigTargets += @{
                'NetworkAddressDetail' = $Ip
            }
        }
        
        $Payload.DiscoveryConfigModels += @{
            DiscoveryConfigTargets = $DiscoveryConfigTargets
            ConnectionProfile      = ([String](@{
                        profileName        = ""
                        profileDescription = ""
                        type               = "DISCOVERY"
                        credentials        = @(
                            @{
                                type        = "WSMAN"
                                authType    = "Basic"
                                modified    = $true
                                credentials = @{
                                    username = $ChassisCredentials.UserName
                                    password = $ChassisCredentials.GetNetworkCredential().Password
                                    port     = 443
                                    retries  = 3
                                    timeout  = 60
                                }
                            }
                        )
                    } | ConvertTo-Json -Depth 6 -Compress))
            DeviceType             = @(2000)
        }
    }

    Write-Host "Creating discovery job..."
    $Payload = $Payload | ConvertTo-Json -Depth 6
    $DiscoverResponse = Invoke-RestMethod -Uri "https://$($IpAddress)/api/DiscoveryConfigService/DiscoveryConfigGroups"`
        -Method POST -Body $Payload -Credential $Credentials -ContentType $Type `
        -SkipCertificateCheck
    $JobId = -1
    Write-Host "Searching for discovery job ID..."
    $JobValues = Get-Data "https://$($IpAddress)/api/DiscoveryConfigService/Jobs"
    foreach ($value in $JobValues) {
        if ($value.DiscoveryConfigGroupId -eq $DiscoverResponse.DiscoveryConfigGroupId) {
            $JobId = $value.JobId
            Write-Host "Discovery job ID is $($JobId)"
            break;
        }
    }
    if ($JobId -gt 0) {
        Write-Host "Polling job to completion....."

        $JobResult = Invoke-TrackJobToCompletion -OmeIpAddress $IpAddress `
            -JobId $JobId -SleepInterval $JobCheckSleepInterval
        if (-not $JobResult) {
            if (-not (Read-Confirmation "Problems occurred during the discovery. See the above and the OME logs for information. Do you want to continue? (Y/N)")) {
                Exit
            }
        }

        Write-Host "Discovery completed successfully!"

        if ($PSBoundParameters.ContainsKey('GroupName')) {

            Write-Host "Checking if the group $($GroupName) already exists..."
            $GroupData = Get-Data "https://$($IpAddress)/api/GroupService/Groups" "Name eq '$($GroupName)'"

            if ($null -eq $GroupData) {
                Write-Error "There was a problem retrieving the group list. See above for errors."
                Exit
            }

            if ($GroupData.count -eq 0) {
                Write-Host "Group $($GroupName) does not already exist - creating it..."
                $StaticGrpResp = Invoke-RestMethod -Uri "https://$($IpAddress)/api/GroupService/Groups?`$filter=Name eq 'Static Groups'" `
                    -Method Get -Credential $Credentials -SkipCertificateCheck
                                        
                $StaticGrpId = $StaticGrpResp.value[0].Id
                $GrpPayload = @{
                    GroupModel = @{
                        Name             = $GroupName;
                        Description      = $GroupDescription;
                        MembershipTypeId = 12;
                        ParentId         = [uint32]$StaticGrpId
                    }
                } | ConvertTo-Json -Depth 6

                Write-Host "Creating new group..."
                $GroupId = Invoke-RestMethod -Uri "https://$($IpAddress)/api/GroupService/Actions/GroupService.CreateGroup" `
                    -Method POST -ContentType $Type -Body $GrpPayload `
                    -Credential $Credentials -SkipCertificateCheck
                Write-Host "Group $($GroupName) created - ID: $($GroupId)"
            }
            else {
                $GroupId = $GroupData.'Id'
            }

            Write-Host "Adding devices to requested group..."

            $JobInfo = Get-Data "https://$($IpAddress)/api/JobService/Jobs($($JobId))"

            if ($JobInfo.PSobject.Properties.name -match 'ExecutionHistories@odata.navigationLink') {
                $JobInfo = Get-Data "https://$($IpAddress)$($JobInfo.'ExecutionHistories@odata.navigationLink')"
            }
            else {
                Write-Error "Error: Something went wrong getting the job with ID $($JobId). Exiting."
                Exit
            }

            if ($JobInfo.PSobject.Properties.name -match 'ExecutionHistoryDetails@odata.navigationLink') {
                $JobInfo = Get-Data "https://$($IpAddress)$($JobInfo[0].'ExecutionHistoryDetails@odata.navigationLink')"
            }
            else {
                Write-Error "Error: Something went wrong getting the execution details"
                Exit
            }

            $Targets = @()
            $Failures = 0
            if ($JobInfo.count -gt 0) {
                foreach ($HostDevice in $JobInfo) {
                    try {
                        $Target = Get-DeviceId -OmeIpAddress $IpAddress -DeviceIdracIp $HostDevice.'Key'
                        if ($Target -ne -1) {
                            $Targets += [uint32]$Target
                        }
                        else {
                            $Failures += 1
                            Write-Warning "Device $($HostDevice.'Key') was part of your discovery job, but was not successfully discovered. We are not adding it to the group."
                        }
                    }
                    catch [System.Management.Automation.ParameterBindingException] {
                        Write-Warning "Skipping $($HostDevice.'Key')"
                    }
                }
            }

            Write-Host "Successfully discovered $($Targets.count) devices successfully! There were $($Failures) failures."

            $GroupPayload = @{
                GroupId         = [uint32]$GroupId
                MemberDeviceIds = $Targets
            } | ConvertTo-Json -Depth 6
            
            try {
                Invoke-RestMethod -Uri "https://$($IpAddress)/api/GroupService/Actions/GroupService.AddMemberDevices" `
                    -Method POST -ContentType $Type -Body $GroupPayload -Credential $Credentials `
                    -SkipCertificateCheck
                Write-Host "Added $($Targets.count) devices successfully!"
            }
            catch [System.Net.Http.HttpRequestException] {
                Write-Error "Adding the devices to the group failed. This usually means that some of those devices were already in the group. Devices that were not already in the group will have populated. You can check OME for confirmation."
            }
            
        }
    }
    else {
        Write-Warning "Unable to get discovery job ID"
    }
}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
