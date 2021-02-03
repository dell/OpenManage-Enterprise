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
    Script to change the power state of a device, set of devices, and/or group in OME.

  .DESCRIPTION
    This script employs the OME REST API to perform power control operations. It accepts idrac IPs, group names, device
    names, service tags, or device ids as arguments. It can optionally write the output of the operation to a CSV file.
    For authentication X-Auth is used over Basic Authentication. Note that the credentials entered are not stored to disk.

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance

  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance

  .PARAMETER GroupName
    The name of the group containing the devices whose power state you want to change.
 
  .PARAMETER DeviceIds
    A comma separated list of device-ids whose power state you want to change.

  .PARAMETER ServiceTags
    A comma separated list of service tags whose power state you want to change.

  .PARAMETER IdracIps
    A comma separated list of idrac IPs whose power state you want to change.

  .PARAMETER DeviceName
    A comma separated list of OME device names whose power state you want to change.

  .PARAMETER CsvFile
    (Optional) If you want to write the output to a CSV you can use this.
 
  .PARAMETER State
    Type of power operation you would like to perform. Can be "POWER_ON", "POWER_OFF_GRACEFUL", 
    "POWER_CYCLE", "POWER_OFF_NON_GRACEFUL", "MASTER_BUS_RESET"

 .EXAMPLE
   $cred = Get-Credential
   .\Set-PowerState.ps1 -IpAddress 192.168.1.93 -Credentials $creds -IdracIps 192.168.1.63 -State POWER_ON -CsvFile test.csv
#>



[CmdletBinding()]
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
    [string] $CsvFile,

    [Parameter(Mandatory)]
    [ValidateSet("POWER_ON", "POWER_OFF_GRACEFUL", "POWER_CYCLE", "POWER_OFF_NON_GRACEFUL", "MASTER_BUS_RESET")]
    [String] $State
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
      # Check to see if $NextLinkUrl is an absolute URI or a relative URI
      if ($null -ne ($CountData.'@odata.nextLink' -as [System.URI]).AbsoluteURI) {
        $NextLinkUrl = $CountData.'@odata.nextLink'
      }
      else {
        $NextLinkUrl = "https://$($IpAddress)$($CountData.'@odata.nextLink')"
      }
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
      
      # Check to see if $NextLinkUrl is an absolute URI or a relative URI
      if ($NextLinkData.'@odata.nextLink') {
        if ($null -ne ($NextLinkData.'@odata.nextLink' -as [System.URI]).AbsoluteURI) {
          $NextLinkUrl = $NextLinkData.'@odata.nextLink'
        }
        else {
          $NextLinkUrl = "https://$($IpAddress)$($NextLinkData.'@odata.nextLink')"
        }
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


function Invoke-PowerControlServers {
    <#
    .SYNOPSIS
      This function handles changing the power state of a device

    .PARAMETER DeviceTargets
      The targets whose power state you want to change.

    .PARAMETER DesiredPowerState
      The power state to which you would like to set devices

    .PARAMETER TargetGroupId
      (optional) The group ID of a group of devices whose power state you want to change

    .OUTPUTS
      Returns True if the power change was successful or false otherwise

    #>

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [array]
        $DeviceTargets,

        [Parameter(Mandatory)]
        [string]
        $DesiredPowerState,

        [Parameter(Mandatory = $false)]
        [int]
        $TargetGroupId = -1
    )

    $Targets = @()
    foreach ($IdToRefresh in $DeviceTargets) {
        $Targets += @{
            Id = [int]$IdToRefresh
            Data = ''
            TargetType = @{
                Id = 1000
                Name = 'DEVICE'
            }
        }
    }

    if ($TargetGroupId -ne -1) {
        $Targets += @{
            Data = ''
            Id = $TargetGroupId
            TargetType = @{
                Id = 6000
                Name = 'GROUP'
            }
        }
    }

    $Payload = @{
        Id = 0
        JobName = "Power operation"
        JobDescription = "Performing a power operation"
        State = "Enabled"
        Schedule = "startnow"
        JobType = @{
            Name = "DeviceAction_Task"
        }
        Targets = $Targets
        Params = @(
            @{
                Key = "override"
                Value = "true"
            } 
            @{
                Key = "powerState"
                Value = $DesiredPowerState
            } 
            @{
                Key = "operationName"
                Value = "POWER_CONTROL"
            } 
            @{
                Key = "deviceTypes"
                Value = "1000"
            }
        )
    } | ConvertTo-Json -Depth 4

    # Get the job information
    $Response = Invoke-RestMethod -Uri "https://$($IpAddress)/api/JobService/Jobs" `
                                  -Credential $Credentials -ContentType $Type -Method POST -Body $Payload -SkipCertificateCheck

    if ($Response) {
        $JobId = $Response.Id
    }
    else {
        Write-Host "Error: Power operation failed. Error was $($Response.content)"
    }

    Write-Host "Waiting for the power operation to complete."
    $JobStatus = Invoke-TrackJobToCompletion -OmeIpAddress $IpAddress -JobId $JobId -SleepInterval 15
    Write-Host "Power operation complete."

    return $JobStatus

}

Try {
    $Type = "application/json"

    $PowerStateMap = @{ 17 = "On"; 18 = "Off"; 20 = "Powering On"; 21 = "Powering Off" }

    $PowerControlStateMap = @{
        "Power On"        = "2";
        "Power Cycle"       = "5";
        "Power Off Non-Graceful" = "8";
        "Master Bus Reset" = "10";
        "Power Off Graceful"  = "12"
    }

    $Targets = @()

    if ($PSBoundParameters.ContainsKey('GroupName')) {

        $GroupData = Get-Data "https://$($IpAddress)/api/GroupService/Groups" "Name eq '$($GroupName)'"

        if ($null -eq $GroupData) {
            Write-Error "We were unable to retrieve the GroupId for group name $($GroupName). Is the name correct?"
            Exit
        }

        $GroupId = $GroupData.'Id'
    }
    else {
        $GroupId = -1
    }

    if ($PSBoundParameters.ContainsKey('ServiceTags')) {
        foreach ($ServiceTag in $ServiceTags -split ',') {
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
        foreach ($IdracIp in $IdracIps -split ',') {
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
        foreach ($DeviceName in $DeviceNames -split ',') {
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

    if ($Targets.Length -lt 1 -and $GroupId -eq -1) {
        Write-Error 'You must provide a set of hosts whose power you want to control.'
    }

    if ($State -eq "POWER_ON") {
        $PowerState = $PowerControlStateMap['Power On']
        write-host "Powering on servers..."
    }
    elseif ($State -eq 'POWER_CYCLE') {
        $PowerState = $PowerControlStateMap['Power Cycle']
        Write-Host "Power cycling servers..."
    }
    elseif ($State -eq 'POWER_OFF_NON_GRACEFUL') {
        $PowerState = $PowerControlStateMap["Power Off Non-Graceful"]
        Write-Host "Non-gracefully shutting down servers..."
    }
    elseif ($State -eq 'MASTER_BUS_RESET') {
        $PowerState = $PowerControlStateMap['Master Bus Reset']
        Write-Host "Performing a master bus reset on the servers..."
    }
    elseif ($State -eq 'POWER_OFF_GRACEFUL') {
        $PowerState = $PowerControlStateMap['Power Off Graceful']
        Write-Host "Performing a graceful shutdown on the servers..."
    }
    else {
        $PowerState = -1
    }
    
    if(Invoke-PowerControlServers -DeviceTargets $Targets -DesiredPowerState $PowerState -TargetGroupId $GroupId) {
        Write-Host "Power state changed successfully!"
    }
    else {
        Write-Error "Error: There was a problem changing device power state. See the output above for details."
        Exit
    }

    if ($GroupId -ne -1) {
        $GroupDevices = Get-Data "https://$($IpAddress)/api/GroupService/Groups($GroupId)/Devices"

        if ($GroupDevices.Length -lt 1) {
            Write-Error "Error: There was a problem retrieving the devices for the group $($GroupName). Exiting."
            Exit
        }

        foreach ($Device in $GroupDevices) {
            $Targets += $Device.Id
        }
    }

    $DevicePowerStates = @()
    foreach ($DeviceId in $Targets) {
        $DeviceStatus = Get-Data "https://$($IpAddress)/api/DeviceService/Devices($DeviceId)"
        $DevicePowerState = @{
            "OME ID" = $DeviceStatus.Id
            Identifier = $DeviceStatus.Identifier
            Model = $DeviceStatus.Model
            "Device Name" = $DeviceStatus.DeviceName
            "idrac IP" = $DeviceStatus.DeviceManagement[0]['NetworkAddress']
            "Power State" = $PowerStateMap[[int]$($DeviceStatus.PowerState)]
        }
        $DevicePowerStates += $DevicePowerState
    }

    if ($PSBoundParameters.ContainsKey('Csvfile')) {
        $DevicePowerStates | Export-Csv -Path $CsvFile -NoTypeInformation
        $(Foreach($Device in $DevicePowerStates){
            New-object psobject -Property $Device
        }) | Export-Csv test.csv

    }
    else {
        $DevicePowerStates
    }

}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}