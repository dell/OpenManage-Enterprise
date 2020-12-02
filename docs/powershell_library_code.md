# PowerShell Library Code

## Interact with an API Resource

This is used to perform any sort of interaction with a REST API resource. It includes the ability to pass in odata filters. Anytime you need to POST or GET an API resource we recommend you use this function.

        function Get-Data {
        <#
        .SYNOPSIS
            Used to interact with API resources

        .DESCRIPTION
            This function retrieves data from a specified URL. Get requests from OME return paginated data. The code below
            handles pagination. This is the equivalent in the UI of a list of results that require you to go to different
            pages to get a complete listing. Assumes there is a variable called Credentials with OME's credentials.

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
                return @{}
            }

        }

## Resolve a device to its ID

Use this function to resolve a service tag, idrac IP, or an OME device name to its OME device ID. Most API resources require you to use the device ID to take action. Use this function to resolve any of the above to the OME device ID.

**WARNING** Relies on Get-Data

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

### Helpful device ID pattern 
You frequently not only want to resolve device IDs, but check the output and then add the device IDs to a list of IDs. Below is a common pattern for this behavior.

    $Targets = @()

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
            $Target = Get-DeviceId $IpAddress -DeviceIdracIp $IdracIp
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

## Track a Job to Completion

Track a job and wait for it to complete before continuing.

**WARNING** Relies on Get-Data


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