# PowerShell Library Code

- [PowerShell Library Code](#powershell-library-code)
  - [Interact with an API Resource](#interact-with-an-api-resource)
  - [Resolve a device to its ID](#resolve-a-device-to-its-id)
    - [Helpful device ID pattern](#helpful-device-id-pattern)
    - [Resolve Group Name to ID](#resolve-group-name-to-id)
  - [Track a Job to Completion](#track-a-job-to-completion)
  - [Working with CSVs](#working-with-csvs)
    - [Writing a CSV to a File Share](#writing-a-csv-to-a-file-share)
    - [Writing an Array of Hashtables to a CSV File](#writing-an-array-of-hashtables-to-a-csv-file)
  - [Prompt a User with a Yes / No Question](#prompt-a-user-with-a-yes--no-question)
  - [Validate a File Path](#validate-a-file-path)
  - [Convert PSObject to a HashTable](#convert-psobject-to-a-hashtable)

## Interact with an API Resource

This is used to perform any sort of interaction with a REST API resource. It includes the ability to pass in odata filters. Anytime you need to POST or GET an API resource we recommend you use this function.

```powershell
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
```

## Resolve a device to its ID

Use this function to resolve a service tag, idrac IP, or an OME device name to its OME device ID. Most API resources require you to use the device ID to take action. Use this function to resolve any of the above to the OME device ID.

**WARNING** Relies on Get-Data
```powershell
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
```

### Helpful device ID pattern 
You frequently not only want to resolve device IDs, but check the output and then add the device IDs to a list of IDs. Below is a common pattern for this behavior.

```powershell
$Targets = @()

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
```

### Resolve Group Name to ID

```powershell
if ($PSBoundParameters.ContainsKey('GroupName')) {
  Write-Host "Resolving group name $($GroupName) to a group ID..."

  $GroupData = Get-Data "https://$($IpAddress)/api/GroupService/Groups" "Name eq '$($GroupName)'"

  if ($null -eq $GroupData) {
      Write-Error "We were unable to retrieve the GroupId for group name $($GroupName). Is the name correct?"
      Exit
  }

  Write-Host "$($GroupName)'s ID is $($GroupData.'Id')"
  $GroupId = $GroupData.'Id'
}
```

## Track a Job to Completion

Track a job and wait for it to complete before continuing.

**WARNING** Relies on Get-Data

```powershell
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
```

## Working with CSVs

### Writing a CSV to a File Share

```powershell
if ($PSBoundParameters.ContainsKey('Share')) {
  $Share = $Share.TrimEnd('\')
  New-SmbMapping -RemotePath $Share -Username $Credentials.UserName -Password $Credentials.Password
  $AuditLogs | Export-Csv -LiteralPath "$($Share)\$(get-date -f yyyy-MM-dd).csv"
}
else {
  Write-Output $AuditLogs
}
```

### Writing an Array of Hashtables to a CSV File

This is a bit strange in PowerShell. The main thing is that before passing code to the second part (the foreach loop actually doing the export) you have to remove the date from the Get-Data output and manually put it in a PS hashtable.

```powershell
$WarrantyInfo = ConvertPSObjectToHashtable $(Get-Data "https://$($IpAddress)/api/WarrantyService/Warranties")

if($WarrantyInfo.count -gt 0) {
  if ($PSBoundParameters.ContainsKey('OutFile')) {
    if (-not $(Confirm-IsValid -OutputFilePath $OutFile)) {
      Exit
    }

    $WarrantyInfo | Export-Csv -Path $OutFile -NoTypeInformation
    $(Foreach($Case in $WarrantyInfo){
        New-object psobject -Property $Case
    }) | Export-Csv $OutFile
  }
  else {
    $WarrantyInfo
  }
}
```

See [this StackOverflow link](https://stackoverflow.com/questions/11173795/powershell-convert-array-of-hastables-into-csv)

## Prompt a User with a Yes / No Question

```powershell
function Read-Confirmation {
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
```

## Validate a File Path

This code is reliant on [Read-Confirmation](#prompt-a-user-with-a-yes--no-question)

```powershell
function Confirm-IsValid {
  <#
  .SYNOPSIS
    Tests whether a filepath is valid or not.

  .DESCRIPTION
    Performs different tests depending on whether you are testing a file for the ability to read
    (InputFilePath) or write (OutputFilePath)

  .PARAMETER OutputFilePath
    The path to an output file you want to test

  .PARAMETER InputFilePath
    The path to an input file you want to test

  .OUTPUTS
    Returns true if the path is valid and false if it is not
  #>
  [CmdletBinding()]
  param (

    [Parameter(Mandatory = $false)]
    [string]
    $OutputFilePath,

    [Parameter(Mandatory = $false)]
    [string]
    $InputFilePath
  )

  if ($PSBoundParameters.ContainsKey('InputFilePath') -and $PSBoundParameters.ContainsKey('OutputFilePath')) {
    Write-Error "You can only provide either an InputFilePath or an OutputFilePath."
    Exit
  }

  # Some of the tests are the same - we can use the same variable name
  if ($PSBoundParameters.ContainsKey('InputFilePath')) {
    $OutputFilePath = $InputFilePath
  }

  if ($PSBoundParameters.ContainsKey('InputFilePath')) {
    if (-not $(Test-Path -Path $InputFilePath -PathType Leaf)) {
      Write-Error "The file $($InputFilePath) does not exist."
      return $false
    }
  }
  else {
    if (Test-Path -Path $OutputFilePath -PathType Leaf) {
      if (-not $(Read-Confirmation "$($OutputFilePath) already exists. Do you want to continue? (Y/N)")) {
        return $false
      } 
    }
  }

  $ParentPath = $(Split-Path -Path $OutputFilePath -Parent)
  if ($ParentPath -ne "") {
    if (-not $(Test-Path -PathType Container $ParentPath)) {
      Write-Error "The path '$($OutputFilePath)' does not appear to be valid."
      return $false
    }
  }

  if (Test-Path $(Split-Path -Path $OutputFilePath -Leaf) -PathType Container) {
    Write-Error "You must provide a filename as part of the path. It looks like you only provided a folder in $($OutputFilePath)!"
    return $false
  }

  return $true
}
```

## Convert PSObject to a HashTable

Often, when we get input back from the API we want to be able to manipulate the output as a hashtable rather than a PSCustomObject. This function will take as input a PSObject and convert it to a hashtable. This will be most often
used in conjunction with Get-Data.

```powershell
function ConvertPSObjectToHashtable
{
  <#
    .SYNOPSIS
      Converts a PSObject to a HashTable

    .DESCRIPTION
      Often, when we get input back from the API we want to be able to manipulate the output as a hashtable rather
      than a PSCustomObject. This function will take as input a PSObject and convert it to a hashtable. When data
      is converted using ConvertFromJson that requires some extra handling.

      Note: This was shamelessly stolen from @Dave Wyatt's answere here:
      https://stackoverflow.com/questions/22002748/hashtables-from-convertfrom-json-have-different-type-from-powershells-built-in-h

    .PARAMETER InputObject
      The PSObject you would like to convert.

    .OUTPUTS
      A HashTable equivalent of the input PSObject.
  #>
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $Collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )

            Write-Output -NoEnumerate $Collection
        }
        elseif ($InputObject -is [psobject])
        {
            $Hash = @{}

            foreach ($Property in $InputObject.PSObject.Properties)
            {
                $Hash[$Property.Name] = ConvertPSObjectToHashtable $Property.Value
            }

            return $Hash
        }
        else
        {
            return $InputObject
        }
    }
}
```