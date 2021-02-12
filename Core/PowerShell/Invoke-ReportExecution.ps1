#Requires -Version 7

<#
_author_ = Raajeev Kalyanaraman <raajeev.kalyanaraman@Dell.com>
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
    Script to invoke execution of a report in OME 

  .DESCRIPTION
    This script uses the OME REST API to execute a pre-canned
    report (this can include custom reports defined by the user)
    and tracks completion of the report. On completion the report
    result is printed to screen.

  .PARAMETER IpAddress
    This is the IP address of the OME Appliance

  .PARAMETER Credentials
    Credentials used to talk to the OME Appliance

  .PARAMETER ReportId
    ID of the report to run. You must provide either a report name or a report ID.

  .PARAMETER ReportName
    The name of the report which you would like to run. You must provide either a report name or
    a report ID.

  .PARAMETER GroupName
    (Optional) The name of a specific group against which you want to run the report.

  .PARAMETER GroupId
    (Optional) The ID of a group against which you want to run a specific report.

  .PARAMETER OutputFilePath
    (Optional) If you would like the output to go to a CSV file you can specify the filename here.
    If this is not specified it will instead output to the terminal.
   
  .EXAMPLE
    $cred = Get-Credential
    .\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred -ReportId 10043 -OutputFilePath test.csv

  .EXAMPLE
    .\Invoke-ReportExecution.ps1 -IpAddress "10.xx.xx.xx" -ReportName SomeReport
    In this instance you will be prompted for credentials to use to
    connect to the appliance
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [System.Net.IPAddress] $IpAddress,

  [Parameter(Mandatory)]
  [pscredential] $Credentials,

  [Parameter(Mandatory = $false)]
  [uint64] $ReportId,

  [Parameter(Mandatory = $false)]
  [string] $ReportName,

  [Parameter(Mandatory = $false)]
  [string] $GroupName,

  [Parameter(Mandatory = $false)]
  [uint64] $GroupId,
  
  [Parameter(Mandatory = $false)]
  [string]$OutputFilePath
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


Try {

  ####################################
  # Lookup and run the target report #
  ####################################

  $ExecRepUrl = "https://$($IpAddress)/api/ReportService/Actions/ReportService.RunReport"
  $Type = "application/json"

  if ($PSBoundParameters.ContainsKey('OutputFilePath')) {
    if (-not $(Confirm-IsValid -OutputFilePath $OutputFilePath) ) {
      Exit
    }
  }

  if ($PSBoundParameters.ContainsKey('ReportName')) {
    Write-Host "Looking up the report with name $($ReportName)"
    $ReportData = Get-Data -Url "https://$($IpAddress)/api/ReportService/ReportDefs" -OdataFilter "Name eq `'$($ReportName)`'"

    if ($ReportData.Count -eq 1) {
      $ReportId = $ReportData.Id
    }
    elseif ($ReportData.Count -gt 1) {
      foreach ($Report in $ReportData) {
        if ($Report.Name -eq $ReportName) {
          $ReportId = $Report.Id
        }
      }
    }

    if ($ReportId -eq 0) {
      Write-Error "Could not find a report with the name $($ReportName). Exiting." -ErrorAction Stop
    }
  }

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
  elseif ( -not $PSBoundParameters.ContainsKey('GroupId')) {
    # This means do not use a GroupId in the report lookup
    $GroupId = 0
  }

  $RepPayload = @{"ReportDefId" = $ReportId; "FilterGroupId" = $GroupId } | ConvertTo-Json

  try {
    $ReportJobId = Invoke-RestMethod -Uri $ExecRepUrl -Credential $Credentials -Method POST -Body $RepPayload `
    -ContentType $Type -SkipCertificateCheck
  }
  catch [Microsoft.PowerShell.Commands.HttpResponseException] {
    Write-Error "The post responded with a status code of $($_.Exception.Response.StatusCode). This typically means the Report ID was invalid. Are you sure $($ReportId) is a valid ID?"
    Exit
  }
  
  Write-Host "Report job successfully submitted. Waiting for completion..."
  if (-not $(Invoke-TrackJobToCompletion -OmeIpAddress $IpAddress -JobId $ReportJobId -SleepInterval 10 -MaxRetries 90)) {
    Write-Error "Something went wrong while running the report or it took too long. Exiting." -ErrorAction Stop
  }
  
  #######################################################
  # Output the file to either CSV or the command prompt #
  #######################################################

  Write-Host "Exporting report..."

  $BaseUri = "https://$($IpAddress)"
  $ReportDetails = $BaseUri + "/api/ReportService/ReportDefs($($ReportId))"
  $OutputArray = @()
  $ColumnNames = @()
  [psobject[]]$ObjList = @()
  $ReportInfo = Get-Data $ReportDetails
  $ColumnNames = $ReportInfo.ColumnNames.Name
  Write-Verbose "Extracting results for report ($($ReportId))"
  $ResultUrl = $BaseUri + "/api/ReportService/ReportDefs($($ReportId))/ReportResults/ResultRows"

  $ReportResultList = Get-Data $ResultUrl
  foreach ($value in $ReportResultList) {
    $ResultValues = $value.Values

    $TempHash = @{}
    for ($i = 0; $i -lt $ColumnNames.Count; $i++) {
      $TempHash[$ColumnNames[$i]] = $ResultValues[$i]
    }
    $OutputArray += , $TempHash
    if ($PSBoundParameters.ContainsKey('OutputFilePath')) {
      $ObjList += New-Object -TypeName psobject -Property $TempHash
    }
  }
  if ($PSBoundParameters.ContainsKey('OutputFilePath')) {
    $ObjList | Export-Csv -Path $OutputFilePath
  }
  else {
    foreach ($ReportItem in $OutputArray) {
      $ReportItem | Format-Table -AutoSize
    }
  }
}
catch {
  Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}