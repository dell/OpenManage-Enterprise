#Requires -Version 7

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
    Retrieves the case data from the SupportAssist Enterprise (SAE) Plugin on OME
 .DESCRIPTION
    The -OutFile argument is optional. If specified the output will go to a CSV file. Otherwise it prints to screen.

    For authentication X-Auth is used over Basic Authentication
    Note that the credentials entered are not stored to disk.
 .PARAMETER IpAddress
    IP Address of the OME Appliance
 .PARAMETER Credentials
    Credentials used to talk to the OME Appliance
 .PARAMETER OutFile
    Path to which you want to write the output.

 .EXAMPLE
   .\Get-SupportassistCases.ps1' -credentials $creds -outfile test.csv -ipaddress 192.168.1.93
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory=$false)]
    [string] $OutFile
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

try {

    Write-Host "Sending the request to OME..."
    $Cases = Get-Data "https://$($IpAddress)/api/SupportAssistService/Cases?sort=id"

    if($Cases.count -gt 0) {
      if ($PSBoundParameters.ContainsKey('OutFile')) {
        if (-not $(Confirm-IsValid -OutputFilePath $OutFile)) {
          Exit
        }

        $CasesDictionary = @()
        foreach ($Case in $Cases) {
            $CaseDict = @{
                "Id" = $Case.Id
                "Name" = $Case.Name
                "Title" = $Case.Title
                "ServiceTag" = $Case.ServiceTag
                "Status" = $Case.Status
                "EventSource" = $Case.EventSource
                "DummyCase" = $Case.DummyCase
                "UpdatedDate" = $Case.UpdatedDate
                "CreatedDate" = $Case.CreatedDate
            }
            $CasesDictionary += $CaseDict
        }

        $Cases | Export-Csv -Path $OutFile -NoTypeInformation
        $(Foreach($Case in $CasesDictionary){
            New-object psobject -Property $Case
        }) | Export-Csv $OutFile
      }
      else {
        $Cases
      }
    }

    Write-Host "Task completed successfully!"
    
}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}
