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
    Copies all VLANs from one OME instance to another

  .DESCRIPTION
    This script expects input in JSON format with two entries. The first should be a json array of dictionaries called
    targets identifying the OME instances to which you want to push VLANs and the second is a single dictionary defining
    the source instance. Example:

    {
        "target": [
            {
                "ip": "100.97.173.67",
                "port": "443",
                "user_name": "admin",
                "password": "your_password"
            },
            {
                "ip": "100.97.173.61",
                "port": "443",
                "user_name": "admin",
                "password": "your_password"
            }
        ],
        "source": {
            "ip": "100.97.173.76",
            "port": "443",
            "user_name": "admin",
            "password": "your_password"
        }
    }

  .PARAMETER Inputs 
    The name of the file containing your JSON

  .EXAMPLE
    .\Copy-Vlans.ps1' -inputs test.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Inputs
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


function Get-Vlan {
    <#
    .SYNOPSIS
        Grabs a list of VLANs

    .DESCRIPTION
        Retrieves a list of dictionaries representing the VLAN entries on a specified OME instance

    .PARAMETER VlanUrl
        The URL from which you want to retrieve VLANs

    .OUTPUTS
        List of dictionaries representing each VLAN entry in OME

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $VlanUrl
    )

    $VlanList = @()

    $VlanData = Get-Data $VlanUrl

    foreach ($Vlan in $VlanData) {
        $VlanList += @{
            Name = $Vlan.Name
            Description = $Vlan.Description
            VlanMaximum = $Vlan.VlanMaximum
            VlanMinimum = $Vlan.VlanMinimum
            Type = $Vlan.Type
        }
    }

    return $VlanList
}

try {

    # Read inputs
    $Inputs = Get-Content $Inputs | Out-String | ConvertFrom-Json
    $Password = ConvertTo-SecureString $Inputs.source.password -AsPlainText -Force
    [pscredential]$Credentials = New-Object System.Management.Automation.PSCredential ($Inputs.source.user_name, $Password)

    [array]$SourceVlanList = Get-Vlan "https://$($Inputs.source.ip)/api/NetworkConfigurationService/Networks"

    # Loop over each target OME instance and grab its VLANs
    foreach ($Target in $Inputs.target) {
        $TargetUrl = "https://$($Target.ip)/api/NetworkConfigurationService/Networks"
        $TargetVlanList = Get-Vlan $TargetUrl

        foreach ($SourceVlanPayload in $SourceVlanList) {
            Write-Host "Replicating VLAN $($SourceVlanPayload.VlanMinimum)-$($SourceVlanPayload.VlanMaximum) on target $($Target.ip)"

            # Determine if VLANs overlap between source and dest OME instances
            $OverlapPresent = $false

            foreach ($TargetVlanPayload in $TargetVlanList) {
                if ($TargetVlanPayload.VlanMinimum -le $SourceVlanPayload.VlanMaximum -and $SourceVlanPayload.VlanMinimum -le $TargetVlanPayload.VlanMaximum) {
                    $OverlapPresent = $true
                }
            }

            # Push VLANs to OME
            if ($OverlapPresent) {
                Write-Host "WARNING: Unable to replicate VLAN $($SourceVlanPayload.VlanMinimum)-$($SourceVlanPayload.VlanMaximum) on the target $($Target.ip) as the VLANs overlap."
                Write-Host $('*' * 180)
            }
            else {
                $Response = Invoke-RestMethod -Uri $TargetUrl -Credential $Credentials -ContentType "application/json" -Method Post -Body ($SourceVlanPayload | ConvertTo-Json) -SkipCertificateCheck
                write-host $Response
                Write-Host $('*' * 180)
            }
        }        
    }

}
catch {
    Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}