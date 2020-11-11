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
          pages to get a complete listing.
    
        .PARAMETER Url
        The API url against which you would like to make a request
    
        .INPUTS
        None. You cannot pipe objects to Get-Data.
    
        .OUTPUTS
        list. The Get-Data function returns a list of hashtables with the headers resulting from authentication against the
        OME server
    
      #>
      
      [CmdletBinding()]
      param (
    
        [Parameter(Mandatory)]
        [string] 
        # The API url against which you would like to make a request
        $Url,
    
        [Parameter(Mandatory = $false)]
        [string]
        # (Optional) A filter to run against the API endpoint
        $Filter
      )
    
      $Data = @()
      $NextLinkUrl = $null
      try {
    
        if ($PSBoundParameters.ContainsKey('Filter')) {
          $CountData = Invoke-RestMethod -Uri $Url"?`$filter=$($Filter)" -UseBasicParsing -Method Get 
          -Credential $Credentials -ContentType $Type -SkipCertificateCheck
    
          if ($CountData.'@odata.count' -lt 1) {
            Write-Error "No results were found for filter $($Filter)."
            return $null
          } 
        }
        else {
          $CountData = Invoke-RestMethod -Uri $Url -UseBasicParsing -Method Get -Credential $Credentials -ContentType $Type `
            -SkipCertificateCheck
        }
    
        $Data += $CountData.'value'
        if ($CountData.'@odata.nextLink') {
          $NextLinkUrl = $BaseUri + $CountData.'@odata.nextLink'
        }
        while ($NextLinkUrl) {
          $NextLinkData = Invoke-RestMethod -Uri $NextLinkUrl -UseBasicParsing -Method Get -Credential $Credentials `
            -ContentType $Type -SkipCertificateCheck
          $Data += $NextLinkData.'value'
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
        Write-Error "There was a problem connecting to OME. Did it become unavailable?"
        return $null
      }
    
    }