
<#
 .SYNOPSIS
   Script to retrieve the inventory for a device by inventory type.

 .DESCRIPTION

   This script uses the OME REST API to get the inventory
   for a device by inventory type. The inventory type can be os 
   or cpus or controllers or memory or disks.
  

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance
 .PARAMETER InventoryType
   The InventoryType can be cpus/memory/controllers/disks/os
 .PARAMETER DeviceId
	The Id of the device. 
	

 .EXAMPLE
   $cred = Get-Credential
   .\Get-DeviceInventory.ps1 -IpAddress "10.xx.xx.xx" -Credentials
    $cred -DeviceId 25627 -InventoryType {InventoryType}
	where {InventoryType} can be cpus or memory or controllers or disks or os

#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [System.Net.IPAddress] $IpAddress,

  [Parameter(Mandatory)]
  [pscredential] $Credentials, 
  [Parameter(Mandatory = $false)]
  [ValidateSet("cpus", "memory", "controllers", "disks", "os")]
  [String] $InventoryType,

  [Parameter(Mandatory)]
  [System.UInt32]$DeviceId
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

Try {
  Set-CertPolicy
  $SessionUrl = "https://$($IpAddress)/api/SessionService/Sessions"
  $Type = "application/json"
  $UserName = $Credentials.username
  $Password = $Credentials.GetNetworkCredential().password
  $UserDetails = @{"UserName" = $UserName; "Password" = $Password; "SessionType" = "API" } | ConvertTo-Json
  $Headers = @{}
  $InventoryTypes = @{"cpus" = "serverProcessors"; "os" = "serverOperatingSystems"; "disks" = "serverArrayDisks"; "controllers" = "serverRaidControllers"; "memory" = "serverMemoryDevices" }
  $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
  if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
    ## Successfully created a session - extract the auth token from the response
    ## header and update our headers for subsequent requests
    $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
    if ($InventoryType) {
      $InventoryUrl = "https://$($IpAddress)/api/DeviceService/Devices($($DeviceId))/InventoryDetails('$($InventoryTypes[$InventoryType])')"
    }
    else {
      $InventoryUrl = "https://$($IpAddress)/api/DeviceService/Devices($($DeviceId))/InventoryDetails"
				}
    $InventoryResp = Invoke-WebRequest -Uri $InventoryUrl -Headers $Headers -Method Get -ContentType $Type
    if ($InventoryResp.StatusCode -eq 200) {
      $InventoryInfo = $InventoryResp.Content | ConvertFrom-Json
      $inventoryDetail = $InventoryInfo | ConvertTo-Json -Depth 6
      write-Host $inventoryDetail
    }
				elseif ($InventoryResp.StatusCode -eq 400) {
      Write-Warning "Inventory type not applicable for device id  $($DeviceId) "
				}
    else {
      Write-Warning "Unable to retrieve inventory for device $($DeviceId) due to status code ($($InventoryResp.StatusCode))"
    }
            
  }
  else {
    Write-Error "Unable to create a session with appliance $($IpAddress)"
  }
}
catch {
  Write-Error "Exception occured at line $($_.InvocationInfo.ScriptLineNumber) - $($_.Exception.Message)"
}