<#
_author_ = Raajeev Kalyanaraman <raajeev.kalyanaraman@Dell.com>
_version_ = 0.1

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
 Script to set the ScaleVlanProfile property for a fabric 

.DESCRIPTION
 Script allows enumeration of all fabrics on the given system and 
 allows the user to select a fabric on which the ScaleVlanProfile
 property can be changed to the input value (Enabled / Disabled)

.PARAMETER OmemIpAddr
 A valid OME-M IP address

.PARAMETER Credentials
 Credentials to access the OME-M instance

.PARAMETER ProfileState
 Enabled / Disabled
 
.EXAMPLE
$credentials = Get-Credentials
Set-ScaleVlanProfile.ps1 -IpAddress 100.200.100.101 -Credentials $cred -ProfileState Enabled

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $OmemIPAddr,

    [Parameter(Mandatory)]
    [pscredential] $Credentials,

    [Parameter(Mandatory)]
    [ValidateSet("Enabled","Disabled")]
    [String] $ProfileState
)

# RKR - changing input param to Idictionary to help use an ordered dictionary
# and prevent scrambling keys in random order ...
function fShowMenu([System.String]$sMenuTitle,[System.Collections.IDictionary]$hMenuEntries)
{
    
	[System.Int16]$iSavedBackgroundColor=[System.Console]::BackgroundColor
	[System.Int16]$iSavedForegroundColor=[System.Console]::ForegroundColor
	# Menu Colors
	# inverse fore- and backgroundcolor 
	[System.Int16]$iMenuForeGroundColor=$iSavedForegroundColor
	[System.Int16]$iMenuBackGroundColor=$iSavedBackgroundColor
	[System.Int16]$iMenuBackGroundColorSelectedLine=$iMenuForeGroundColor
	[System.Int16]$iMenuForeGroundColorSelectedLine=$iMenuBackGroundColor
	[System.Int16]$iMenuStartLineAbsolute=0
	[System.Int16]$iMenuLoopCount=0
	[System.Int16]$iMenuSelectLine=1
	[System.Int16]$iMenuEntries=$hMenuEntries.Count
	[Hashtable]$hMenu=@{};
	[Hashtable]$hMenuHotKeyList=@{};
	[Hashtable]$hMenuHotKeyListReverse=@{};
	[System.Int16]$iMenuHotKeyChar=0
	[System.String]$sValidChars=""
	[System.Console]::WriteLine(" "+$sMenuTitle)
	$iMenuLoopCount=1
	$iMenuHotKeyChar=49
	foreach ($sKey in $hMenuEntries.Keys){
        ## RKR - fix showing values instead of keys....
		$hMenu.Add([System.Int16]$iMenuLoopCount,[System.String]$hMenuEntries[$sKey])
		$hMenuHotKeyList.Add([System.Int16]$iMenuLoopCount,[System.Convert]::ToChar($iMenuHotKeyChar))
		$hMenuHotKeyListReverse.Add([System.Convert]::ToChar($iMenuHotKeyChar),[System.Int16]$iMenuLoopCount)
		$sValidChars+=[System.Convert]::ToChar($iMenuHotKeyChar)
		$iMenuLoopCount++
		$iMenuHotKeyChar++
		if($iMenuHotKeyChar -eq 58){$iMenuHotKeyChar=97}
		elseif($iMenuHotKeyChar -eq 123){$iMenuHotKeyChar=65}
		elseif($iMenuHotKeyChar -eq 91){
			Write-Error " Menu too big!"
			exit(99)
		}
	}
	# Remember Menu start
	[System.Int16]$iBufferFullOffset=0
	$iMenuStartLineAbsolute=[System.Console]::CursorTop
	do{
		####### Draw Menu  #######
		[System.Console]::CursorTop=($iMenuStartLineAbsolute-$iBufferFullOffset)
		for ($iMenuLoopCount=1;$iMenuLoopCount -le $iMenuEntries;$iMenuLoopCount++){
			[System.Console]::Write("`r")
			[System.String]$sPreMenuline=""
			$sPreMenuline="  "+$hMenuHotKeyList[[System.Int16]$iMenuLoopCount]
			$sPreMenuline+=": "
			if ($iMenuLoopCount -eq $iMenuSelectLine){
				[System.Console]::BackgroundColor=$iMenuBackGroundColorSelectedLine
				[System.Console]::ForegroundColor=$iMenuForeGroundColorSelectedLine
			}
			if ($hMenuEntries.Item([System.String]$hMenu.Item($iMenuLoopCount)).Length -gt 0){
				[System.Console]::Write($sPreMenuline+$hMenuEntries.Item([System.String]$hMenu.Item($iMenuLoopCount)))
			}
			else{
				[System.Console]::Write($sPreMenuline+$hMenu.Item($iMenuLoopCount))
			}
			[System.Console]::BackgroundColor=$iMenuBackGroundColor
			[System.Console]::ForegroundColor=$iMenuForeGroundColor
			[System.Console]::WriteLine("")
		}
		[System.Console]::BackgroundColor=$iMenuBackGroundColor
		[System.Console]::ForegroundColor=$iMenuForeGroundColor
		[System.Console]::Write("  Your choice: " )
		if (($iMenuStartLineAbsolute+$iMenuLoopCount) -gt [System.Console]::BufferHeight){
			$iBufferFullOffset=($iMenuStartLineAbsolute+$iMenuLoopCount)-[System.Console]::BufferHeight
		}
		####### End Menu #######
		####### Read Kex from Console 
		$oInputChar=[System.Console]::ReadKey($true)
		# Down Arrow?
		if ([System.Int16]$oInputChar.Key -eq [System.ConsoleKey]::DownArrow){
			if ($iMenuSelectLine -lt $iMenuEntries){
				$iMenuSelectLine++
			}
		}
		# Up Arrow
		elseif([System.Int16]$oInputChar.Key -eq [System.ConsoleKey]::UpArrow){
			if ($iMenuSelectLine -gt 1){
				$iMenuSelectLine--
			}
		}
		elseif([System.Char]::IsLetterOrDigit($oInputChar.KeyChar)){
			[System.Console]::Write($oInputChar.KeyChar.ToString())	
		}
		[System.Console]::BackgroundColor=$iMenuBackGroundColor
		[System.Console]::ForegroundColor=$iMenuForeGroundColor
	} while(([System.Int16]$oInputChar.Key -ne [System.ConsoleKey]::Enter) -and ($sValidChars.IndexOf($oInputChar.KeyChar) -eq -1))
	
	# reset colors
	[System.Console]::ForegroundColor=$iSavedForegroundColor
	[System.Console]::BackgroundColor=$iSavedBackgroundColor
	if($oInputChar.Key -eq [System.ConsoleKey]::Enter){
		[System.Console]::Writeline($hMenuHotKeyList[$iMenuSelectLine])
		return([System.String]$hMenu.Item($iMenuSelectLine))
	}
	else{
		[System.Console]::Writeline("")
		return($hMenu[$hMenuHotKeyListReverse[$oInputChar.KeyChar]])
	}
}

function Set-CertPolicy() {
## Trust all certs - for sample usage only
## customers are expected to use strict cert validation
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
    Catch {
        Write-Error "Unable to add type for cert policy"
    }

}

function Get-Session($IpAddress, $Credentials) {
    $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions"
    $Type        = "application/json"
    $UserName    = $Credentials.username
    $Password    = $Credentials.GetNetworkCredential().password
    $UserDetails = @{"UserName"=$UserName;"Password"=$Password;"SessionType"="API"} | ConvertTo-Json

    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
    if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
        Write-Host "Successful authentication with $($IpAddress)"
        $SessResponseData = $SessResponse.Content | ConvertFrom-Json
        $SessionAuthToken = @{
        "token"= $SessResponse.Headers["X-Auth-Token"];
        "id"= $SessResponseData.Id
        }
    }
    return $SessionAuthToken
}

function Remove-Session($IpAddress, $Headers, $Id) {
    $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions('$($Id)')"
    $Type        = "application/json"
    $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Delete -Headers $Headers -ContentType $Type
    Write-Host "Deleted authentication token ..."
}

function Get-Networks($BaseUri, $Headers) {
    # Display Networks
    $Type        = "application/json"
    $NetworkUrl  = $BaseUri + "/api/NetworkService/Fabrics"
    Write-Host "Enumerating fabrics ..."
    $NetworkResp = Invoke-WebRequest -Uri $NetworkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
    $FabricData  = @()
    $FabricLookup = @{}
    $NextLinkUrl = $null

    if ($NetworkResp.StatusCode -eq 200) {
        $NetworkRespData = $NetworkResp.Content | ConvertFrom-Json
        $FabricCount = $NetworkRespData.'@odata.count'
        if ($FabricCount -gt 0) {
            $FabricData += $NetworkRespData.'value'
            if ($NetworkRespData.'@odata.nextLink') {
                $NextLinkUrl = $BaseUri + $NetworkRespData.'@odata.nextLink'
            }
            while ($NextLinkUrl) {
                $NextLinkResponse = Invoke-WebRequest -Uri $NextLinkUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                if ($NextLinkResponse.StatusCode -eq 200) {
                    $NextLinkData = $NextLinkResponse.Content | ConvertFrom-Json
                    $FabricData += $NextLinkData.'value'
                    if ($NextLinkData.'@odata.nextLink') {
                        $NextLinkUrl = $BaseUri + $NextLinkData.'@odata.nextLink'
                    }
                    else {
                        $NextLinkUrl = $null
                    }
                }
                else {
                    Write-Warning "Unable to get nextlink response for $($NextLinkUrl)"
                    $NextLinkUrl = $null
                }
            }
            Write-Host "Successfully enumerated fabrics..."
            foreach ($Fabric in $FabricData) {
                $FabricLookup[$Fabric.Id] = $Fabric
            }            
        }
        else {
            Write-Warning "No fabrics found on host ....Exiting"
        }
    }
    else {
        Write-Error "Unable to enumerate fabrics on host "
    }
    $FabricData, $FabricLookup
}

function Set-ScaleVlanProfileProperty($BaseUri, $Headers, $selection, $FabricData) {
    $Type        = "application/json"
    Write-Host "Enumerating Fabric Design ...."
    $DesignURL = $BaseUri + "/api/NetworkService/Fabrics" + "('" + "$($selection)" + "')/FabricDesign"
    $DesignResp = Invoke-WebRequest -Uri $DesignURL -UseBasicParsing -Method Get -H $Headers -Con $Type
    if ($DesignResp.StatusCode -eq 200) {
        $DesignRespData = $DesignResp.Content | ConvertFrom-Json
        $foo = @{"Name" = $DesignRespData.Name}
        $FabricData.FabricDesign = $foo
        $PayloadInfo = $FabricData | Select-Object Name, Id, Description, ScaleVlanProfile, FabricDesignMapping,OverrideLLDPConfiguration,FabricDesign | ConvertTo-Json -Depth 4 | ForEach-Object {[System.Text.RegularExpressions.Regex]::Unescape($_) }
        Write-Host "Modifying ScaleVLANProfile property ....."
        $ActionURL = $BaseUri + "/api/NetworkService/Fabrics" + "('" + "$($selection)" + "')"    
        $ReplaceResp = Invoke-WebRequest -Uri $ActionURL -UseBasicParsing -Me Put -H $Headers -Con $Type -Body $PayloadInfo
        if ($ReplaceResp.StatusCode -eq 201 -or $ReplaceResp.StatusCode -eq 200) {
            Write-Host "Successfully modified ScaleVlanProfile property ...."
        }
        else {
            Write-Warning "Failed to modify ScaleVlanProfileProperty ....please check error logs"
            Write-Host "Response code is $($ReplaceResp.StatusCode)"
        }
    }
    else {
        Write-Warning "Unable to enumerate fabric design info ...Exiting"
    }
}

Try {
    Set-CertPolicy
    $IpAddress = $OmemIPAddr
    $BaseUri = "https://$($IpAddress)"
    $Type        = "application/json"
    $Headers     = @{}


    # Request authentication session token
    $AuthToken = Get-Session $IpAddress $Credentials
    if ($AuthToken) {
        # Successfully created a session, extract token
        $Headers."X-Auth-Token" = $AuthToken["token"]       
        $FabricDataArr = Get-Networks $BaseUri $Headers
        if ($FabricDataArr) 
        {
            $FabricData = $FabricDataArr[0]
            Write-Host "Enumerated IOMs ... Displaying fabric info ...."
            $FabricData | Select-Object Name, Id, ScaleVlanProfile, Description| Format-Table | Out-String
            $FabricChoices = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
            $FabricMap = [ordered]@{}
            $ctr = 0
            $caption = "Select fabric on which ScaleVLANProfile property will be set ..."
            foreach ($Fabric in $FabricData) {
                $nix =  $FabricMap.Insert($ctr,$ctr, $Fabric.Id)
                $ctr += 1
            }

            $selection = fShowMenu $caption $FabricMap
            Write-Host "Selected Fabric is ", $selection
            $FabricLookup = $FabricDataArr[1]
            $FabricDetails = $FabricLookup[$selection]
            if ($FabricDetails.ScaleVlanProfile -eq $ProfileState) {
                Write-Host "Fabric $($selection) ScaleVlanProfile is already set to $($ProfileState)"
            }
            else {
                $FabricDetails.ScaleVlanProfile = $ProfileState
                Set-ScaleVlanProfileProperty $BaseUri $Headers $selection $FabricDetails
            }
        }
    }
    else {
        Write-Warning "Unable to create a session with appliance $($IpAddress)"
    }
}
Catch {
    Write-Error "Exception: $($_)"
}
Finally {
    if ($AuthToken) {
      Remove-Session $IpAddress $Headers $AuthToken["id"]
    }
}