
<#
 .SYNOPSIS
   Script to get chassis inventory details in CSV format
 .DESCRIPTION

    This script exercises the OME REST API to get chassis inventory
    in a CSV format for external consumption. For authentication X-Auth
    is used over Basic Authentication

   Note that the credentials entered are not stored to disk.

 .PARAMETER IpAddress
   This is the IP address of the OME Appliance
 .PARAMETER Credentials
   Credentials used to talk to the OME Appliance

   .EXAMPLE
   $cred = Get-Credential
   .\Get-ChassisInventory.ps1 -IpAddress "10.xx.xx.xx" -Credentials $cred

 .EXAMPLE
   .\Get-ChassisInventory.ps1 -IpAddress "10.xx.xx.xx"
   In this instance you will be prompted for credentials to use
#>





[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [System.Net.IPAddress] $IpAddress,

    [Parameter(Mandatory)]
    [pscredential] $Credentials
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
        Catch {
            Write-Error "Unable to add type for cert policy"
        }
    }

    function Get-ManagedDeviceCount($IpAddress, $Headers, $Type){
        Try{
            $Count = 0
            $CountUrl = "https://$($IpAddress)/api/DeviceService/Devices"+"?`$count=true&`$top=0"
            Write-Host "Determining number of managed devices ..."
            $CountResp = Invoke-WebRequest -Uri $CountUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
            if( $CountResp.StatusCode -eq 200){
                $CountInfo = $CountResp.Content|ConvertFrom-Json
                $Count = $CountInfo.'@odata.count'
                Write-Host "Total managed device count : $($Count)"

            }else{
                Write-Host "*** ERROR: Unable to retrieve device count from $($IpAddress)"
            }

        }catch{
            Write-Error "Exception occured - $($_.Exception.Message)"
        }
        return $Count
    }

    function Get-NonServerMacAddress($DeviceInfo){
        $DeviceMgmtAddresses = @{}
        Try{
            $MgmtInfo = $DeviceInfo.'DeviceManagement' 

            if($MgmtInfo){
                $MgmtCount = 1
                foreach($MgmtNode in $MgmtInfo){
                    if($MgmtNode.'MacAddress'){
                        $CurrentMac = "System_MAC_" + [string] $MgmtCount
                        $DeviceMgmtAddresses.$CurrentMac =[string] $MgmtNode.'MacAddress'
                        $MgmtCount = $MgmtCount+1
                    } 
                }
            }
        }catch{
            Write-Error "Exception occured - $($_.Exception.Message)"
        }
        return $DeviceMgmtAddresses

    }

    

    function  Write-OutputCsvFile ($CsvData, $CsvColumns){
        $CsvFile = "chassis_inventory.csv"
        Try{
            if([System.IO.File]::Exists($CsvFile)){
                Remove-Item $CsvFile
            }
            $user = new-object psobject -property $CsvData
            $columnName = [system.String]::Join(",", $CsvColumns)
            Add-Content -Path $CsvFile -Value $columnName
            $user.psObject.properties|ForEach-Object{
                $value =$_.value
                
               foreach($val in $value){
                $keys = @()
                foreach($key in $val.Keys){
                    $keys +=$key 
                }
                 $item= $null
               for($i = 0;$i -lt $CsvColumns.length;$i++){
                    if($Keys -Contains $CsvColumns[$i] ){
                       $item += $val[$CsvColumns[$i]]
                    }else{
                        $item += ""
                    }
                    if($i -ne $CsvColumns.length-1){
                        $item= $item+","
                    }
                }
                Add-Content -Path $CsvFile -Value  $item
            }
                }
                 write-Host "Completed writing output to file chassis_inventory.csv"
        }catch{
            Write-Error "Exception occured - $($_.Exception.Message)"
        }


    }

    function Get-ServerMacAddress ($DeviceInfo, $IpAddress, $Headers, $Type){
        $DeviceMgmtAddresses = @{}
        Try{
            write-Host "Determining BMC MAC address information ..."
            $MgmtInfo = $DeviceInfo.'DeviceManagement'
            if($MgmtInfo){
                $MacCount = 1
                foreach($MgmtNode in $MgmtInfo){
                    if($MgmtNode.'MacAddress'){
                        $CurrentMac = "BMC_MAC_" +[string]$MacCount
                        $DeviceMgmtAddresses.$CurrentMac = [string] $MgmtNode.'MacAddress'
                        $MacCount = $MacCount +1
                        break
                    }

                }
            }
            $DeviceId = [string]$DeviceInfo.'Id'
            $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices"
            $DeviceInventoryUrl = $DeviceUrl +"($($DeviceId))/InventoryDetails('serverNetworkInterfaces')"
            Try{
                $DeviceInventoryResp = Invoke-WebRequest -Uri $DeviceInventoryUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
            }catch{
                $err=$_.Exception
                $err | Get-Member -MemberType Property
            }
            if($DeviceInventoryResp.StatusCode -eq 200){
                $DeviceInventoryInfo = $DeviceInventoryResp.Content | ConvertFrom-Json
                if($DeviceInventoryInfo.'InventoryInfo'.length -gt 0){
                    foreach($NicInfo in $DeviceInventoryInfo.'InventoryInfo'){
                        $MacCount =1
                       foreach($NicData in $NicInfo.'Ports'){
                            $CurrentMac = "System_MAC_" +[string]$MacCount
                            $FullProductName = [string] $NicData.'ProductName'
                            Write-Host "Analyzing $($FullProductName)"
                            if($FullProductName.Contains("-")){
                                 $MacAddr = $FullProductName.Split('-')[-1]
                                $DeviceMgmtAddresses.$CurrentMac = $MacAddr
                                $MacCount = $MacCount +1

                            }else{
                                foreach($NicPartition in $NicData.'Partitions'){
                                    if($NicPartition.'CurrentMacAddress'){
                                        $MacAddr = $NicPartition.'CurrentMacAddress'
                                        $DeviceMgmtAddresses.$CurrentMac = $MacAddr
                                        $MacCount = $MacCount+1
                                    }
                                }
                            }
                        }
                    }
                }else{
                    Write-Host "*** ERROR: No network inventory info returned for $($DeviceInfo.'DeviceServiceTag')"
                } 
            }else{
                Write-Host "*** WARN: No network inventory info returned for $($DeviceInfo.'DeviceServiceTag')"
            }
        }catch{
            Write-Error "Exception occured - $($_.Exception.Message)"
        }
      
        return $DeviceMgmtAddresses

    }

    function Get-DeviceInventory($IpAddress, $Headers, $Type){
        Try{
            $CsvColumns = @('Hostname', 'Unit', 'SerialNumber', 'System_MAC_1',
            'System_MAC_2', 'System_MAC_3', 'System_MAC_4',
            'System_MAC_5', 'System_MAC_6', 'System_MAC_7',
            'System_MAC_8', 'BMC_MAC_1', 'Chassis',
            'Chassis_Location', 'Model')
            $UnitMap = @{"1000"= "System"; "2000"="Chassis";
            "3000"="Storage"; "4000"= "Switch";
            "8000"= "Storage-IOM"}
            $CsvData = @{}
            $DeviceUrl = "https://$($IpAddress)/api/DeviceService/Devices"
            $DeviceCount = Get-ManagedDeviceCount $IpAddress $Headers $Type
            if($DeviceCount -gt 0){
                $AllDeviceUrl = $DeviceUrl + "?`$skip=0&`$top=$($DeviceCount)"
                Write-Host "Enumerating all device info ..."
                $AllDeviceResp = Invoke-WebRequest -Uri $AllDeviceUrl -UseBasicParsing -Method Get -Headers $Headers -ContentType $Type
                if($AllDeviceResp.StatusCode -eq 200){
                    $AllDeviceInfo = $AllDeviceResp.Content|ConvertFrom-Json
                    Write-Host "Iterating through devices and correlating data ..."
                    foreach($DeviceInfo in $AllDeviceInfo.'value'){
                        $DeviceId = $DeviceInfo.'Id'
                        $DeviceType =[string]$DeviceInfo.'Type'
                        $DeviceUnitName = $null
                        if ($UnitMap.ContainsKey($DeviceType)) {
                            $DeviceUnitName = $UnitMap.$DeviceType
                        }
                        $DeviceModel = $null
                        if($DeviceInfo.'Model'){
                            $DeviceModel = [string]$DeviceInfo.'Model'
                        }
                        $DeviceSvcTag = $null
                        if($DeviceInfo.'DeviceServiceTag'){
                            $DeviceSvcTag = [string]$DeviceInfo.'DeviceServiceTag'
                        }
                        $DeviceHostName = $null
                        if($DeviceInfo.'DeviceName'){
                            $DeviceHostName = [string]$DeviceInfo.'DeviceName'
                        }
                        Write-Host "Processing ID:$($DeviceId), Type:$($DeviceUnitName),Model:$($DeviceModel),SvcTag:$($DeviceSvcTag),Host:$($DeviceHostName)"
                         
                        
                        ## Assemble device dictionary info
                        $TempHash = @{}
                        $TempHash.'Model' =$DeviceModel
                        $TempHash.'SerialNumber' =$DeviceSvcTag
                        $TempHash.'Hostname' = $DeviceHostName
                        $TempHash.'Unit' = $DeviceUnitName
                        if( $DeviceUnitName){
                            $MacAddress = @{}
                            if($DeviceUnitName -eq "Chassis"){
                                if($DeviceSvcTag){
                                    if (!$CsvData.ContainsKey($DeviceSvcTag)){
                                       $CsvData.$DeviceSvcTag = @()
                                    }
                                }else{
                                    Write-Host "*** WARNING: Chassis service tag is NULL..."
                                }
                                $MacAddress = Get-NonServerMacAddress $DeviceInfo
                                foreach($MacAddr in $MacAddress.keys){
                                    $TempHash.$MacAddr = $MacAddress.$MacAddr
                                }
                                $CsvData.$DeviceSvcTag +=$TempHash  
                            }else{
                                $ChassisSvcTag = $null
                                if($DeviceInfo.'ChassisServiceTag'){
                                    $ChassisSvcTag = [string]$DeviceInfo.'ChassisServiceTag'
                                }else{
                                    Write-Host "Warning...Chassis service tag is Null"
                                }
                                $TempHash.'Chassis' = $ChassisSvcTag
                                $SlotFound = $false
                              foreach ($item in $DeviceInfo.psObject.properties) {
                                  if($item.Name -eq 'SlotConfiguration'){
                                      if([string]$item.Value -ne ''){
                                          $SlotFound = $true
                                          $slotConfig = $item.Value
                                          foreach($slotItem in $slotConfig.psObject.properties){
                                              if([string]$slotItem.Name -eq 'SlotName'){
                                                  $TempHash.'Chassis_Location' = $slotItem.Value 
                                              }
                                          }
                                      }
                                  }
                                  
                              }
                              if(!$SlotFound){
                                     Write-Host("*** WARNING: No slot configuration information available ")
                                }
                               if($DeviceUnitName -ne "System"){
                                    $MacAddress = Get-NonServerMacAddress $DeviceInfo
                                }else{
                                    $MacAddress = Get-ServerMacAddress $DeviceInfo $IpAddress $Headers $Type
                                  
                                }
                               foreach($MacAddr in $MacAddress.Keys){
                                   $TempHash.$MacAddr = $MacAddress.$MacAddr
                               }
                                if($ChassisSvcTag){
                                   if(! $CsvData.ContainsKey($ChassisSvcTag) ){
                                       $CsvData.$ChassisSvcTag = @()
                                   }
                                   $CsvData.$ChassisSvcTag +=$TempHash
                               }else{
                                Write-Host("*** WARNING: Unable to add ($($DeviceId),$($DeviceSvcTag)) - chassis_svc_tag is NULL")
                               }    
                          }
                        }else{
                            Write-Host "*** ERROR: Unable to find a mapping for device in unit map"
                        }  
                    }
                    if($CsvData){
                       
                        Write-OutputCsvFile $CsvData  $CsvColumns
                    }
                }else{
                    Write-Host "*** ERROR: Unable to retrieve all device info from $($IpAddress) .. Exiting"
                }
            }else{
                Write-Host "*** ERROR: No devices retrieved from $($IpAddress)"
            }
        }catch{
            Write-Error "Exception occured - $($_.Exception.Message)"
        }
    }

    Try {
        Set-CertPolicy
        $SessionUrl  = "https://$($IpAddress)/api/SessionService/Sessions"
        $Type        = "application/json"
        $UserName    = $Credentials.username
        $Password    = $Credentials.GetNetworkCredential().password
        $UserDetails = @{"UserName"=$UserName;"Password"=$Password;"SessionType"="API"} | ConvertTo-Json
        $Headers     = @{}
        $SessResponse = Invoke-WebRequest -Uri $SessionUrl -Method Post -Body $UserDetails -ContentType $Type
        if ($SessResponse.StatusCode -eq 200 -or $SessResponse.StatusCode -eq 201) {
            $Headers."X-Auth-Token" = $SessResponse.Headers["X-Auth-Token"]
            Get-DeviceInventory $IpAddress $Headers $Type
        }
        else{
            Write-Error "*** ERROR: Unable to authenticate with endpoint .. Check IP/Username/Pwd"
        }
    }catch {
        Write-Error "Exception occured - $($_.Exception.Message)"
    }