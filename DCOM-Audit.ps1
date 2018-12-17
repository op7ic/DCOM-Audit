<#

VERSION      DATE          AUTHOR
0.1A      14/12/2018       op7ic

#> # Revision History


<#
  .SYNOPSIS
    Dumps DCOM object permissions and shows potentially vulnerable methods exported by DCOM

  .EXAMPLE
    Audit-DCOM 
  
  .EXAMPLE
    #To dump permissions and audit DCOM methods 
    Audit-DCOM -audit 

  .SOURCES
    https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Get-DCOM-22da5b96
    https://hackdefense.nl/docs/automating-the-enumeration-of-possible-dcom-vulnerabilities-axel-boesenach%20v1.0.pdf
    https://github.com/sud0woodo/DCOMrade
    https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
    https://www.cybereason.com/blog/dcom-lateral-movement-techniques

  .OUTPUT
    [+] BUILTIN\Users have Access permissions for HKEY_CLASSES_ROOT\AppID\{49EBD8BE-1A92-4A86-A651-70AC565E0FEB} and the following permission are present: LocalAccess
    [!] WARNING: Launch permissions are not applied for HKEY_CLASSES_ROOT\AppID\{49f171dd-b51a-40d3-9a6c-52d674cc729d}, default permission in place
    [!] WARNING: Access permissions are not applied for HKEY_CLASSES_ROOT\AppID\{49f171dd-b51a-40d3-9a6c-52d674cc729d}, default permission in place 
    [!] WARNING: Launch permissions are not applied for HKEY_CLASSES_ROOT\AppID\{4A0F9AA8-A71E-4CC3-891B-76CAC67E67C0}, default permission in place
    [!] WARNING: Access permissions are not applied for HKEY_CLASSES_ROOT\AppID\{4A0F9AA8-A71E-4CC3-891B-76CAC67E67C0}, default permission in place
    [+] NT AUTHORITY\SYSTEM have Launch permissions for HKEY_CLASSES_ROOT\AppID\{4A3F2F56-454A-4CC5-9734-BB7D8141AC0A} and the following permission are present: LocalLaunch LocalActivation
    [+] NT AUTHORITY\INTERACTIVE have Access permissions for HKEY_CLASSES_ROOT\AppID\{4A3F2F56-454A-4CC5-9734-BB7D8141AC0A} and the following permission are present: LocalAccess
    [+] NT AUTHORITY\INTERACTIVE have Launch permissions for HKEY_CLASSES_ROOT\AppID\{4A6B8BAD-9872-4525-A812-71A52367DC17} and the following permission are present: LocalLaunch LocalActivation
    [+] NT AUTHORITY\INTERACTIVE have Access permissions for HKEY_CLASSES_ROOT\AppID\{4A6B8BAD-9872-4525-A812-71A52367DC17} and the following permission are present: LocalAccess
    [+] NT AUTHORITY\SYSTEM have Launch permissions for HKEY_CLASSES_ROOT\AppID\{4BC67F23-D805-4384-BCA3-6F1EDFF50E2C} and the following permission are present: LocalLaunch LocalActivation
    [+] NT AUTHORITY\INTERACTIVE have Access permissions for HKEY_CLASSES_ROOT\AppID\{4BC67F23-D805-4384-BCA3-6F1EDFF50E2C} and the following permission are present: LocalAccess
    [...]
#>

#Map COM rights
$COM_RIGHTS_EXECUTE = 1
$COM_RIGHTS_EXECUTE_LOCAL = 2
$COM_RIGHTS_EXECUTE_REMOTE = 4
$COM_RIGHTS_ACTIVATE_LOCAL = 8
$COM_RIGHTS_ACTIVATE_REMOTE = 16
$ErrorActionPreference = "Stop"

#Resolve permissions for com object
function resolvePermission ($sd, $TypePermission) {
     
     foreach ($ace in $sd.DiscretionaryAcl) {
            try { 
            $access = @()
            if ($TypePermission -eq "Launch") {
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL) -or 
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and 
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_LOCAL))) ) { $access += "LocalLaunch" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_LOCAL -bor
                                                 $COM_RIGHTS_ACTIVATE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_LOCAL))) ) { $access += "RemoteLaunch" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_ACTIVATE_LOCAL) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_LOCAL -bor
                                                 $COM_RIGHTS_EXECUTE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_REMOTE))) ) { $access += "LocalActivation" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_ACTIVATE_REMOTE) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_LOCAL -bor
                                                 $COM_RIGHTS_EXECUTE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_LOCAL))) ) { $access += "RemoteActivation" }
            } else {
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE)) ) { $access += "LocalAccess" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL)) ) { $access += "RemoteAccess" }
            }
            }catch { 
                Write-Warning "[+] Unable to calculate permissions based on the Access Mask"
            }
      }
      #Map User permissions
      try{
      $User = (($ace.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])).Value 
     
      if ($User -eq "Everyone") {
          Write-Host "[!] WARNING: 'Everyone' have $TypePermission permissions for $APPID and the following application-specific permission are present: $access" -ForegroundColor Green         
      }elseif ($User -like "NT AUTHORITY\Authenticated Users") { 
          Write-Host "[!] WARNING: 'Authenticated Users' have $TypePermission permissions for $APPID and the following application-specific permission are present: $access" -ForegroundColor Green
      }elseif ($User -like "*ALL APPLICATION PACKAGES"){
          Write-Host "[!] WARNING: 'ALL APPLICATION PACKAGES' have $TypePermission permissions for $APPID and the following application-specific permission are present: $access" -ForegroundColor Green
      }else{
          Write-Host "[+] '$User' have $TypePermission permissions for $APPID and the following application-specific permission are present: $access" -ForegroundColor DarkYellow
      }
      }catch{
          #Sometimes SID resolution fails? TODO
          Write-Host "[+] SID: $($ace.SecurityIdentifier) have $TypePermission permissions for $APPID and the following application-specific permission are present: $access" -ForegroundColor DarkYellow; $User=$null 
      }
            
}

#Map Methods for given CLSID by creating instance of CLSID and then checking exposed methods. 
function getCLIDMethods ($CLID){
#TODO timeout here ..
try{
  #Claim COM Object
  $COM = [activator]::CreateInstance([type]::GetTypeFromCLSID("$CLID","localhost"))
  #Potentially dangerous methods
  $vulnerable= @("Shell","Execute","Navigate","DDEInitiate","CreateObject","RegisterXLL","ExecuteLine","NewCurrentDatabase","Service","Create","Run","Exec","Invoke","File","Method","Explore")
  #Count the number of methods in the COM object
  $MemberCount = ($COM | Get-Member).Count
  $cOMmethods= @($COM | Get-Member).Name

  if($cOMmethods| Where {$vulnerable -Contains $_})
  {
   Write-host "[!] Potentially dangerous method is present in $CLID" -ForegroundColor Green 
  }
  #Relase COM object
 [System.Runtime.Interopservices.Marshal]::ReleaseComObject($COM) | Out-Null -ErrorAction Continue
}catch{
  if($_.Exception.Message -like "*80040154*"){
   Write-Host "[*] WARNING: Cannot load x86 $CLID into x64 process. Method check skipped." -ForegroundColor Yellow
  }
}

}


function Audit-DCOM{

param (
    [switch]$audit
);

write-host "-=[ DCOM-Audit v0.1 ]=-"
write-host "      by op7ic        "


#Extract all application IDs from registry and filter out just DCOM IDs, this varies based on x86 or x64 achitecture
New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR -Scope Local -ErrorAction SilentlyContinue | Out-Null
$ApplicationID = Get-ChildItem -Path HKCR:\AppID\ | Select-String -Pattern '\{(?i)[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}\}'
#There are two typr of access and we want to check both of them
$PermissionKeys=("Launch","Access")

#Loop over each APPID and Permission Key
foreach ($APPID in $ApplicationID) {
   #Loop over each permission type
   foreach ($Type in $PermissionKeys){
   #Retrieve regiestry key
   $regkey = Get-Item -Path "HKCR:\$APPID"

   
   try {
   $reg_perms = ($regkey | Get-ItemProperty -Name "$($Type)Permission")."$($Type)Permission"
   $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($reg_perms, 0)
   $permissionsApplied = resolvePermission $sd $Type
   if ($audit){
   getCLIDMethods($APPID.ToString().split("\\")[2])
   }
   } catch {
      #If there is no Access or Launch key this means DCOM is using "default" permissions
      if ($_.Exception.Message -match "Property $($Type)Permission does not exist") {
         Write-Host "[!] WARNING: $Type permissions are not applied for $APPID, default permission in place" -ForegroundColor Red
   } else {throw $_ }


     }#EOL 
   }#EOL
 }#EOL
}#EOF 


Audit-DCOM