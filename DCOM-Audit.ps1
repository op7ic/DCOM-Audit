<#
.SYNOPSIS
    DCOM Audit - Audits DCOM permissions and identifies security vulnerabilities
    
.DESCRIPTION
    Dumps DCOM object permissions, analyzes access flags, checks for dangerous methods,
    and provides security recommendations with .NET fallback methods
    
.PARAMETER Audit
    Enables deep audit mode to check for potentially dangerous methods
    
.PARAMETER OutputPath
    Path to save detailed report (default: current directory)
    
.PARAMETER FastMode
    Skip method enumeration for faster execution
    
.PARAMETER ExportCSV
    Export results to CSV format
    
.PARAMETER CheckMitigations
    Check if DCOM hardening mitigations are applied
    
.EXAMPLE
    .\DCOM-Auditor-Enhanced.ps1 -Audit
    
.EXAMPLE
    .\DCOM-Auditor-Enhanced.ps1 -Audit -OutputPath "C:\Reports" -ExportCSV
    
.NOTES
	Author: op7ic
    Repository: https://github.com/op7ic/DCOM-Audit
#>

[CmdletBinding()]
param(
    [switch]$Audit,
    [string]$OutputPath = $PWD,
    [switch]$FastMode,
    [switch]$ExportCSV,
    [switch]$CheckMitigations
)

# Constants
$ACL_REVISION = 2
$COM_RIGHTS_EXECUTE = 1
$COM_RIGHTS_EXECUTE_LOCAL = 2
$COM_RIGHTS_EXECUTE_REMOTE = 4
$COM_RIGHTS_ACTIVATE_LOCAL = 8
$COM_RIGHTS_ACTIVATE_REMOTE = 16

$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Dangerous DCOM methods blacklist
$DangerousMethods = @(
    "Shell", "Execute", "Navigate", "DDEInitiate", "CreateObject", 
    "RegisterXLL", "ExecuteLine", "NewCurrentDatabase", "Service", 
    "Create", "Run", "Exec", "Invoke", "File", "Method", 
    "Explore", "ExecWB", "Item", "Document", "Application",
    "ShellExecute", "ExecuteShellCommand", "DoVerb", "GetObject",
    "Open", "Save", "SaveAs", "Import", "Export", "ExecuteExcel4Macro"
)

# Known DCOM objects used in attacks
$KnownExploitableDCOM = @{
    "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}" = @{
        Name = "ShellWindows"
        Technique = "Lateral Movement"
        Example = "`$com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39','target'); `$obj = [Activator]::CreateInstance(`$com); `$obj.Navigate('c:\windows\system32\calc.exe')"
        Mitre = "T1021.003"
    }
    "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}" = @{
        Name = "MMC20.Application"
        Technique = "Remote Code Execution"
        Example = "`$com = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','target')); `$com.Document.ActiveView.ExecuteShellCommand('cmd.exe',`$null,'/c calc.exe','7')"
        Mitre = "T1021.003"
    }
    "{00021401-0000-0000-C000-000000000046}" = @{
        Name = "ShellBrowserWindow"
        Technique = "Remote Process Creation"
        Example = "Used with ShellWindows to execute commands remotely"
        Mitre = "T1021.003"
    }
    "{F5078F35-C551-11D3-89B9-0000F81FE221}" = @{
        Name = "Outlook.Application"
        Technique = "Phishing/Macro Execution"
        Example = "`$outlook = [activator]::CreateInstance([type]::GetTypeFromProgID('Outlook.Application')); `$outlook.CreateObject('Shell.Application').ShellExecute('calc.exe')"
        Mitre = "T1566.001"
    }
}

# High-risk users/groups
$HighRiskPrincipals = @(
    "Everyone",
    "NT AUTHORITY\Authenticated Users",
    "BUILTIN\Users",
    "Domain Users",
    "ALL APPLICATION PACKAGES"
)

# Results storage
$global:DCOMResults = @()
$global:VulnerableObjects = @()
$global:Recommendations = @()
$global:DLLRisks = @()
$global:ServiceRisks = @()
$global:AttackScenarios = @()

# Add .NET types for advanced DCOM operations
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DCOMAuditor
{
    public enum DCOM_RIGHTS : uint
    {
        COM_RIGHTS_EXECUTE = 1,
        COM_RIGHTS_EXECUTE_LOCAL = 2,
        COM_RIGHTS_EXECUTE_REMOTE = 4,
        COM_RIGHTS_ACTIVATE_LOCAL = 8,
        COM_RIGHTS_ACTIVATE_REMOTE = 16
    }

    public class DCOMSecurity
    {
        [DllImport("ole32.dll")]
        public static extern int CoInitializeSecurity(
            IntPtr pSecDesc,
            int cAuthSvc,
            IntPtr asAuthSvc,
            IntPtr pReserved1,
            uint dwAuthnLevel,
            uint dwImpLevel,
            IntPtr pAuthList,
            uint dwCapabilities,
            IntPtr pReserved3
        );

        public static string[] ParseAccessMask(uint accessMask, bool isLaunch)
        {
            var permissions = new System.Collections.Generic.List<string>();
            
            if (isLaunch)
            {
                if ((accessMask & (uint)DCOM_RIGHTS.COM_RIGHTS_EXECUTE_LOCAL) != 0 ||
                    ((accessMask & (uint)DCOM_RIGHTS.COM_RIGHTS_EXECUTE) != 0 &&
                     (accessMask & ((uint)DCOM_RIGHTS.COM_RIGHTS_EXECUTE_REMOTE | 
                                   (uint)DCOM_RIGHTS.COM_RIGHTS_ACTIVATE_REMOTE | 
                                   (uint)DCOM_RIGHTS.COM_RIGHTS_ACTIVATE_LOCAL)) == 0))
                {
                    permissions.Add("LocalLaunch");
                }
                
                if ((accessMask & (uint)DCOM_RIGHTS.COM_RIGHTS_EXECUTE_REMOTE) != 0)
                {
                    permissions.Add("RemoteLaunch");
                }
                
                if ((accessMask & (uint)DCOM_RIGHTS.COM_RIGHTS_ACTIVATE_LOCAL) != 0)
                {
                    permissions.Add("LocalActivation");
                }
                
                if ((accessMask & (uint)DCOM_RIGHTS.COM_RIGHTS_ACTIVATE_REMOTE) != 0)
                {
                    permissions.Add("RemoteActivation");
                }
            }
            else
            {
                if ((accessMask & (uint)DCOM_RIGHTS.COM_RIGHTS_EXECUTE_LOCAL) != 0)
                {
                    permissions.Add("LocalAccess");
                }
                
                if ((accessMask & (uint)DCOM_RIGHTS.COM_RIGHTS_EXECUTE_REMOTE) != 0)
                {
                    permissions.Add("RemoteAccess");
                }
            }
            
            return permissions.ToArray();
        }
    }
}
'@ -ErrorAction SilentlyContinue

# Additional type definitions for file permission checking
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO;

namespace DCOMAuditor
{
    public class FilePermissionChecker
    {
        public static bool IsWritableByNonAdmins(string path)
        {
            try
            {
                if (!File.Exists(path) && !Directory.Exists(path))
                    return false;
                    
                var acl = File.GetAccessControl(path);
                var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
                
                var everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
                var authUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                
                foreach (FileSystemAccessRule rule in rules)
                {
                    if ((rule.IdentityReference.Equals(everyoneSid) || 
                         rule.IdentityReference.Equals(usersSid) || 
                         rule.IdentityReference.Equals(authUsersSid)) &&
                        rule.AccessControlType == AccessControlType.Allow &&
                        (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.FullControl)) != 0)
                    {
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        public static string[] GetWritableUsers(string path)
        {
            var users = new System.Collections.Generic.List<string>();
            try
            {
                var acl = File.GetAccessControl(path);
                var rules = acl.GetAccessRules(true, true, typeof(NTAccount));
                
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Allow &&
                        (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.FullControl)) != 0)
                    {
                        users.Add(rule.IdentityReference.Value);
                    }
                }
            }
            catch { }
            return users.ToArray();
        }
    }
}
'@ -ErrorAction SilentlyContinue

# Functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewLine
    )
    
    $params = @{
        Object = $Message
        ForegroundColor = $Color
        NoNewLine = $NoNewLine
    }
    
    Write-Host @params
}

function Get-DCOMSecurityDescriptor {
    param(
        [string]$AppID,
        [string]$PermissionType
    )
    
    try {
        $regPath = "HKCR:\AppID\$AppID"
        $regKey = Get-Item -Path $regPath -ErrorAction Stop
        
        $permissionName = "${PermissionType}Permission"
        $sdBytes = ($regKey | Get-ItemProperty -Name $permissionName -ErrorAction SilentlyContinue).$permissionName
        
        if ($null -eq $sdBytes) {
            return $null
        }
        
        return New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
    }
    catch {
        Write-Verbose "Error getting security descriptor for $AppID : $_"
        return $null
    }
}

function Get-DCOMApplicationInfo {
    param(
        [string]$AppID
    )
    
    try {
        $regPath = "HKCR:\AppID\$AppID"
        $regKey = Get-Item -Path $regPath -ErrorAction Stop
        
        $info = @{
            AppID = $AppID
            Name = ($regKey | Get-ItemProperty -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
            LocalService = ($regKey | Get-ItemProperty -Name "LocalService" -ErrorAction SilentlyContinue).LocalService
            RunAs = ($regKey | Get-ItemProperty -Name "RunAs" -ErrorAction SilentlyContinue).RunAs
            ServiceParameters = ($regKey | Get-ItemProperty -Name "ServiceParameters" -ErrorAction SilentlyContinue).ServiceParameters
            DllSurrogate = ($regKey | Get-ItemProperty -Name "DllSurrogate" -ErrorAction SilentlyContinue).DllSurrogate
        }
        
        # Get associated CLSIDs and InprocServer32 paths
        $clsids = @()
        $dllPaths = @()
        $exePaths = @()
        
        Get-ChildItem -Path "HKCR:\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
            $clsidAppId = ($_ | Get-ItemProperty -Name "AppID" -ErrorAction SilentlyContinue).AppID
            if ($clsidAppId -eq $AppID) {
                $clsidPath = $_.PSPath
                $clsids += $_.PSChildName
                
                # Check for InprocServer32 (DLL)
                if (Test-Path "$clsidPath\InprocServer32") {
                    $dll = (Get-ItemProperty -Path "$clsidPath\InprocServer32" -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
                    if ($dll -and $dll -ne "") {
                        $dllPaths += [System.Environment]::ExpandEnvironmentVariables($dll)
                    }
                }
                
                # Check for LocalServer32 (EXE)
                if (Test-Path "$clsidPath\LocalServer32") {
                    $exe = (Get-ItemProperty -Path "$clsidPath\LocalServer32" -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
                    if ($exe -and $exe -ne "") {
                        # Extract exe path from command line
                        if ($exe -match '^"([^"]+)"' -or $exe -match '^(\S+)') {
                            $exePaths += [System.Environment]::ExpandEnvironmentVariables($matches[1])
                        }
                    }
                }
            }
        }
        
        $info.CLSIDs = $clsids
        $info.DllPaths = $dllPaths | Select-Object -Unique
        $info.ExePaths = $exePaths | Select-Object -Unique
        
        return $info
    }
    catch {
        Write-Verbose "Error getting application info for $AppID : $_"
        return @{ AppID = $AppID }
    }
}

function Get-ServicePermissions {
    param(
        [string]$ServiceName
    )
    
    try {
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($service) {
            $sd = $service.GetSecurityDescriptor()
            if ($sd.ReturnValue -eq 0) {
                $dacl = $sd.Descriptor.DACL
                $vulnerableUsers = @()
                
                foreach ($ace in $dacl) {
                    $trustee = $ace.Trustee
                    $principal = "$($trustee.Domain)\$($trustee.Name)".Trim('\')
                    
                    # Check for dangerous permissions
                    # 0x10 = Start, 0x20 = Stop, 0x2 = Change Config
                    if (($ace.AccessMask -band 0x2) -or ($ace.AccessMask -band 0xF01FF)) {
                        if ($principal -in @("Everyone", "Authenticated Users", "BUILTIN\Users", "Domain Users")) {
                            $vulnerableUsers += $principal
                        }
                    }
                }
                
                return @{
                    ServiceName = $ServiceName
                    ExecutablePath = $service.PathName
                    StartMode = $service.StartMode
                    Status = $service.State
                    VulnerableUsers = $vulnerableUsers
                }
            }
        }
    }
    catch {
        Write-Verbose "Error checking service permissions for $ServiceName : $_"
    }
    
    return $null
}

function Get-DLLHijackingRisk {
    param(
        [string]$DllPath
    )
    
    $risks = @()
    
    if (-not $DllPath -or -not (Test-Path $DllPath -ErrorAction SilentlyContinue)) {
        return $risks
    }
    
    # Check if DLL is writable by non-admins
    if ([DCOMAuditor.FilePermissionChecker]::IsWritableByNonAdmins($DllPath)) {
        $writableUsers = [DCOMAuditor.FilePermissionChecker]::GetWritableUsers($DllPath)
        $risks += [PSCustomObject]@{
            Type = "Writable DLL"
            Path = $DllPath
            Risk = "High"
            Issue = "DLL can be replaced by non-admin users"
            WritableBy = $writableUsers -join ", "
        }
    }
    
    # Check directory permissions (DLL planting)
    $dllDir = Split-Path $DllPath -Parent
    if ([DCOMAuditor.FilePermissionChecker]::IsWritableByNonAdmins($dllDir)) {
        $writableUsers = [DCOMAuditor.FilePermissionChecker]::GetWritableUsers($dllDir)
        $risks += [PSCustomObject]@{
            Type = "Writable Directory"
            Path = $dllDir
            Risk = "High"
            Issue = "Directory allows DLL planting"
            WritableBy = $writableUsers -join ", "
        }
    }
    
    # Check for missing DLLs (phantom DLL hijacking)
    if (-not (Test-Path $DllPath)) {
        # Check if parent directory exists and is writable
        $parentDir = Split-Path $DllPath -Parent
        if ((Test-Path $parentDir) -and [DCOMAuditor.FilePermissionChecker]::IsWritableByNonAdmins($parentDir)) {
            $risks += [PSCustomObject]@{
                Type = "Phantom DLL"
                Path = $DllPath
                Risk = "Critical"
                Issue = "Missing DLL in writable directory"
                WritableBy = ([DCOMAuditor.FilePermissionChecker]::GetWritableUsers($parentDir)) -join ", "
            }
        }
    }
    
    return $risks
}

function Get-AttackScenario {
    param(
        [string]$AppID,
        [hashtable]$AppInfo,
        [array]$Permissions,
        [array]$Methods
    )
    
    $scenarios = @()
    
    # Check if this is a known exploitable DCOM
    if ($KnownExploitableDCOM.ContainsKey($AppID)) {
        $exploit = $KnownExploitableDCOM[$AppID]
        $scenarios += [PSCustomObject]@{
            Technique = $exploit.Technique
            Description = "Known DCOM abuse technique for $($exploit.Name)"
            Example = $exploit.Example
            MitreID = $exploit.Mitre
            Severity = "Critical"
        }
    }
    
    # Check for lateral movement potential
    $hasRemoteAccess = $Permissions | Where-Object { 
        $_.Permissions -like "*Remote*" -and 
        $_.Principal -in @("Everyone", "NT AUTHORITY\Authenticated Users", "BUILTIN\Users", "Domain Users")
    }
    
    if ($hasRemoteAccess -and ($Methods | Where-Object { $DangerousMethods -contains $_ })) {
        $scenarios += [PSCustomObject]@{
            Technique = "Lateral Movement"
            Description = "Remote access with dangerous methods allows code execution on remote systems"
            Example = "Attacker can use DCOM to move laterally: `$com = [activator]::CreateInstance([type]::GetTypeFromCLSID('$AppID','TARGET'))"
            MitreID = "T1021.003"
            Severity = "High"
        }
    }
    
    # Check for privilege escalation via service
    if ($AppInfo.LocalService) {
        $servicePerms = Get-ServicePermissions -ServiceName $AppInfo.LocalService
        if ($servicePerms -and $servicePerms.VulnerableUsers.Count -gt 0) {
            $scenarios += [PSCustomObject]@{
                Technique = "Privilege Escalation"
                Description = "Service '$($AppInfo.LocalService)' has weak permissions"
                Example = "Non-admin users can modify service: $($servicePerms.VulnerableUsers -join ', ')"
                MitreID = "T1543.003"
                Severity = "High"
            }
        }
    }
    
    # Check for DLL hijacking
    foreach ($dllPath in $AppInfo.DllPaths) {
        $dllRisks = Get-DLLHijackingRisk -DllPath $dllPath
        foreach ($risk in $dllRisks) {
            $scenarios += [PSCustomObject]@{
                Technique = "DLL Hijacking"
                Description = "$($risk.Type): $($risk.Issue)"
                Example = "Attacker can replace/plant DLL at: $($risk.Path)"
                MitreID = "T1574.001"
                Severity = $risk.Risk
            }
        }
    }
    
    # Check for living off the land
    if ($AppInfo.Name -match "Office|Excel|Word|Outlook|PowerPoint" -and $Methods -contains "CreateObject") {
        $scenarios += [PSCustomObject]@{
            Technique = "Living Off The Land"
            Description = "Office application can be abused for code execution"
            Example = "`$app = New-Object -ComObject '$($AppInfo.Name)'; `$app.CreateObject('WScript.Shell').Run('calc.exe')"
            MitreID = "T1218"
            Severity = "Medium"
        }
    }
    
    return $scenarios
}

function Test-DCOMInterfaces {
    param(
        [string]$CLSID
    )
    
    $interfaces = @()
    
    try {
        # Check for IDispatch interface (scriptable)
        $type = [System.Type]::GetTypeFromCLSID([Guid]$CLSID)
        if ($type) {
            $isDispatch = $type.GetInterfaces() | Where-Object { $_.Name -eq "IDispatch" }
            if ($isDispatch) {
                $interfaces += "IDispatch (Scriptable)"
            }
            
            # Try to get all interfaces
            $type.GetInterfaces() | ForEach-Object {
                $interfaces += $_.Name
            }
        }
    }
    catch {
        Write-Verbose "Failed to enumerate interfaces for $CLSID : $_"
    }
    
    return $interfaces | Select-Object -Unique
}

function Test-DCOMObjectMethods {
    param(
        [string]$CLSID,
        [int]$Timeout = 5000
    )
    
    $methods = @()
    $isDangerous = $false
    
    # Try PowerShell method first
    try {
        $comType = [type]::GetTypeFromCLSID($CLSID, "localhost")
        if ($null -ne $comType) {
            $job = Start-Job -ScriptBlock {
                param($clsid, $dangerousMethods)
                try {
                    $com = [activator]::CreateInstance([type]::GetTypeFromCLSID($clsid))
                    $members = $com | Get-Member -MemberType Method | Select-Object -ExpandProperty Name
                    $dangerous = $members | Where-Object { $dangerousMethods -contains $_ }
                    
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($com) | Out-Null
                    
                    return @{
                        Methods = $members
                        Dangerous = $dangerous
                    }
                }
                catch {
                    return @{ Error = $_.Exception.Message }
                }
            } -ArgumentList $CLSID, $DangerousMethods
            
            $result = Wait-Job -Job $job -Timeout ($Timeout / 1000) | Receive-Job
            Remove-Job -Job $job -Force
            
            if ($result.Methods) {
                $methods = $result.Methods
                if ($result.Dangerous) {
                    $isDangerous = $true
                }
            }
        }
    }
    catch {
        Write-Verbose "PowerShell method enumeration failed for $CLSID : $_"
    }
    
    # .NET fallback method
    if ($methods.Count -eq 0) {
        try {
            $type = [System.Type]::GetTypeFromCLSID([Guid]$CLSID)
            if ($null -ne $type) {
                $methodInfos = $type.GetMethods() | Select-Object -ExpandProperty Name -Unique
                $methods = $methodInfos
                $isDangerous = ($methodInfos | Where-Object { $DangerousMethods -contains $_ }).Count -gt 0
            }
        }
        catch {
            Write-Verbose ".NET method enumeration failed for $CLSID : $_"
        }
    }
    
    return @{
        Methods = $methods
        IsDangerous = $isDangerous
    }
}

function Analyze-DCOMPermissions {
    param(
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,
        [string]$PermissionType,
        [string]$AppID,
        [hashtable]$AppInfo
    )
    
    $results = @()
    $hasDefaultPerms = $false
    
    if ($null -eq $SecurityDescriptor) {
        $hasDefaultPerms = $true
        $results += [PSCustomObject]@{
            AppID = $AppID
            AppName = $AppInfo.Name
            PermissionType = $PermissionType
            Principal = "DEFAULT"
            PrincipalSID = "DEFAULT"
            Permissions = "Default $PermissionType permissions"
            RiskLevel = "Medium"
            IsVulnerable = $true
        }
    }
    else {
        foreach ($ace in $SecurityDescriptor.DiscretionaryAcl) {
            try {
                $principal = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
            }
            catch {
                $principal = $ace.SecurityIdentifier.ToString()
            }
            
            # Use .NET method to parse permissions
            $permissions = [DCOMAuditor.DCOMSecurity]::ParseAccessMask(
                $ace.AccessMask, 
                $PermissionType -eq "Launch"
            )
            
            $isHighRisk = $HighRiskPrincipals -contains $principal
            $hasRemotePerms = ($permissions -contains "RemoteLaunch") -or 
                              ($permissions -contains "RemoteActivation") -or 
                              ($permissions -contains "RemoteAccess")
            
            $riskLevel = "Low"
            if ($isHighRisk -and $hasRemotePerms) {
                $riskLevel = "Critical"
            }
            elseif ($isHighRisk -or $hasRemotePerms) {
                $riskLevel = "High"
            }
            elseif ($principal -notlike "*Administrator*" -and $principal -ne "NT AUTHORITY\SYSTEM") {
                $riskLevel = "Medium"
            }
            
            $results += [PSCustomObject]@{
                AppID = $AppID
                AppName = $AppInfo.Name
                PermissionType = $PermissionType
                Principal = $principal
                PrincipalSID = $ace.SecurityIdentifier.ToString()
                Permissions = $permissions -join ", "
                AccessMask = $ace.AccessMask
                AceType = $ace.AceType
                RiskLevel = $riskLevel
                IsVulnerable = ($riskLevel -in @("High", "Critical"))
                RunAs = $AppInfo.RunAs
                LocalService = $AppInfo.LocalService
            }
        }
    }
    
    return $results
}

function Get-DCOMHardeningStatus {
    $status = @{}
    
    # Check for KB5004442 related settings
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Ole"
        
        $status.EnableDCOMHTTP = (Get-ItemProperty -Path $regPath -Name "EnableDCOMHTTP" -ErrorAction SilentlyContinue).EnableDCOMHTTP
        $status.AllowLaunchActAsInteractiveUser = (Get-ItemProperty -Path $regPath -Name "AllowLaunchActAsInteractiveUser" -ErrorAction SilentlyContinue).AllowLaunchActAsInteractiveUser
        
        # Check authentication level
        $status.LegacyAuthenticationLevel = (Get-ItemProperty -Path $regPath -Name "LegacyAuthenticationLevel" -ErrorAction SilentlyContinue).LegacyAuthenticationLevel
        $status.DefaultAuthenticationLevel = (Get-ItemProperty -Path $regPath -Name "DefaultAuthenticationLevel" -ErrorAction SilentlyContinue).DefaultAuthenticationLevel
        
        # Check if DCOM is enabled
        $status.EnableDCOM = (Get-ItemProperty -Path $regPath -Name "EnableDCOM" -ErrorAction SilentlyContinue).EnableDCOM
    }
    catch {
        Write-Warning "Unable to check DCOM hardening status: $_"
    }
    
    return $status
}

function Generate-Recommendations {
    param(
        [array]$Results,
        [hashtable]$HardeningStatus
    )
    
    $recommendations = @()
    
    # Group by risk level
    $criticalIssues = $Results | Where-Object { $_.RiskLevel -eq "Critical" }
    $highIssues = $Results | Where-Object { $_.RiskLevel -eq "High" }
    
    if ($criticalIssues.Count -gt 0) {
        $recommendations += [PSCustomObject]@{
            Severity = "Critical"
            Issue = "Found $($criticalIssues.Count) DCOM objects with critical security risks"
            Recommendation = "Immediately restrict permissions on these objects. Remove 'Everyone' and 'Authenticated Users' from remote permissions."
            AffectedObjects = ($criticalIssues | Select-Object -ExpandProperty AppID -Unique)
        }
    }
    
    if ($highIssues.Count -gt 0) {
        $recommendations += [PSCustomObject]@{
            Severity = "High"
            Issue = "Found $($highIssues.Count) DCOM objects with high security risks"
            Recommendation = "Review and restrict permissions, especially remote access rights for non-administrative users."
            AffectedObjects = ($highIssues | Select-Object -ExpandProperty AppID -Unique)
        }
    }
    
    # Check hardening status
    if ($HardeningStatus.EnableDCOMHTTP -eq 1) {
        $recommendations += [PSCustomObject]@{
            Severity = "High"
            Issue = "DCOM HTTP is enabled"
            Recommendation = "Disable DCOM HTTP by setting HKLM\SOFTWARE\Microsoft\Ole\EnableDCOMHTTP to 0"
        }
    }
    
    if ($HardeningStatus.DefaultAuthenticationLevel -lt 5) {
        $recommendations += [PSCustomObject]@{
            Severity = "Medium"
            Issue = "DCOM authentication level is below recommended (Packet Integrity)"
            Recommendation = "Set DefaultAuthenticationLevel to 5 (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or higher"
        }
    }
    
    # Check for dangerous methods
    $dangerousObjects = $global:VulnerableObjects | Where-Object { $_.HasDangerousMethods }
    if ($dangerousObjects.Count -gt 0) {
        $recommendations += [PSCustomObject]@{
            Severity = "High"
            Issue = "Found $($dangerousObjects.Count) DCOM objects exposing potentially dangerous methods"
            Recommendation = "Review access permissions for these objects and ensure only trusted users have access"
            AffectedObjects = $dangerousObjects.AppID
        }
    }
    
    return $recommendations
}

function Export-Results {
    param(
        [string]$OutputPath,
        [array]$Results,
        [array]$Recommendations,
        [hashtable]$HardeningStatus
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $OutputPath "DCOM_Audit_Report_$timestamp"
    
    # Create report directory
    New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
    
    # Export detailed results
    if ($ExportCSV) {
        $Results | Export-Csv -Path "$reportPath\DCOM_Permissions.csv" -NoTypeInformation
        $Recommendations | Export-Csv -Path "$reportPath\Recommendations.csv" -NoTypeInformation
        $global:VulnerableObjects | Export-Csv -Path "$reportPath\Vulnerable_Objects.csv" -NoTypeInformation
    }
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>DCOM Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .critical { background-color: #ff4444; color: white; }
        .high { background-color: #ff8844; }
        .medium { background-color: #ffaa44; }
        .low { background-color: #44ff44; }
        .summary { background-color: #e0e0e0; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .attack-scenario { background-color: #ffe0e0; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .code-example { background-color: #f0f0f0; padding: 5px; font-family: monospace; border-radius: 3px; }
        .dll-risk { background-color: #fff0e0; padding: 5px; margin: 5px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>DCOM Security Audit Report - Enhanced</h1>
    <p>Generated on: $(Get-Date)</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total DCOM Objects Analyzed: $($Results | Select-Object -ExpandProperty AppID -Unique | Measure-Object).Count</p>
        <p>Critical Issues: $($Results | Where-Object { $_.RiskLevel -eq "Critical" } | Measure-Object).Count</p>
        <p>High Risk Issues: $($Results | Where-Object { $_.RiskLevel -eq "High" } | Measure-Object).Count</p>
        <p>Objects with Dangerous Methods: $($global:VulnerableObjects | Where-Object { $_.HasDangerousMethods } | Measure-Object).Count</p>
        <p>DLL Hijacking Risks: $($global:DLLRisks | Measure-Object).Count</p>
        <p>Service Permission Issues: $($global:ServiceRisks | Measure-Object).Count</p>
    </div>
    
    <h2>Known Attack Vectors Detected</h2>
    <div class="attack-scenario">
"@
    
    # Add known exploitable DCOMs found
    foreach ($vuln in $global:VulnerableObjects) {
        if ($KnownExploitableDCOM.ContainsKey($vuln.AppID)) {
            $exploit = $KnownExploitableDCOM[$vuln.AppID]
            $htmlReport += @"
        <h3>$($exploit.Name) - $($vuln.AppID)</h3>
        <p><strong>Technique:</strong> $($exploit.Technique) (MITRE $($exploit.Mitre))</p>
        <p><strong>Risk:</strong> Critical - Known exploitation technique</p>
        <p><strong>Attack Example:</strong></p>
        <div class="code-example">$($exploit.Example)</div>
"@
        }
    }
    
    $htmlReport += @"
    </div>
    
    <h2>DCOM Hardening Status</h2>
    <table>
        <tr><th>Setting</th><th>Current Value</th><th>Recommended Value</th></tr>
        <tr><td>EnableDCOM</td><td>$($HardeningStatus.EnableDCOM)</td><td>1 (if DCOM is required)</td></tr>
        <tr><td>EnableDCOMHTTP</td><td>$($HardeningStatus.EnableDCOMHTTP)</td><td>0 (disabled)</td></tr>
        <tr><td>DefaultAuthenticationLevel</td><td>$($HardeningStatus.DefaultAuthenticationLevel)</td><td>5 or 6</td></tr>
    </table>
    
    <h2>DLL/Service Security Risks</h2>
"@
    
    # Add DLL hijacking risks
    if ($global:DLLRisks.Count -gt 0) {
        $htmlReport += "<h3>DLL Hijacking Opportunities</h3><ul>"
        foreach ($risk in $global:DLLRisks) {
            $htmlReport += "<li class='dll-risk'><strong>$($risk.Type):</strong> $($risk.Path)<br/>$($risk.Issue) - Writable by: $($risk.WritableBy)</li>"
        }
        $htmlReport += "</ul>"
    }
    
    # Add service risks
    if ($global:ServiceRisks.Count -gt 0) {
        $htmlReport += "<h3>Service Permission Vulnerabilities</h3><ul>"
        foreach ($risk in $global:ServiceRisks) {
            $htmlReport += "<li><strong>$($risk.ServiceName):</strong> Vulnerable to modification by $($risk.VulnerableUsers -join ', ')</li>"
        }
        $htmlReport += "</ul>"
    }
    
    $htmlReport += @"
    
    <h2>Top Recommendations</h2>
    <ol>
"@
    
    foreach ($rec in ($Recommendations | Sort-Object Severity)) {
        $htmlReport += "<li><strong>[$($rec.Severity)]</strong> $($rec.Issue)<br/>$($rec.Recommendation)</li>"
    }
    
    $htmlReport += @"
    </ol>
    
    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>AppID</th>
            <th>App Name</th>
            <th>Permission Type</th>
            <th>Principal</th>
            <th>Permissions</th>
            <th>Risk Level</th>
        </tr>
"@
    
    foreach ($result in ($Results | Sort-Object RiskLevel -Descending)) {
        $rowClass = switch ($result.RiskLevel) {
            "Critical" { "critical" }
            "High" { "high" }
            "Medium" { "medium" }
            "Low" { "low" }
            default { "" }
        }
        
        $htmlReport += @"
        <tr class="$rowClass">
            <td>$($result.AppID)</td>
            <td>$($result.AppName)</td>
            <td>$($result.PermissionType)</td>
            <td>$($result.Principal)</td>
            <td>$($result.Permissions)</td>
            <td>$($result.RiskLevel)</td>
        </tr>
"@
    }
    
    $htmlReport += @"
    </table>
</body>
</html>
"@
    
    $htmlReport | Out-File -FilePath "$reportPath\DCOM_Audit_Report.html" -Encoding UTF8
    
    Write-ColorOutput "`nReport saved to: $reportPath" -Color Green
}

# Main execution
function Start-DCOMAudit {
    Write-ColorOutput @"
╔═══════════════════════════════════╗
║     DCOM Security Auditor v2.0    ║
║     Enhanced Edition              ║
╚═══════════════════════════════════╝
"@ -Color Cyan
    
    Write-ColorOutput "`nInitializing DCOM audit..." -Color Yellow
    
    # Create PSDrive for HKCR if not exists
    if (-not (Test-Path "HKCR:")) {
        New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR -Scope Script | Out-Null
    }
    
    # Get all DCOM AppIDs
    Write-ColorOutput "Enumerating DCOM objects..." -Color Yellow
    $appIDs = Get-ChildItem -Path "HKCR:\AppID" -ErrorAction SilentlyContinue | 
              Where-Object { $_.PSChildName -match '^{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}}$' }
    
    $totalObjects = $appIDs.Count
    Write-ColorOutput "Found $totalObjects DCOM objects to analyze`n" -Color Green
    
    # Check DCOM hardening status if requested
    $hardeningStatus = @{}
    if ($CheckMitigations) {
        Write-ColorOutput "Checking DCOM hardening status..." -Color Yellow
        $hardeningStatus = Get-DCOMHardeningStatus
    }
    
    # Process each AppID
    $counter = 0
    foreach ($appID in $appIDs) {
        $counter++
        $appIDString = $appID.PSChildName
        
        # Progress indicator
        if ($counter % 50 -eq 0) {
            Write-Progress -Activity "Auditing DCOM Objects" -Status "$counter of $totalObjects" -PercentComplete (($counter / $totalObjects) * 100)
        }
        
        # Get application info
        $appInfo = Get-DCOMApplicationInfo -AppID $appIDString
        
        # Check Launch and Access permissions
        foreach ($permType in @("Launch", "Access")) {
            $sd = Get-DCOMSecurityDescriptor -AppID $appIDString -PermissionType $permType
            $permResults = Analyze-DCOMPermissions -SecurityDescriptor $sd -PermissionType $permType -AppID $appIDString -AppInfo $appInfo
            
            foreach ($result in $permResults) {
                $global:DCOMResults += $result
                
                # Display high-risk findings immediately
                if ($result.IsVulnerable) {
                    $color = switch ($result.RiskLevel) {
                        "Critical" { "Red" }
                        "High" { "Magenta" }
                        "Medium" { "Yellow" }
                        default { "Gray" }
                    }
                    
                    Write-ColorOutput "[!] " -Color $color -NoNewLine
                    Write-ColorOutput "$($result.RiskLevel) Risk: " -Color $color -NoNewLine
                    Write-ColorOutput "$($result.Principal) has $($result.PermissionType) permissions " -NoNewLine
                    Write-ColorOutput "($($result.Permissions)) " -Color Cyan -NoNewLine
                    Write-ColorOutput "for $appIDString"
                    
                    if ($result.AppName) {
                        Write-ColorOutput "    Application: $($result.AppName)" -Color Gray
                    }
                }
            }
        }
        
        # Check for dangerous methods if audit mode is enabled
        if ($Audit -and -not $FastMode -and $appInfo.CLSIDs.Count -gt 0) {
            foreach ($clsid in $appInfo.CLSIDs) {
                $methodCheck = Test-DCOMObjectMethods -CLSID $clsid
                $interfaces = Test-DCOMInterfaces -CLSID $clsid
                
                if ($methodCheck.IsDangerous -or $interfaces.Count -gt 0) {
                    $vulnerableObj = [PSCustomObject]@{
                        AppID = $appIDString
                        CLSID = $clsid
                        AppName = $appInfo.Name
                        DangerousMethods = ($methodCheck.Methods | Where-Object { $DangerousMethods -contains $_ })
                        AllMethods = $methodCheck.Methods
                        Interfaces = $interfaces
                        HasDangerousMethods = $methodCheck.IsDangerous
                        DllPaths = $appInfo.DllPaths
                        ExePaths = $appInfo.ExePaths
                        LocalService = $appInfo.LocalService
                    }
                    
                    if ($methodCheck.IsDangerous) {
                        Write-ColorOutput "[!] WARNING: " -Color Red -NoNewLine
                        Write-ColorOutput "Dangerous methods found in $clsid" -Color Yellow
                        Write-ColorOutput "    Methods: $($vulnerableObj.DangerousMethods -join ', ')" -Color Gray
                    }
                    
                    $global:VulnerableObjects += $vulnerableObj
                }
            }
        }
        
        # Check for attack scenarios
        $attackScenarios = Get-AttackScenario -AppID $appIDString -AppInfo $appInfo -Permissions $global:DCOMResults -Methods $methodCheck.Methods
        
        if ($attackScenarios.Count -gt 0) {
            Write-ColorOutput "`n[ATTACK VECTOR] " -Color Red -NoNewLine
            Write-ColorOutput "Potential attack scenarios for $appIDString :" -Color Yellow
            foreach ($scenario in $attackScenarios) {
                Write-ColorOutput "  → $($scenario.Technique) [$($scenario.MitreID)]" -Color Magenta
                Write-ColorOutput "    $($scenario.Description)" -Color Gray
                if ($VerbosePreference -eq 'Continue') {
                    Write-ColorOutput "    Example: $($scenario.Example)" -Color DarkGray
                }
                $global:AttackScenarios += $scenario
            }
        }
        
        # Check DLL permissions
        if ($appInfo.DllPaths.Count -gt 0) {
            foreach ($dllPath in $appInfo.DllPaths) {
                $dllRisks = Get-DLLHijackingRisk -DllPath $dllPath
                foreach ($risk in $dllRisks) {
                    Write-ColorOutput "[DLL RISK] " -Color Red -NoNewLine
                    Write-ColorOutput "$($risk.Type) - $($risk.Path)" -Color Yellow
                    Write-ColorOutput "    Issue: $($risk.Issue)" -Color Gray
                    Write-ColorOutput "    Writable by: $($risk.WritableBy)" -Color Gray
                    $risk | Add-Member -NotePropertyName AppID -NotePropertyValue $appIDString
                    $global:DLLRisks += $risk
                }
            }
        }
        
        # Check service permissions
        if ($appInfo.LocalService) {
            $servicePerms = Get-ServicePermissions -ServiceName $appInfo.LocalService
            if ($servicePerms -and $servicePerms.VulnerableUsers.Count -gt 0) {
                Write-ColorOutput "[SERVICE RISK] " -Color Red -NoNewLine
                Write-ColorOutput "Weak permissions on service: $($appInfo.LocalService)" -Color Yellow
                Write-ColorOutput "    Vulnerable to: $($servicePerms.VulnerableUsers -join ', ')" -Color Gray
                Write-ColorOutput "    Executable: $($servicePerms.ExecutablePath)" -Color Gray
                $servicePerms | Add-Member -NotePropertyName AppID -NotePropertyValue $appIDString
                $global:ServiceRisks += $servicePerms
            }
        }
    }
    
    Write-Progress -Activity "Auditing DCOM Objects" -Completed
    
    # Generate recommendations
    Write-ColorOutput "`nGenerating security recommendations..." -Color Yellow
    $recommendations = Generate-Recommendations -Results $global:DCOMResults -HardeningStatus $hardeningStatus
    
    # Display summary
    Write-ColorOutput "`n═══════════════════════════════════════════════════════" -Color Cyan
    Write-ColorOutput "                    AUDIT SUMMARY                       " -Color Cyan
    Write-ColorOutput "═══════════════════════════════════════════════════════" -Color Cyan
    
    $criticalCount = ($global:DCOMResults | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = ($global:DCOMResults | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumCount = ($global:DCOMResults | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    
    Write-ColorOutput "Total Objects Analyzed: $totalObjects" -Color White
    Write-ColorOutput "Critical Risk Issues: $criticalCount" -Color Red
    Write-ColorOutput "High Risk Issues: $highCount" -Color Magenta
    Write-ColorOutput "Medium Risk Issues: $mediumCount" -Color Yellow
    Write-ColorOutput "Objects with Dangerous Methods: $($global:VulnerableObjects.Count)" -Color Red
    Write-ColorOutput "DLL Hijacking Risks: $($global:DLLRisks.Count)" -Color Red
    Write-ColorOutput "Service Permission Issues: $($global:ServiceRisks.Count)" -Color Red
    Write-ColorOutput "Attack Scenarios Identified: $($global:AttackScenarios.Count)" -Color Magenta
    
    # Display top recommendations
    if ($recommendations.Count -gt 0) {
        Write-ColorOutput "`n═══════════════════════════════════════════════════════" -Color Cyan
        Write-ColorOutput "                TOP RECOMMENDATIONS                     " -Color Cyan
        Write-ColorOutput "═══════════════════════════════════════════════════════" -Color Cyan
        
        foreach ($rec in ($recommendations | Select-Object -First 5)) {
            $color = switch ($rec.Severity) {
                "Critical" { "Red" }
                "High" { "Magenta" }
                "Medium" { "Yellow" }
                default { "White" }
            }
            
            Write-ColorOutput "`n[$($rec.Severity)]" -Color $color -NoNewLine
            Write-ColorOutput " $($rec.Issue)" -Color White
            Write-ColorOutput "Recommendation: $($rec.Recommendation)" -Color Gray
        }
    }
    
    # Export results
    Export-Results -OutputPath $OutputPath -Results $global:DCOMResults -Recommendations $recommendations -HardeningStatus $hardeningStatus
    
    Write-ColorOutput "`nAudit completed successfully!" -Color Green
}

# Run the audit
Start-DCOMAudit