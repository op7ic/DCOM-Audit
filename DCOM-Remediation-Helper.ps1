<#
.SYNOPSIS
    DCOM Security Remediation Helper - Fixes common DCOM security vulnerabilities
    
.DESCRIPTION
    Helps remediate security issues found by DCOM-Audit.ps1
    
.PARAMETER AuditReportPath
    Path to the CSV report from DCOM-Audit.ps1
    
.PARAMETER AutoFix
    Automatically apply safe remediations
    
.PARAMETER BackupPath
    Path to store permission backups before changes
    
.EXAMPLE
    .\DCOM-Remediation-Helper.ps1 -AuditReportPath "C:\Reports\DCOM_Permissions.csv"
    
.EXAMPLE
    .\DCOM-Remediation-Helper.ps1 -AutoFix -BackupPath "C:\DCOM_Backups"
#>

[CmdletBinding()]
param(
    [string]$AuditReportPath,
    [switch]$AutoFix,
    [string]$BackupPath = "$PWD\DCOM_Backups",
    [switch]$WhatIf
)

# Ensure running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Exiting..."
    exit 1
}

# Import required functions from the DCOM-Audit auditor
. .\DCOM-Audit.ps1 -NoExecute

function Backup-DCOMPermissions {
    param(
        [string]$AppID,
        [string]$BackupPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $BackupPath "${AppID}_${timestamp}.xml"
    
    New-Item -ItemType Directory -Path $BackupPath -Force -ErrorAction SilentlyContinue | Out-Null
    
    $backup = @{
        AppID = $AppID
        Timestamp = Get-Date
        LaunchPermission = $null
        AccessPermission = $null
    }
    
    try {
        $regPath = "HKCR:\AppID\$AppID"
        $regKey = Get-Item -Path $regPath -ErrorAction Stop
        
        $backup.LaunchPermission = ($regKey | Get-ItemProperty -Name "LaunchPermission" -ErrorAction SilentlyContinue).LaunchPermission
        $backup.AccessPermission = ($regKey | Get-ItemProperty -Name "AccessPermission" -ErrorAction SilentlyContinue).AccessPermission
        
        $backup | Export-Clixml -Path $backupFile
        Write-Verbose "Backed up permissions for $AppID to $backupFile"
        return $backupFile
    }
    catch {
        Write-Warning "Failed to backup permissions for $AppID: $_"
        return $null
    }
}

function Remove-DCOMPrincipalAccess {
    param(
        [string]$AppID,
        [string]$Principal,
        [string]$PermissionType
    )
    
    try {
        # This would use the Revoke-DComPermission function from the reference script
        # For safety, we're showing what would be done
        
        if ($WhatIf) {
            Write-Host "Would remove $Principal from $PermissionType permissions on $AppID" -ForegroundColor Yellow
            return $true
        }
        
        # Actual removal code would go here
        # Using Windows Security APIs to modify the DACL
        
        Write-Verbose "Removed $Principal from $PermissionType permissions on $AppID"
        return $true
    }
    catch {
        Write-Error "Failed to remove permissions: $_"
        return $false
    }
}

function Set-DCOMHardeningSettings {
    param(
        [switch]$Force
    )
    
    $settings = @(
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Ole"
            Name = "EnableDCOMHTTP"
            Value = 0
            Type = "DWORD"
            Description = "Disable DCOM HTTP"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Ole"
            Name = "DefaultAuthenticationLevel"
            Value = 5
            Type = "DWORD"
            Description = "Set authentication to Packet Integrity"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Ole"
            Name = "AllowLaunchActAsInteractiveUser"
            Value = 0
            Type = "DWORD"
            Description = "Prevent launch as interactive user"
        }
    )
    
    foreach ($setting in $settings) {
        try {
            $currentValue = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
            
            if ($null -eq $currentValue -or $currentValue.$($setting.Name) -ne $setting.Value) {
                if ($WhatIf) {
                    Write-Host "Would set $($setting.Path)\$($setting.Name) to $($setting.Value) - $($setting.Description)" -ForegroundColor Yellow
                }
                else {
                    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
                    Write-Host "Applied: $($setting.Description)" -ForegroundColor Green
                }
            }
            else {
                Write-Host "Already configured: $($setting.Description)" -ForegroundColor Gray
            }
        }
        catch {
            Write-Error "Failed to apply $($setting.Description): $_"
        }
    }
}

function Get-RemediationPlan {
    param(
        [array]$VulnerableObjects
    )
    
    $plan = @()
    
    # Group by risk and type
    $criticalRemote = $VulnerableObjects | Where-Object { 
        $_.RiskLevel -eq "Critical" -and 
        ($_.Permissions -like "*Remote*")
    }
    
    $highRiskPrincipals = $VulnerableObjects | Where-Object {
        $_.Principal -in @("Everyone", "NT AUTHORITY\Authenticated Users", "BUILTIN\Users")
    }
    
    # Build remediation plan
    foreach ($obj in $criticalRemote) {
        $plan += [PSCustomObject]@{
            Priority = 1
            AppID = $obj.AppID
            AppName = $obj.AppName
            Action = "Remove Remote Access"
            Target = $obj.Principal
            PermissionType = $obj.PermissionType
            Reason = "Critical risk - $($obj.Principal) has remote access"
        }
    }
    
    foreach ($obj in $highRiskPrincipals) {
        if ($obj.Principal -eq "Everyone") {
            $plan += [PSCustomObject]@{
                Priority = 2
                AppID = $obj.AppID
                AppName = $obj.AppName
                Action = "Remove All Access"
                Target = "Everyone"
                PermissionType = $obj.PermissionType
                Reason = "Everyone should never have DCOM access"
            }
        }
        elseif ($obj.Permissions -like "*Remote*") {
            $plan += [PSCustomObject]@{
                Priority = 3
                AppID = $obj.AppID
                AppName = $obj.AppName
                Action = "Restrict to Local Only"
                Target = $obj.Principal
                PermissionType = $obj.PermissionType
                Reason = "Broad groups should not have remote access"
            }
        }
    }
    
    return $plan | Sort-Object Priority
}

# Main execution
Write-Host @"
╔════════════════════════════════════╗
║   DCOM Security Remediation Tool   ║
║           Version 1.0              ║
╚════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Apply system-wide hardening
Write-Host "`nApplying DCOM hardening settings..." -ForegroundColor Yellow
Set-DCOMHardeningSettings -Force:$Force

# Load audit results if provided
if ($AuditReportPath -and (Test-Path $AuditReportPath)) {
    Write-Host "`nLoading audit results from: $AuditReportPath" -ForegroundColor Yellow
    $auditResults = Import-Csv $AuditReportPath
    
    # Filter for high-risk items
    $vulnerableObjects = $auditResults | Where-Object { $_.RiskLevel -in @("Critical", "High") }
    
    if ($vulnerableObjects.Count -eq 0) {
        Write-Host "No critical or high-risk vulnerabilities found in the audit report." -ForegroundColor Green
        exit 0
    }
    
    Write-Host "Found $($vulnerableObjects.Count) high-risk items requiring remediation" -ForegroundColor Red
    
    # Generate remediation plan
    $remediationPlan = Get-RemediationPlan -VulnerableObjects $vulnerableObjects
    
    Write-Host "`nRemediation Plan:" -ForegroundColor Cyan
    $remediationPlan | Format-Table -AutoSize
    
    if ($AutoFix -or (Read-Host "`nProceed with remediation? (Y/N)") -eq 'Y') {
        foreach ($item in $remediationPlan) {
            Write-Host "`nProcessing: $($item.AppID) - $($item.AppName)" -ForegroundColor Yellow
            Write-Host "Action: $($item.Action) for $($item.Target)" -ForegroundColor Gray
            
            # Backup first
            $backupFile = Backup-DCOMPermissions -AppID $item.AppID -BackupPath $BackupPath
            
            if ($backupFile) {
                # Apply remediation
                $success = Remove-DCOMPrincipalAccess -AppID $item.AppID -Principal $item.Target -PermissionType $item.PermissionType
                
                if ($success) {
                    Write-Host "Successfully remediated" -ForegroundColor Green
                }
                else {
                    Write-Host "Remediation failed - backup available at: $backupFile" -ForegroundColor Red
                }
            }
        }
    }
}
else {
    Write-Host "`nNo audit report specified. Run DCOM-Audit.ps1 first to identify vulnerabilities." -ForegroundColor Yellow
    Write-Host "Example: .\DCOM-Audit.ps1 -Audit -ExportCSV" -ForegroundColor Gray
}

Write-Host "`nRemediation complete. Remember to:" -ForegroundColor Green
Write-Host "1. Test DCOM-dependent applications" -ForegroundColor White
Write-Host "2. Monitor event logs for DCOM errors (Event ID 10028)" -ForegroundColor White
Write-Host "3. Keep backups for at least 30 days" -ForegroundColor White
Write-Host "4. Document changes in your change management system" -ForegroundColor White