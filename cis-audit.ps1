<#
.SYNOPSIS
    Audits Windows Server 2022 against CIS Benchmark controls.

.DESCRIPTION
    This script checks Windows Server 2022 configuration against selected CIS Benchmark
    recommendations. It examines security policies, registry settings, user rights,
    and services configuration.

.PARAMETER ReportPath
    Path where the HTML report will be saved. Default: C:\CIS_Audit_Report.html

.PARAMETER ExportCSV
    Optional path to export results as CSV.

.EXAMPLE
    .\CIS-Audit.ps1
    
.EXAMPLE
    .\CIS-Audit.ps1 -ReportPath "C:\Reports\CIS_Audit.html" -ExportCSV "C:\Reports\CIS_Audit.csv"

.NOTES
    Requires Administrator privileges.
    Based on CIS Microsoft Windows Server 2022 Benchmark v2.0.0
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = "C:\CIS_Audit_Report.html",
    
    [Parameter(Mandatory=$false)]
    [string]$ExportCSV = ""
)

# Requires Administrator
#Requires -RunAsAdministrator

$results = @()
$passCount = 0
$failCount = 0
$manualCount = 0

function Add-AuditResult {
    param(
        [string]$Section,
        [string]$Control,
        [string]$Description,
        [string]$Status,  # Pass, Fail, Manual
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$Severity  # Critical, High, Medium, Low
    )
    
    $script:results += [PSCustomObject]@{
        Section = $Section
        Control = $Control
        Description = $Description
        Status = $Status
        CurrentValue = $CurrentValue
        ExpectedValue = $ExpectedValue
        Severity = $Severity
    }
    
    switch ($Status) {
        "Pass" { $script:passCount++ }
        "Fail" { $script:failCount++ }
        "Manual" { $script:manualCount++ }
    }
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            return $value.$Name
        }
        return $null
    } catch {
        return $null
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue,
        [string]$Comparison = "eq"  # eq, ne, ge, le, gt, lt
    )
    
    $currentValue = Get-RegistryValue -Path $Path -Name $Name
    
    if ($null -eq $currentValue) {
        return $false
    }
    
    switch ($Comparison) {
        "eq" { return $currentValue -eq $ExpectedValue }
        "ne" { return $currentValue -ne $ExpectedValue }
        "ge" { return $currentValue -ge $ExpectedValue }
        "le" { return $currentValue -le $ExpectedValue }
        "gt" { return $currentValue -gt $ExpectedValue }
        "lt" { return $currentValue -lt $ExpectedValue }
        default { return $false }
    }
}

function Get-SecurityPolicy {
    param([string]$PolicyName)
    
    $tempFile = [System.IO.Path]::GetTempFileName()
    secedit /export /cfg $tempFile /quiet | Out-Null
    
    $content = Get-Content $tempFile
    Remove-Item $tempFile -Force
    
    $value = $content | Where-Object { $_ -match "^$PolicyName\s*=" } | ForEach-Object {
        $_ -replace "^$PolicyName\s*=\s*", ""
    }
    
    return $value
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CIS Benchmark Audit - Windows Server 2022" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ====================
# Section 1: Account Policies
# ====================
Write-Host "[1/10] Checking Account Policies..." -ForegroundColor Yellow

# 1.1.1 Password Policy - Enforce password history
$secpol = Get-SecurityPolicy -PolicyName "PasswordHistorySize"
$status = if ($secpol -ge 24) { "Pass" } else { "Fail" }
Add-AuditResult -Section "1.1 Password Policy" -Control "1.1.1" `
    -Description "Ensure 'Enforce password history' is set to '24 or more password(s)'" `
    -Status $status -CurrentValue $secpol -ExpectedValue "24 or more" -Severity "High"

# 1.1.2 Maximum password age
$secpol = Get-SecurityPolicy -PolicyName "MaximumPasswordAge"
$status = if ($secpol -le 365 -and $secpol -ge 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "1.1 Password Policy" -Control "1.1.2" `
    -Description "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'" `
    -Status $status -CurrentValue $secpol -ExpectedValue "1-365 days" -Severity "High"

# 1.1.3 Minimum password age
$secpol = Get-SecurityPolicy -PolicyName "MinimumPasswordAge"
$status = if ($secpol -ge 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "1.1 Password Policy" -Control "1.1.3" `
    -Description "Ensure 'Minimum password age' is set to '1 or more day(s)'" `
    -Status $status -CurrentValue $secpol -ExpectedValue "1 or more" -Severity "Medium"

# 1.1.4 Minimum password length
$secpol = Get-SecurityPolicy -PolicyName "MinimumPasswordLength"
$status = if ($secpol -ge 14) { "Pass" } else { "Fail" }
Add-AuditResult -Section "1.1 Password Policy" -Control "1.1.4" `
    -Description "Ensure 'Minimum password length' is set to '14 or more character(s)'" `
    -Status $status -CurrentValue $secpol -ExpectedValue "14 or more" -Severity "Critical"

# 1.1.5 Password must meet complexity requirements
$secpol = Get-SecurityPolicy -PolicyName "PasswordComplexity"
$status = if ($secpol -eq "1") { "Pass" } else { "Fail" }
Add-AuditResult -Section "1.1 Password Policy" -Control "1.1.5" `
    -Description "Ensure 'Password must meet complexity requirements' is set to 'Enabled'" `
    -Status $status -CurrentValue $(if($secpol -eq "1"){"Enabled"}else{"Disabled"}) `
    -ExpectedValue "Enabled" -Severity "Critical"

# 1.2.1 Account lockout duration
$secpol = Get-SecurityPolicy -PolicyName "LockoutDuration"
$status = if ($secpol -ge 15) { "Pass" } else { "Fail" }
Add-AuditResult -Section "1.2 Account Lockout Policy" -Control "1.2.1" `
    -Description "Ensure 'Account lockout duration' is set to '15 or more minute(s)'" `
    -Status $status -CurrentValue $secpol -ExpectedValue "15 or more" -Severity "Medium"

# 1.2.2 Account lockout threshold
$secpol = Get-SecurityPolicy -PolicyName "LockoutBadCount"
$status = if ($secpol -le 5 -and $secpol -ge 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "1.2 Account Lockout Policy" -Control "1.2.2" `
    -Description "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s)'" `
    -Status $status -CurrentValue $secpol -ExpectedValue "1-5 attempts" -Severity "High"

# ====================
# Section 2: Local Policies - Security Options
# ====================
Write-Host "[2/10] Checking Local Policies - Security Options..." -ForegroundColor Yellow

# 2.3.1.1 Accounts: Administrator account status
$adminDisabled = (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Enabled
$status = if ($adminDisabled -eq $false) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.1 Accounts" -Control "2.3.1.1" `
    -Description "Ensure 'Accounts: Administrator account status' is set to 'Disabled'" `
    -Status $status -CurrentValue $(if($adminDisabled){"Enabled"}else{"Disabled"}) `
    -ExpectedValue "Disabled" -Severity "High"

# 2.3.1.5 Accounts: Rename administrator account
Add-AuditResult -Section "2.3.1 Accounts" -Control "2.3.1.5" `
    -Description "Ensure 'Accounts: Rename administrator account' (Manual Check)" `
    -Status "Manual" -CurrentValue "Check manually" -ExpectedValue "Not 'Administrator'" -Severity "Medium"

# 2.3.6.1 Domain member: Digitally encrypt or sign secure channel data (always)
$regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal"
$status = if ($regValue -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.6 Domain Member" -Control "2.3.6.1" `
    -Description "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "1 (Enabled)" -Severity "High"

# 2.3.7.1 Interactive logon: Do not require CTRL+ALT+DEL
$regValue = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD"
$status = if ($regValue -eq 0) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.7 Interactive Logon" -Control "2.3.7.1" `
    -Description "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "0 (Disabled)" -Severity "Medium"

# 2.3.7.4 Interactive logon: Machine inactivity limit
$regValue = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs"
$status = if ($regValue -le 900 -and $regValue -gt 0) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.7 Interactive Logon" -Control "2.3.7.4" `
    -Description "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s)'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "900 or less" -Severity "Medium"

# 2.3.10.1 Network access: Do not allow anonymous enumeration of SAM accounts
$regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM"
$status = if ($regValue -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.10 Network Access" -Control "2.3.10.1" `
    -Description "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "1 (Enabled)" -Severity "High"

# 2.3.10.2 Network access: Do not allow anonymous enumeration of SAM accounts and shares
$regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous"
$status = if ($regValue -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.10 Network Access" -Control "2.3.10.2" `
    -Description "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "1 (Enabled)" -Severity "High"

# 2.3.11.3 Network security: Do not store LAN Manager hash value on next password change
$regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash"
$status = if ($regValue -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.11 Network Security" -Control "2.3.11.3" `
    -Description "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "1 (Enabled)" -Severity "Critical"

# 2.3.11.5 Network security: LAN Manager authentication level
$regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
$status = if ($regValue -eq 5) { "Pass" } else { "Fail" }
Add-AuditResult -Section "2.3.11 Network Security" -Control "2.3.11.5" `
    -Description "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "5" -Severity "Critical"

# ====================
# Section 5: System Services
# ====================
Write-Host "[3/10] Checking System Services..." -ForegroundColor Yellow

$servicesToCheck = @{
    "RemoteRegistry" = @{ Expected = "Disabled"; Severity = "High"; Description = "Remote Registry" }
    "SSDPSRV" = @{ Expected = "Disabled"; Severity = "Medium"; Description = "SSDP Discovery" }
    "WMPNetworkSvc" = @{ Expected = "Disabled"; Severity = "Low"; Description = "Windows Media Player Network Sharing Service" }
    "RemoteAccess" = @{ Expected = "Disabled"; Severity = "Medium"; Description = "Routing and Remote Access" }
}

foreach ($serviceName in $servicesToCheck.Keys) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        $startType = (Get-Service -Name $serviceName).StartType
        $status = if ($startType -eq "Disabled") { "Pass" } else { "Fail" }
        Add-AuditResult -Section "5.0 System Services" -Control "5.x" `
            -Description "Ensure '$($servicesToCheck[$serviceName].Description)' is set to 'Disabled'" `
            -Status $status -CurrentValue $startType -ExpectedValue "Disabled" `
            -Severity $servicesToCheck[$serviceName].Severity
    }
}

# ====================
# Section 9: Windows Firewall
# ====================
Write-Host "[4/10] Checking Windows Firewall..." -ForegroundColor Yellow

$firewallProfiles = @("Domain", "Private", "Public")
foreach ($profile in $firewallProfiles) {
    $fwProfile = Get-NetFirewallProfile -Name $profile
    
    # Firewall state
    $status = if ($fwProfile.Enabled -eq $true) { "Pass" } else { "Fail" }
    Add-AuditResult -Section "9.1 Windows Firewall" -Control "9.1.x" `
        -Description "Ensure Windows Firewall: $profile: Firewall state is set to 'On'" `
        -Status $status -CurrentValue $fwProfile.Enabled -ExpectedValue "True" -Severity "Critical"
    
    # Inbound connections
    $status = if ($fwProfile.DefaultInboundAction -eq "Block") { "Pass" } else { "Fail" }
    Add-AuditResult -Section "9.1 Windows Firewall" -Control "9.1.x" `
        -Description "Ensure Windows Firewall: $profile: Inbound connections is set to 'Block'" `
        -Status $status -CurrentValue $fwProfile.DefaultInboundAction -ExpectedValue "Block" -Severity "High"
}

# ====================
# Section 17: Advanced Audit Policy
# ====================
Write-Host "[5/10] Checking Advanced Audit Policy..." -ForegroundColor Yellow

Add-AuditResult -Section "17.0 Advanced Audit Policy" -Control "17.x" `
    -Description "Advanced Audit Policy Configuration (Manual Check Required)" `
    -Status "Manual" -CurrentValue "Use auditpol /get /category:*" -ExpectedValue "See CIS Benchmark" -Severity "High"

# ====================
# Section 18: Administrative Templates - Computer
# ====================
Write-Host "[6/10] Checking Administrative Templates..." -ForegroundColor Yellow

# 18.1.1.1 Prevent enabling lock screen camera
$regValue = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera"
$status = if ($regValue -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "18.1 Control Panel" -Control "18.1.1.1" `
    -Description "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "1 (Enabled)" -Severity "Medium"

# 18.3.1 Apply UAC restrictions to local accounts on network logons
$regValue = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy"
$status = if ($regValue -eq 0 -or $null -eq $regValue) { "Pass" } else { "Fail" }
Add-AuditResult -Section "18.3 MS Network Client" -Control "18.3.1" `
    -Description "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "0 or not defined" -Severity "High"

# 18.4.1 MSS: (DisableIPSourceRouting) IP source routing protection level
$regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting"
$status = if ($regValue -eq 2) { "Pass" } else { "Fail" }
Add-AuditResult -Section "18.4 MSS (Legacy)" -Control "18.4.1" `
    -Description "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Highest protection'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "2" -Severity "Medium"

# 18.5.4.1 NetBIOS node type
$regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType"
$status = if ($regValue -eq 2) { "Pass" } else { "Fail" }
Add-AuditResult -Section "18.5 Network" -Control "18.5.4.1" `
    -Description "Ensure 'NetBIOS node type' is set to 'P-node'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "2 (P-node)" -Severity "Low"

# 18.9.6.1 Allow Windows Ink Workspace
$regValue = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace"
$status = if ($regValue -eq 0 -or $regValue -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "18.9 Windows Components" -Control "18.9.6.1" `
    -Description "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "0 or 1" -Severity "Low"

# 18.9.8.1 Turn off Help Experience Improvement Program
$regValue = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback"
$status = if ($regValue -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "18.9 Windows Components" -Control "18.9.8.1" `
    -Description "Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'" `
    -Status $status -CurrentValue $regValue -ExpectedValue "1 (Enabled)" -Severity "Low"

# ====================
# Section 19: Administrative Templates - User
# ====================
Write-Host "[7/10] Checking User Administrative Templates..." -ForegroundColor Yellow

# 19.7.4.1 Do not preserve zone information
$regValue = Get-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation"
Add-AuditResult -Section "19.7 Attachment Manager" -Control "19.7.4.1" `
    -Description "Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'" `
    -Status "Manual" -CurrentValue "Check per-user" -ExpectedValue "2 (Disabled)" -Severity "Low"

# ====================
# Additional Security Checks
# ====================
Write-Host "[8/10] Checking Additional Security Settings..." -ForegroundColor Yellow

# Check Windows Update
$wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
$status = if ($wuService.Status -eq "Running" -or $wuService.StartType -ne "Disabled") { "Pass" } else { "Fail" }
Add-AuditResult -Section "Additional Checks" -Control "AC.1" `
    -Description "Ensure Windows Update service is not disabled" `
    -Status $status -CurrentValue $wuService.StartType -ExpectedValue "Not Disabled" -Severity "Critical"

# Check Windows Defender
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defenderStatus) {
    $status = if ($defenderStatus.RealTimeProtectionEnabled) { "Pass" } else { "Fail" }
    Add-AuditResult -Section "Additional Checks" -Control "AC.2" `
        -Description "Ensure Windows Defender Real-time protection is enabled" `
        -Status $status -CurrentValue $defenderStatus.RealTimeProtectionEnabled `
        -ExpectedValue "True" -Severity "Critical"
}

# Check BitLocker (if available)
$bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
if ($bitlockerVolumes) {
    $osVolume = $bitlockerVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" }
    if ($osVolume) {
        $status = if ($osVolume.ProtectionStatus -eq "On") { "Pass" } else { "Fail" }
        Add-AuditResult -Section "Additional Checks" -Control "AC.3" `
            -Description "Ensure BitLocker is enabled on OS drive" `
            -Status $status -CurrentValue $osVolume.ProtectionStatus `
            -ExpectedValue "On" -Severity "High"
    }
}

# Check SMBv1
$smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($smbv1) {
    $status = if ($smbv1.State -eq "Disabled") { "Pass" } else { "Fail" }
    Add-AuditResult -Section "Additional Checks" -Control "AC.4" `
        -Description "Ensure SMBv1 is disabled" `
        -Status $status -CurrentValue $smbv1.State -ExpectedValue "Disabled" -Severity "Critical"
}

# Check RDP Status
$rdpEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
$status = if ($rdpEnabled -eq 1) { "Pass" } else { "Manual" }
Add-AuditResult -Section "Additional Checks" -Control "AC.5" `
    -Description "Remote Desktop is disabled (if not required)" `
    -Status $status -CurrentValue $(if($rdpEnabled -eq 1){"Disabled"}else{"Enabled"}) `
    -ExpectedValue "Disabled (if not needed)" -Severity "High"

# Check PowerShell logging
$psTranscription = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting"
$status = if ($psTranscription -eq 1) { "Pass" } else { "Fail" }
Add-AuditResult -Section "Additional Checks" -Control "AC.6" `
    -Description "Ensure PowerShell transcription is enabled" `
    -Status $status -CurrentValue $psTranscription -ExpectedValue "1 (Enabled)" -Severity "Medium"

Write-Host "[9/10] Generating Report..." -ForegroundColor Yellow

# ====================
# Generate HTML Report
# ====================
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Benchmark Audit Report - Windows Server 2022</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { display: flex; justify-content: space-around; margin: 30px 0; }
        .summary-box { padding: 20px; border-radius: 8px; text-align: center; min-width: 150px; }
        .summary-box h3 { margin: 0; font-size: 36px; }
        .summary-box p { margin: 5px 0 0 0; color: #7f8c8d; }
        .pass { background-color: #d4edda; color: #155724; }
        .fail { background-color: #f8d7da; color: #721c24; }
        .manual { background-color: #fff3cd; color: #856404; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background-color: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .status { padding: 5px 10px; border-radius: 4px; display: inline-block; font-weight: bold; }
        .status-pass { background-color: #d4edda; color: #155724; }
        .status-fail { background-color: #f8d7da; color: #721c24; }
        .status-manual { background-color: #fff3cd; color: #856404; }
        .severity { padding: 5px 10px; border-radius: 4px; display: inline-block; }
        .sev-critical { background-color: #dc3545; color: white; }
        .sev-high { background-color: #fd7e14; color: white; }
        .sev-medium { background-color: #ffc107; color: black; }
        .sev-low { background-color: #17a2b8; color: white; }
        .metadata { color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CIS Benchmark Audit Report</h1>
        <div class="metadata">
            <strong>Server:</strong> $env:COMPUTERNAME<br>
            <strong>Report Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>OS Version:</strong> $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)<br>
            <strong>Auditor:</strong> $env:USERNAME
        </div>
        
        <h2>📊 Summary</h2>
        <div class="summary">
            <div class="summary-box pass">
                <h3>$passCount</h3>
                <p>Passed</p>
            </div>
            <div class="summary-box fail">
                <h3>$failCount</h3>
                <p>Failed</p>
            </div>
            <div class="summary-box manual">
                <h3>$manualCount</h3>
                <p>Manual Review</p>
            </div>
            <div class="summary-box" style="background-color: #e8f4f8;">
                <h3>$($results.Count)</h3>
                <p>Total Checks</p>
            </div>
        </div>
        
        <h2>📋 Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Control</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Current Value</th>
                    <th>Expected Value</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
"@

foreach ($result in $results | Sort-Object Section, Control) {
    $statusClass = switch ($result.Status) {
        "Pass" { "status-pass" }
        "Fail" { "status-fail" }
        "Manual" { "status-manual" }
    }
    
    $severityClass = switch ($result.Severity) {
        "Critical" { "sev-critical" }
        "High" { "sev-high" }
        "Medium" { "sev-medium" }
        "Low" { "sev-low" }
    }
    
    $htmlReport += @"
                <tr>
                    <td><strong>$($result.Control)</strong><br><small style="color: #7f8c8d;">$($result.Section)</small></td>
                    <td>$($result.Description)</td>
                    <td><span class="status $statusClass">$($result.Status)</span></td>
                    <td>$($result.CurrentValue)</td>
                    <td>$($result.ExpectedValue)</td>
                    <td><span class="severity $severityClass">$($result.Severity)</span></td>
                </tr>
"@
}

$htmlReport += @"
            </tbody>
        </table>
        
        <h2>🔍 Recommendations</h2>
        <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin-top: 20px;">
            <h3 style="margin-top: 0;">Critical Actions Required:</h3>
            <ul>
"@

$criticalFailures = $results | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }
if ($criticalFailures) {
    foreach ($failure in $criticalFailures) {
        $htmlReport += "                <li><strong>$($failure.Control):</strong> $($failure.Description)</li>`n"
    }
} else {
    $htmlReport += "                <li>No critical failures found.</li>`n"
}

$htmlReport += @"
            </ul>
        </div>
        
        <div style="background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin-top: 20px;">
            <h3 style="margin-top: 0;">High Priority Actions:</h3>
            <ul>
"@

$highFailures = $results | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "High" }
if ($highFailures) {
    foreach ($failure in $highFailures) {
        $htmlReport += "                <li><strong>$($failure.Control):</strong> $($failure.Description)</li>`n"
    }
} else {
    $htmlReport += "                <li>No high priority failures found.</li>`n"
}

$htmlReport += @"
            </ul>
        </div>
        
        <h2>📝 Manual Review Items</h2>
        <table>
            <thead>
                <tr>
                    <th>Control</th>
                    <th>Description</th>
                    <th>Action Required</th>
                </tr>
            </thead>
            <tbody>
"@

$manualItems = $results | Where-Object { $_.Status -eq "Manual" }
foreach ($item in $manualItems) {
    $htmlReport += @"
                <tr>
                    <td><strong>$($item.Control)</strong></td>
                    <td>$($item.Description)</td>
                    <td>$($item.CurrentValue)</td>
                </tr>
"@
}

$htmlReport += @"
            </tbody>
        </table>
        
        <h2>📚 Additional Resources</h2>
        <ul>
            <li><a href="https://www.cisecurity.org/benchmark/windows_server" target="_blank">CIS Windows Server 2022 Benchmark</a></li>
            <li><a href="https://docs.microsoft.com/en-us/windows/security/" target="_blank">Microsoft Security Documentation</a></li>
            <li><a href="https://learn.microsoft.com/en-us/windows-server/security/security-and-assurance" target="_blank">Windows Server Security Best Practices</a></li>
        </ul>
        
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em;">
            <p><strong>Note:</strong> This audit script checks a subset of CIS Benchmark controls. For complete compliance assessment, 
            manual review and additional tools may be required. Always refer to the official CIS Benchmark documentation.</p>
            <p><strong>Disclaimer:</strong> This tool is provided as-is for informational purposes. Always test configuration changes 
            in a non-production environment before applying to production systems.</p>
        </div>
    </div>
</body>
</html>
"@

# Save HTML report
try {
    $htmlReport | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "✓ HTML Report saved to: $ReportPath" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to save HTML report: $($_.Exception.Message)" -ForegroundColor Red
}

# Export to CSV if requested
if ($ExportCSV) {
    try {
        $results | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "✓ CSV Report saved to: $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to save CSV report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "[10/10] Audit Complete!" -ForegroundColor Yellow

# ====================
# Display Summary
# ====================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Audit Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Checks:    $($results.Count)" -ForegroundColor White
Write-Host "Passed:          $passCount" -ForegroundColor Green
Write-Host "Failed:          $failCount" -ForegroundColor Red
Write-Host "Manual Review:   $manualCount" -ForegroundColor Yellow
Write-Host ""
Write-Host "Compliance Rate: $([math]::Round(($passCount / ($passCount + $failCount)) * 100, 2))%" -ForegroundColor Cyan
Write-Host ""
Write-Host "Report Location: $ReportPath" -ForegroundColor White
Write-Host ""

# Display critical and high failures
if ($criticalFailures) {
    Write-Host "⚠️  CRITICAL FAILURES FOUND: $($criticalFailures.Count)" -ForegroundColor Red
    $criticalFailures | ForEach-Object {
        Write-Host "   - $($_.Control): $($_.Description)" -ForegroundColor Red
    }
    Write-Host ""
}

if ($highFailures) {
    Write-Host "⚠️  HIGH PRIORITY FAILURES: $($highFailures.Count)" -ForegroundColor Yellow
    $highFailures | Select-Object -First 5 | ForEach-Object {
        Write-Host "   - $($_.Control): $($_.Description)" -ForegroundColor Yellow
    }
    if ($highFailures.Count -gt 5) {
        Write-Host "   ... and $($highFailures.Count - 5) more. See full report for details." -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "Open the HTML report in a browser for detailed results and remediation guidance." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Optional: Open report in default browser
$openReport = Read-Host "Would you like to open the report now? (Y/N)"
if ($openReport -eq "Y" -or $openReport -eq "y") {
    Start-Process $ReportPath
}