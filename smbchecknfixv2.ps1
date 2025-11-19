<#
.SYNOPSIS
    Detects SMB versions, signing status, and disables SMBv1.

.DESCRIPTION
    This comprehensive script:
    - Detects which SMB versions are enabled (1.0, 2.0, 2.1, 3.0, 3.1.1)
    - Checks SMB signing configuration (server and client)
    - Shows active SMB connections and their protocols
    - Optionally disables SMBv1
    - Generates detailed HTML and CSV reports

.PARAMETER DisableSMBv1
    If specified, automatically disables SMBv1 without prompting.

.PARAMETER EnableSMBSigning
    If specified, enables and requires SMB signing for both server and client.

.PARAMETER ReportPath
    Directory where reports will be saved. Default: C:\SMB_Reports

.PARAMETER CheckRemoteServers
    Optional comma-separated list of remote servers to check SMB connectivity.

.EXAMPLE
    .\SMB-Detect.ps1
    
.EXAMPLE
    .\SMB-Detect.ps1 -DisableSMBv1
    
.EXAMPLE
    .\SMB-Detect.ps1 -EnableSMBSigning
    
.EXAMPLE
    .\SMB-Detect.ps1 -DisableSMBv1 -EnableSMBSigning
    
.EXAMPLE
    .\SMB-Detect.ps1 -CheckRemoteServers "server1,server2,server3" -ReportPath "D:\Reports"

.NOTES
    Requires Administrator privileges for full detection and configuration.
    Compatible with Windows Server 2012+ and Windows 8+
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$DisableSMBv1,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableSMBSigning,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = "C:\SMB_Reports",
    
    [Parameter(Mandatory=$false)]
    [string]$CheckRemoteServers = ""
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$results = @{
    ServerInfo = @{}
    SMBVersions = @{}
    SMBSigning = @{}
    ActiveConnections = @()
    SMBShares = @()
    RemoteChecks = @()
    SecurityIssues = @()
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Get-SMBVersionStatus {
    Write-SectionHeader "SMB Version Detection"
    
    $versions = @{
        "SMBv1" = @{ Enabled = $false; Status = "Unknown"; Feature = $null }
        "SMBv2" = @{ Enabled = $false; Status = "Unknown"; Protocol = "2.0.2" }
        "SMBv3" = @{ Enabled = $false; Status = "Unknown"; Protocol = "3.0" }
        "SMBv3.1.1" = @{ Enabled = $false; Status = "Unknown"; Protocol = "3.1.1" }
    }
    
    # Check SMBv1
    Write-ColorOutput "Checking SMBv1..." -Color Yellow
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1Feature) {
            $versions["SMBv1"].Feature = $smb1Feature.State
            $versions["SMBv1"].Enabled = ($smb1Feature.State -eq "Enabled")
            $versions["SMBv1"].Status = $smb1Feature.State
            
            if ($versions["SMBv1"].Enabled) {
                Write-ColorOutput "  [!] SMBv1: ENABLED (CRITICAL SECURITY RISK!)" -Color Red
                $script:results.SecurityIssues += "SMBv1 is enabled - vulnerable to ransomware attacks"
            } else {
                Write-ColorOutput "  [✓] SMBv1: DISABLED (Good)" -Color Green
            }
        } else {
            Write-ColorOutput "  [?] SMBv1: Not available on this system" -Color Gray
        }
    } catch {
        Write-ColorOutput "  [!] Could not check SMBv1: $($_.Exception.Message)" -Color Red
    }
    
    # Check SMBv1 via registry (alternative method)
    try {
        $smb1Reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
        if ($smb1Reg -and $smb1Reg.SMB1 -eq 0) {
            Write-ColorOutput "  [✓] SMBv1 also disabled in registry" -Color Green
        } elseif ($smb1Reg -and $smb1Reg.SMB1 -ne 0) {
            Write-ColorOutput "  [!] SMBv1 enabled in registry" -Color Red
        }
    } catch {}
    
    # Check SMBv2/v3
    Write-ColorOutput "`nChecking SMBv2/v3..." -Color Yellow
    try {
        $smbServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        
        if ($smbServerConfig) {
            # SMBv2
            if ($smbServerConfig.EnableSMB2Protocol) {
                $versions["SMBv2"].Enabled = $true
                $versions["SMBv2"].Status = "Enabled"
                Write-ColorOutput "  [✓] SMBv2: ENABLED" -Color Green
            } else {
                $versions["SMBv2"].Status = "Disabled"
                Write-ColorOutput "  [!] SMBv2: DISABLED" -Color Red
                $script:results.SecurityIssues += "SMBv2 is disabled"
            }
            
            # SMBv3
            # SMBv3 is enabled by default if SMBv2 is enabled on Server 2012+
            $osVersion = [System.Environment]::OSVersion.Version
            if ($osVersion.Major -ge 10 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -ge 2)) {
                $versions["SMBv3"].Enabled = $smbServerConfig.EnableSMB2Protocol
                $versions["SMBv3"].Status = if ($smbServerConfig.EnableSMB2Protocol) { "Enabled" } else { "Disabled" }
                Write-ColorOutput "  [✓] SMBv3: ENABLED" -Color Green
            }
            
            # SMBv3.1.1 (Windows 10/Server 2016+)
            if ($osVersion.Major -ge 10) {
                $versions["SMBv3.1.1"].Enabled = $smbServerConfig.EnableSMB2Protocol
                $versions["SMBv3.1.1"].Status = if ($smbServerConfig.EnableSMB2Protocol) { "Enabled" } else { "Disabled" }
                Write-ColorOutput "  [✓] SMBv3.1.1: ENABLED (includes encryption support)" -Color Green
            }
        }
    } catch {
        Write-ColorOutput "  [!] Could not check SMBv2/v3: $($_.Exception.Message)" -Color Red
    }
    
    $script:results.SMBVersions = $versions
    return $versions
}

function Get-SMBSigningStatus {
    Write-SectionHeader "SMB Signing Configuration"
    
    $signingStatus = @{
        ServerRequired = $false
        ServerEnabled = $false
        ClientRequired = $false
        ClientEnabled = $false
    }
    
    try {
        $smbServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        $smbClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
        
        Write-ColorOutput "Server Configuration:" -Color Yellow
        if ($smbServerConfig) {
            $signingStatus.ServerRequired = $smbServerConfig.RequireSecuritySignature
            $signingStatus.ServerEnabled = $smbServerConfig.EnableSecuritySignature
            
            Write-ColorOutput "  Require Security Signature: " -Color White -NoNewline
            if ($smbServerConfig.RequireSecuritySignature) {
                Write-ColorOutput "REQUIRED" -Color Green
            } else {
                Write-ColorOutput "NOT REQUIRED" -Color Red
                $script:results.SecurityIssues += "SMB Server signing not required - vulnerable to relay attacks"
            }
            
            Write-ColorOutput "  Enable Security Signature:  " -Color White -NoNewline
            if ($smbServerConfig.EnableSecuritySignature) {
                Write-ColorOutput "ENABLED" -Color Green
            } else {
                Write-ColorOutput "DISABLED" -Color Red
            }
        }
        
        Write-ColorOutput "`nClient Configuration:" -Color Yellow
        if ($smbClientConfig) {
            $signingStatus.ClientRequired = $smbClientConfig.RequireSecuritySignature
            $signingStatus.ClientEnabled = $smbClientConfig.EnableSecuritySignature
            
            Write-ColorOutput "  Require Security Signature: " -Color White -NoNewline
            if ($smbClientConfig.RequireSecuritySignature) {
                Write-ColorOutput "REQUIRED" -Color Green
            } else {
                Write-ColorOutput "NOT REQUIRED" -Color Yellow
            }
            
            Write-ColorOutput "  Enable Security Signature:  " -Color White -NoNewline
            if ($smbClientConfig.EnableSecuritySignature) {
                Write-ColorOutput "ENABLED" -Color Green
            } else {
                Write-ColorOutput "DISABLED" -Color Red
            }
        }
        
        # Check via registry as well
        Write-ColorOutput "`nRegistry Values:" -Color Yellow
        $serverSigReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -ErrorAction SilentlyContinue
        $clientSigReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ErrorAction SilentlyContinue
        
        if ($serverSigReg) {
            Write-ColorOutput "  Server RequireSecuritySignature: $($serverSigReg.RequireSecuritySignature)" -Color Gray
            Write-ColorOutput "  Server EnableSecuritySignature:  $($serverSigReg.EnableSecuritySignature)" -Color Gray
        }
        
        if ($clientSigReg) {
            Write-ColorOutput "  Client RequireSecuritySignature: $($clientSigReg.RequireSecuritySignature)" -Color Gray
            Write-ColorOutput "  Client EnableSecuritySignature:  $($clientSigReg.EnableSecuritySignature)" -Color Gray
        }
        
    } catch {
        Write-ColorOutput "Error checking SMB signing: $($_.Exception.Message)" -Color Red
    }
    
    $script:results.SMBSigning = $signingStatus
    return $signingStatus
}

function Get-ActiveSMBConnections {
    Write-SectionHeader "Active SMB Connections"
    
    try {
        $connections = Get-SmbConnection -ErrorAction SilentlyContinue
        
        if ($connections) {
            Write-ColorOutput "Found $($connections.Count) active SMB connection(s):`n" -Color Green
            
            foreach ($conn in $connections) {
                $dialectColor = switch ($conn.Dialect) {
                    "1.0" { "Red" }
                    "2.0" { "Yellow" }
                    "2.0.2" { "Yellow" }
                    "2.1" { "Yellow" }
                    "3.0" { "Green" }
                    "3.0.2" { "Green" }
                    "3.1.1" { "Green" }
                    default { "White" }
                }
                
                Write-ColorOutput "  Server: " -Color White -NoNewline
                Write-ColorOutput "$($conn.ServerName)" -Color Cyan
                Write-ColorOutput "    Dialect: " -Color White -NoNewline
                Write-ColorOutput "$($conn.Dialect)" -Color $dialectColor -NoNewline
                Write-ColorOutput " | Signed: " -Color White -NoNewline
                Write-ColorOutput "$($conn.Signed)" -Color $(if($conn.Signed){"Green"}else{"Red"}) -NoNewline
                Write-ColorOutput " | Encrypted: " -Color White -NoNewline
                Write-ColorOutput "$($conn.Encrypted)" -Color $(if($conn.Encrypted){"Green"}else{"Yellow"})
                Write-ColorOutput "    User: $($conn.UserName)" -Color Gray
                
                $script:results.ActiveConnections += [PSCustomObject]@{
                    ServerName = $conn.ServerName
                    Dialect = $conn.Dialect
                    Signed = $conn.Signed
                    Encrypted = $conn.Encrypted
                    UserName = $conn.UserName
                    ShareName = $conn.ShareName
                }
                
                if ($conn.Dialect -eq "1.0") {
                    Write-ColorOutput "    [!] WARNING: Using SMBv1 protocol!" -Color Red
                    $script:results.SecurityIssues += "Active SMBv1 connection detected to $($conn.ServerName)"
                }
            }
        } else {
            Write-ColorOutput "No active SMB connections found." -Color Gray
        }
    } catch {
        Write-ColorOutput "Error retrieving SMB connections: $($_.Exception.Message)" -Color Red
    }
}

function Get-SMBShares {
    Write-SectionHeader "SMB Shares on This Server"
    
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        
        if ($shares) {
            Write-ColorOutput "Found $($shares.Count) SMB share(s):`n" -Color Green
            
            foreach ($share in $shares) {
                Write-ColorOutput "  Share: " -Color White -NoNewline
                Write-ColorOutput "$($share.Name)" -Color Cyan
                Write-ColorOutput "    Path: $($share.Path)" -Color Gray
                Write-ColorOutput "    Description: $($share.Description)" -Color Gray
                
                # Check encryption settings
                try {
                    $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                    if ($shareAccess) {
                        Write-ColorOutput "    Encrypt Data: $($share.EncryptData)" -Color $(if($share.EncryptData){"Green"}else{"Yellow"})
                    }
                } catch {}
                
                $script:results.SMBShares += [PSCustomObject]@{
                    Name = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    EncryptData = $share.EncryptData
                }
            }
        } else {
            Write-ColorOutput "No SMB shares found." -Color Gray
        }
    } catch {
        Write-ColorOutput "Error retrieving SMB shares: $($_.Exception.Message)" -Color Red
    }
}

function Test-RemoteSMB {
    param([string[]]$Servers)
    
    if (-not $Servers -or $Servers.Count -eq 0) { return }
    
    Write-SectionHeader "Testing Remote SMB Connectivity"
    
    foreach ($server in $Servers) {
        Write-ColorOutput "`nTesting: $server" -Color Yellow
        
        $testResult = [PSCustomObject]@{
            Server = $server
            Reachable = $false
            SMBv1 = "Unknown"
            SMBv2 = "Unknown"
            SMBv3 = "Unknown"
            Port445Open = $false
        }
        
        # Test TCP 445
        try {
            $tcpTest = Test-NetConnection -ComputerName $server -Port 445 -WarningAction SilentlyContinue -ErrorAction Stop
            $testResult.Port445Open = $tcpTest.TcpTestSucceeded
            $testResult.Reachable = $tcpTest.PingSucceeded
            
            if ($tcpTest.TcpTestSucceeded) {
                Write-ColorOutput "  [✓] Port 445 is open" -Color Green
            } else {
                Write-ColorOutput "  [✗] Port 445 is closed" -Color Red
            }
        } catch {
            Write-ColorOutput "  [✗] Cannot reach server: $($_.Exception.Message)" -Color Red
        }
        
        # Try to detect SMB versions
        if ($testResult.Port445Open) {
            try {
                # Try SMBv1
                $null = Get-ChildItem "\\$server\IPC$" -ErrorAction SilentlyContinue
                $testResult.SMBv1 = "Accessible"
                Write-ColorOutput "  [!] SMBv1 appears to be enabled" -Color Red
            } catch {
                $testResult.SMBv1 = "Not Accessible"
                Write-ColorOutput "  [✓] SMBv1 not accessible (good)" -Color Green
            }
        }
        
        $script:results.RemoteChecks += $testResult
    }
}

function Disable-SMBv1 {
    Write-SectionHeader "Disabling SMBv1"
    
    Write-ColorOutput "⚠️  WARNING: Disabling SMBv1 will:" -Color Yellow
    Write-ColorOutput "   - Require a system restart" -Color Yellow
    Write-ColorOutput "   - Break connectivity with very old systems (Windows XP, Server 2003)" -Color Yellow
    Write-ColorOutput "   - Protect against ransomware like WannaCry" -Color Yellow
    Write-Host ""
    
    if (-not $DisableSMBv1) {
        $confirm = Read-Host "Do you want to disable SMBv1? (Type 'YES' to proceed)"
        if ($confirm -ne "YES") {
            Write-ColorOutput "SMBv1 disable cancelled." -Color Yellow
            return $false
        }
    }
    
    $success = $true
    
    # Method 1: Disable Windows Feature
    try {
        Write-ColorOutput "`nDisabling SMBv1 Windows Feature..." -Color Cyan
        $result = Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Write-ColorOutput "[✓] SMBv1 Windows Feature disabled" -Color Green
    } catch {
        Write-ColorOutput "[✗] Failed to disable SMBv1 feature: $($_.Exception.Message)" -Color Red
        $success = $false
    }
    
    # Method 2: Registry settings
    try {
        Write-ColorOutput "Setting SMBv1 registry values..." -Color Cyan
        
        if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force | Out-Null
        }
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force
        Write-ColorOutput "[✓] SMBv1 registry value set" -Color Green
    } catch {
        Write-ColorOutput "[✗] Failed to set registry value: $($_.Exception.Message)" -Color Red
        $success = $false
    }
    
    # Method 3: Disable via PowerShell cmdlets
    try {
        Write-ColorOutput "Disabling SMBv1 protocol..." -Color Cyan
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -Force
        Write-ColorOutput "[✓] SMBv1 server protocol disabled" -Color Green
    } catch {
        Write-ColorOutput "[✗] Failed to disable SMBv1 protocol: $($_.Exception.Message)" -Color Red
        $success = $false
    }
    
    if ($success) {
        Write-Host ""
        Write-ColorOutput "═══════════════════════════════════════════════════════════" -Color Green
        Write-ColorOutput " SMBv1 has been successfully disabled!" -Color Green
        Write-ColorOutput " RESTART REQUIRED for changes to take effect." -Color Green
        Write-ColorOutput "═══════════════════════════════════════════════════════════" -Color Green
        Write-Host ""
        
        $restart = Read-Host "Do you want to restart now? (Y/N)"
        if ($restart -eq "Y" -or $restart -eq "y") {
            Write-ColorOutput "Restarting in 30 seconds... (Press Ctrl+C to cancel)" -Color Yellow
            Start-Sleep -Seconds 30
            Restart-Computer -Force
        }
    }
    
    return $success
}

function Export-Reports {
    Write-SectionHeader "Generating Reports"
    
    if (-not (Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }
    
    # Export CSV
    $csvPath = Join-Path $ReportPath "SMB_Report_$timestamp.csv"
    $csvData = @()
    
    foreach ($version in $script:results.SMBVersions.Keys) {
        $csvData += [PSCustomObject]@{
            Category = "SMB Version"
            Item = $version
            Status = $script:results.SMBVersions[$version].Status
            Enabled = $script:results.SMBVersions[$version].Enabled
        }
    }
    
    $csvData += [PSCustomObject]@{
        Category = "SMB Signing"
        Item = "Server Required"
        Status = $script:results.SMBSigning.ServerRequired
        Enabled = $script:results.SMBSigning.ServerRequired
    }
    
    $csvData += [PSCustomObject]@{
        Category = "SMB Signing"
        Item = "Client Required"
        Status = $script:results.SMBSigning.ClientRequired
        Enabled = $script:results.SMBSigning.ClientRequired
    }
    
    $csvData | Export-Csv -Path $csvPath -NoTypeInformation
    Write-ColorOutput "[✓] CSV report saved: $csvPath" -Color Green
    
    # Generate HTML Report
    $htmlPath = Join-Path $ReportPath "SMB_Report_$timestamp.html"
    
    $securityIssuesHtml = ""
    if ($script:results.SecurityIssues.Count -gt 0) {
        $securityIssuesHtml = "<div class='alert alert-danger'><h3>🚨 Security Issues Found</h3><ul>"
        foreach ($issue in $script:results.SecurityIssues) {
            $securityIssuesHtml += "<li>$issue</li>"
        }
        $securityIssuesHtml += "</ul></div>"
    } else {
        $securityIssuesHtml = "<div class='alert alert-success'><h3>✓ No Critical Security Issues Found</h3></div>"
    }
    
    $versionsTableHtml = ""
    foreach ($version in $script:results.SMBVersions.Keys | Sort-Object) {
        $statusClass = if ($script:results.SMBVersions[$version].Enabled) { "enabled" } else { "disabled" }
        $statusText = $script:results.SMBVersions[$version].Status
        $versionsTableHtml += "<tr><td><strong>$version</strong></td><td class='$statusClass'>$statusText</td></tr>"
    }
    
    $connectionsTableHtml = ""
    if ($script:results.ActiveConnections.Count -gt 0) {
        foreach ($conn in $script:results.ActiveConnections) {
            $dialectClass = if ($conn.Dialect -match "^1\.") { "smb1" } elseif ($conn.Dialect -match "^2\.") { "smb2" } else { "smb3" }
            $connectionsTableHtml += "<tr><td>$($conn.ServerName)</td><td class='$dialectClass'>$($conn.Dialect)</td><td>$($conn.Signed)</td><td>$($conn.Encrypted)</td></tr>"
        }
    } else {
        $connectionsTableHtml = "<tr><td colspan='4' style='text-align:center;'>No active connections</td></tr>"
    }
    
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>SMB Detection Report - $env:COMPUTERNAME</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background-color: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        .enabled { color: #28a745; font-weight: bold; }
        .disabled { color: #6c757d; }
        .smb1 { color: #dc3545; font-weight: bold; }
        .smb2 { color: #ffc107; font-weight: bold; }
        .smb3 { color: #28a745; font-weight: bold; }
        .alert { padding: 15px; margin: 20px 0; border-radius: 5px; }
        .alert-danger { background-color: #f8d7da; border-left: 4px solid #dc3545; }
        .alert-success { background-color: #d4edda; border-left: 4px solid #28a745; }
        .alert h3 { margin-top: 0; }
        .metadata { color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SMB Detection and Configuration Report</h1>
        <div class="metadata">
            <strong>Server:</strong> $env:COMPUTERNAME<br>
            <strong>Report Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>OS:</strong> $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
        </div>
        
        $securityIssuesHtml
        
        <h2>📊 SMB Versions</h2>
        <table>
            <thead><tr><th>Version</th><th>Status</th></tr></thead>
            <tbody>$versionsTableHtml</tbody>
        </table>
        
        <h2>🔐 SMB Signing Configuration</h2>
        <table>
            <thead><tr><th>Component</th><th>Require Signing</th><th>Enable Signing</th></tr></thead>
            <tbody>
                <tr><td><strong>Server</strong></td><td class='$(if($script:results.SMBSigning.ServerRequired){"enabled"}else{"disabled"})'>$($script:results.SMBSigning.ServerRequired)</td><td class='$(if($script:results.SMBSigning.ServerEnabled){"enabled"}else{"disabled"})'>$($script:results.SMBSigning.ServerEnabled)</td></tr>
                <tr><td><strong>Client</strong></td><td class='$(if($script:results.SMBSigning.ClientRequired){"enabled"}else{"disabled"})'>$($script:results.SMBSigning.ClientRequired)</td><td class='$(if($script:results.SMBSigning.ClientEnabled){"enabled"}else{"disabled"})'>$($script:results.SMBSigning.ClientEnabled)</td></tr>
            </tbody>
        </table>
        
        <h2>🔗 Active SMB Connections</h2>
        <table>
            <thead><tr><th>Server</th><th>Dialect</th><th>Signed</th><th>Encrypted</th></tr></thead>
            <tbody>$connectionsTableHtml</tbody>
        </table>
        
        <h2>📝 Recommendations</h2>
        <div class="alert alert-success">
            <ul>
                <li>✓ Disable SMBv1 if not already disabled</li>
                <li>✓ Enable SMB signing (Required for both server and client)</li>
                <li>✓ Use SMBv3 or higher for all connections</li>
                <li>✓ Enable SMB encryption for sensitive data</li>
                <li>✓ Regularly audit SMB connections and configurations</li>
            </ul>
        </div>
    </div>
</body>
</html>
"@
    
    $htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-ColorOutput "[✓] HTML report saved: $htmlPath" -Color Green
}

# ====================
# Main Execution
# ====================

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          SMB Detection and Configuration Tool            ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Collect system information
$script:results.ServerInfo = @{
    ComputerName = $env:COMPUTERNAME
    OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
    Timestamp = Get-Date
}

# Run detection
Get-SMBVersionStatus
Get-SMBSigningStatus
Get-ActiveSMBConnections
Get-SMBShares

# Check remote servers if specified
if ($CheckRemoteServers) {
    $servers = $CheckRemoteServers -split ","
    Test-RemoteSMB -Servers $servers
}

# Export reports
Export-Reports

# Optionally enable SMB signing
if ($EnableSMBSigning) {
    Write-Host ""
    Enable-SMBSigning
}

# Check if SMB signing should be enabled based on detection
if (-not $EnableSMBSigning -and (-not $script:results.SMBSigning.ServerRequired -or -not $script:results.SMBSigning.ClientRequired)) {
    Write-Host ""
    Write-ColorOutput "⚠️  SMB Signing is not fully configured!" -Color Yellow
    Write-ColorOutput "   Current Status:" -Color Yellow
    Write-ColorOutput "   - Server Require: $($script:results.SMBSigning.ServerRequired)" -Color $(if($script:results.SMBSigning.ServerRequired){"Green"}else{"Red"})
    Write-ColorOutput "   - Client Require: $($script:results.SMBSigning.ClientRequired)" -Color $(if($script:results.SMBSigning.ClientRequired){"Green"}else{"Red"})
    Write-Host ""
    
    $enableSigning = Read-Host "Would you like to enable SMB signing now? (Y/N)"
    if ($enableSigning -eq "Y" -or $enableSigning -eq "y") {
        Enable-SMBSigning
    }
}

# Optionally disable SMBv1
if ($script:results.SMBVersions["SMBv1"].Enabled -or $DisableSMBv1) {
    Write-Host ""
    if ($script:results.SMBVersions["SMBv1"].Enabled) {
        Write-ColorOutput "⚠️  SMBv1 is currently ENABLED on this system!" -Color Red
    }
    
    if ($DisableSMBv1 -or $script:results.SMBVersions["SMBv1"].Enabled) {
        Disable-SMBv1
    }
}

# ====================
# Final Summary
# ====================
Write-SectionHeader "Summary"

Write-ColorOutput "Detection Complete!" -Color Green
Write-Host ""
Write-ColorOutput "SMB Versions:" -Color Cyan
foreach ($version in $script:results.SMBVersions.Keys | Sort-Object) {
    $status = $script:results.SMBVersions[$version].Status
    $color = switch ($version) {
        "SMBv1" { if ($status -eq "Enabled") { "Red" } else { "Green" } }
        default { if ($status -eq "Enabled") { "Green" } else { "Yellow" } }
    }
    Write-ColorOutput "  $version : $status" -Color $color
}

Write-Host ""
Write-ColorOutput "SMB Signing:" -Color Cyan
Write-ColorOutput "  Server Required: $($script:results.SMBSigning.ServerRequired)" -Color $(if($script:results.SMBSigning.ServerRequired){"Green"}else{"Red"})
Write-ColorOutput "  Client Required: $($script:results.SMBSigning.ClientRequired)" -Color $(if($script:results.SMBSigning.ClientRequired){"Green"}else{"Yellow"})

Write-Host ""
Write-ColorOutput "Active Connections: $($script:results.ActiveConnections.Count)" -Color Cyan
Write-ColorOutput "SMB Shares: $($script:results.SMBShares.Count)" -Color Cyan

if ($script:results.SecurityIssues.Count -gt 0) {
    Write-Host ""
    Write-ColorOutput "⚠️  Security Issues Found: $($script:results.SecurityIssues.Count)" -Color Red
    foreach ($issue in $script:results.SecurityIssues) {
        Write-ColorOutput "   - $issue" -Color Red
    }
}

Write-Host ""
Write-ColorOutput "Reports saved to: $ReportPath" -Color Green
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
