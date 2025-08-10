#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Device Hardener v1.2.7 - Production-hardened Windows 10/11 security baseline
    
.DESCRIPTION
    This script implements comprehensive Windows security hardening with backup capabilities,
    idempotent operations, and modular design. Suitable for standalone execution, Intune/ConfigMgr
    deployment, or RMM one-liner execution.
    
.PARAMETER Preview
    Show planned changes without applying them
    
.PARAMETER NoBackup
    Skip backup operations to speed up execution
    
.PARAMETER ASRRules
    Comma-separated list of ASR rule GUIDs to enable (optional)
    
.PARAMETER ExploitProtectionXml
    Path to Exploit Protection baseline XML file (optional)
    
.PARAMETER StrictRDP
    Enable additional RDP security layer and transport controls
    
.PARAMETER EnableHVCI
    Enable Hypervisor-protected Code Integrity (Device Guard HVCI)
    
.PARAMETER QuietFirewall
    Disable firewall notifications (recommended for managed endpoints)
    
.PARAMETER EnforceNETTLS
    Force .NET Framework applications to use TLS 1.2+ via strong crypto settings
    
.PARAMETER EnableCFA
    Enable Controlled Folder Access (can break legacy applications - use with caution)
    
.PARAMETER DisableLLMNR
    Disable LLMNR (Link-Local Multicast Name Resolution) to prevent lateral movement attacks
    
.PARAMETER DisableSMBGuest
    Disable insecure SMB guest authentication fallback
    
.PARAMETER HardenWinRM
    Enable WinRM security hardening (disable unencrypted traffic, Basic/Digest auth)
    
.PARAMETER HardenNTLM
    Enable NTLM/LM protocol hardening (compatibility level, session security, anonymous restrictions)
    
.PARAMETER HardenPrintSpooler
    Enable Print Spooler hardening against PrintNightmare and Point-and-Print attacks
    
.PARAMETER DisableAutoRun
    Disable AutoRun and AutoPlay to prevent USB-based malware spread
    
.PARAMETER RemovePSv2
    Remove PowerShell v2 engine to eliminate downgrade attack surface
    
.PARAMETER HardenCipherSuites
    Configure modern cipher suite order and disable weak ciphers (RC4, 3DES)
    
.PARAMETER DisableWPAD
    Disable WPAD (Web Proxy Auto-Discovery) to prevent MitM attacks
    
.PARAMETER DisableNetBIOS
    Disable NetBIOS over TCP/IP on active network adapters
    
.PARAMETER WinRMHttpsOnly
    Configure WinRM for HTTPS-only communication (requires WinRMThumbprint)
    
.PARAMETER WinRMThumbprint
    Certificate thumbprint for WinRM HTTPS listener (used with WinRMHttpsOnly)
    
.PARAMETER DisableWebClient
    Disable WebClient (WebDAV) service if not required
    
.EXAMPLE
    .\Windows-Device-Hardener.ps1
    
.EXAMPLE
    .\Windows-Device-Hardener.ps1 -Preview
    
.EXAMPLE
    .\Windows-Device-Hardener.ps1 -NoBackup -ASRRules "56a863a9-875e-4185-98a7-b882c64b5ce5,7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
    
.EXAMPLE
    .\Windows-Device-Hardener.ps1 -StrictRDP -EnableHVCI -QuietFirewall -EnforceNETTLS
    
.EXAMPLE
    .\Windows-Device-Hardener.ps1 -DisableLLMNR -DisableSMBGuest -HardenWinRM
    
.EXAMPLE
    .\Windows-Device-Hardener.ps1 -HardenNTLM -HardenPrintSpooler -DisableAutoRun -RemovePSv2 -HardenCipherSuites
    
.NOTES
    Author: Windows Device Hardener
    Version: 1.2.7 - Complete security hardening with network and service lockdown
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
    
    v1.2.7 Complete Security Hardening:
    - Fixed duplicate PowerShell function and PSv2 state detection
    - Enhanced AutoPlay disable with machine-wide Policies enforcement
    - Added WPAD/Auto-proxy disable to prevent MitM attacks
    - Added NetBIOS over TCP/IP disable per active network adapter
    - Added WinRM HTTPS-only mode with certificate thumbprint support
    - Added WebClient (WebDAV) service disable option
    - Extended NTLM hardening with outbound traffic restrictions
    - Enhanced cipher suite configuration with both Local and Policy paths
    
    v1.2.6 Advanced Security Hardening:
    - Added comprehensive NTLM/LM hardening with compatibility level and session security
    - Added PrintNightmare/Point-and-Print lockdown controls
    - Added AutoRun/AutoPlay disable to prevent USB-based malware spread
    - Added PowerShell v2 removal option for attack surface reduction
    - Added modern cipher suite ordering and weak cipher elimination
    - Enhanced Defender policy mirroring for PUA Protection and Cloud Block Level
    - Added WDigest credential protection guard
    
    v1.2.5 Enhanced Defensive Hardening:
    - Added Network Protection policy mirror for tamper resistance
    - Disabled insecure SMB guest authentication fallback
    - Disabled LLMNR to prevent lateral movement attacks
    - Added optional WinRM hardening with secure transport controls
    - Enhanced RDP security with password prompt requirements
    - Added PendingRebootDetected flag to JSON summary for orchestration
    
    v1.2.4 Defensive Improvements:
    - Made auditpol check locale-immune with RAW output and bitmask validation
    - Added Defender Network Protection (SmartScreen for network traffic)
    - Hardened Remote Assistance by disabling fAllowToGetHelp (lateral movement prevention)
    - Added Defender archive and email scanning safeguards (tamper-safe defaults)
    - Enhanced BitLocker protector metadata capture with comprehensive null guards
    - Added LogPath existence guard to Log function for early operation safety
    
    v1.2.3 Correctness Fixes:
    - Fixed ASR state export to honor -NoBackup flag (uses log folder when backups disabled)
    - Added Set-MpPrefSafe retry wrapper for reliable Defender preference setting
    - Added LocalAccounts module availability check for Server/Core compatibility
    - Enhanced resilience for enterprise deployment edge cases
    
    v1.2.2 Final Polish:
    - Fixed Start-Transcript log folder creation race condition
    - Replaced audit GUID hashtable with collision-free pure GUID array
    - Removed unused audit policies dictionary for cleaner code
    - Enhanced operational reliability and deployment readiness
    
    v1.2.1 Production Hardening:
    - ASR merge with deterministic ID↔action alignment (prevents rule misalignment)
    - RDP UDP transport disable for full StrictRDP lockdown
    - LSA RunAsPPLBoot flag for enhanced persistence
    - BitLocker NTFS validation and status artifacts
    - .NET path existence checks and per-path logging
    - Defender preference retry wrapper for service restart resilience
    - SMB server signing reboot requirement for fleet reliability
    - DPAPI Activity audit for token abuse detection
    - Machine-readable exit codes (0=OK, 1=errors, 3010=reboot required)
    
    v1.2 Enterprise Features:
    - ASR rule action verification (Block vs Audit state checking)
    - Complete Account Logon audit coverage (Credential Validation, Kerberos)
    - .NET Framework TLS enforcement for legacy applications
    - Enhanced RDP security layer controls and transport hardening
    - SMB signing interoperability flags (Enable + Require)
    - BitLocker SKU detection and policy enforcement
    - Optional HVCI (Hypervisor-protected Code Integrity)
    - Feature flags for deployment ring flexibility
    - JSON summary output for automation and monitoring
    
    v1.1 Foundation:
    - Fixed registry writes using safe New-ItemProperty operations
    - Fixed Defender preference tests for string/int tolerance
    - Added Controlled Folder Access (CFA) configuration
    - Fixed BitLocker test to use ProtectionStatus instead of EncryptionPercentage
    - Enhanced RDP hardening with policy keys and full device redirection control
    - Complete VBS/Credential Guard configuration with platform security features
    - ASR rules now merge with existing tenant rules instead of overwriting
    - Added 4688 command-line capture for process auditing
    - Explicit TLS 1.2/1.3 enablement alongside legacy protocol disabling
    - Replaced deprecated Get-WmiObject with Get-CimInstance
#>

[CmdletBinding()]
param(
    [switch]$Preview,
    [switch]$NoBackup,
    [string[]]$ASRRules = @(),
    [string]$ExploitProtectionXml = "",
    [switch]$StrictRDP,
    [switch]$EnableHVCI,
    [switch]$QuietFirewall,
    [switch]$EnforceNETTLS,
    [switch]$EnableCFA,
    [switch]$DisableLLMNR,
    [switch]$DisableSMBGuest,
    [switch]$HardenWinRM,
    [switch]$HardenNTLM,
    [switch]$HardenPrintSpooler,
    [switch]$DisableAutoRun,
    [switch]$RemovePSv2,
    [switch]$HardenCipherSuites,
    [switch]$DisableWPAD,
    [switch]$DisableNetBIOS,
    [switch]$WinRMHttpsOnly,
    [string]$WinRMThumbprint = "",
    [switch]$DisableWebClient
)

# Handle comma-separated ASR input gracefully
if ($ASRRules.Count -eq 1 -and $ASRRules[0] -match ',') {
    $ASRRules = $ASRRules[0] -split '\s*,\s*'
}

$script:BackupPath = "C:\HardeningBackup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$script:LogPath = "C:\HardeningLogs"
$script:LogFile = "$LogPath\DeviceHardener.log"
$script:RebootRequired = $false
$script:ChangesApplied = 0
$script:ErrorsEncountered = 0

# Default ASR Rules (Microsoft recommended)
$script:DefaultASRRules = @(
    "56a863a9-875e-4185-98a7-b882c64b5ce5", # Block abuse of exploited vulnerable signed drivers
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", # Block Adobe Reader from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", # Block all Office applications from creating child processes
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", # Block credential stealing from the Windows local security authority subsystem
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", # Block executable content from email client and webmail
    "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet a prevalence, age, or trusted list criteria
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc", # Block execution of potentially obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d", # Block JavaScript or VBScript from launching downloaded executable content
    "3b576869-a4ec-4529-8536-b80a7769e899", # Block Office applications from creating executable content
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", # Block Office applications from injecting code into other processes
    "26190899-1602-49e8-8b27-eb1d0a1ce869", # Block Office communication application from creating child processes
    "e6db77e5-3df2-4cf1-b95a-636979351e5b", # Block persistence through WMI event subscription
    "d1e49aac-8f56-4280-b9ba-993a6d77406c", # Block process creations originating from PSExec and WMI commands
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", # Block untrusted and unsigned processes that run from USB
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", # Block Win32 API calls from Office macros
    "c1db55ab-c21a-4637-bb3f-a12568109d35"  # Use advanced protection against ransomware
)

# Core utility functions
function ConvertTo-SafeInt {
    param($Value)
    try { [int]$Value } catch { -1 }
}

function Test-TamperProtectionEnabled {
    try {
        $reg = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        $value = (Get-ItemProperty -Path $reg -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
        return ($value -eq 5) # 5 = Enabled
    } catch { 
        return $false 
    }
}

# Check for pending reboot beyond manual flags
function Test-PendingReboot {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )
    return ($paths | Where-Object { Test-Path $_ } | Measure-Object).Count -gt 0
}

# Export ASR state for change review trails
function Export-ASRState {
    param([Parameter(Mandatory)][string]$Label)
    
    try {
        $preference = Get-MpPrefSafe
        $asrState = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString('o')
            Ids = @($preference.AttackSurfaceReductionRules_Ids)
            Actions = @($preference.AttackSurfaceReductionRules_Actions)
        }
        
        # Use log folder if NoBackup, otherwise use backup folder
        $outputDir = if ($NoBackup) { $script:LogPath } else { $script:BackupPath }
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }
        
        $outputPath = Join-Path $outputDir "ASR-$Label.json"
        $asrState | ConvertTo-Json -Depth 3 | Out-File $outputPath -Encoding UTF8 -Force
        Log "ASR state exported: $outputPath" "INFO"
    } catch {
        Log "Failed to export ASR state ($Label): $_" "WARN"
    }
}

# Robust Defender preference wrapper with retry logic for service restarts
function Get-MpPrefSafe {
    param([int]$Retries = 3)
    
    for ($i = 0; $i -lt $Retries; $i++) {
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            if ($pref) { return $pref }
        } catch {
            Log "Get-MpPreference attempt $($i+1)/$Retries failed: $($_.Exception.Message)" "WARN"
        }
        if ($i -lt ($Retries - 1)) { Start-Sleep -Milliseconds 300 }
    }
    throw "Get-MpPreference unavailable after $Retries attempts"
}

# Robust Defender preference setter with retry logic for service restarts
function Set-MpPrefSafe {
    param(
        [Parameter(Mandatory)][hashtable]$Params,
        [int]$Retries = 3
    )
    
    for ($i = 0; $i -lt $Retries; $i++) {
        try {
            Set-MpPreference @Params -ErrorAction Stop
            return $true
        } catch {
            Log "Set-MpPreference attempt $($i+1)/$Retries failed: $($_.Exception.Message)" "WARN"
            if ($i -lt ($Retries - 1)) { Start-Sleep -Milliseconds 300 }
        }
    }
    return $false
}

function Set-RegistryProperty {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        $Value,
        [Parameter(Mandatory)]
        [string]$PropertyType
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
        return $true
    }
    catch {
        Log "Failed to set registry property $Path\$Name`: $_" "ERROR"
        return $false
    }
}

function Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    if (-not (Test-Path $script:LogPath)) {
        New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARN"    { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor White }
    }
    
    try {
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Export-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$RegistryPath,
        [Parameter(Mandatory)]
        [string]$BackupName
    )
    
    if ($NoBackup) {
        Log "Skipping registry backup for $RegistryPath (NoBackup specified)" "INFO"
        return $true
    }
    
    if (-not (Test-Path -LiteralPath ($RegistryPath -replace '^HKEY_LOCAL_MACHINE','HKLM:'))) {
        Log "Registry path not found for backup (skipping): $RegistryPath" "INFO"
        return $true
    }
    
    try {
        $backupFile = Join-Path $script:BackupPath "$BackupName.reg"
        $regPath = $RegistryPath -replace "^HKEY_LOCAL_MACHINE", "HKLM"
        
        $result = Start-Process -FilePath "reg.exe" -ArgumentList @("export", $regPath, $backupFile, "/y") -Wait -PassThru -NoNewWindow
        
        if ($result.ExitCode -eq 0) {
            Log "Registry backup created: $backupFile" "SUCCESS"
            return $true
        }
        else {
            Log "Failed to backup registry path $RegistryPath (Exit code: $($result.ExitCode))" "ERROR"
            return $false
        }
    }
    catch {
        Log "Exception during registry backup of $RegistryPath`: $_" "ERROR"
        return $false
    }
}

function Do-Change {
    param(
        [Parameter(Mandatory)]
        [string]$Description,
        [Parameter(Mandatory)]
        [scriptblock]$TestScript,
        [scriptblock]$BackupScript,
        [Parameter(Mandatory)]
        [scriptblock]$ChangeScript,
        [switch]$RequiresReboot
    )
    
    Log "Processing: $Description" "INFO"
    
    try {
        $currentState = & $TestScript
        
        if ($currentState) {
            Log "Already configured: $Description" "INFO"
            return $true
        }
        
        if ($Preview) {
            Log "PREVIEW: Would apply change - $Description" "WARN"
            return $true
        }
        
        if ($BackupScript -and -not $NoBackup) {
            Log "Creating backup for: $Description" "INFO"
            $backupResult = & $BackupScript
            if (-not $backupResult) {
                Log "Backup failed for: $Description. Skipping change for safety." "ERROR"
                $script:ErrorsEncountered++
                return $false
            }
        }
        
        Log "Applying change: $Description" "INFO"
        $changeResult = & $ChangeScript
        
        if ($changeResult) {
            Log "Successfully applied: $Description" "SUCCESS"
            $script:ChangesApplied++
            
            if ($RequiresReboot) {
                $script:RebootRequired = $true
            }
            
            return $true
        }
        else {
            Log "Failed to apply: $Description" "ERROR"
            $script:ErrorsEncountered++
            return $false
        }
    }
    catch {
        Log "Exception during change '$Description': $_" "ERROR"
        $script:ErrorsEncountered++
        return $false
    }
}

function Initialize-Script {
    if (-not (Test-Path $script:LogPath)) {
        New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
    }
    
    if (-not $NoBackup -and -not (Test-Path $script:BackupPath)) {
        New-Item -Path $script:BackupPath -ItemType Directory -Force | Out-Null
    }
    
    Log "Windows Device Hardener started" "INFO"
    Log "Parameters: Preview=$Preview, NoBackup=$NoBackup" "INFO"
    
    if ([Version](Get-CimInstance -ClassName Win32_OperatingSystem).Version -lt [Version]"10.0") {
        Log "Unsupported Windows version. Requires Windows 10/11." "ERROR"
        throw "Unsupported Windows version"
    }
    
    if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
        Log "Unsupported PowerShell version. Requires 5.1 or later." "ERROR"
        throw "Unsupported PowerShell version"
    }
    
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Log "Administrator privileges required" "ERROR"
        throw "Administrator privileges required"
    }
}


function Set-FirewallConfiguration {
    Log "Configuring Windows Firewall" "INFO"
    
    Do-Change -Description "Enable Domain Firewall Profile" -TestScript {
        (Get-NetFirewallProfile -Profile Domain).Enabled -eq $true
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" "Firewall-Domain"
    } -ChangeScript {
        try {
            Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
            return $true
        } catch { Log "Failed to configure domain firewall: $_" "ERROR"; return $false }
    }
    
    Do-Change -Description "Enable Private Firewall Profile" -TestScript {
        (Get-NetFirewallProfile -Profile Private).Enabled -eq $true
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" "Firewall-Private"
    } -ChangeScript {
        try {
            Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
            return $true
        } catch { Log "Failed to configure private firewall: $_" "ERROR"; return $false }
    }
    
    Do-Change -Description "Enable Public Firewall Profile" -TestScript {
        (Get-NetFirewallProfile -Profile Public).Enabled -eq $true
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" "Firewall-Public"
    } -ChangeScript {
        try {
            Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
            return $true
        } catch { Log "Failed to configure public firewall: $_" "ERROR"; return $false }
    }
    
    if ($QuietFirewall) {
        Do-Change -Description "Disable Firewall Notifications (QuietFirewall)" -TestScript {
            $domain = (Get-NetFirewallProfile -Profile Domain).NotifyOnListen -eq $false
            $private = (Get-NetFirewallProfile -Profile Private).NotifyOnListen -eq $false
            $public = (Get-NetFirewallProfile -Profile Public).NotifyOnListen -eq $false
            return ($domain -and $private -and $public)
        } -ChangeScript {
            try {
                Set-NetFirewallProfile -All -NotifyOnListen False
                return $true
            } catch { Log "Failed to disable firewall notifications: $_" "ERROR"; return $false }
        }
    } else {
        Log "Firewall notifications enabled (use -QuietFirewall to disable for managed endpoints)" "INFO"
    }
}

function Set-DefenderConfiguration {
    Log "Configuring Microsoft Defender" "INFO"
    
    if (Test-TamperProtectionEnabled) {
        Log "Defender Tamper Protection appears enabled; some Defender settings may be enforced by policy" "WARN"
    }
    
    # Enable Real-time Protection
    Do-Change -Description "Enable Defender Real-time Protection" -TestScript {
        (Get-MpPrefSafe).DisableRealtimeMonitoring -eq $false
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ DisableRealtimeMonitoring = $false })
    }
    
    # Enable PUA Protection (handle string/int variations)
    Do-Change -Description "Enable PUA Protection" -TestScript {
        ConvertTo-SafeInt((Get-MpPrefSafe).PUAProtection) -eq 1
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ PUAProtection = 'Enabled' })
    }
    
    # Mirror PUA Protection via policy for tamper resistance
    Do-Change -Description "Mirror PUA Protection Policy (Tamper Resistant)" -TestScript {
        $puaPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -ErrorAction SilentlyContinue
        return ($puaPolicy -and $puaPolicy.PUAProtection -eq 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" "Defender-PUA-Policy"
    } -ChangeScript {
        return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -PropertyType "DWord")
    }
    
    # Enable Cloud Protection (MAPS) - Advanced = 2, Basic = 1
    Do-Change -Description "Enable Cloud Protection (MAPS)" -TestScript {
        ConvertTo-SafeInt((Get-MpPrefSafe).MAPSReporting) -in 1,2
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ MAPSReporting = 'Advanced' })
    }
    
    # Enable Cloud File Analysis (SendAllSamples = 3)
    Do-Change -Description "Send All Samples" -TestScript {
        ConvertTo-SafeInt((Get-MpPrefSafe).SubmitSamplesConsent) -eq 3
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ SubmitSamplesConsent = 'SendAllSamples' })
    }
    
    # Enable Behavior Monitoring
    Do-Change -Description "Enable Behavior Monitoring" -TestScript {
        (Get-MpPrefSafe).DisableBehaviorMonitoring -eq $false
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ DisableBehaviorMonitoring = $false })
    }
    
    # Enable IOAV Protection
    Do-Change -Description "Enable IOAV Protection" -TestScript {
        (Get-MpPrefSafe).DisableIOAVProtection -eq $false
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ DisableIOAVProtection = $false })
    }
    
    # Enable Script Scanning
    Do-Change -Description "Enable Script Scanning" -TestScript {
        (Get-MpPrefSafe).DisableScriptScanning -eq $false
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ DisableScriptScanning = $false })
    }
    
    # Set Cloud Block Level to High (preference scale: High = 4, policy scale: High = 2)
    Do-Change -Description "Cloud Block Level High" -TestScript {
        ConvertTo-SafeInt((Get-MpPrefSafe).CloudBlockLevel) -ge 3
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ CloudBlockLevel = 'High' })
    }
    
    # Mirror Cloud Block Level via policy for tamper resistance (policy uses different scale)
    Do-Change -Description "Mirror Cloud Block Level Policy (Tamper Resistant)" -TestScript {
        $blockLevelPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpCloudBlockLevel" -ErrorAction SilentlyContinue
        return ($blockLevelPolicy -and $blockLevelPolicy.MpCloudBlockLevel -eq 2)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" "Defender-CloudBlock-Policy"
    } -ChangeScript {
        return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpCloudBlockLevel" -Value 2 -PropertyType "DWord")
    }
    
    # Controlled Folder Access (optional due to legacy app compatibility)
    if ($EnableCFA) {
        Do-Change -Description "Enable Controlled Folder Access" -TestScript {
            ConvertTo-SafeInt((Get-MpPrefSafe).EnableControlledFolderAccess) -eq 1
        } -ChangeScript {
            return (Set-MpPrefSafe -Params @{ EnableControlledFolderAccess = 'Enabled' })
        }
    } else {
        Log "CFA not enabled (use -EnableCFA to turn it on)" "INFO"
    }
    
    # Enable Defender Network Protection (SmartScreen for network traffic)
    Do-Change -Description "Enable Defender Network Protection" -TestScript {
        ConvertTo-SafeInt((Get-MpPrefSafe).EnableNetworkProtection) -eq 1
    } -ChangeScript {
        return (Set-MpPrefSafe -Params @{ EnableNetworkProtection = 'Enabled' })
    }
    
    # Mirror Network Protection via policy for tamper resistance
    Do-Change -Description "Mirror Network Protection Policy (Tamper Resistant)" -TestScript {
        $policyValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -ErrorAction SilentlyContinue
        return ($policyValue -and $policyValue.EnableNetworkProtection -eq 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" "NetworkProtection-Policy"
    } -ChangeScript {
        return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -PropertyType "DWord")
    }
    
    # Enable Defender archive and email scanning (tamper-safe defaults)
    Do-Change -Description "Enable Defender Archive & Email Scanning" -TestScript {
        $pref = Get-MpPrefSafe
        return ($pref.DisableArchiveScanning -eq $false -and $pref.DisableEmailScanning -eq $false)
    } -ChangeScript {
        $archiveResult = Set-MpPrefSafe -Params @{ DisableArchiveScanning = $false }
        $emailResult = Set-MpPrefSafe -Params @{ DisableEmailScanning = $false }
        return ($archiveResult -and $emailResult)
    }
}

function Set-ASRRules {
    Log "Configuring Attack Surface Reduction Rules" "INFO"
    
    Export-ASRState -Label "Before"
    
    $rulesToApply = if ($ASRRules.Count -gt 0) { 
        $ASRRules 
    } else { 
        $script:DefaultASRRules 
    }
    
    # Normalize ASR IDs: lowercase + dedupe to prevent case/dup misalignment
    $rulesToApply = $rulesToApply | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique
    
    Log "Applying $($rulesToApply.Count) ASR rules" "INFO"
    
    # Enable ASR rules (merge + verify Block actions with deterministic ordering)
    Do-Change -Description "Enable ASR Rules (merge + verify actions)" -TestScript {
        $preference = Get-MpPrefSafe
        $currentRules = @($preference.AttackSurfaceReductionRules_Ids | ForEach-Object { $_.ToLowerInvariant() })
        $currentActions = @($preference.AttackSurfaceReductionRules_Actions)
        
        # Build mapping of current rule states
        $ruleState = @{}
        for ($i = 0; $i -lt $currentRules.Count; $i++) {
            $ruleState[$currentRules[$i]] = [int]$currentActions[$i]
        }
        
        # Check if all our rules are present AND set to Block (1)
        $notBlockedRules = $rulesToApply | Where-Object { 
            -not $ruleState.ContainsKey($_) -or $ruleState[$_] -ne 1 
        }
        return $notBlockedRules.Count -eq 0
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ASR-Rules"
    } -ChangeScript {
        try {
            $preference = Get-MpPrefSafe
            $currentRules = @($preference.AttackSurfaceReductionRules_Ids | ForEach-Object { $_.ToLowerInvariant() })
            $currentActions = @($preference.AttackSurfaceReductionRules_Actions)
            
            # Build deterministic arrays for Set-MpPreference (preserves ID↔action alignment)
            $finalIds = New-Object System.Collections.Generic.List[string]
            $finalActs = New-Object System.Collections.Generic.List[int]
            
            # Start with current rules to preserve existing configuration
            for ($i = 0; $i -lt $currentRules.Count; $i++) {
                $finalIds.Add($currentRules[$i]) | Out-Null
                $finalActs.Add([int]$currentActions[$i]) | Out-Null
            }
            
            # Ensure our rules exist and are set to Block (1)
            foreach ($ruleId in $rulesToApply) {
                $idx = $finalIds.IndexOf($ruleId)
                if ($idx -ge 0) {
                    # Rule exists, set to Block
                    $finalActs[$idx] = 1
                } else {
                    # Rule doesn't exist, add it as Block
                    $finalIds.Add($ruleId) | Out-Null
                    $finalActs.Add(1) | Out-Null
                }
            }
            
            # Apply with guaranteed index alignment using retry wrapper
            $asrParams = @{
                AttackSurfaceReductionRules_Ids = $finalIds.ToArray()
                AttackSurfaceReductionRules_Actions = $finalActs.ToArray()
            }
            if (-not (Set-MpPrefSafe -Params $asrParams)) {
                throw "Failed to apply ASR rules after retries"
            }
            Log "ASR rules configured: $($rulesToApply.Count) enforced as Block, $($finalIds.Count) total rules" "SUCCESS"
            
            # Export post-change ASR state for review trail
            Export-ASRState -Label "After"
            
            return $true
        } catch { 
            Log "Failed to configure ASR rules: $_" "ERROR"
            return $false 
        }
    }
    
    # Export final ASR state regardless of outcome
    Export-ASRState -Label "Final"
}

function Set-BitLockerConfiguration {
    Log "Configuring BitLocker" "INFO"
    
    # Check BitLocker availability (SKU guard)
    if (-not (Get-Command Enable-BitLocker -ErrorAction SilentlyContinue)) {
        Log "BitLocker not available on this Windows SKU (Home edition detected)" "WARN"
        return
    }
    
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm -or -not $tpm.TpmReady) {
        Log "TPM not ready or available. BitLocker requires TPM." "WARN"
        return
    }
    
    $systemDrive = $env:SystemDrive
    $volume = Get-Volume -DriveLetter $systemDrive.TrimEnd(':') -ErrorAction SilentlyContinue
    if (-not $volume -or $volume.FileSystem -ne 'NTFS') {
        Log "System drive ($systemDrive) is not NTFS (found: $($volume.FileSystem)). BitLocker requires NTFS." "WARN"
        return
    }
    
    # Capture BitLocker status before changes
    if (-not $NoBackup) {
        try {
            $beforeStatus = Join-Path $script:BackupPath "BitLocker-Status-Before.txt"
            & manage-bde.exe -status | Out-File -FilePath $beforeStatus -Force
            Log "BitLocker status captured: $beforeStatus" "INFO"
        } catch {
            Log "Failed to capture BitLocker status before changes: $_" "WARN"
        }
    }
    
    # Set BitLocker policies for consistency across reboots
    Do-Change -Description "Configure BitLocker Group Policy Settings" -TestScript {
        $encMethodReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -ErrorAction SilentlyContinue
        $useTPMReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -ErrorAction SilentlyContinue
        return ($encMethodReg -and $encMethodReg.EncryptionMethodWithXtsOs -eq 7 -and 
                $useTPMReg -and $useTPMReg.UseTPM -eq 1)
    } -ChangeScript {
        # Pin XTS-AES 256 via policy for OS drive (7 = XTS-AES 256)
        $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EncryptionMethodWithXtsOs" -Value 7 -PropertyType "DWord"
        $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -Value 1 -PropertyType "DWord"
        return ($success1 -and $success2)
    }
    
    # Get system drive
    $systemDrive = $env:SystemDrive
    
    # Enable BitLocker with TPM and recovery key
    Do-Change -Description "Enable BitLocker on System Drive" -TestScript {
        $volume = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue
        if ($volume) {
            if ($volume.ProtectionStatus -eq 'On') {
                return $true
            } elseif ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 'Off') {
                Log "BitLocker volume is encrypted but protection is suspended/off - will attempt Resume-BitLocker" "WARN"
                return $false # Trigger change to resume protection
            }
        }
        return $false
    } -BackupScript {
        # Create recovery key backup directory
        $recoveryPath = Join-Path $script:BackupPath "BitLocker-Recovery"
        if (-not (Test-Path $recoveryPath)) {
            New-Item -Path $recoveryPath -ItemType Directory -Force | Out-Null
        }
        return $true
    } -ChangeScript {
        try {
            # Check if volume is already encrypted but protection is off
            $volume = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction SilentlyContinue
            if ($volume -and $volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 'Off') {
                Log "Resuming BitLocker protection on already encrypted volume" "INFO"
                Resume-BitLocker -MountPoint $systemDrive -ErrorAction Stop
            } else {
                Log "Enabling BitLocker with TPM protector" "INFO"
                # Enable BitLocker with TPM protector and used space only for faster encryption
                Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -ErrorAction Stop
            }
            
            # Add recovery password protector if not already present
            $volume = Get-BitLockerVolume -MountPoint $systemDrive
            if (-not ($volume.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')) {
                $keyProtector = Add-BitLockerKeyProtector -MountPoint $systemDrive -RecoveryPasswordProtector -ErrorAction Stop
                
                # Extract recovery password with enhanced metadata capture and null guards
                $recoveryPassword = $null
                if ($keyProtector.RecoveryPassword) {
                    $recoveryPassword = $keyProtector.RecoveryPassword
                } elseif ($keyProtector.KeyProtector -and $keyProtector.KeyProtector[0].RecoveryPassword) {
                    $recoveryPassword = $keyProtector.KeyProtector[0].RecoveryPassword
                } else {
                    # Try alternative path for different PowerShell versions
                    $recoveryPassword = $keyProtector.KeyProtector | Select-Object -ExpandProperty RecoveryPassword -ErrorAction SilentlyContinue
                }
                
                if ($recoveryPassword) {
                    # Backup recovery key with metadata
                    $recoveryPath = Join-Path $script:BackupPath "BitLocker-Recovery\RecoveryKey-$((Get-Date).ToString('yyyyMMdd-HHmmss')).txt"
                    $recoveryPassword | Out-File -FilePath $recoveryPath -Force
                    Log "BitLocker recovery key saved to: $recoveryPath" "SUCCESS"
                } else {
                    Log "Could not read recovery password from protector; verify protector state" "WARN"
                }
            }
            
            # Capture status after changes
            if (-not $NoBackup) {
                try {
                    $afterStatus = Join-Path $script:BackupPath "BitLocker-Status-After.txt"
                    & manage-bde.exe -status | Out-File -FilePath $afterStatus -Force
                    Log "BitLocker status captured after changes: $afterStatus" "INFO"
                } catch {
                    Log "Failed to capture BitLocker status after changes: $_" "WARN"
                }
            }
            
            return $true
        } catch {
            Log "Failed to enable BitLocker: $_" "ERROR"
            return $false
        }
    } -RequiresReboot
}

function Set-SMBHardening {
    Log "Configuring SMB hardening" "INFO"
    
    # Disable SMBv1 Client
    Do-Change -Description "Disable SMBv1 Client" -TestScript {
        $smb1Client = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -ErrorAction SilentlyContinue
        return ($smb1Client -and $smb1Client.State -eq "Disabled")
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" "SMB-Client"
    } -ChangeScript {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
            return $true
        } catch {
            Log "Failed to disable SMBv1 client: $_" "ERROR"
            return $false
        }
    } -RequiresReboot
    
    # Disable SMBv1 Server
    Do-Change -Description "Disable SMBv1 Server" -TestScript {
        $smb1Server = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -ErrorAction SilentlyContinue
        return ($smb1Server -and $smb1Server.State -eq "Disabled")
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB-Server"
    } -ChangeScript {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart
            return $true
        } catch {
            Log "Failed to disable SMBv1 server: $_" "ERROR"
            return $false
        }
    } -RequiresReboot
    
    # Enable SMB signing (server) - both Enable and Require for interop
    Do-Change -Description "Enable SMB Server Signing (Enable + Require)" -TestScript {
        $enableValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue
        $requireValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
        return ($enableValue -and $enableValue.EnableSecuritySignature -eq 1 -and
                $requireValue -and $requireValue.RequireSecuritySignature -eq 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB-ServerSigning"
    } -ChangeScript {
        $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -PropertyType "DWord"
        $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType "DWord"
        return ($success1 -and $success2)
    } -RequiresReboot
    
    # Enable SMB signing (client) - both Enable and Require for interop
    Do-Change -Description "Enable SMB Client Signing (Enable + Require)" -TestScript {
        $enableValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue
        $requireValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
        return ($enableValue -and $enableValue.EnableSecuritySignature -eq 1 -and
                $requireValue -and $requireValue.RequireSecuritySignature -eq 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "SMB-ClientSigning"
    } -ChangeScript {
        $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -PropertyType "DWord"
        $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType "DWord"
        return ($success1 -and $success2)
    } -RequiresReboot
    
    # Disable insecure SMB guest authentication if specified
    if ($DisableSMBGuest) {
        Do-Change -Description "Disable Insecure SMB Guest Authentication" -TestScript {
            $guestValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
            return ($guestValue -and $guestValue.AllowInsecureGuestAuth -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "SMB-GuestAuth"
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -PropertyType "DWord")
        }
        Log "DisableSMBGuest enabled: SMB guest fallback authentication disabled" "INFO"
    } else {
        Log "SMB guest auth enabled (use -DisableSMBGuest to disable insecure fallback)" "INFO"
    }
}

function Set-LSAProtection {
    Log "Configuring LSA Protection and Credential Guard" "INFO"
    
    # Enable LSA Protection
    Do-Change -Description "Enable LSA Protection" -TestScript {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.RunAsPPL -eq 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "LSA-Protection"
    } -ChangeScript {
        $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType "DWord"
        # Add boot-time key for enhanced persistence in some estates
        $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -Value 1 -PropertyType "DWord"
        return ($success1 -and $success2)
    } -RequiresReboot
    
    # Enable VBS and Credential Guard (complete configuration)
    Do-Change -Description "Enable VBS + Credential Guard" -TestScript {
        $deviceGuardValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
        $lsaValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
        
        return ($deviceGuardValue -and $deviceGuardValue.EnableVirtualizationBasedSecurity -eq 1 -and 
                $lsaValue -and $lsaValue.LsaCfgFlags -ge 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" "Credential-Guard"
    } -ChangeScript {
        try {
            # Check if virtualization features are available
            $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor -ErrorAction SilentlyContinue
            if (-not $hyperVFeature -or $hyperVFeature.State -ne "Enabled") {
                Log "Hyper-V virtualization not available. VBS/Credential Guard requires hardware virtualization support." "WARN"
                return $true  # Don't fail the entire process
            }
            
            $deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            
            # Enable VBS
            $success = Set-RegistryProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType "DWord"
            if (-not $success) { return $false }
            
            # Set platform security features (1=SecureBoot required, 3=SecureBoot+DMA protection)
            $success = Set-RegistryProperty -Path $deviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 1 -PropertyType "DWord"
            if (-not $success) { return $false }
            
            # Enable Credential Guard (1=Enabled, 2=Enabled without UEFI lock)
            $success = Set-RegistryProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -PropertyType "DWord"
            if (-not $success) { return $false }
            
            Log "VBS and Credential Guard enabled successfully" "SUCCESS"
            return $true
        } catch {
            Log "Failed to enable VBS/Credential Guard: $_" "ERROR"
            return $false
        }
    } -RequiresReboot
    
    # Optional HVCI (Hypervisor-protected Code Integrity)
    if ($EnableHVCI) {
        Do-Change -Description "Enable HVCI (Hypervisor-protected Code Integrity)" -TestScript {
            $hcviValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
            return ($hcviValue -and $hcviValue.Enabled -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" "HVCI"
        } -ChangeScript {
            $hvcip = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
            Set-RegistryProperty -Path $hvcip -Name "Enabled" -Value 1 -PropertyType "DWord"
        } -RequiresReboot
        
        Log "EnableHVCI specified: Memory integrity (HVCI) enabled" "INFO"
    } else {
        Log "HVCI disabled (use -EnableHVCI for hypervisor-protected code integrity)" "INFO"
    }
}

function Set-NTLMHardening {
    Log "Configuring NTLM/LM Protocol Hardening" "INFO"
    
    if ($HardenNTLM) {
        # Set LM Compatibility Level to 5 (NTLMv2 only)
        Do-Change -Description "Set NTLM Compatibility Level (NTLMv2 only)" -TestScript {
            $lmCompat = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
            return ($lmCompat -and $lmCompat.LmCompatibilityLevel -eq 5)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "NTLM-Hardening"
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -PropertyType "DWord")
        }
        
        # Disable LM Hash storage
        Do-Change -Description "Disable LM Hash Storage" -TestScript {
            $noLM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue
            return ($noLM -and $noLM.NoLMHash -eq 1)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -PropertyType "DWord")
        }
        
        # Restrict anonymous access
        Do-Change -Description "Restrict Anonymous LSA Access" -TestScript {
            $restrictAnon = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
            $restrictAnonSAM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
            return ($restrictAnon -and $restrictAnon.RestrictAnonymous -eq 1 -and
                    $restrictAnonSAM -and $restrictAnonSAM.RestrictAnonymousSAM -eq 1)
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
        
        # Set NTLM minimum session security (0x20080030 = NTLMv2 + 128-bit + key exchange + message integrity)
        Do-Change -Description "Set NTLM Client Session Security" -TestScript {
            $clientSec = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -ErrorAction SilentlyContinue
            return ($clientSec -and $clientSec.NtlmMinClientSec -eq 0x20080030)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value 0x20080030 -PropertyType "DWord")
        }
        
        Do-Change -Description "Set NTLM Server Session Security" -TestScript {
            $serverSec = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -ErrorAction SilentlyContinue
            return ($serverSec -and $serverSec.NtlmMinServerSec -eq 0x20080030)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Value 0x20080030 -PropertyType "DWord")
        }
        
        # Disable WDigest credential caching
        Do-Change -Description "Disable WDigest Credential Caching" -TestScript {
            $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
            return ($wdigest -and $wdigest.UseLogonCredential -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "WDigest-Settings"
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType "DWord")
        }
        
        # Restrict NTLM outbound traffic (1 = audit, 2 = deny)
        Do-Change -Description "Restrict NTLM Outbound Traffic to Deny" -TestScript {
            $restrictOutbound = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
            return ($restrictOutbound -and $restrictOutbound.RestrictSendingNTLMTraffic -eq 2)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2 -PropertyType "DWord")
        }
        
        Log "HardenNTLM enabled: NTLMv2 only, strong session security, anonymous restrictions, WDigest disabled, outbound NTLM restricted" "INFO"
    } else {
        Log "NTLM hardening disabled (use -HardenNTLM for authentication protocol hardening)" "INFO"
    }
}

function Set-RDPSecurity {
    Log "Configuring RDP security" "INFO"
    
    $terminalServicesPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    
    # Require Network Level Authentication (policy path)
    Do-Change -Description "Require RDP Network Level Authentication" -TestScript {
        $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "UserAuthentication" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.UserAuthentication -eq 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "RDP-Policy"
    } -ChangeScript {
        Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "UserAuthentication" -Value 1 -PropertyType "DWord"
    }
    
    # Disable drive redirection
    Do-Change -Description "Disable RDP Drive Redirection" -TestScript {
        $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "fDisableCdm" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.fDisableCdm -eq 1)
    } -ChangeScript {
        Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "fDisableCdm" -Value 1 -PropertyType "DWord"
    }
    
    # Disable printer redirection
    Do-Change -Description "Disable RDP Printer Redirection" -TestScript {
        $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "fDisableCpm" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.fDisableCpm -eq 1)
    } -ChangeScript {
        Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "fDisableCpm" -Value 1 -PropertyType "DWord"
    }
    
    # Disable clipboard redirection
    Do-Change -Description "Disable RDP Clipboard Redirection" -TestScript {
        $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "fDisableClip" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.fDisableClip -eq 1)
    } -ChangeScript {
        Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "fDisableClip" -Value 1 -PropertyType "DWord"
    }
    
    # Set minimum encryption level to High (also use policy path for consistency)
    Do-Change -Description "Set RDP High Encryption Level" -TestScript {
        $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.MinEncryptionLevel -eq 3)
    } -ChangeScript {
        Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "MinEncryptionLevel" -Value 3 -PropertyType "DWord"
    }
    
    # StrictRDP additional controls
    if ($StrictRDP) {
        # Force SSL (TLS) security layer (2 = SSL/TLS, 1 = RDP Security legacy)
        Do-Change -Description "Force RDP SSL Security Layer (StrictRDP)" -TestScript {
            $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "SecurityLayer" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.SecurityLayer -eq 2)
        } -ChangeScript {
            Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "SecurityLayer" -Value 2 -PropertyType "DWord"
        }
        
        # Disable UDP transport to prevent TLS bypass
        Do-Change -Description "Disable RDP UDP Transport (StrictRDP)" -TestScript {
            $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "fClientDisableUDP" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.fClientDisableUDP -eq 1)
        } -ChangeScript {
            Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "fClientDisableUDP" -Value 1 -PropertyType "DWord"
        }
        
        # Enable RDP Keep-Alive for connection stability
        Do-Change -Description "Enable RDP Keep-Alive (StrictRDP)" -TestScript {
            $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "KeepAliveEnable" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.KeepAliveEnable -eq 1)
        } -ChangeScript {
            Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "KeepAliveEnable" -Value 1 -PropertyType "DWord"
        }
        
        # Set RDP Keep-Alive interval (60 seconds)
        Do-Change -Description "Set RDP Keep-Alive Interval (60 sec)" -TestScript {
            $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "KeepAliveInterval" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.KeepAliveInterval -eq 60)
        } -ChangeScript {
            Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "KeepAliveInterval" -Value 60 -PropertyType "DWord"
        }
        
        Log "StrictRDP enabled: SSL security layer enforced, UDP transport disabled, keep-alive enabled" "INFO"
    } else {
        Log "StrictRDP disabled (use -StrictRDP for enhanced transport security)" "INFO"
    }
    
    # Always prompt for password upon connection (disable password bypasses)
    Do-Change -Description "Require RDP Password Prompt" -TestScript {
        $regValue = Get-ItemProperty -Path $terminalServicesPolicyPath -Name "fPromptForPassword" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.fPromptForPassword -eq 1)
    } -ChangeScript {
        Set-RegistryProperty -Path $terminalServicesPolicyPath -Name "fPromptForPassword" -Value 1 -PropertyType "DWord"
    }
    
    # Disable Remote Assistance (common lateral movement path)
    Do-Change -Description "Disable Remote Assistance (System Policy)" -TestScript {
        $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.fAllowToGetHelp -eq 0)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "RemoteAssistance"
    } -ChangeScript {
        return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -PropertyType "DWord")
    }
}

function Set-LocalAdminSecurity {
    Log "Minimizing local administrator group membership" "INFO"
    
    # Check if LocalAccounts module is available
    try {
        Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    } catch {
        Log "LocalAccounts module not available; skipping admin group review" "WARN"
        return
    }
    
    $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction SilentlyContinue
    if (-not $adminGroup) {
        Log "Could not access Administrators group" "ERROR"
        return
    }
    
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if (-not $adminMembers) {
        Log "Could not enumerate administrator group members" "WARN"
        return
    }
    
    Log "Current administrator group has $($adminMembers.Count) members:" "INFO"
    foreach ($member in $adminMembers) {
        Log "  - $($member.Name) ($($member.ObjectClass))" "INFO"
    }
    
    # Note: We don't automatically remove users from admin group for safety
    # This requires manual intervention or specific configuration
    Log "Manual review of administrator group membership recommended" "WARN"
    Log "Consider removing unnecessary accounts from the Administrators group" "WARN"
}

function Set-ExploitProtection {
    Log "Configuring Exploit Protection" "INFO"
    
    if ($ExploitProtectionXml -and (Test-Path $ExploitProtectionXml)) {
        Do-Change -Description "Import Exploit Protection Baseline" -TestScript {
            # Check if we can query current exploit protection settings
            try {
                Get-ProcessMitigation -System -ErrorAction Stop | Out-Null
                
                # Check if this XML hash was already applied
                $xmlHash = (Get-FileHash $ExploitProtectionXml -Algorithm SHA256).Hash
                $regPath = "HKLM:\SOFTWARE\HardenerLogs"
                $lastHash = (Get-ItemProperty -Path $regPath -Name "LastExploitProtectionXMLHash" -ErrorAction SilentlyContinue).LastExploitProtectionXMLHash
                
                if ($lastHash -eq $xmlHash) {
                    Log "Exploit Protection XML unchanged (hash: $($xmlHash.Substring(0,16))...)" "INFO"
                    return $true # Skip if same XML already applied
                }
                
                return $false # Apply if XML is new/different
            } catch {
                return $false # Apply on any error
            }
        } -BackupScript {
            try {
                $backupPath = Join-Path $script:BackupPath "ExploitProtection-Current.xml"
                Get-ProcessMitigation -System | Export-Clixml -Path $backupPath -Force
                return $true
            } catch {
                Log "Failed to backup current exploit protection settings: $_" "WARN"
                return $true # Continue anyway
            }
        } -ChangeScript {
            try {
                # Explicit scope for system-wide policy application
                Set-ProcessMitigation -System -PolicyFilePath $ExploitProtectionXml
                
                # Store XML hash to avoid reapplying unchanged files
                $xmlHash = (Get-FileHash $ExploitProtectionXml -Algorithm SHA256).Hash
                $regPath = "HKLM:\SOFTWARE\HardenerLogs"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "LastExploitProtectionXMLHash" -Value $xmlHash
                
                Log "Exploit Protection baseline imported from: $ExploitProtectionXml" "SUCCESS"
                return $true
            } catch {
                Log "Failed to import exploit protection baseline: $_" "ERROR"
                return $false
            }
        }
    } else {
        Log "No Exploit Protection XML file specified or file not found" "INFO"
        Log "Consider using Windows Defender Exploit Guard baseline from Microsoft" "INFO"
    }
}

function Set-TLSHardening {
    Log "Configuring TLS/SSL hardening" "INFO"
    
    $baseProtocolPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    
    function Set-ProtocolState {
        param($ProtocolName, $Enabled, $DisabledByDefault)
        
        $regPath = "$baseProtocolPath\$ProtocolName"
        foreach ($type in @("Server", "Client")) {
            $fullPath = "$regPath\$type"
            $success1 = Set-RegistryProperty -Path $fullPath -Name "Enabled" -Value $Enabled -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path $fullPath -Name "DisabledByDefault" -Value $DisabledByDefault -PropertyType "DWord"
            if (-not ($success1 -and $success2)) {
                return $false
            }
        }
        return $true
    }
    
    # Disable SSL 2.0
    Do-Change -Description "Disable SSL 2.0" -TestScript {
        $regValue = Get-ItemProperty -Path "$baseProtocolPath\SSL 2.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.Enabled -eq 0)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" "TLS-Protocols"
    } -ChangeScript {
        return (Set-ProtocolState "SSL 2.0" 0 1)
    }
    
    # Disable SSL 3.0
    Do-Change -Description "Disable SSL 3.0" -TestScript {
        $regValue = Get-ItemProperty -Path "$baseProtocolPath\SSL 3.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.Enabled -eq 0)
    } -ChangeScript {
        return (Set-ProtocolState "SSL 3.0" 0 1)
    }
    
    # Disable TLS 1.0
    Do-Change -Description "Disable TLS 1.0" -TestScript {
        $regValue = Get-ItemProperty -Path "$baseProtocolPath\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.Enabled -eq 0)
    } -ChangeScript {
        return (Set-ProtocolState "TLS 1.0" 0 1)
    }
    
    # Disable TLS 1.1
    Do-Change -Description "Disable TLS 1.1" -TestScript {
        $regValue = Get-ItemProperty -Path "$baseProtocolPath\TLS 1.1\Server" -Name "Enabled" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.Enabled -eq 0)
    } -ChangeScript {
        return (Set-ProtocolState "TLS 1.1" 0 1)
    }
    
    # Explicitly enable TLS 1.2
    Do-Change -Description "Enable TLS 1.2" -TestScript {
        $regValue = Get-ItemProperty -Path "$baseProtocolPath\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.Enabled -eq 1)
    } -ChangeScript {
        return (Set-ProtocolState "TLS 1.2" 1 0)
    }
    
    # Explicitly enable TLS 1.3 (Windows 11/Server 2022+)
    Do-Change -Description "Enable TLS 1.3" -TestScript {
        $regValue = Get-ItemProperty -Path "$baseProtocolPath\TLS 1.3\Server" -Name "Enabled" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.Enabled -eq 1)
    } -ChangeScript {
        # TLS 1.3 may not be available on older systems
        try {
            return (Set-ProtocolState "TLS 1.3" 1 0)
        } catch {
            Log "TLS 1.3 not supported on this system version" "INFO"
            return $true  # Don't fail if TLS 1.3 isn't supported
        }
    }
    
    # .NET Framework TLS enforcement (EnforceNETTLS parameter)
    if ($EnforceNETTLS) {
        Do-Change -Description "Enforce .NET Framework Strong Crypto and TLS 1.2+" -TestScript {
            $paths = @(
                "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
            )
            
            foreach ($path in $paths) {
                $strongCrypto = Get-ItemProperty -Path $path -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
                $systemDefaultTLS = Get-ItemProperty -Path $path -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
                
                if (-not ($strongCrypto -and $strongCrypto.SchUseStrongCrypto -eq 1) -or
                    -not ($systemDefaultTLS -and $systemDefaultTLS.SystemDefaultTlsVersions -eq 1)) {
                    return $false
                }
            }
            return $true
        } -ChangeScript {
            $netPairs = @(
                @{Path="HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319";             Name="SchUseStrongCrypto";        Value=1},
                @{Path="HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319";             Name="SystemDefaultTlsVersions";  Value=1},
                @{Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"; Name="SchUseStrongCrypto";        Value=1},
                @{Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"; Name="SystemDefaultTlsVersions";  Value=1}
            )
            
            $success = $true
            $appliedCount = 0
            foreach ($pair in $netPairs) {
                # Check if .NET path exists to avoid errors in Preview mode or stripped runtimes
                if (Test-Path $pair.Path) {
                    $result = Set-RegistryProperty -Path $pair.Path -Name $pair.Name -Value $pair.Value -PropertyType "DWord"
                    if ($result) {
                        $appliedCount++
                        Log "Applied .NET TLS enforcement: $($pair.Path)\$($pair.Name)" "INFO"
                    } else {
                        $success = $false
                        Log "Failed .NET TLS enforcement: $($pair.Path)\$($pair.Name)" "WARN"
                    }
                } else {
                    Log "Skipped .NET TLS enforcement (path not found): $($pair.Path)" "INFO"
                }
            }
            
            if ($success -and $appliedCount -gt 0) {
                Log "EnforceNETTLS: $appliedCount .NET Framework paths configured for TLS 1.2+ and strong cryptography" "SUCCESS"
            } elseif ($appliedCount -eq 0) {
                Log "EnforceNETTLS: No .NET Framework paths found (may be a stripped runtime or Server Core)" "WARN"
            }
            return $success
        }
    } else {
        Log ".NET TLS enforcement disabled (use -EnforceNETTLS to force legacy .NET apps to use modern TLS)" "INFO"
    }
    
    # Cipher Suite Hardening
    if ($HardenCipherSuites) {
        Do-Change -Description "Configure Modern Cipher Suite Order (Policy)" -TestScript {
            $cipherOrder = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -ErrorAction SilentlyContinue
            # Check if modern cipher suites are configured (TLS_AES, TLS_CHACHA20, ECDHE suites)
            if ($cipherOrder -and $cipherOrder.Functions) {
                $cipherString = $cipherOrder.Functions
                return ($cipherString -match "TLS_AES" -or $cipherString -match "TLS_ECDHE")
            }
            return $false
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" "CipherSuite-Order"
        } -ChangeScript {
            # Modern cipher suite order prioritizing AEAD ciphers and forward secrecy
            # Note: Some entries (e.g., TLS_CHACHA20_POLY1305_SHA256) may be ignored on older Win10 builds
            $modernCiphers = @(
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256", 
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            )
            $cipherString = $modernCiphers -join ","
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherString -PropertyType "String")
        }
        
        # Also configure Local cipher suite order for standalone systems
        Do-Change -Description "Configure Modern Cipher Suite Order (Local)" -TestScript {
            $localCipherOrder = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -ErrorAction SilentlyContinue
            if ($localCipherOrder -and $localCipherOrder.Functions) {
                $cipherString = $localCipherOrder.Functions
                return ($cipherString -match "TLS_AES" -or $cipherString -match "TLS_ECDHE")
            }
            return $false
        } -ChangeScript {
            $modernCiphers = @(
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256", 
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            )
            $cipherString = $modernCiphers -join ","
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherString -PropertyType "String")
        }
        
        # Disable weak cipher suites
        $weakCiphers = @(
            "RC4 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128",
            "Triple DES 168", "DES 56/56", "NULL"
        )
        
        foreach ($cipher in $weakCiphers) {
            $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
            Do-Change -Description "Disable Weak Cipher: $cipher" -TestScript {
                $enabled = Get-ItemProperty -Path $cipherPath -Name "Enabled" -ErrorAction SilentlyContinue
                return ($enabled -and $enabled.Enabled -eq 0)
            } -ChangeScript {
                return (Set-RegistryProperty -Path $cipherPath -Name "Enabled" -Value 0 -PropertyType "DWord")
            }
        }
        
        # Disable MD5 hash algorithm
        Do-Change -Description "Disable MD5 Hash Algorithm" -TestScript {
            $md5Enabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -ErrorAction SilentlyContinue
            return ($md5Enabled -and $md5Enabled.Enabled -eq 0)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -Value 0 -PropertyType "DWord")
        }
        
        Log "HardenCipherSuites enabled: Modern cipher suites prioritized, weak ciphers (RC4, 3DES) disabled" "INFO"
    } else {
        Log "Cipher suite hardening disabled (use -HardenCipherSuites for modern crypto configuration)" "INFO"
    }
}

function Set-NetworkProtocolHardening {
    Log "Configuring Network Protocol Hardening" "INFO"
    
    # Disable LLMNR (Link-Local Multicast Name Resolution) if specified
    if ($DisableLLMNR) {
        Do-Change -Description "Disable LLMNR (Multicast DNS)" -TestScript {
            $llmnrValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
            return ($llmnrValue -and $llmnrValue.EnableMulticast -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "LLMNR-Policy"
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType "DWord")
        }
        Log "DisableLLMNR enabled: LLMNR multicast name resolution disabled" "INFO"
    } else {
        Log "LLMNR enabled (use -DisableLLMNR to disable multicast name resolution)" "INFO"
    }
    
    # Disable WPAD (Web Proxy Auto-Discovery) to prevent MitM attacks
    if ($DisableWPAD) {
        Do-Change -Description "Disable WPAD Auto-Detection" -TestScript {
            $autoDetect = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableAutoDetect" -ErrorAction SilentlyContinue
            $autoProxyCache = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableAutoProxyResultCache" -ErrorAction SilentlyContinue
            return ($autoDetect -and $autoDetect.EnableAutoDetect -eq 0 -and
                    $autoProxyCache -and $autoProxyCache.EnableAutoProxyResultCache -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" "WPAD-Settings"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableAutoDetect" -Value 0 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableAutoProxyResultCache" -Value 0 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
        Log "DisableWPAD enabled: WPAD auto-detection and proxy caching disabled" "INFO"
    } else {
        Log "WPAD enabled (use -DisableWPAD to prevent auto-proxy MitM attacks)" "INFO"
    }
    
    # Disable NetBIOS over TCP/IP on active network adapters
    if ($DisableNetBIOS) {
        Do-Change -Description "Disable NetBIOS over TCP/IP (Active Adapters)" -TestScript {
            try {
                $activeAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true -and $_.TcpipNetbiosOptions -ne $null }
                $enabledAdapters = $activeAdapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
                return ($enabledAdapters.Count -eq 0)
            } catch {
                return $false
            }
        } -BackupScript {
            try {
                $backupPath = Join-Path $script:BackupPath "NetBIOS-Adapters-Before.txt"
                $adapterInfo = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | 
                               Select-Object Description, SettingID, TcpipNetbiosOptions | Out-String
                $adapterInfo | Out-File -FilePath $backupPath -Force
                return $true
            } catch {
                Log "Failed to backup NetBIOS adapter configuration: $_" "WARN"
                return $true
            }
        } -ChangeScript {
            try {
                $activeAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true -and $_.TcpipNetbiosOptions -ne $null }
                $disabledCount = 0
                
                foreach ($adapter in $activeAdapters) {
                    try {
                        if ($adapter.TcpipNetbiosOptions -ne 2) {
                            $result = $adapter | Invoke-CimMethod -MethodName "SetTcpipNetbios" -Arguments @{ TcpipNetbiosOptions = 2 }
                            if ($result.ReturnValue -eq 0) {
                                $disabledCount++
                                Log "Disabled NetBIOS on adapter: $($adapter.Description)" "INFO"
                            } else {
                                Log "Failed to disable NetBIOS on adapter: $($adapter.Description) (Return: $($result.ReturnValue))" "WARN"
                            }
                        }
                    } catch {
                        Log "Exception disabling NetBIOS on adapter $($adapter.Description): $_" "WARN"
                    }
                }
                
                Log "NetBIOS disabled on $disabledCount active network adapters" "SUCCESS"
                return ($disabledCount -gt 0)
            } catch {
                Log "Failed to disable NetBIOS over TCP/IP: $_" "ERROR"
                return $false
            }
        }
        Log "DisableNetBIOS enabled: NetBIOS over TCP/IP disabled on active network adapters" "INFO"
    } else {
        Log "NetBIOS enabled (use -DisableNetBIOS to prevent NetBIOS name resolution attacks)" "INFO"
    }
}

function Set-PrintSpoolerHardening {
    Log "Configuring Print Spooler Security Hardening" "INFO"
    
    if ($HardenPrintSpooler) {
        # Restrict Point and Print driver installation to administrators
        Do-Change -Description "Restrict Point and Print Driver Installation" -TestScript {
            $restrictDriver = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue
            return ($restrictDriver -and $restrictDriver.RestrictDriverInstallationToAdministrators -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "PrintSpooler-PointAndPrint"
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -PropertyType "DWord")
        }
        
        # Disable warning and elevation prompts for Point and Print
        Do-Change -Description "Disable Point and Print Warning Bypasses" -TestScript {
            $noWarning = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -ErrorAction SilentlyContinue
            $updatePrompt = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -ErrorAction SilentlyContinue
            return ($noWarning -and $noWarning.NoWarningNoElevationOnInstall -eq 0 -and
                    $updatePrompt -and $updatePrompt.UpdatePromptSettings -eq 0)
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
        
        # Optional: Check if we should disable the Print Spooler service entirely
        $spoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
        if ($spoolerService) {
            Log "Print Spooler service detected - consider disabling if not required (especially on servers)" "WARN"
            Log "To disable: Set-Service -Name 'Spooler' -StartupType Disabled; Stop-Service -Name 'Spooler' -Force" "INFO"
        }
        
        Log "HardenPrintSpooler enabled: Point-and-Print restricted to administrators, warnings enforced" "INFO"
    } else {
        Log "Print Spooler hardening disabled (use -HardenPrintSpooler for PrintNightmare protection)" "INFO"
    }
}

function Set-WinRMHardening {
    Log "Configuring WinRM Security Hardening" "INFO"
    
    if ($HardenWinRM) {
        # Check if WinRM service exists
        $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
        if (-not $winrmService) {
            Log "WinRM service not found - skipping WinRM hardening" "INFO"
            return
        }
        
        # Disable unencrypted traffic
        Do-Change -Description "Disable WinRM Unencrypted Traffic" -TestScript {
            try {
                $config = & winrm get winrm/config/service | Out-String
                return ($config -match "AllowUnencrypted\s*=\s*false")
            } catch {
                return $false
            }
        } -BackupScript {
            try {
                $backupPath = Join-Path $script:BackupPath "WinRM-Config-Before.xml"
                & winrm get winrm/config | Out-File -FilePath $backupPath -Force
                return $true
            } catch {
                Log "Failed to backup WinRM configuration: $_" "WARN"
                return $true
            }
        } -ChangeScript {
            try {
                & winrm set winrm/config/service "@{AllowUnencrypted=`"false`"}" | Out-Null
                return $true
            } catch {
                Log "Failed to disable WinRM unencrypted traffic: $_" "ERROR"
                return $false
            }
        }
        
        # Disable Basic authentication
        Do-Change -Description "Disable WinRM Basic Authentication" -TestScript {
            try {
                $config = & winrm get winrm/config/service/auth | Out-String
                return ($config -match "Basic\s*=\s*false")
            } catch {
                return $false
            }
        } -ChangeScript {
            try {
                & winrm set winrm/config/service/auth "@{Basic=`"false`"}" | Out-Null
                return $true
            } catch {
                Log "Failed to disable WinRM basic auth: $_" "ERROR"
                return $false
            }
        }
        
        # Disable Digest authentication
        Do-Change -Description "Disable WinRM Digest Authentication" -TestScript {
            try {
                $config = & winrm get winrm/config/service/auth | Out-String
                return ($config -match "Digest\s*=\s*false")
            } catch {
                return $false
            }
        } -ChangeScript {
            try {
                & winrm set winrm/config/service/auth "@{Digest=`"false`"}" | Out-Null
                return $true
            } catch {
                Log "Failed to disable WinRM digest auth: $_" "ERROR"
                return $false
            }
        }
        
        # Set reasonable MaxEnvelopeSizekb
        Do-Change -Description "Set WinRM Max Envelope Size (8192KB)" -TestScript {
            try {
                $config = & winrm get winrm/config/service | Out-String
                return ($config -match "MaxEnvelopeSizekb\s*=\s*8192")
            } catch {
                return $false
            }
        } -ChangeScript {
            try {
                & winrm set winrm/config/service "@{MaxEnvelopeSizekb=`"8192`"}" | Out-Null
                return $true
            } catch {
                Log "Failed to set WinRM max envelope size: $_" "ERROR"
                return $false
            }
        }
        
        Log "HardenWinRM enabled: Unencrypted traffic, Basic, and Digest auth disabled" "INFO"
    } else {
        Log "WinRM hardening disabled (use -HardenWinRM to secure WinRM transport)" "INFO"
    }
    
    # Configure WinRM HTTPS-only listener if specified
    if ($WinRMHttpsOnly) {
        Do-Change -Description "Configure WinRM HTTPS-only listener" -TestScript {
            try {
                $cfg = & winrm enumerate winrm/config/listener | Out-String
                return (($cfg -match 'Transport = HTTPS') -and ($cfg -notmatch 'Transport = HTTP'))
            } catch {
                return $false
            }
        } -BackupScript {
            try {
                $backupPath = Join-Path $script:BackupPath "WinRM-Listeners-Before.txt"
                & winrm enumerate winrm/config/listener | Out-File -FilePath $backupPath -Force
                return $true
            } catch {
                Log "Failed to backup WinRM listeners: $_" "WARN"
                return $true
            }
        } -ChangeScript {
            try {
                if ([string]::IsNullOrWhiteSpace($WinRMThumbprint)) {
                    throw "WinRMThumbprint is required when using -WinRMHttpsOnly."
                }

                # Remove any HTTP listener
                try { 
                    & winrm delete winrm/config/listener?Address=*+Transport=HTTP 2>$null | Out-Null 
                    Log "Removed HTTP listener" "INFO"
                } catch {
                    Log "No HTTP listener to remove or removal failed" "INFO"
                }

                # Ensure HTTPS listener exists with the provided cert
                $cfg = & winrm enumerate winrm/config/listener | Out-String
                if ($cfg -notmatch 'Transport = HTTPS') {
                    & winrm create winrm/config/listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`";CertificateThumbprint=`"$WinRMThumbprint`"}" | Out-Null
                    Log "Created HTTPS listener with certificate thumbprint" "SUCCESS"
                } else {
                    # Update thumbprint if different
                    & winrm set winrm/config/listener?Address=*+Transport=HTTPS "@{CertificateThumbprint=`"$WinRMThumbprint`"}" | Out-Null
                    Log "Updated HTTPS listener certificate thumbprint" "INFO"
                }

                # Harden client/service auth surface further
                & winrm set winrm/config/service/auth "@{Basic=`"false`";Digest=`"false`"}" | Out-Null
                & winrm set winrm/config/service "@{AllowUnencrypted=`"false`"}" | Out-Null
                
                return $true
            } catch {
                Log "Failed to configure WinRM HTTPS-only: $_" "ERROR"
                return $false
            }
        }
        Log "WinRMHttpsOnly enabled: HTTP listener removed, HTTPS listener enforced with cert $($WinRMThumbprint.Substring(0,8))..." "INFO"
    }
}

function Set-WebClientService {
    Log "Configuring WebClient (WebDAV) Service" "INFO"
    
    if ($DisableWebClient) {
        Do-Change -Description "Disable WebClient service" -TestScript {
            $svc = Get-Service -Name "WebClient" -ErrorAction SilentlyContinue
            return ($svc -and $svc.StartType -eq 'Disabled' -and $svc.Status -ne 'Running')
        } -BackupScript {
            try {
                $backupPath = Join-Path $script:BackupPath "WebClient-Service-Before.txt"
                Get-Service WebClient | Format-List * | Out-File -FilePath $backupPath -Force
                return $true
            } catch {
                Log "Failed to backup WebClient service state: $_" "WARN"
                return $true
            }
        } -ChangeScript {
            try {
                Set-Service -Name WebClient -StartupType Disabled -ErrorAction Stop
                if ((Get-Service WebClient).Status -eq 'Running') {
                    Stop-Service WebClient -Force -ErrorAction Stop
                    Log "Stopped running WebClient service" "INFO"
                }
                return $true
            } catch {
                Log "Failed to disable/stop WebClient: $_" "ERROR"
                return $false
            }
        }
        Log "DisableWebClient enabled: WebClient service disabled to reduce WebDAV attack surface" "INFO"
    } else {
        Log "WebClient not disabled (use -DisableWebClient to reduce WebDAV attack surface)" "INFO"
    }
}

function Set-AutoRunHardening {
    Log "Configuring AutoRun/AutoPlay Hardening" "INFO"
    
    if ($DisableAutoRun) {
        # Disable AutoRun for all drive types (255 = all drive types)
        Do-Change -Description "Disable AutoRun for All Drive Types" -TestScript {
            $autoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            return ($autoRun -and $autoRun.NoDriveTypeAutoRun -eq 255)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AutoRun-Policies"
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType "DWord")
        }
        
        # Disable AutoRun completely
        Do-Change -Description "Disable AutoRun Globally" -TestScript {
            $noAutoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -ErrorAction SilentlyContinue
            return ($noAutoRun -and $noAutoRun.NoAutorun -eq 1)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -PropertyType "DWord")
        }
        
        # Disable AutoPlay via machine-wide policy (applies to all users)
        Do-Change -Description "Disable AutoPlay Machine-Wide Policy" -TestScript {
            $policyAutoPlay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableAutoplay" -ErrorAction SilentlyContinue
            return ($policyAutoPlay -and $policyAutoPlay.DisableAutoplay -eq 1)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableAutoplay" -Value 1 -PropertyType "DWord")
        }
        
        # Disable AutoPlay for non-volume devices policy
        Do-Change -Description "Disable AutoPlay for Non-Volume Devices Policy" -TestScript {
            $nonVolumePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -ErrorAction SilentlyContinue
            return ($nonVolumePolicy -and $nonVolumePolicy.NoAutoplayfornonVolume -eq 1)
        } -ChangeScript {
            return (Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -PropertyType "DWord")
        }
        
        Log "DisableAutoRun enabled: AutoRun and AutoPlay disabled for all drive types and users" "INFO"
    } else {
        Log "AutoRun/AutoPlay enabled (use -DisableAutoRun to prevent USB-based malware spread)" "INFO"
    }
}

function Set-PowerShellV2Removal {
    Log "Configuring PowerShell v2 Removal" "INFO"
    
    if ($RemovePSv2) {
        Do-Change -Description "Remove PowerShell v2 Engine" -TestScript {
            $psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction SilentlyContinue
            return ($psv2 -and ($psv2.State -eq "Disabled" -or $psv2.State -eq "DisabledWithPayloadRemoved"))
        } -BackupScript {
            try {
                $backupPath = Join-Path $script:BackupPath "PowerShellV2-Feature-Status.txt"
                $psv2Status = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2*" | Out-String
                $psv2Status | Out-File -FilePath $backupPath -Force
                return $true
            } catch {
                Log "Failed to backup PowerShell v2 feature status: $_" "WARN"
                return $true
            }
        } -ChangeScript {
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart -ErrorAction Stop
                Log "PowerShell v2 engine disabled successfully" "SUCCESS"
                return $true
            } catch {
                Log "Failed to disable PowerShell v2: $_" "ERROR"
                return $false
            }
        } -RequiresReboot
        
        # Also disable PowerShell v2 Root feature if present
        Do-Change -Description "Remove PowerShell v2 Root Feature" -TestScript {
            $psv2Root = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
            return (-not $psv2Root -or $psv2Root.State -eq "Disabled" -or $psv2Root.State -eq "DisabledWithPayloadRemoved")
        } -ChangeScript {
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction Stop
                return $true
            } catch {
                Log "PowerShell v2 Root feature not found or already disabled" "INFO"
                return $true
            }
        } -RequiresReboot
        
        Log "RemovePSv2 enabled: PowerShell v2 downgrade attack surface eliminated" "INFO"
    } else {
        Log "PowerShell v2 retained (use -RemovePSv2 to eliminate downgrade attack surface)" "INFO"
    }
}

function Set-PowerShellSecurity {
    Log "Configuring PowerShell security logging" "INFO"
    
    # Enable PowerShell Script Block Logging
    Do-Change -Description "Enable PowerShell Script Block Logging" -TestScript {
        $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.EnableScriptBlockLogging -eq 1)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "PowerShell-Logging"
    } -ChangeScript {
        Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType "DWord"
    }
    
    # Enable PowerShell Module Logging
    Do-Change -Description "Enable PowerShell Module Logging" -TestScript {
        $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.EnableModuleLogging -eq 1)
    } -ChangeScript {
        $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -PropertyType "DWord"
        
        # Enable logging for all modules
        $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -PropertyType "String"
        
        return ($success1 -and $success2)
    }
    
    # Enable PowerShell Transcription
    Do-Change -Description "Enable PowerShell Transcription" -TestScript {
        $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
        return ($regValue -and $regValue.EnableTranscripting -eq 1)
    } -ChangeScript {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        
        $success1 = Set-RegistryProperty -Path $regPath -Name "EnableTranscripting" -Value 1 -PropertyType "DWord"
        $success2 = Set-RegistryProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1 -PropertyType "DWord"
        
        # Set transcription output directory
        $transcriptPath = "C:\PSTranscripts"
        try {
            if (-not (Test-Path $transcriptPath)) {
                New-Item -Path $transcriptPath -ItemType Directory -Force | Out-Null
            }
            
            # Harden ACL: Administrators + SYSTEM only
            $acl = Get-Acl $transcriptPath
            $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
            $admin = New-Object System.Security.Principal.NTAccount('BUILTIN', 'Administrators')
            $system = New-Object System.Security.Principal.NTAccount('NT AUTHORITY', 'SYSTEM')
            $rules = @(
                New-Object System.Security.AccessControl.FileSystemAccessRule($admin, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'),
                New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            )
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            $rules | ForEach-Object { $acl.AddAccessRule($_) | Out-Null }
            Set-Acl -Path $transcriptPath -AclObject $acl
            Log "Hardened ACL on $transcriptPath (Admins + SYSTEM)" "SUCCESS"
        } catch {
            Log "Failed to create/harden PowerShell transcript directory: $_" "WARN"
        }
        
        $success3 = Set-RegistryProperty -Path $regPath -Name "OutputDirectory" -Value $transcriptPath -PropertyType "String"
        
        return ($success1 -and $success2 -and $success3)
    }
}

function Set-AuditPolicy {
    Log "Configuring Audit Policy" "INFO"
    
    # Enable audit policies using auditpol.exe with GUIDs (locale-immune)
    Do-Change -Description "Configure Security Audit Policies" -TestScript {
        # Check if audit policies are already configured using RAW output (locale-immune)
        try {
            $rawResult = & auditpol.exe /get /subcategory:"{0cce923f-69ae-11d9-bed3-505054503030}" /r 2>$null
            # RAW format uses hex mask: 0x1=Success, 0x2=Failure, 0x3=both
            return ($rawResult -match '(?i)0x3')
        } catch {
            return $false
        }
    } -BackupScript {
        try {
            $backupPath = Join-Path $script:BackupPath "AuditPolicy-Current.csv"
            & auditpol.exe /backup /file:$backupPath | Out-Null
            return $true
        } catch {
            Log "Failed to backup current audit policy: $_" "WARN"
            return $true
        }
    } -ChangeScript {
        try {
            $success = $true
            
            # Audit subcategories to enable (pure GUID list - collision-free, locale-immune)
            $auditsToEnable = @(
                '{0cce923f-69ae-11d9-bed3-505054503030}', # Logon
                '{0cce9236-69ae-11d9-bed3-505054503030}', # Logoff  
                '{0cce9237-69ae-11d9-bed3-505054503030}', # Account Lockout
                '{0cce9241-69ae-11d9-bed3-505054503030}', # Special Logon
                '{0cce9240-69ae-11d9-bed3-505054503030}', # Credential Validation
                '{0cce9242-69ae-11d9-bed3-505054503030}', # Kerberos Authentication Service
                '{0cce9243-69ae-11d9-bed3-505054503030}', # Kerberos Service Ticket Operations
                '{0cce9251-69ae-11d9-bed3-505054503030}', # DPAPI Activity
                '{0cce9233-69ae-11d9-bed3-505054503030}', # Sensitive Privilege Use
                '{0cce9232-69ae-11d9-bed3-505054503030}', # Security System Extension
                '{0cce9235-69ae-11d9-bed3-505054503030}', # System Integrity
                '{0cce9231-69ae-11d9-bed3-505054503030}', # IPSec Driver
                '{0cce9230-69ae-11d9-bed3-505054503030}', # Security State Change
                '{0cce922b-69ae-11d9-bed3-505054503030}', # File System
                '{0cce922e-69ae-11d9-bed3-505054503030}', # Registry
                '{0cce922d-69ae-11d9-bed3-505054503030}'  # Removable Storage
            )
            
            foreach ($guid in $auditsToEnable) {
                try {
                    & auditpol.exe /set /subcategory:"$guid" /success:enable /failure:enable | Out-Null
                    Log "Enabled audit policy for GUID: $guid" "INFO"
                } catch {
                    Log "Failed to enable audit policy for GUID $guid`: $_" "WARN"
                    $success = $false
                }
            }
            
            # Enable Process Creation (4688) with command line capture
            try {
                & auditpol.exe /set /subcategory:"{0cce922f-69ae-11d9-bed3-505054503030}" /success:enable /failure:disable | Out-Null
                Log "Enabled Process Creation auditing (4688)" "INFO"
                
                # Enable command line capture in 4688 events
                $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
                $cmdSuccess = Set-RegistryProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType "DWord"
                if ($cmdSuccess) {
                    Log "Enabled command line capture in 4688 events" "SUCCESS"
                } else {
                    Log "Failed to enable command line capture in 4688 events" "WARN"
                    $success = $false
                }
            } catch {
                Log "Failed to enable Process Creation auditing: $_" "WARN"
                $success = $false
            }
            
            return $success
        } catch {
            Log "Failed to configure audit policies: $_" "ERROR"
            return $false
        }
    }
}

function Start-HardeningProcess {
    Log "=== Windows Device Hardening Started ===" "INFO"
    
    try {
        # Initialize the script environment
        Initialize-Script
        
            Log "Executing hardening functions..." "INFO"
        
        Set-FirewallConfiguration
        Set-DefenderConfiguration
        Set-ASRRules
        Set-BitLockerConfiguration
        Set-SMBHardening
        Set-LSAProtection
        Set-NTLMHardening
        Set-RDPSecurity
        Set-LocalAdminSecurity
        Set-PowerShellV2Removal
        Set-PowerShellSecurity
        Set-ExploitProtection
        Set-TLSHardening
        Set-NetworkProtocolHardening
        Set-PrintSpoolerHardening
        Set-WinRMHardening
        Set-WebClientService
        Set-AutoRunHardening
        Set-AuditPolicy
        
            return (Show-FinalReport)
        
    } catch {
        Log "Critical error during hardening process: $_" "ERROR"
        $script:ErrorsEncountered++
        return (Show-FinalReport)   # still emit a summary if possible
    }
}

function Show-FinalReport {
    Log "=== Windows Device Hardening Completed ===" "INFO"
    Log "" "INFO"
    
    if (Test-PendingReboot) {
        $script:RebootRequired = $true
    }
    
    Log "SUMMARY:" "INFO"
    Log "  Changes Applied: $script:ChangesApplied" "INFO"
    Log "  Errors Encountered: $script:ErrorsEncountered" "INFO"
    Log "  Reboot Required: $(if ($script:RebootRequired) { 'YES' } else { 'NO' })" "INFO"
    Log "" "INFO"
    
    if (-not $NoBackup) {
        Log "Backup Location: $script:BackupPath" "INFO"
    }
    Log "Log File: $script:LogFile" "INFO"
    
    try {
        $summary = [PSCustomObject]@{
            Version = "1.2.7"
            Timestamp = (Get-Date).ToString("o")
            ComputerName = $env:COMPUTERNAME
            Parameters = @{
                Preview = $Preview.IsPresent
                NoBackup = $NoBackup.IsPresent  
                StrictRDP = $StrictRDP.IsPresent
                EnableHVCI = $EnableHVCI.IsPresent
                QuietFirewall = $QuietFirewall.IsPresent
                EnforceNETTLS = $EnforceNETTLS.IsPresent
                EnableCFA = $EnableCFA.IsPresent
                DisableLLMNR = $DisableLLMNR.IsPresent
                DisableSMBGuest = $DisableSMBGuest.IsPresent
                HardenWinRM = $HardenWinRM.IsPresent
                HardenNTLM = $HardenNTLM.IsPresent
                HardenPrintSpooler = $HardenPrintSpooler.IsPresent
                DisableAutoRun = $DisableAutoRun.IsPresent
                RemovePSv2 = $RemovePSv2.IsPresent
                HardenCipherSuites = $HardenCipherSuites.IsPresent
                DisableWPAD = $DisableWPAD.IsPresent
                DisableNetBIOS = $DisableNetBIOS.IsPresent
                WinRMHttpsOnly = $WinRMHttpsOnly.IsPresent
                WinRMThumbprint = $WinRMThumbprint
                DisableWebClient = $DisableWebClient.IsPresent
                ASRRulesCount = $ASRRules.Count
                ExploitProtectionXml = $ExploitProtectionXml
            }
            Results = @{
                ChangesApplied = $script:ChangesApplied
                ErrorsEncountered = $script:ErrorsEncountered
                RebootRequired = $script:RebootRequired
                PendingRebootDetected = (Test-PendingReboot)
            }
            Paths = @{
                BackupLocation = if (-not $NoBackup) { $script:BackupPath } else { $null }
                LogFile = $script:LogFile
            }
        }
        
        $jsonPath = Join-Path $script:LogPath "DeviceHardener-Summary.json"
        $summary | ConvertTo-Json -Depth 4 | Out-File $jsonPath -Encoding UTF8 -Force
        Log "JSON summary written to: $jsonPath" "INFO"
    } catch {
        Log "Failed to generate JSON summary: $_" "WARN"
    }
    
    Log "" "INFO"
    
    # Operational guidance
    Log "OPERATIONAL GUIDANCE:" "INFO"
    Log "1. Testing: Verify system functionality after applying changes" "INFO"
    Log "2. Monitoring: Review Windows Event Logs for security events" "INFO"
    Log "3. Maintenance: Regularly update Windows Defender definitions" "INFO"
    Log "4. Compliance: Document changes for audit and compliance purposes" "INFO"
    Log "" "INFO"
    
    # Exception handling guidance
    if ($script:ErrorsEncountered -gt 0) {
        Log "ERROR HANDLING:" "WARN"
        Log "- Review error messages in the log file" "WARN"
        Log "- Some features may not be available on this system" "WARN"
        Log "- Consider manual configuration for failed items" "WARN"
        Log "" "WARN"
    }
    
    if ($script:RebootRequired) {
        Log "REBOOT REQUIRED:" "WARN"
        Log "Some changes require a system restart to take effect." "WARN"
        Log "Please restart the system when convenient." "WARN"
    }
    
    Log "TELEMETRY INTEGRATION:" "INFO"
    Log "- PowerShell logs: Windows Event Log (Application and Services Logs)" "INFO"
    Log "- Defender events: Windows Event Log (Applications and Services Logs > Microsoft > Windows > Windows Defender)" "INFO"
    Log "- Firewall events: Windows Event Log (Applications and Services Logs > Microsoft > Windows > Windows Firewall With Advanced Security)" "INFO"
    Log "" "INFO"
    
    Log "Windows Device Hardening process completed." "SUCCESS"
    
    # Stop inline transcript if it was started
    try { 
        Stop-Transcript | Out-Null 
    } catch { 
        # Transcript may not be running
    }
    
    return $jsonPath
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $Preview) {
            try {
                    if (-not (Test-Path $script:LogPath)) {
                    New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
                }
                $transcriptPath = Join-Path $script:LogPath ("Hardener-Transcript-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
                Start-Transcript -Path $transcriptPath -Force | Out-Null
                Log "Started inline transcript: $transcriptPath" "INFO"
            } catch { 
                Log "Could not start inline transcript: $_" "WARN" 
            }
        }
        
        $summaryPath = Start-HardeningProcess
        
        $exitCode = if ($script:ErrorsEncountered -gt 0) { 1 }
                    elseif ($script:RebootRequired)      { 3010 }
                    else                                  { 0 }
        
        if ($summaryPath) {
            Write-Host $summaryPath
        }
        
        exit $exitCode
    } catch {
        Log "Critical script failure: $_" "ERROR"
        exit 1
    }
}