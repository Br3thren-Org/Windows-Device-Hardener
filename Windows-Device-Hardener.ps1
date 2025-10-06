#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Endpoint Hardener Complete v2.0.0 - Unified CISA/NSA Security Baseline
    
.DESCRIPTION
    Complete Windows security hardening solution combining the core Windows-Device-Hardener
    with all CISA/NSA enhancement modules into a single deployable script.
    
    Features:
    - Quick/Standard/Maximum security presets
    - Enterprise deployment ready (Intune/SCCM/RMM)
    - Complete CISA/NSA compliance controls
    - Backup/restore capabilities
    - Comprehensive audit logging
    - Hardware security validation
    - Network protocol hardening
    - Certificate and PKI security
    - Enhanced Windows services security
    - Boot security and TPM validation
    
.PARAMETER SecurityLevel
    Security hardening level: Quick, Standard, or Maximum (default: Standard)
    
.PARAMETER Preview
    Show planned changes without applying them
    
.PARAMETER NoBackup
    Skip backup operations to speed up execution
    
.PARAMETER Silent
    Suppress console output (useful for enterprise deployment)
    
.PARAMETER LogOnly
    Log to file only, suppress console output
    
.PARAMETER CustomConfig
    Path to JSON configuration file for advanced customization
    
.PARAMETER DisableIPv6
    Completely disable IPv6 protocol stack (use with caution)
    
.PARAMETER EnterpriseMode
    Enable enterprise-specific hardening (domain-joined systems)
    
.PARAMETER StandaloneMode
    Enable standalone workstation hardening (non-domain systems)
    
.PARAMETER ComplianceReport
    Generate detailed compliance report in JSON/HTML format
    
.PARAMETER RollbackMode
    Restore system from previous hardening backup
    
.PARAMETER ASRRules
    Custom ASR rule GUIDs (comma-separated)
    
.PARAMETER ExploitProtectionXml
    Path to custom Exploit Protection XML configuration
    
.PARAMETER WinRMThumbprint
    Certificate thumbprint for WinRM HTTPS configuration
    
.EXAMPLE
    .\Windows-Endpoint-Hardener-Complete.ps1
    Apply Standard security level with default settings
    
.EXAMPLE
    .\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Quick -Preview
    Preview Quick security level changes
    
.EXAMPLE
    .\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Maximum -EnterpriseMode -Silent
    Apply Maximum security for enterprise domain-joined systems silently
    
.EXAMPLE
    .\Windows-Endpoint-Hardener-Complete.ps1 -StandaloneMode -ComplianceReport
    Harden standalone workstation and generate compliance report
    
.EXAMPLE
    .\Windows-Endpoint-Hardener-Complete.ps1 -RollbackMode
    Restore system from previous backup
    
.EXAMPLE
    # Enterprise RMM One-liner (PowerShell command line)
    powershell.exe -ExecutionPolicy Bypass -Command "& {Invoke-WebRequest -Uri 'https://your-server/Windows-Endpoint-Hardener-Complete.ps1' -UseBasicParsing | Invoke-Expression; .\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Standard -EnterpriseMode -Silent}"
    
.NOTES
    Author: Windows Endpoint Security Team
    Version: 2.0.0 - Complete CISA/NSA Integration
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
    
    Security Levels:
    - Quick: Essential hardening (15-30 minutes)
    - Standard: Comprehensive hardening (30-60 minutes) 
    - Maximum: Full CISA/NSA compliance (60+ minutes)
    
    CISA/NSA Compliance Features:
    - Boot security and hardware validation
    - Enhanced audit policy (complete coverage)
    - Certificate and PKI security hardening  
    - Windows services security optimization
    - Network protocol hardening
    - UAC and security options enhancement
    - Advanced cipher suite configuration
    - Enterprise deployment automation
    
    Exit Codes:
    0 = Success, no reboot required
    1 = Errors encountered during execution
    3010 = Success, reboot required
    3011 = Rollback completed successfully
    1601 = Invalid parameters or configuration
    1603 = Insufficient privileges or system incompatibility
#>

[CmdletBinding()]
param(
    [ValidateSet("Quick", "Standard", "Maximum")]
    [string]$SecurityLevel = "Standard",
    
    [switch]$Preview,
    [switch]$NoBackup,
    [switch]$Silent,
    [switch]$LogOnly,
    
    [string]$CustomConfig = "",
    
    [switch]$DisableIPv6,
    [switch]$EnterpriseMode,
    [switch]$StandaloneMode,
    [switch]$ComplianceReport,
    [switch]$RollbackMode,
    
    # Legacy compatibility parameters
    [string[]]$ASRRules = @(),
    [string]$ExploitProtectionXml = "",
    [string]$WinRMThumbprint = ""
)

# Script-level variables
$script:Version = "2.1.1"
$script:BackupPath = "$env:SystemDrive\HardeningBackup\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$script:LogPath = "$env:SystemDrive\HardeningLogs"
$script:LogFile = "$LogPath\EndpointHardener.log"
$script:RebootRequired = $false
$script:ChangesApplied = 0
$script:ErrorsEncountered = 0
$script:ComplianceResults = @{}
$script:StartTime = Get-Date

# Handle comma-separated ASR input
if ($ASRRules.Count -eq 1 -and $ASRRules[0] -match ',') {
    $ASRRules = $ASRRules[0] -split '\s*,\s*'
}

# Security Level Configurations
$script:SecurityLevelConfigs = @{
    Quick = @{
        Description = "Essential hardening for immediate security improvement"
        EstimatedTime = "15-30 minutes"
        Features = @(
            "BasicFirewall", "DefenderBasic", "ASRCore", "TLSBasic", "AuditBasic", "UACBasic"
        )
    }
    Standard = @{
        Description = "Comprehensive hardening for most environments"
        EstimatedTime = "30-60 minutes"
        Features = @(
            "BasicFirewall", "DefenderAdvanced", "ASRComplete", "BitLocker", "SMBHardening",
            "LSAProtection", "NTLMHardening", "RDPSecurity", "TLSAdvanced", "NetworkProtocols",
            "AuditAdvanced", "UACAdvanced", "ServicesHardening", "PrintSpooler", "PowerShellSecurity"
        )
    }
    Maximum = @{
        Description = "Full CISA/NSA compliance hardening"
        EstimatedTime = "60+ minutes"
        Features = @(
            "BasicFirewall", "DefenderMaximum", "ASRComplete", "BitLocker", "SMBHardening",
            "LSAProtection", "NTLMHardening", "RDPSecurity", "TLSMaximum", "NetworkProtocols",
            "AuditComplete", "UACMaximum", "ServicesHardening", "PrintSpooler", "PowerShellSecurity",
            "BootSecurity", "CertificateSecurity", "WinRMHardening", "AutoRunDisable", "CipherSuites",
            "CredentialGuard", "HVCI", "NetworkAdvanced"
        )
    }
}

# Default ASR Rules (Microsoft + CISA recommended)
$script:DefaultASRRules = @(
    "56a863a9-875e-4185-98a7-b882c64b5ce5", # Block abuse of exploited vulnerable signed drivers
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", # Block Adobe Reader from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", # Block all Office applications from creating child processes
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", # Block credential stealing from LSASS
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", # Block executable content from email and webmail
    "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet criteria
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc", # Block execution of potentially obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d", # Block JavaScript/VBScript from launching downloaded executable
    "3b576869-a4ec-4529-8536-b80a7769e899", # Block Office applications from creating executable content
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", # Block Office applications from injecting code
    "26190899-1602-49e8-8b27-eb1d0a1ce869", # Block Office communication applications from creating child processes
    "e6db77e5-3df2-4cf1-b95a-636979351e5b", # Block persistence through WMI event subscription
    "d1e49aac-8f56-4280-b9ba-993a6d77406c", # Block process creations from PSExec and WMI
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", # Block untrusted and unsigned processes from USB
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", # Block Win32 API calls from Office macros
    "c1db55ab-c21a-4637-bb3f-a12568109d35"  # Use advanced protection against ransomware
)

#region Core Utility Functions

function ConvertTo-SafeInt {
    param($Value)
    try { [int]$Value } catch { -1 }
}

function Test-TamperProtectionEnabled {
    try {
        $reg = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        $value = (Get-ItemProperty -Path $reg -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
        return (ConvertTo-SafeInt $value) -eq 1
    } catch {
        return $false
    }
}

function Test-PendingReboot {
    $rebootPending = $false
    $rebootPending = $rebootPending -or (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) -ne $null
    $rebootPending = $rebootPending -or (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue) -ne $null
    return $rebootPending
}

function Export-ASRState {
    param([string]$Path)
    try {
        $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
        $asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
        
        $asrState = @{
            Rules = $asrRules
            Actions = $asrActions
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        $asrState | ConvertTo-Json -Depth 3 | Out-File -FilePath "$Path\ASR-State.json" -Encoding UTF8
        return $true
    } catch {
        Log "Failed to export ASR state: $_" "WARN"
        return $false
    }
}

function Get-MpPrefSafe {
    $retryCount = 3
    for ($i = 1; $i -le $retryCount; $i++) {
        try {
            return Get-MpPreference -ErrorAction Stop
        } catch {
            if ($i -eq $retryCount) {
                Log "Failed to get Defender preferences after $retryCount attempts: $_" "ERROR"
                return $null
            }
            Log "Attempt $i failed, retrying Get-MpPreference..." "WARN"
            Start-Sleep -Seconds 2
        }
    }
}

function Set-MpPrefSafe {
    param([hashtable]$Preferences)
    
    $retryCount = 3
    for ($i = 1; $i -le $retryCount; $i++) {
        try {
            Set-MpPreference @Preferences -ErrorAction Stop
            return $true
        } catch {
            if ($i -eq $retryCount) {
                Log "Failed to set Defender preferences after $retryCount attempts: $_" "ERROR"
                return $false
            }
            Log "Attempt $i failed, retrying Set-MpPreference..." "WARN"
            Start-Sleep -Seconds 3
        }
    }
}

function Set-RegistryProperty {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$PropertyType = "String"
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        $existingProperty = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($existingProperty) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType | Out-Null
        }
        
        return $true
    } catch {
        Log "Registry operation failed for $Path\$Name : $_" "ERROR"
        return $false
    }
}

function Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output (unless suppressed)
    if (-not $Silent -and -not $LogOnly) {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "SUCCESS" { "Green" }
            "DEBUG" { "Cyan" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
    
    # File logging
    if (Test-Path $script:LogPath) {
        try {
            $logEntry | Add-Content -Path $script:LogFile -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
}

function Export-RegistryPath {
    param(
        [string]$RegPath,
        [string]$BackupName
    )

    try {
        # Check if registry path exists first
        $psPath = $RegPath -replace "HKEY_LOCAL_MACHINE", "HKLM:" -replace "HKEY_CURRENT_USER", "HKCU:"
        if (-not (Test-Path $psPath)) {
            Log "Registry path doesn't exist yet (will be created): $RegPath" "DEBUG"
            return $true  # Not an error - key will be created by change
        }

        $backupFile = Join-Path $script:BackupPath "$BackupName.reg"
        $exportCmd = "reg export `"$RegPath`" `"$backupFile`" /y"

        $result = cmd /c $exportCmd 2>&1
        if ($LASTEXITCODE -eq 0) {
            Log "Registry backup created: $backupFile" "DEBUG"
            return $true
        } else {
            Log "Registry export failed: $result" "WARN"
            return $true  # Don't block changes due to backup failures
        }
    } catch {
        Log "Registry backup error: $_" "WARN"
        return $true  # Don't block changes due to backup failures
    }
}

function Export-ServiceState {
    param([string]$ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            $serviceState = @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                StartType = $service.StartType
                Status = $service.Status
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            $backupFile = Join-Path $script:BackupPath "Service-$ServiceName.json"
            $serviceState | ConvertTo-Json | Out-File -FilePath $backupFile -Encoding UTF8
            return $true
        }
        return $false
    } catch {
        Log "Failed to export service state for $ServiceName`: $_" "WARN"
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
            Log "Creating backup for: $Description" "DEBUG"
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

#endregion

#region Security Configuration Functions

function Set-FirewallConfiguration {
    param([string[]]$Features)
    
    if ($Features -contains "BasicFirewall") {
        Log "Configuring Windows Firewall (Basic)" "INFO"
        
        Do-Change -Description "Enable Windows Firewall - Domain Profile" -TestScript {
            (Get-NetFirewallProfile -Profile Domain).Enabled -eq "True"
        } -ChangeScript {
            Set-NetFirewallProfile -Profile Domain -Enabled True
            return $?
        }
        
        Do-Change -Description "Enable Windows Firewall - Private Profile" -TestScript {
            (Get-NetFirewallProfile -Profile Private).Enabled -eq "True"
        } -ChangeScript {
            Set-NetFirewallProfile -Profile Private -Enabled True
            return $?
        }
        
        Do-Change -Description "Enable Windows Firewall - Public Profile" -TestScript {
            (Get-NetFirewallProfile -Profile Public).Enabled -eq "True"
        } -ChangeScript {
            Set-NetFirewallProfile -Profile Public -Enabled True
            return $?
        }
        
        # Enhanced firewall settings for Maximum security
        if ($SecurityLevel -eq "Maximum") {
            Do-Change -Description "Configure Firewall Logging - Domain" -TestScript {
                $profile = Get-NetFirewallProfile -Profile Domain
                return ($profile.LogAllowed -eq "True" -and $profile.LogBlocked -eq "True")
            } -ChangeScript {
                Set-NetFirewallProfile -Profile Domain -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 4096
                return $?
            }
            
            Do-Change -Description "Configure Firewall Logging - Private" -TestScript {
                $profile = Get-NetFirewallProfile -Profile Private
                return ($profile.LogAllowed -eq "True" -and $profile.LogBlocked -eq "True")
            } -ChangeScript {
                Set-NetFirewallProfile -Profile Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 4096
                return $?
            }
            
            Do-Change -Description "Configure Firewall Logging - Public" -TestScript {
                $profile = Get-NetFirewallProfile -Profile Public
                return ($profile.LogAllowed -eq "True" -and $profile.LogBlocked -eq "True")
            } -ChangeScript {
                Set-NetFirewallProfile -Profile Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 4096
                return $?
            }
        }
    }
}

function Set-DefenderConfiguration {
    param([string[]]$Features)
    
    if ($Features -contains "DefenderBasic") {
        Log "Configuring Windows Defender (Basic)" "INFO"
        
        Do-Change -Description "Enable Real-time Protection" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.DisableRealtimeMonitoring -eq $false)
        } -ChangeScript {
            return Set-MpPrefSafe @{ DisableRealtimeMonitoring = $false }
        }
        
        Do-Change -Description "Enable Cloud Protection" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.MAPSReporting -ne 0)
        } -ChangeScript {
            return Set-MpPrefSafe @{ MAPSReporting = 2 }
        }
    }
    
    if ($Features -contains "DefenderAdvanced") {
        Log "Configuring Windows Defender (Advanced)" "INFO"
        
        Do-Change -Description "Enable Behavior Monitoring" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.DisableBehaviorMonitoring -eq $false)
        } -ChangeScript {
            return Set-MpPrefSafe @{ DisableBehaviorMonitoring = $false }
        }
        
        Do-Change -Description "Enable IOAV Protection" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.DisableIOAVProtection -eq $false)
        } -ChangeScript {
            return Set-MpPrefSafe @{ DisableIOAVProtection = $false }
        }
        
        Do-Change -Description "Enable Script Scanning" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.DisableScriptScanning -eq $false)
        } -ChangeScript {
            return Set-MpPrefSafe @{ DisableScriptScanning = $false }
        }
        
        Do-Change -Description "Configure Archive Scanning" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.DisableArchiveScanning -eq $false)
        } -ChangeScript {
            return Set-MpPrefSafe @{ DisableArchiveScanning = $false }
        }
        
        Do-Change -Description "Configure Email Scanning" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.DisableEmailScanning -eq $false)
        } -ChangeScript {
            return Set-MpPrefSafe @{ DisableEmailScanning = $false }
        }
    }
    
    if ($Features -contains "DefenderMaximum") {
        Log "Configuring Windows Defender (Maximum)" "INFO"
        
        # Include all DefenderAdvanced settings plus additional hardening
        Set-DefenderConfiguration @("DefenderAdvanced")
        
        Do-Change -Description "Enable Network Protection" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.EnableNetworkProtection -eq 1)
        } -ChangeScript {
            return Set-MpPrefSafe @{ EnableNetworkProtection = 1 }
        }
        
        Do-Change -Description "Enable PUA Protection" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.PUAProtection -eq 1)
        } -ChangeScript {
            return Set-MpPrefSafe @{ PUAProtection = 1 }
        }
        
        Do-Change -Description "Set Cloud Block Level to High" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.CloudBlockLevel -eq 4)
        } -ChangeScript {
            return Set-MpPrefSafe @{ CloudBlockLevel = 4 }
        }
        
        Do-Change -Description "Set Cloud Extended Timeout" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.CloudExtendedTimeout -ge 50)
        } -ChangeScript {
            return Set-MpPrefSafe @{ CloudExtendedTimeout = 50 }
        }
    }
}

function Set-ASRRules {
    param([string[]]$Features)
    
    if ($Features -contains "ASRCore" -or $Features -contains "ASRComplete") {
        Log "Configuring Attack Surface Reduction Rules" "INFO"
        
        # Use custom rules if provided, otherwise use defaults
        $rulesToApply = if ($ASRRules.Count -gt 0) { $ASRRules } else { $script:DefaultASRRules }
        
        Do-Change -Description "Configure ASR Rules" -TestScript {
            $currentPref = Get-MpPrefSafe
            if (-not $currentPref) { return $false }
            
            $currentRules = $currentPref.AttackSurfaceReductionRules_Ids
            $currentActions = $currentPref.AttackSurfaceReductionRules_Actions
            
            foreach ($rule in $rulesToApply) {
                $index = $currentRules.IndexOf($rule)
                if ($index -eq -1 -or $currentActions[$index] -ne 1) {
                    return $false
                }
            }
            return $true
        } -BackupScript {
            return Export-ASRState -Path $script:BackupPath
        } -ChangeScript {
            try {
                $currentPref = Get-MpPrefSafe
                $existingRules = @($currentPref.AttackSurfaceReductionRules_Ids)
                $existingActions = @($currentPref.AttackSurfaceReductionRules_Actions)
                
                $newRules = [System.Collections.ArrayList]::new($existingRules)
                $newActions = [System.Collections.ArrayList]::new($existingActions)
                
                foreach ($rule in $rulesToApply) {
                    $index = $newRules.IndexOf($rule)
                    if ($index -eq -1) {
                        $newRules.Add($rule)
                        $newActions.Add(1)  # Block mode
                    } else {
                        $newActions[$index] = 1
                    }
                }
                
                return Set-MpPrefSafe @{
                    AttackSurfaceReductionRules_Ids = $newRules.ToArray()
                    AttackSurfaceReductionRules_Actions = $newActions.ToArray()
                }
            } catch {
                Log "ASR configuration failed: $_" "ERROR"
                return $false
            }
        }
    }
}

function Set-BitLockerConfiguration {
    param([string[]]$Features)
    
    if ($Features -contains "BitLocker") {
        Log "Configuring BitLocker Drive Encryption" "INFO"
        
        # Check if BitLocker is available
        $bitlockerStatus = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
        if (-not $bitlockerStatus) {
            Log "BitLocker not available on this system/SKU" "WARN"
            return
        }
        
        Do-Change -Description "Enable BitLocker for System Drive" -TestScript {
            try {
                $systemDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
                return ($systemDrive -and $systemDrive.ProtectionStatus -eq "On")
            } catch {
                return $false
            }
        } -BackupScript {
            try {
                $bitlockerInfo = Get-BitLockerVolume | ConvertTo-Json -Depth 3
                $bitlockerInfo | Out-File -FilePath "$script:BackupPath\BitLocker-Status.json" -Encoding UTF8
                return $true
            } catch {
                return $false
            }
        } -ChangeScript {
            try {
                # Check for TPM
                $tpm = Get-Tpm -ErrorAction SilentlyContinue
                if (-not ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady)) {
                    Log "TPM not available - using recovery password protector" "WARN"
                    Enable-BitLocker -MountPoint $env:SystemDrive -PasswordProtector
                } else {
                    Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector
                }
                return $true
            } catch {
                Log "BitLocker enable failed: $_" "ERROR"
                return $false
            }
        } -RequiresReboot
    }
}

function Set-TLSHardening {
    param([string[]]$Features)
    
    if ($Features -contains "TLSBasic") {
        Log "Configuring TLS Security (Basic)" "INFO"
        
        Do-Change -Description "Enable TLS 1.2 for .NET Framework" -TestScript {
            $schUseStrong = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $sysDefaultTls = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
            return ($schUseStrong -and $schUseStrong.SchUseStrongCrypto -eq 1 -and 
                    $sysDefaultTls -and $sysDefaultTls.SystemDefaultTlsVersions -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" "NET-TLS-Config"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
    }
    
    if ($Features -contains "TLSAdvanced" -or $Features -contains "TLSMaximum") {
        Log "Configuring TLS Security (Advanced)" "INFO"
        
        # Disable weak protocols
        $weakProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
        foreach ($protocol in $weakProtocols) {
            Do-Change -Description "Disable $protocol Client" -TestScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
                $enabled = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
                return ($enabled -and $enabled.Enabled -eq 0)
            } -BackupScript {
                Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" "SCHANNEL-Protocols"
            } -ChangeScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
                return Set-RegistryProperty -Path $regPath -Name "Enabled" -Value 0 -PropertyType "DWord"
            }
            
            Do-Change -Description "Disable $protocol Server" -TestScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
                $enabled = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
                return ($enabled -and $enabled.Enabled -eq 0)
            } -ChangeScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
                return Set-RegistryProperty -Path $regPath -Name "Enabled" -Value 0 -PropertyType "DWord"
            }
        }
        
        # Enable strong protocols
        $strongProtocols = @("TLS 1.2", "TLS 1.3")
        foreach ($protocol in $strongProtocols) {
            Do-Change -Description "Enable $protocol Client" -TestScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
                $enabled = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
                return ($enabled -and $enabled.Enabled -eq 1)
            } -ChangeScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
                $success1 = Set-RegistryProperty -Path $regPath -Name "Enabled" -Value 1 -PropertyType "DWord"
                $success2 = Set-RegistryProperty -Path $regPath -Name "DisabledByDefault" -Value 0 -PropertyType "DWord"
                return ($success1 -and $success2)
            }
            
            Do-Change -Description "Enable $protocol Server" -TestScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
                $enabled = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
                return ($enabled -and $enabled.Enabled -eq 1)
            } -ChangeScript {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
                $success1 = Set-RegistryProperty -Path $regPath -Name "Enabled" -Value 1 -PropertyType "DWord"
                $success2 = Set-RegistryProperty -Path $regPath -Name "DisabledByDefault" -Value 0 -PropertyType "DWord"
                return ($success1 -and $success2)
            }
        }
    }
}

function Set-AuditPolicy {
    param([string[]]$Features)
    
    if ($Features -contains "AuditBasic") {
        Log "Configuring Audit Policy (Basic)" "INFO"
        
        $basicAuditPolicies = @(
            @{ Category = "Account Logon"; Setting = "Success,Failure" },
            @{ Category = "Account Management"; Setting = "Success,Failure" },
            @{ Category = "Logon/Logoff"; Setting = "Success,Failure" },
            @{ Category = "Privilege Use"; Setting = "Success,Failure" }
        )
        
        foreach ($policy in $basicAuditPolicies) {
            Do-Change -Description "Configure Audit: $($policy.Category)" -TestScript {
                try {
                    $result = auditpol /get /category:"$($policy.Category)" /r | ConvertFrom-Csv
                    foreach ($subcategory in $result) {
                        if ($subcategory."Inclusion Setting" -notmatch "Success.*Failure|Failure.*Success") {
                            return $false
                        }
                    }
                    return $true
                } catch {
                    return $false
                }
            } -ChangeScript {
                try {
                    # auditpol requires /success and /failure as separate flags
                    $settingLower = $policy.Setting.ToLower()
                    if ($settingLower -eq "success,failure") {
                        $cmd = "auditpol /set /category:`"$($policy.Category)`" /success:enable /failure:enable"
                    } elseif ($settingLower -eq "success") {
                        $cmd = "auditpol /set /category:`"$($policy.Category)`" /success:enable /failure:disable"
                    } elseif ($settingLower -eq "failure") {
                        $cmd = "auditpol /set /category:`"$($policy.Category)`" /success:disable /failure:enable"
                    }
                    $result = cmd /c $cmd 2>&1
                    return $LASTEXITCODE -eq 0
                } catch {
                    return $false
                }
            }
        }
    }
    
    if ($Features -contains "AuditAdvanced") {
        Log "Configuring Audit Policy (Advanced)" "INFO"
        
        # Include basic policies plus additional coverage
        Set-AuditPolicy @("AuditBasic")
        
        $advancedAuditPolicies = @(
            @{ Category = "Detailed Tracking"; Setting = "Success" },
            @{ Category = "Policy Change"; Setting = "Success,Failure" },
            @{ Category = "System"; Setting = "Success,Failure" }
        )
        
        foreach ($policy in $advancedAuditPolicies) {
            Do-Change -Description "Configure Audit: $($policy.Category)" -TestScript {
                try {
                    $result = auditpol /get /category:"$($policy.Category)" /r | ConvertFrom-Csv
                    foreach ($subcategory in $result) {
                        $expectedSetting = $policy.Setting
                        if ($expectedSetting -eq "Success,Failure") {
                            if ($subcategory."Inclusion Setting" -notmatch "Success.*Failure|Failure.*Success") {
                                return $false
                            }
                        } elseif ($expectedSetting -eq "Success") {
                            if ($subcategory."Inclusion Setting" -notmatch "Success") {
                                return $false
                            }
                        }
                    }
                    return $true
                } catch {
                    return $false
                }
            } -ChangeScript {
                try {
                    # auditpol requires /success and /failure as separate flags
                    $settingLower = $policy.Setting.ToLower()
                    if ($settingLower -eq "success,failure") {
                        $cmd = "auditpol /set /category:`"$($policy.Category)`" /success:enable /failure:enable"
                    } elseif ($settingLower -eq "success") {
                        $cmd = "auditpol /set /category:`"$($policy.Category)`" /success:enable /failure:disable"
                    } elseif ($settingLower -eq "failure") {
                        $cmd = "auditpol /set /category:`"$($policy.Category)`" /success:disable /failure:enable"
                    }
                    $result = cmd /c $cmd 2>&1
                    return $LASTEXITCODE -eq 0
                } catch {
                    return $false
                }
            }
        }
    }
    
    if ($Features -contains "AuditComplete") {
        Log "Configuring Audit Policy (Complete - CISA/NSA)" "INFO"
        
        # Include all previous levels plus comprehensive coverage
        Set-AuditPolicy @("AuditAdvanced")
        
        # Enable command line auditing for process tracking
        Do-Change -Description "Enable Process Command Line Auditing" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.ProcessCreationIncludeCmdLine_Enabled -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "Process-Audit-Config"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType "DWord"
        }
        
        # Set audit log sizes
        Do-Change -Description "Configure Security Event Log Size" -TestScript {
            $logInfo = Get-WinEvent -ListLog Security
            return ($logInfo.MaximumSizeInBytes -ge 1073741824)  # 1GB
        } -ChangeScript {
            try {
                wevtutil sl Security /ms:1073741824  # 1GB
                return $LASTEXITCODE -eq 0
            } catch {
                return $false
            }
        }
    }
}

function Set-LSAProtection {
    param([string[]]$Features)
    
    if ($Features -contains "LSAProtection" -and $SecurityLevel -ne "Quick") {
        Log "Configuring LSA Protection" "INFO"
        
        Do-Change -Description "Enable LSA Protection (RunAsPPL)" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.RunAsPPL -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "LSA-Protection"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType "DWord"
        } -RequiresReboot
        
        Do-Change -Description "Disable WDigest Authentication" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.UseLogonCredential -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "WDigest-Config"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType "DWord"
        }
    }
}

function Set-SMBHardening {
    param([string[]]$Features)
    
    if ($Features -contains "SMBHardening") {
        Log "Configuring SMB Security Hardening" "INFO"
        
        Do-Change -Description "Enable SMB Client Signing" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "enablesecuritysignature" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.enablesecuritysignature -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" "SMB-Server-Config"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "enablesecuritysignature" -Value 1 -PropertyType "DWord"
        }
        
        Do-Change -Description "Require SMB Client Signing" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "requiresecuritysignature" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.requiresecuritysignature -eq 1)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "requiresecuritysignature" -Value 1 -PropertyType "DWord"
        } -RequiresReboot
        
        if ($SecurityLevel -eq "Maximum") {
            Do-Change -Description "Disable SMB1 Protocol" -TestScript {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
                return ($feature -and $feature.State -eq "Disabled")
            } -ChangeScript {
                try {
                    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                    return $true
                } catch {
                    return $false
                }
            } -RequiresReboot
        }
    }
}

function Set-RDPSecurity {
    param([string[]]$Features)
    
    if ($Features -contains "RDPSecurity") {
        Log "Configuring RDP Security" "INFO"
        
        Do-Change -Description "Enable Network Level Authentication" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.UserAuthentication -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" "RDP-Security-Config"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -PropertyType "DWord"
        }
        
        Do-Change -Description "Set RDP Security Layer" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.SecurityLayer -eq 2)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -PropertyType "DWord"
        }
        
        if ($SecurityLevel -eq "Maximum") {
            Do-Change -Description "Disable RDP UDP Transport" -TestScript {
                $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fEnableUdpTransport" -ErrorAction SilentlyContinue
                return ($regValue -and $regValue.fEnableUdpTransport -eq 0)
            } -ChangeScript {
                return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fEnableUdpTransport" -Value 0 -PropertyType "DWord"
            }
        }
    }
}

#endregion

#region CISA/NSA Enhancement Functions

function Set-BootSecurityHardening {
    param([string[]]$Features)
    
    if ($Features -contains "BootSecurity") {
        Log "Configuring Boot Security and Hardware Validation (CISA/NSA Standards)" "INFO"
        
        # Validate Secure Boot
        Do-Change -Description "Validate Secure Boot Configuration" -TestScript {
            try {
                $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                $bootPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
                return ($secureBootState -eq $true -and $bootPolicy -and $bootPolicy.UEFISecureBootEnabled -eq 1)
            } catch {
                Log "Secure Boot validation failed - may not be supported: $_" "WARN"
                return $false
            }
        } -ChangeScript {
            Log "Secure Boot must be enabled in UEFI firmware settings manually" "WARN"
            Log "This is a critical security requirement for CISA/NSA compliance" "WARN"
            $script:ComplianceResults["SecureBoot"] = "Manual configuration required"
            return $false
        }
        
        # Validate TPM
        Do-Change -Description "Validate TPM Configuration" -TestScript {
            try {
                $tpm = Get-Tpm -ErrorAction SilentlyContinue
                return ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled)
            } catch {
                return $false
            }
        } -ChangeScript {
            try {
                $tpm = Get-Tpm -ErrorAction SilentlyContinue
                if ($tpm -and $tpm.TpmPresent -and -not $tpm.TpmReady) {
                    Log "TPM present but not ready - attempting initialization" "INFO"
                    Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction Stop
                    return $true
                } else {
                    Log "TPM not present or available - required for CISA/NSA compliance" "WARN"
                    $script:ComplianceResults["TPM"] = "Not available or not ready"
                    return $false
                }
            } catch {
                Log "TPM initialization failed: $_" "ERROR"
                return $false
            }
        }
        
        # Validate HVCI if requested
        if ($Features -contains "HVCI") {
            Do-Change -Description "Enable Hypervisor-Protected Code Integrity (HVCI)" -TestScript {
                $hvciReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
                $hvciPol = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
                return ($hvciReg -and $hvciReg.EnableVirtualizationBasedSecurity -eq 1 -and 
                        $hvciPol -and $hvciPol.Enabled -eq 1)
            } -BackupScript {
                Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" "DeviceGuard-HVCI"
            } -ChangeScript {
                $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType "DWord"
                $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -PropertyType "DWord"
                return ($success1 -and $success2)
            } -RequiresReboot
        }
    }
}

function Set-UACAndSecurityOptions {
    param([string[]]$Features)
    
    if ($Features -contains "UACBasic") {
        Log "Configuring UAC (Basic)" "INFO"
        
        Do-Change -Description "Enable UAC - Admin Approval Mode" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.EnableLUA -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "UAC-Settings"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -PropertyType "DWord"
        }
    }
    
    if ($Features -contains "UACAdvanced" -or $Features -contains "UACMaximum") {
        Log "Configuring UAC and Security Options (CISA/NSA Standards)" "INFO"
        
        # Include basic UAC
        Set-UACAndSecurityOptions @("UACBasic")
        
        Do-Change -Description "UAC - Admin Approval Mode for Built-in Admin" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.FilterAdministratorToken -eq 1)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -PropertyType "DWord"
        }
        
        Do-Change -Description "UAC - Elevate UIAccess Applications in Secure Locations" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUIADesktopToggle" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.EnableUIADesktopToggle -eq 0)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUIADesktopToggle" -Value 0 -PropertyType "DWord"
        }
        
        Do-Change -Description "UAC - Behavior of Elevation Prompt for Administrators" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.ConsentPromptBehaviorAdmin -eq 2)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -PropertyType "DWord"
        }
        
        Do-Change -Description "UAC - Behavior of Elevation Prompt for Standard Users" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.ConsentPromptBehaviorUser -eq 1)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 1 -PropertyType "DWord"
        }
    }
}

function Set-WindowsServicesHardening {
    param([string[]]$Features)
    
    if ($Features -contains "ServicesHardening") {
        Log "Configuring Windows Services Security (CISA/NSA Standards)" "INFO"
        
        $dangerousServices = @(
            @{ Name = "Fax"; DisplayName = "Fax Service"; Reason = "Unnecessary service with security vulnerabilities" },
            @{ Name = "TapiSrv"; DisplayName = "Telephony API Service"; Reason = "Legacy service, potential attack vector" },
            @{ Name = "RemoteRegistry"; DisplayName = "Remote Registry"; Reason = "Allows remote registry access" },
            @{ Name = "Browser"; DisplayName = "Computer Browser"; Reason = "Legacy NetBIOS service" },
            @{ Name = "TrkWks"; DisplayName = "Distributed Link Tracking Client"; Reason = "Information disclosure risk" },
            @{ Name = "RasAuto"; DisplayName = "Remote Access Auto Connection Manager"; Reason = "Automatic connection security risk" }
        )
        
        foreach ($service in $dangerousServices) {
            Do-Change -Description "Disable $($service.DisplayName)" -TestScript {
                $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
                return ($svc -eq $null -or $svc.StartType -eq 'Disabled')
            } -BackupScript {
                $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
                if ($svc) {
                    Export-ServiceState -ServiceName $service.Name
                }
                return $true
            } -ChangeScript {
                try {
                    $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
                    if ($svc) {
                        Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                        Set-Service -Name $service.Name -StartupType Disabled
                        Log "Disabled $($service.DisplayName) - Reason: $($service.Reason)" "INFO"
                    }
                    return $true
                } catch {
                    Log "Failed to disable $($service.DisplayName): $_" "ERROR"
                    return $false
                }
            }
        }
    }
}

function Set-CertificateSecurityHardening {
    param([string[]]$Features)
    
    if ($Features -contains "CertificateSecurity") {
        Log "Configuring Certificate and PKI Security (CISA/NSA Standards)" "INFO"
        
        Do-Change -Description "Disable Weak Certificate Hash Algorithms" -TestScript {
            $md5Reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -ErrorAction SilentlyContinue
            $sha1Reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Name "Enabled" -ErrorAction SilentlyContinue
            return ($md5Reg -and $md5Reg.Enabled -eq 0 -and $sha1Reg -and $sha1Reg.Enabled -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes" "Certificate-Hashes"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -Value 0 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Name "Enabled" -Value 0 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
        
        Do-Change -Description "Enable Strong Certificate Validation" -TestScript {
            $certReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -Name "MaxUrlRetrievalByteCount" -ErrorAction SilentlyContinue
            $certReg2 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -Name "MaxUrlRetrievalTimeout" -ErrorAction SilentlyContinue
            return ($certReg -and $certReg.MaxUrlRetrievalByteCount -le 1048576 -and
                    $certReg2 -and $certReg2.MaxUrlRetrievalTimeout -le 15000)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" "Certificate-Validation"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -Name "MaxUrlRetrievalByteCount" -Value 1048576 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -Name "MaxUrlRetrievalTimeout" -Value 15000 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
    }
}

function Set-EnhancedNetworkSecurity {
    param([string[]]$Features)
    
    if ($Features -contains "NetworkAdvanced") {
        Log "Configuring Enhanced Network Security (CISA/NSA Standards)" "INFO"
        
        if ($DisableIPv6) {
            Do-Change -Description "Disable IPv6 Protocol Stack" -TestScript {
                $ipv6Reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
                return ($ipv6Reg -and $ipv6Reg.DisabledComponents -eq 0xFF)
            } -BackupScript {
                Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "IPv6-Settings"
            } -ChangeScript {
                return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF -PropertyType "DWord"
            } -RequiresReboot
        }
        
        # TCP/IP Stack Hardening
        Do-Change -Description "Enable TCP/IP Stack Hardening - SYN Attack Protection" -TestScript {
            $tcpReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -ErrorAction SilentlyContinue
            return ($tcpReg -and $tcpReg.SynAttackProtect -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TCP-IP-Security"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -Value 1 -PropertyType "DWord"
        }
        
        Do-Change -Description "Disable NetBIOS over TCP/IP" -TestScript {
            $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
            foreach ($adapter in $adapters) {
                if ($adapter.TcpipNetbiosOptions -ne 2) {
                    return $false
                }
            }
            return $true
        } -ChangeScript {
            try {
                $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
                foreach ($adapter in $adapters) {
                    $adapter.SetTcpipNetbios(2)  # Disable NetBIOS over TCP/IP
                }
                return $true
            } catch {
                return $false
            }
        } -RequiresReboot
        
        # Disable LLMNR
        Do-Change -Description "Disable LLMNR (Link-Local Multicast Name Resolution)" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.EnableMulticast -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "LLMNR-Config"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType "DWord"
        }
        
        # Disable WPAD
        Do-Change -Description "Disable WPAD (Web Proxy Auto-Discovery)" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.WpadOverride -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "WPAD-Config"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -PropertyType "DWord"
        }
    }
}

function Set-PowerShellSecurity {
    param([string[]]$Features)
    
    if ($Features -contains "PowerShellSecurity") {
        Log "Configuring PowerShell Security" "INFO"
        
        Do-Change -Description "Enable PowerShell Script Block Logging" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.EnableScriptBlockLogging -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "PowerShell-Security"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
        
        Do-Change -Description "Enable PowerShell Module Logging" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.EnableModuleLogging -eq 1)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -PropertyType "DWord"
        }
        
        Do-Change -Description "Enable PowerShell Transcription" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.EnableTranscripting -eq 1)
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -PropertyType "DWord"
            $success3 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts" -PropertyType "String"
            return ($success1 -and $success2 -and $success3)
        }
        
        # Remove PowerShell v2 for Maximum security
        if ($SecurityLevel -eq "Maximum") {
            Do-Change -Description "Remove PowerShell v2 Engine" -TestScript {
                $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
                return ($psv2Feature -and $psv2Feature.State -eq "Disabled")
            } -ChangeScript {
                try {
                    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
                    return $true
                } catch {
                    return $false
                }
            } -RequiresReboot
        }
    }
}

function Set-PrintSpoolerHardening {
    param([string[]]$Features)
    
    if ($Features -contains "PrintSpooler") {
        Log "Configuring Print Spooler Security" "INFO"
        
        Do-Change -Description "Enable Point and Print Restrictions" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.RestrictDriverInstallationToAdministrators -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "PrintSpooler-Security"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0 -PropertyType "DWord"
            $success3 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -PropertyType "DWord"
            return ($success1 -and $success2 -and $success3)
        }
        
        Do-Change -Description "Configure Print Spooler Service Security" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "RpcAuthnLevelPrivacyEnabled" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.RpcAuthnLevelPrivacyEnabled -eq 1)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -PropertyType "DWord"
        }
    }
}

function Set-NTLMHardening {
    param([string[]]$Features)
    
    if ($Features -contains "NTLMHardening") {
        Log "Configuring NTLM Protocol Hardening" "INFO"
        
        Do-Change -Description "Set NTLM Authentication Level" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.LmCompatibilityLevel -eq 5)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "NTLM-Security"
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -PropertyType "DWord"
        }
        
        Do-Change -Description "Configure NTLM Session Security" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.NTLMMinClientSec -eq 537395200)
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
    }
}

function Set-WinRMHardening {
    param([string[]]$Features)
    
    if ($Features -contains "WinRMHardening") {
        Log "Configuring WinRM Security Hardening" "INFO"
        
        Do-Change -Description "Disable WinRM Unencrypted Traffic" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.AllowUnencryptedTraffic -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM" "WinRM-Security"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Value 0 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
        
        Do-Change -Description "Disable WinRM Basic Authentication" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.AllowBasic -eq 0)
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
    }
}

function Set-AutoRunHardening {
    param([string[]]$Features)
    
    if ($Features -contains "AutoRunDisable") {
        Log "Configuring AutoRun/AutoPlay Security" "INFO"
        
        Do-Change -Description "Disable AutoRun for All Drives" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.NoDriveTypeAutoRun -eq 255)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AutoRun-Config"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -PropertyType "DWord"
            return ($success1 -and $success2)
        }
        
        Do-Change -Description "Disable AutoPlay for All Media" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -ErrorAction SilentlyContinue
            return ($regValue -and $regValue.NoAutorun -eq 1)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -PropertyType "DWord"
        }
    }
}

function Set-CipherSuites {
    param([string[]]$Features)
    
    if ($Features -contains "CipherSuites") {
        Log "Configuring Modern Cipher Suite Order" "INFO"
        
        # Modern cipher suite order (TLS 1.2/1.3)
        $cipherSuiteOrder = @(
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        )
        
        Do-Change -Description "Configure Modern Cipher Suite Order" -TestScript {
            $currentOrder = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -ErrorAction SilentlyContinue
            if ($currentOrder) {
                $currentSuites = $currentOrder.Functions -split ","
                foreach ($suite in $cipherSuiteOrder[0..3]) {  # Check first few critical suites
                    if ($suite -notin $currentSuites) {
                        return $false
                    }
                }
                return $true
            }
            return $false
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL" "Cipher-Suites"
        } -ChangeScript {
            $cipherString = $cipherSuiteOrder -join ","
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherString -PropertyType "String"
        } -RequiresReboot
    }
}

function Set-ExploitProtection {
    param([string[]]$Features)

    if ($Features -contains "DefenderMaximum") {
        Log "Configuring Windows Exploit Protection" "INFO"

        Do-Change -Description "Enable System-wide DEP (Data Execution Prevention)" -TestScript {
            try {
                $epConfig = Get-ProcessMitigation -System
                return ($epConfig.DEP.Enable -eq "ON")
            } catch {
                return $false
            }
        } -BackupScript {
            try {
                Get-ProcessMitigation -System | ConvertTo-Json -Depth 5 | Out-File "$script:BackupPath\ExploitProtection-System.json"
                return $true
            } catch {
                Log "Failed to backup exploit protection settings: $_" "WARN"
                return $true  # Don't block the change
            }
        } -ChangeScript {
            try {
                Set-ProcessMitigation -System -Enable DEP,EmulateAtlThunks,SEHOP,ForceRelocateImages,RequireInfo,BottomUp,HighEntropy

                # Apply custom XML if provided
                if ($ExploitProtectionXml -and (Test-Path $ExploitProtectionXml)) {
                    Log "Applying custom Exploit Protection XML: $ExploitProtectionXml" "INFO"
                    Set-ProcessMitigation -PolicyFilePath $ExploitProtectionXml
                }

                return $true
            } catch {
                Log "Failed to configure exploit protection: $_" "ERROR"
                return $false
            }
        }

        Do-Change -Description "Enable Control Flow Guard (CFG) for System Processes" -TestScript {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -ErrorAction SilentlyContinue
            return $null -ne $regValue
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "CFG-Mitigation"
        } -ChangeScript {
            # Enable CFG and other mitigations
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -Value ([byte[]](0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType "Binary"
        } -RequiresReboot
    }
}

function Set-CredentialGuard {
    param([string[]]$Features)

    if ($Features -contains "CredentialGuard" -or $SecurityLevel -eq "Maximum") {
        Log "Configuring Windows Credential Guard" "INFO"

        Do-Change -Description "Enable Virtualization Based Security (VBS)" -TestScript {
            $vbsReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
            return ($vbsReg -and $vbsReg.EnableVirtualizationBasedSecurity -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" "VBS-Config"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType "DWord"
            $success2 = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1 -PropertyType "DWord"
            return ($success1 -and $success2)
        } -RequiresReboot

        Do-Change -Description "Enable Credential Guard (LSA Protection)" -TestScript {
            $lsaCfg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
            return ($lsaCfg -and $lsaCfg.LsaCfgFlags -eq 1)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" "CredentialGuard-LSA"
        } -ChangeScript {
            $success = Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -PropertyType "DWord"
            if ($success) {
                Log "Credential Guard enabled - Pass-the-Hash/Ticket attacks mitigated" "SUCCESS"
                $script:ComplianceResults["CredentialGuard"] = "Enabled"
            }
            return $success
        } -RequiresReboot

        Do-Change -Description "Enable Secure Boot Requirement for VBS" -TestScript {
            $secureBootReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "Locked" -ErrorAction SilentlyContinue
            return ($secureBootReg -and $secureBootReg.Locked -eq 1)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "Locked" -Value 1 -PropertyType "DWord"
        }
    }
}

function Set-ControlledFolderAccess {
    param([string[]]$Features)

    if ($Features -contains "DefenderMaximum") {
        Log "Configuring Controlled Folder Access (Ransomware Protection)" "INFO"

        Do-Change -Description "Enable Controlled Folder Access" -TestScript {
            $pref = Get-MpPrefSafe
            return ($pref -and $pref.EnableControlledFolderAccess -eq 1)
        } -BackupScript {
            $pref = Get-MpPrefSafe
            if ($pref) {
                @{
                    EnableControlledFolderAccess = $pref.EnableControlledFolderAccess
                    ControlledFolderAccessProtectedFolders = $pref.ControlledFolderAccessProtectedFolders
                    ControlledFolderAccessAllowedApplications = $pref.ControlledFolderAccessAllowedApplications
                } | ConvertTo-Json | Out-File "$script:BackupPath\ControlledFolderAccess.json"
            }
            return $true
        } -ChangeScript {
            $success = Set-MpPrefSafe @{ EnableControlledFolderAccess = 1 }
            if ($success) {
                Log "Controlled Folder Access enabled - ransomware protection active" "SUCCESS"
                $script:ComplianceResults["ControlledFolderAccess"] = "Enabled"
            }
            return $success
        }

        Do-Change -Description "Add Protected Folders for Controlled Folder Access" -TestScript {
            $pref = Get-MpPrefSafe
            $protectedFolders = $pref.ControlledFolderAccessProtectedFolders
            return ($protectedFolders -and $protectedFolders.Count -gt 0)
        } -ChangeScript {
            try {
                # Add common user data folders
                Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Users" -ErrorAction SilentlyContinue
                Add-MpPreference -ControlledFolderAccessProtectedFolders "$env:USERPROFILE\Documents" -ErrorAction SilentlyContinue
                Add-MpPreference -ControlledFolderAccessProtectedFolders "$env:USERPROFILE\Pictures" -ErrorAction SilentlyContinue
                Add-MpPreference -ControlledFolderAccessProtectedFolders "$env:USERPROFILE\Desktop" -ErrorAction SilentlyContinue
                Log "Protected folders added: Users, Documents, Pictures, Desktop" "INFO"
                return $true
            } catch {
                Log "Failed to add protected folders: $_" "WARN"
                return $false
            }
        }
    }
}

function Set-DMAProtection {
    param([string[]]$Features)

    if ($Features -contains "BootSecurity" -or $SecurityLevel -eq "Maximum") {
        Log "Configuring DMA (Direct Memory Access) Protection" "INFO"

        Do-Change -Description "Enable Kernel DMA Protection" -TestScript {
            $dmaReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
            return ($dmaReg -and $dmaReg.DeviceEnumerationPolicy -eq 0)
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DMA-Protection"
        } -ChangeScript {
            $success = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value 0 -PropertyType "DWord"
            if ($success) {
                Log "Kernel DMA Protection enabled - Thunderbolt/PCIe attacks mitigated" "SUCCESS"
                $script:ComplianceResults["DMAProtection"] = "Enabled"
            }
            return $success
        }

        if ($SecurityLevel -eq "Maximum") {
            Do-Change -Description "Disable Thunderbolt (Maximum Security)" -TestScript {
                $tbService = Get-Service -Name "thunderboltservice" -ErrorAction SilentlyContinue
                return ($tbService -and $tbService.StartType -eq 'Disabled')
            } -BackupScript {
                Export-ServiceState -ServiceName "thunderboltservice"
            } -ChangeScript {
                try {
                    $tbService = Get-Service -Name "thunderboltservice" -ErrorAction SilentlyContinue
                    if ($tbService) {
                        Stop-Service -Name "thunderboltservice" -Force -ErrorAction SilentlyContinue
                        Set-Service -Name "thunderboltservice" -StartupType Disabled
                        Log "Thunderbolt service disabled for maximum DMA protection" "INFO"
                        return $true
                    }
                    return $true  # Service doesn't exist, that's fine
                } catch {
                    Log "Failed to disable Thunderbolt: $_" "WARN"
                    return $false
                }
            } -RequiresReboot
        }
    }
}

function Set-WindowsUpdateSecurity {
    param([string[]]$Features)

    # Apply to all security levels - patching is critical
    Log "Configuring Windows Update Security" "INFO"

    Do-Change -Description "Enable Automatic Windows Updates" -TestScript {
        $wuReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        $auOptions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
        return ($wuReg -and $wuReg.NoAutoUpdate -eq 0 -and $auOptions -and $auOptions.AUOptions -eq 4)
    } -BackupScript {
        Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WindowsUpdate-Config"
    } -ChangeScript {
        $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -PropertyType "DWord"
        $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 -PropertyType "DWord"
        $success3 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -PropertyType "DWord"

        if ($success1 -and $success2 -and $success3) {
            Log "Windows Update configured for automatic download and install" "SUCCESS"
            $script:ComplianceResults["WindowsUpdate"] = "Automatic"
        }
        return ($success1 -and $success2 -and $success3)
    }

    Do-Change -Description "Prevent Auto-Reboot During Active Hours" -TestScript {
        $rebootReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
        return ($rebootReg -and $rebootReg.NoAutoRebootWithLoggedOnUsers -eq 1)
    } -ChangeScript {
        return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -PropertyType "DWord"
    }

    Do-Change -Description "Enable Microsoft Update (Office/Defender Updates)" -TestScript {
        $muReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AllowMUUpdateService" -ErrorAction SilentlyContinue
        return ($muReg -and $muReg.AllowMUUpdateService -eq 1)
    } -ChangeScript {
        return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AllowMUUpdateService" -Value 1 -PropertyType "DWord"
    }
}

function Set-AppLockerPolicies {
    param([string[]]$Features)

    if ($Features -contains "DefenderMaximum") {
        Log "Configuring AppLocker Application Control" "INFO"

        # Check if AppLocker is available
        $appLockerAvailable = $null -ne (Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue)

        if (-not $appLockerAvailable) {
            Log "AppLocker not available on this Windows SKU - requires Pro/Enterprise/Education" "WARN"
            $script:ComplianceResults["AppLocker"] = "Not available on this SKU"
            return
        }

        Do-Change -Description "Enable AppLocker Service" -TestScript {
            $service = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
            return ($service -and $service.Status -eq "Running" -and $service.StartType -eq "Automatic")
        } -BackupScript {
            Export-ServiceState -ServiceName "AppIDSvc"
        } -ChangeScript {
            Set-Service -Name "AppIDSvc" -StartupType Automatic
            Start-Service -Name "AppIDSvc"
            return $?
        }

        Do-Change -Description "Configure AppLocker Baseline Policy" -TestScript {
            $policies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
            return ($policies -and $policies.RuleCollections.Count -gt 0)
        } -BackupScript {
            try {
                Get-AppLockerPolicy -Effective -Xml | Out-File "$script:BackupPath\AppLocker-Policy.xml"
                return $true
            } catch {
                Log "No existing AppLocker policy to backup" "INFO"
                return $true
            }
        } -ChangeScript {
            try {
                # Create a simple baseline policy allowing Windows and Program Files
                Log "Creating AppLocker baseline policy (Audit mode)" "INFO"

                # Note: Full AppLocker configuration typically requires custom XML
                # This creates a basic policy - organizations should customize
                $policyXml = @'
<?xml version="1.0"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="Allow Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="Allow Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
                $policyPath = "$env:TEMP\applocker-baseline.xml"
                $policyXml | Out-File $policyPath -Encoding UTF8
                Set-AppLockerPolicy -XmlPolicy $policyPath -Merge
                Remove-Item $policyPath -Force

                Log "AppLocker baseline policy applied in Audit mode" "SUCCESS"
                $script:ComplianceResults["AppLocker"] = "AuditOnly - Baseline"
                return $true
            } catch {
                Log "Failed to configure AppLocker: $_" "ERROR"
                return $false
            }
        }
    }
}

function Set-LocalAccountSecurity {
    param([string[]]$Features)

    if ($Features -contains "UACAdvanced" -or $SecurityLevel -ne "Quick") {
        Log "Configuring Local Account Security" "INFO"

        Do-Change -Description "Disable Guest Account" -TestScript {
            $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            return ($guest -and $guest.Enabled -eq $false)
        } -BackupScript {
            $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            if ($guest) {
                @{Name=$guest.Name; Enabled=$guest.Enabled} | ConvertTo-Json | Out-File "$script:BackupPath\Guest-Account.json"
            }
            return $true
        } -ChangeScript {
            try {
                Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                Log "Guest account disabled" "SUCCESS"
                return $true
            } catch {
                Log "Failed to disable Guest account: $_" "WARN"
                return $false
            }
        }

        if ($SecurityLevel -eq "Maximum") {
            Do-Change -Description "Rename Built-in Administrator Account" -TestScript {
                $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
                return ($admin -and $admin.Name -ne "Administrator")
            } -BackupScript {
                $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
                if ($admin) {
                    @{OriginalName=$admin.Name; SID=$admin.SID} | ConvertTo-Json | Out-File "$script:BackupPath\Administrator-Rename.json"
                }
                return $true
            } -ChangeScript {
                try {
                    $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
                    if ($admin -and $admin.Name -eq "Administrator") {
                        $newName = "AdminUser$(Get-Random -Maximum 9999)"
                        Rename-LocalUser -Name "Administrator" -NewName $newName
                        Log "Built-in Administrator renamed to: $newName" "SUCCESS"
                        return $true
                    }
                    return $true  # Already renamed
                } catch {
                    Log "Failed to rename Administrator: $_" "ERROR"
                    return $false
                }
            }
        }
    }
}

function Set-ScreenLockPolicies {
    param([string[]]$Features)

    if ($Features -contains "UACAdvanced" -or $SecurityLevel -ne "Quick") {
        Log "Configuring Screen Lock and Inactivity Policies" "INFO"

        Do-Change -Description "Enable Screen Saver Lock" -TestScript {
            $ssSecure = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
            return ($ssSecure -and $ssSecure.ScreenSaverIsSecure -eq "1")
        } -BackupScript {
            Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaver-Config"
        } -ChangeScript {
            $success1 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value "1" -PropertyType "String"
            $success2 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "900" -PropertyType "String"  # 15 minutes
            $success3 = Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "1" -PropertyType "String"
            return ($success1 -and $success2 -and $success3)
        }

        Do-Change -Description "Set Machine Inactivity Limit (15 minutes)" -TestScript {
            $inactivity = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue
            return ($inactivity -and $inactivity.InactivityTimeoutSecs -le 900)
        } -ChangeScript {
            return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -PropertyType "DWord"
        }
    }
}

function Set-EventLogHardening {
    param([string[]]$Features)

    if ($Features -contains "AuditAdvanced" -or $Features -contains "AuditComplete") {
        Log "Configuring Event Log Hardening" "INFO"

        $criticalLogs = @(
            @{ Name = "Security"; Size = 1073741824 },  # 1GB
            @{ Name = "System"; Size = 536870912 },      # 512MB
            @{ Name = "Application"; Size = 536870912 }, # 512MB
            @{ Name = "Microsoft-Windows-PowerShell/Operational"; Size = 268435456 }, # 256MB
            @{ Name = "Windows PowerShell"; Size = 268435456 }  # 256MB
        )

        foreach ($log in $criticalLogs) {
            Do-Change -Description "Configure $($log.Name) Log Size" -TestScript {
                try {
                    $logInfo = Get-WinEvent -ListLog $log.Name -ErrorAction SilentlyContinue
                    return ($logInfo -and $logInfo.MaximumSizeInBytes -ge $log.Size)
                } catch {
                    return $false
                }
            } -ChangeScript {
                try {
                    wevtutil sl "$($log.Name)" /ms:$($log.Size)
                    wevtutil sl "$($log.Name)" /rt:false  # Retain old logs
                    return $LASTEXITCODE -eq 0
                } catch {
                    Log "Failed to configure $($log.Name) log: $_" "WARN"
                    return $false
                }
            }
        }
    }
}

#endregion

#region Main Execution Functions

function Initialize-Script {
    # Create directories
    if (-not (Test-Path $script:LogPath)) {
        New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
    }
    
    if (-not $NoBackup -and -not (Test-Path $script:BackupPath)) {
        New-Item -Path $script:BackupPath -ItemType Directory -Force | Out-Null
    }
    
    # Start transcript
    try {
        Start-Transcript -Path "$script:LogPath\Transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -ErrorAction SilentlyContinue
    } catch {
        Log "Failed to start transcript: $_" "WARN"
    }
    
    Log "Windows Endpoint Hardener Complete v$script:Version" "INFO"
    Log "Security Level: $SecurityLevel" "INFO"
    Log "Preview Mode: $Preview" "INFO"
    Log "Enterprise Mode: $EnterpriseMode" "INFO"
    Log "Standalone Mode: $StandaloneMode" "INFO"
    
    if (-not $Preview) {
        Log "Backup Path: $script:BackupPath" "INFO"
    }
    
    # Check for pending reboot
    if (Test-PendingReboot) {
        Log "Pending reboot detected - some changes may not take effect until after reboot" "WARN"
    }
}

function Start-HardeningProcess {
    $config = $script:SecurityLevelConfigs[$SecurityLevel]
    $features = $config.Features
    
    Log "Starting $SecurityLevel hardening process" "INFO"
    Log "Estimated time: $($config.EstimatedTime)" "INFO"
    Log "Features to configure: $($features -join ', ')" "INFO"
    
    try {
        # Core security configurations
        Set-FirewallConfiguration $features
        Set-DefenderConfiguration $features
        Set-ASRRules $features
        Set-BitLockerConfiguration $features
        Set-TLSHardening $features
        Set-AuditPolicy $features

        # Phase 1 Critical Security Controls (all levels)
        Set-WindowsUpdateSecurity $features
        
        # Advanced configurations (Standard/Maximum)
        if ($SecurityLevel -ne "Quick") {
            Set-LSAProtection $features
            Set-SMBHardening $features
            Set-RDPSecurity $features
            Set-NTLMHardening $features
            Set-UACAndSecurityOptions $features
            Set-WindowsServicesHardening $features
            Set-PowerShellSecurity $features
            Set-PrintSpoolerHardening $features

            # Phase 2 High Priority - Federal Compliance
            Set-LocalAccountSecurity $features
            Set-ScreenLockPolicies $features
            Set-EventLogHardening $features
        }
        
        # Maximum-only configurations
        if ($SecurityLevel -eq "Maximum") {
            Set-BootSecurityHardening $features
            Set-CertificateSecurityHardening $features
            Set-EnhancedNetworkSecurity $features
            Set-WinRMHardening $features
            Set-AutoRunHardening $features
            Set-CipherSuites $features

            # Phase 1 Critical - Maximum Security
            Set-ExploitProtection $features
            Set-CredentialGuard $features
            Set-ControlledFolderAccess $features
            Set-DMAProtection $features

            # Phase 2 High Priority - Maximum Only
            Set-AppLockerPolicies $features
        }
        
        # Apply environment-specific hardening
        Set-EnterpriseSpecificHardening
        Set-StandaloneSpecificHardening
        
        # Generate deployment package if requested
        if (-not $Preview -and $SecurityLevel -eq "Maximum") {
            New-DeploymentPackage
        }
        
    } catch {
        Log "Critical error during hardening process: $_" "ERROR"
        $script:ErrorsEncountered++
    }
}

function New-ComplianceReport {
    if ($ComplianceReport) {
        Log "Generating compliance report" "INFO"
        
        $reportData = @{
            Version = $script:Version
            SecurityLevel = $SecurityLevel
            ExecutionTime = (Get-Date) - $script:StartTime
            ChangesApplied = $script:ChangesApplied
            ErrorsEncountered = $script:ErrorsEncountered
            RebootRequired = $script:RebootRequired
            ComplianceResults = $script:ComplianceResults
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                ExecutedBy = $env:USERNAME
                ExecutionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        $reportJson = $reportData | ConvertTo-Json -Depth 4
        $reportPath = "$script:LogPath\ComplianceReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $reportJson | Out-File -FilePath $reportPath -Encoding UTF8
        
        Log "Compliance report saved: $reportPath" "INFO"
    }
}

function Show-FinalReport {
    $endTime = Get-Date
    $executionTime = $endTime - $script:StartTime
    
    Log "==================== HARDENING COMPLETE ====================" "SUCCESS"
    Log "Security Level: $SecurityLevel" "INFO"
    Log "Execution Time: $($executionTime.ToString('hh\:mm\:ss'))" "INFO"
    Log "Changes Applied: $script:ChangesApplied" "INFO"
    Log "Errors Encountered: $script:ErrorsEncountered" "INFO"
    Log "Reboot Required: $script:RebootRequired" "INFO"
    
    if ($script:ComplianceResults.Count -gt 0) {
        Log "Compliance Issues Detected:" "WARN"
        foreach ($item in $script:ComplianceResults.GetEnumerator()) {
            Log "  $($item.Key): $($item.Value)" "WARN"
        }
    }
    
    if (-not $Preview) {
        if (-not $NoBackup) {
            Log "Backup Location: $script:BackupPath" "INFO"
        }
        Log "Log Files: $script:LogPath" "INFO"
    }
    
    # Generate compliance report
    New-ComplianceReport
    
    # Stop transcript
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    } catch {}
    
    Log "=============================================================" "SUCCESS"
    
    # Set exit code
    if ($script:ErrorsEncountered -gt 0) {
        exit 1
    } elseif ($script:RebootRequired) {
        exit 3010
    } else {
        exit 0
    }
}

function Restore-FromBackup {
    if ($RollbackMode) {
        Log "Starting system restoration from backup" "INFO"
        
        $backupDirs = Get-ChildItem -Path "C:\HardeningBackup" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        
        if (-not $backupDirs) {
            Log "No backup directories found for restoration" "ERROR"
            exit 1603
        }
        
        $latestBackup = $backupDirs[0].FullName
        Log "Using backup from: $latestBackup" "INFO"
        
        # Restore registry files
        $regFiles = Get-ChildItem -Path $latestBackup -Filter "*.reg" -ErrorAction SilentlyContinue
        foreach ($regFile in $regFiles) {
            try {
                Log "Restoring registry: $($regFile.Name)" "INFO"
                $result = cmd /c "reg import `"$($regFile.FullName)`" /reg:64" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Log "Failed to restore $($regFile.Name): $result" "ERROR"
                }
            } catch {
                Log "Error restoring $($regFile.Name): $_" "ERROR"
            }
        }
        
        # Restore services
        $serviceFiles = Get-ChildItem -Path $latestBackup -Filter "Service-*.json" -ErrorAction SilentlyContinue
        foreach ($serviceFile in $serviceFiles) {
            try {
                $serviceData = Get-Content $serviceFile.FullName | ConvertFrom-Json
                Log "Restoring service: $($serviceData.Name)" "INFO"
                Set-Service -Name $serviceData.Name -StartupType $serviceData.StartType
            } catch {
                Log "Error restoring service $($serviceFile.Name): $_" "ERROR"
            }
        }
        
        Log "System restoration completed - reboot recommended" "SUCCESS"
        exit 3011
    }
}

#endregion

#region Enterprise Deployment Functions

function Test-EnterpriseEnvironment {
    # Detect domain membership
    $computerSystem = Get-CimInstance Win32_ComputerSystem
    $isDomainJoined = $computerSystem.PartOfDomain

    # Detect management tools
    $hasIntune = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
    $hasSCCM = Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue

    return @{
        IsDomainJoined = $isDomainJoined
        DomainName = if ($isDomainJoined) { $computerSystem.Domain } else { $null }
        HasIntune = $hasIntune -ne $null
        HasSCCM = $hasSCCM -ne $null
    }
}

function Set-EnterpriseSpecificHardening {
    if ($EnterpriseMode) {
        Log "Applying Enterprise-specific hardening" "INFO"

        $envInfo = Test-EnterpriseEnvironment

        if ($envInfo.IsDomainJoined) {
            Log "Domain-joined system detected: $($envInfo.DomainName)" "INFO"

            # Domain-specific hardening
            Do-Change -Description "Configure Kerberos Encryption Types" -TestScript {
                $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue
                return ($regValue -and $regValue.SupportedEncryptionTypes -eq 2147483640)
            } -BackupScript {
                Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "Kerberos-Config"
            } -ChangeScript {
                return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -PropertyType "DWord"
            }

            # Enable LDAPS requirement
            Do-Change -Description "Require LDAP Signing" -TestScript {
                $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue
                return ($regValue -and $regValue.LDAPClientIntegrity -eq 2)
            } -BackupScript {
                Export-RegistryPath "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" "LDAP-Security"
            } -ChangeScript {
                return Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 2 -PropertyType "DWord"
            }
        }

        if ($envInfo.HasIntune) {
            Log "Microsoft Intune detected - enabling MDM-specific policies" "INFO"

            # Intune-specific configurations
            Do-Change -Description "Enable Windows Analytics Data Collection" -TestScript {
                $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
                return ($regValue -and $regValue.AllowTelemetry -eq 2)
            } -BackupScript {
                Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "Intune-Telemetry"
            } -ChangeScript {
                return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 2 -PropertyType "DWord"
            }
        }

        if ($envInfo.HasSCCM) {
            Log "Microsoft SCCM detected - enabling SCCM-compatible settings" "INFO"

            # SCCM-specific configurations
            Do-Change -Description "Configure SCCM Client Certificate Selection" -TestScript {
                $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Security" -Name "ClientCertificateSelectionCriteria" -ErrorAction SilentlyContinue
                return $regValue -ne $null
            } -BackupScript {
                Export-RegistryPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM\Security" "SCCM-Security"
            } -ChangeScript {
                return Set-RegistryProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Security" -Name "ClientCertificateSelectionCriteria" -Value "ClientAuthentication" -PropertyType "String"
            }
        }
    }
}

function Set-StandaloneSpecificHardening {
    if ($StandaloneMode) {
        Log "Applying Standalone workstation hardening" "INFO"

        # Disable unnecessary network services for standalone systems
        Do-Change -Description "Disable Server Service (Standalone)" -TestScript {
            $service = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
            return ($service -and $service.StartType -eq 'Disabled')
        } -BackupScript {
            Export-ServiceState -ServiceName "LanmanServer"
        } -ChangeScript {
            try {
                Stop-Service -Name "LanmanServer" -Force -ErrorAction SilentlyContinue
                Set-Service -Name "LanmanServer" -StartupType Disabled
                return $true
            } catch {
                return $false
            }
        }

        # Enhanced local account security for standalone systems
        Do-Change -Description "Configure Local Account Password Policies" -TestScript {
            $secpol = secedit /export /cfg "$env:temp\secpol.cfg" /areas SECURITYPOLICY
            $content = Get-Content "$env:temp\secpol.cfg" -ErrorAction SilentlyContinue
            $minPwdLen = $content | Where-Object { $_ -match "MinimumPasswordLength" }
            return ($minPwdLen -and $minPwdLen -match "= 14")
        } -BackupScript {
            secedit /export /cfg "$script:BackupPath\secpol-backup.cfg" /areas SECURITYPOLICY | Out-Null
            return $true
        } -ChangeScript {
            try {
                $secpolContent = @"
[Version]
signature="`$CHICAGO`$"
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
ClearTextPassword = 0
"@
                $tempConfig = "$env:temp\secpol-hardening.cfg"
                $secpolContent | Out-File $tempConfig -Encoding ASCII
                secedit /configure /db secedit.sdb /cfg $tempConfig /areas SECURITYPOLICY | Out-Null
                Remove-Item $tempConfig -Force -ErrorAction SilentlyContinue
                return $LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3
            } catch {
                return $false
            }
        }
    }
}

function New-DeploymentPackage {
    param(
        [string]$OutputPath = "C:\Deploy"
    )

    if (-not $Preview) {
        Log "Creating deployment package" "INFO"

        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }

        # Copy script to deployment location
        $scriptName = "Windows-Endpoint-Hardener-Complete.ps1"
        Copy-Item -Path $PSCommandPath -Destination "$OutputPath\$scriptName" -Force

        # Create batch deployment files
        $batchContent = @"
@echo off
REM Windows Endpoint Hardener - Batch Deployment
REM Run as Administrator

echo Checking for Administrator privileges...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
) else (
    echo ERROR: This script requires Administrator privileges.
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Starting Windows Endpoint Hardening...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0$scriptName" -SecurityLevel Standard -EnterpriseMode -Silent

echo Deployment completed. Check logs in C:\HardeningLogs\
if %ERRORLEVEL% EQU 3010 (
    echo REBOOT REQUIRED - Please restart the computer.
)
pause
"@

        $batchContent | Out-File -FilePath "$OutputPath\Deploy-Enterprise-Hardening.bat" -Encoding ASCII

        # Create PowerShell deployment script for RMM tools
        $psDeployContent = @"
# PowerShell Deployment Script for Windows Endpoint Hardener
# Can be used with RMM tools like ConnectWise, Kaseya, N-able, etc.

param(
    [ValidateSet("Quick", "Standard", "Maximum")]
    [string]`$Level = "Standard",
    [switch]`$Enterprise,
    [switch]`$Standalone
)

# Download and execute hardening script
try {
    `$scriptPath = "`$env:TEMP\Windows-Endpoint-Hardener-Complete.ps1"

    # If local file exists, use it; otherwise download
    if (Test-Path "`$PSScriptRoot\Windows-Endpoint-Hardener-Complete.ps1") {
        Copy-Item "`$PSScriptRoot\Windows-Endpoint-Hardener-Complete.ps1" `$scriptPath -Force
    } else {
        # Uncomment and modify URL for remote deployment
        # Invoke-WebRequest -Uri "https://your-server.com/Windows-Endpoint-Hardener-Complete.ps1" -OutFile `$scriptPath -UseBasicParsing
        throw "Script not found locally and no remote URL configured"
    }

    # Build parameters
    `$params = @{
        SecurityLevel = `$Level
        Silent = `$true
        LogOnly = `$true
    }

    if (`$Enterprise) { `$params.EnterpriseMode = `$true }
    if (`$Standalone) { `$params.StandaloneMode = `$true }

    # Execute hardening
    & `$scriptPath @params

    Write-Output "Hardening completed. Exit code: `$LASTEXITCODE"

} catch {
    Write-Error "Deployment failed: `$_"
    exit 1
} finally {
    # Cleanup
    if (Test-Path `$scriptPath) {
        Remove-Item `$scriptPath -Force -ErrorAction SilentlyContinue
    }
}
"@

        $psDeployContent | Out-File -FilePath "$OutputPath\RMM-Deploy-Hardening.ps1" -Encoding UTF8

        # Create Intune detection script
        $intuneDetectionScript = @"
# Intune Detection Script - Windows Endpoint Hardener
# This script detects if hardening has been applied successfully

try {
    # Check for hardening log file
    `$logPath = "C:\HardeningLogs\EndpointHardener.log"
    if (-not (Test-Path `$logPath)) {
        Write-Output "Hardening not detected - log file missing"
        exit 1
    }

    # Check log file age (should be recent)
    `$logFile = Get-Item `$logPath
    `$daysSinceHardening = (Get-Date) - `$logFile.LastWriteTime

    if (`$daysSinceHardening.Days -gt 30) {
        Write-Output "Hardening detected but outdated (> 30 days)"
        exit 1
    }

    # Check for key registry indicators
    `$indicators = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging"
    )

    foreach (`$indicator in `$indicators) {
        `$path = Split-Path `$indicator
        `$name = Split-Path `$indicator -Leaf
        `$value = Get-ItemProperty -Path `$path -Name `$name -ErrorAction SilentlyContinue

        if (-not `$value -or `$value.`$name -ne 1) {
            Write-Output "Key hardening indicator missing: `$indicator"
            exit 1
        }
    }

    Write-Output "Windows Endpoint Hardening detected and current"
    exit 0

} catch {
    Write-Output "Detection script error: `$_"
    exit 1
}
"@

        $intuneDetectionScript | Out-File -FilePath "$OutputPath\Intune-Detection-Script.ps1" -Encoding UTF8

        Log "Deployment package created in: $OutputPath" "SUCCESS"
    }
}

#endregion

#region Main Execution

# Parameter validation and early exit conditions
if ($RollbackMode) {
    Restore-FromBackup
    return
}

if ($EnterpriseMode -and $StandaloneMode) {
    Log "Cannot specify both EnterpriseMode and StandaloneMode" "ERROR"
    exit 1601
}

# Load custom configuration if provided
if ($CustomConfig -and (Test-Path $CustomConfig)) {
    try {
        $customSettings = Get-Content $CustomConfig | ConvertFrom-Json
        Log "Loaded custom configuration from: $CustomConfig" "INFO"
        # Apply custom settings (implementation depends on JSON structure)
    } catch {
        Log "Failed to load custom configuration: $_" "ERROR"
        exit 1601
    }
}

# Initialize script environment
Initialize-Script

# Handle preview mode information
if ($Preview) {
    Log "==================== PREVIEW MODE ACTIVE ====================" "WARN"
    Log "No changes will be applied - showing planned configuration only" "WARN"
    Log "=============================================================" "WARN"
}

# Main hardening execution
try {
    Start-HardeningProcess
} catch {
    Log "Fatal error during hardening: $_" "ERROR"
    $script:ErrorsEncountered++
} finally {
    Show-FinalReport
}

#endregion
