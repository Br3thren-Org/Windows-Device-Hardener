# Windows Device Hardener

A comprehensive Windows security hardening script implementing defense-in-depth security controls for Windows 10/11 systems.

## Overview

Windows Device Hardener v1.2.7 is a production-ready PowerShell script that implements comprehensive security hardening based on industry best practices including NIST, CIS, and Microsoft security baselines. It provides automated deployment of security configurations with backup capabilities and idempotent operations.

## Features

### Core Security Controls
- **Windows Defender Configuration**: Enhanced real-time protection, cloud-based protection, and sample submission
- **Attack Surface Reduction (ASR) Rules**: Configurable ASR rule deployment with verification
- **Windows Firewall Hardening**: Advanced firewall rules and logging configuration
- **User Account Control (UAC)**: Enhanced UAC settings for privilege escalation protection
- **Audit Policy Configuration**: Comprehensive security auditing for compliance and monitoring
- **BitLocker Encryption**: Automated BitLocker policy enforcement (Pro/Enterprise editions)

### Network Security Hardening
- **LLMNR Disabling**: Prevents Link-Local Multicast Name Resolution attacks
- **SMB Security**: Guest authentication disabling and SMB signing enforcement
- **WinRM Hardening**: Secure remote management configuration with HTTPS-only options
- **NTLM/LM Protocol Security**: Authentication protocol hardening
- **NetBIOS Disabling**: Removes legacy NetBIOS over TCP/IP
- **WPAD Disabling**: Prevents Web Proxy Auto-Discovery attacks

### Service and Protocol Hardening
- **Print Spooler Security**: PrintNightmare and Point-and-Print protection
- **PowerShell v2 Removal**: Eliminates downgrade attack surface
- **Cipher Suite Configuration**: Modern cryptographic standards enforcement
- **AutoRun/AutoPlay Disabling**: USB-based malware prevention
- **WebClient Service**: Optional WebDAV service disabling

### Advanced Security Features
- **Hypervisor-protected Code Integrity (HVCI)**: Hardware-based code integrity protection
- **Controlled Folder Access**: Ransomware protection (optional due to compatibility concerns)
- **Exploit Protection**: XML-based exploit mitigation deployment
- **.NET TLS Enforcement**: Forces legacy .NET applications to use modern TLS

## Requirements

- Windows 10/11 (Professional, Enterprise, or Education editions recommended)
- PowerShell 5.1 or later
- Administrator privileges
- Active Windows Defender installation

## Usage

### Basic Usage
```powershell
# Run with default settings
.\Windows-Device-Hardener.ps1

# Preview mode - show changes without applying
.\Windows-Device-Hardener.ps1 -Preview

# Skip backup operations for faster execution
.\Windows-Device-Hardener.ps1 -NoBackup
```

### Advanced Configuration
```powershell
# Enable comprehensive hardening
.\Windows-Device-Hardener.ps1 -StrictRDP -EnableHVCI -QuietFirewall -EnforceNETTLS

# Network security hardening
.\Windows-Device-Hardener.ps1 -DisableLLMNR -DisableSMBGuest -HardenWinRM

# Protocol and service hardening
.\Windows-Device-Hardener.ps1 -HardenNTLM -HardenPrintSpooler -DisableAutoRun -RemovePSv2 -HardenCipherSuites

# Custom ASR rules deployment
.\Windows-Device-Hardener.ps1 -ASRRules "56a863a9-875e-4185-98a7-b882c64b5ce5,7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-Preview` | Show planned changes without applying them |
| `-NoBackup` | Skip backup operations for faster execution |
| `-ASRRules` | Comma-separated list of ASR rule GUIDs to enable |
| `-ExploitProtectionXml` | Path to Exploit Protection baseline XML file |
| `-StrictRDP` | Enable additional RDP security controls |
| `-EnableHVCI` | Enable Hypervisor-protected Code Integrity |
| `-QuietFirewall` | Disable firewall notifications |
| `-EnforceNETTLS` | Force .NET applications to use TLS 1.2+ |
| `-EnableCFA` | Enable Controlled Folder Access (use with caution) |
| `-DisableLLMNR` | Disable LLMNR to prevent lateral movement |
| `-DisableSMBGuest` | Disable SMB guest authentication |
| `-HardenWinRM` | Enable WinRM security hardening |
| `-HardenNTLM` | Enable NTLM/LM protocol hardening |
| `-HardenPrintSpooler` | Enable Print Spooler security controls |
| `-DisableAutoRun` | Disable AutoRun and AutoPlay |
| `-RemovePSv2` | Remove PowerShell v2 engine |
| `-HardenCipherSuites` | Configure modern cipher suites |
| `-DisableWPAD` | Disable Web Proxy Auto-Discovery |
| `-DisableNetBIOS` | Disable NetBIOS over TCP/IP |
| `-WinRMHttpsOnly` | Configure WinRM for HTTPS-only |
| `-WinRMThumbprint` | Certificate thumbprint for WinRM HTTPS |
| `-DisableWebClient` | Disable WebClient (WebDAV) service |

## Deployment Scenarios

### Enterprise Deployment
- **Microsoft Intune**: Deploy via PowerShell script policy
- **System Center Configuration Manager**: Package as application or script
- **Group Policy**: Deploy via computer startup script
- **RMM Tools**: One-liner execution with parameters

### Standalone Deployment
- Local administrator execution
- USB/removable media deployment
- Remote execution via WinRM/PowerShell remoting

## Safety Features

- **Backup Creation**: Automatic registry and configuration backups before changes
- **Idempotent Operations**: Safe to run multiple times without adverse effects
- **Preview Mode**: Test changes before implementation
- **Rollback Capability**: Restore from backups if needed
- **Compatibility Checking**: Validates Windows version and edition compatibility

## Logging and Monitoring

The script provides comprehensive logging including:
- Detailed operation logs with timestamps
- JSON summary output for automation integration
- Error handling and recovery logging
- Backup verification and restoration logs

## Security Considerations

This script implements defense-in-depth security controls that may impact:
- Legacy application compatibility
- Network connectivity in mixed environments
- Administrative workflows requiring elevated privileges
- Third-party security software integration

**Recommendation**: Test thoroughly in a non-production environment before enterprise deployment.

## Version History

- **v1.2.7**: Complete security hardening with network and service lockdown
- **v1.2**: Enterprise features with ASR verification and advanced controls
- **v1.1**: Enhanced RDP security and SMB hardening
- **v1.0**: Initial release with core security controls

## License

This project is provided as-is for security hardening purposes. Use at your own risk and ensure compliance with organizational security policies.

## Contributing

This is a defensive security tool designed to improve Windows system security posture. Contributions should focus on:
- Security control improvements
- Compatibility enhancements
- Documentation updates
- Bug fixes and error handling

---

**Warning**: This script makes significant system security changes. Always test in a non-production environment first and ensure you have appropriate backups and recovery procedures in place.
