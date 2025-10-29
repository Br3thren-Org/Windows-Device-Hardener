# Windows Endpoint Hardener

[![Version](https://img.shields.io/badge/version-2.2.0-blue.svg)](https://github.com/Br3thren-Org/Windows-Device-Hardener)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/powershell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Bash](https://img.shields.io/badge/bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)

> **Comprehensive security hardening scripts for Windows endpoints implementing CISA/NSA compliance standards**

Enterprise-grade security hardening solutions that automate the implementation of defense-in-depth security controls across Windows 10/11 systems. Built for government agencies, security professionals, and organizations requiring high-security baseline configurations.

---

## 🎯 Features

### Windows Endpoint Hardener (v2.2.0)

- ✅ **Three Security Levels**: Quick (30 min), Standard (60 min), Maximum (60+ min)
- ✅ **Pre-Flight Validation**: Automatic compatibility checks before execution
- ✅ **Real-Time Progress Tracking**: Visual progress indicators with percentage completion
- ✅ **Compliance Reporting**: Automated JSON + HTML compliance reports with scoring
- ✅ **Enterprise Deployment**: Intune/SCCM/RMM ready with silent execution
- ✅ **Idempotent Design**: Safe to run multiple times without breaking system
- ✅ **Comprehensive Backup**: Automatic backup before all changes with rollback capability
- ✅ **150+ Security Controls**: Complete CISA/NSA hardening baseline

---

## 🚀 Quick Start

### Windows

```powershell
# Download the script
git clone https://github.com/yourusername/endpoint-hardener.git
cd endpoint-hardener

# Run as Administrator - Standard hardening
.\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Standard

# Preview mode (see changes without applying)
.\Windows-Endpoint-Hardener-Complete.ps1 -Preview -SecurityLevel Quick

# Generate compliance report
.\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Maximum -ComplianceReport
```

---

## 📋 Security Controls Implemented

### Windows Security Domains

| Domain | Controls | Description |
|--------|----------|-------------|
| **Windows Defender** | Real-time protection, ASR rules, tamper protection, cloud protection, PUA protection | Complete endpoint protection configuration |
| **Firewall** | Profile hardening, logging, rule management | Network perimeter security |
| **Network Security** | LLMNR, NetBIOS, SMB, WinRM, NTLM hardening | Protocol-level attack prevention |
| **Credential Protection** | LSA Protection, Credential Guard, WDigest disable | Credential theft mitigation |
| **BitLocker** | Full disk encryption with TPM/recovery password | Data at rest protection |
| **TLS/SSL** | Disable weak protocols (SSL 2/3, TLS 1.0/1.1), enable TLS 1.2/1.3 | Transport security |
| **Audit Policy** | Complete CISA/NSA audit logging | Security monitoring |
| **UAC** | Advanced User Account Control with STIG compliance | Privilege escalation prevention |
| **Services** | Disable 15+ dangerous services per CISA guidance | Attack surface reduction |
| **Boot Security** | Secure Boot, TPM validation, HVCI, VBS | Firmware-level security |
| **Certificate/PKI** | Weak hash algorithm disable, certificate validation | PKI security |
| **Exploit Protection** | DEP, SEHOP, CFG, ASLR, control flow guard | Memory corruption prevention |
| **PowerShell** | Script block logging, module logging, transcription, PSv2 removal | PowerShell security |
| **RDP** | NLA, security layer, encryption | Remote access security |
| **Print Spooler** | Point and Print restrictions, RPC security | PrintNightmare mitigation |
| **DMA Protection** | Kernel DMA protection, Thunderbolt disable | DMA attack prevention |
| **AppLocker** | Application whitelisting baseline | Application control |
| **Windows Update** | Automatic updates, Microsoft Update | Patch management |

---

## 📊 Security Levels Explained

### Quick Level (15-30 minutes)
**Use Case:** Immediate security improvement, time-sensitive deployments

**Windows:** ~30 operations covering firewall, basic Defender, ASR core, TLS basics, basic audit, basic UAC

### Standard Level (30-60 minutes)
**Use Case:** Recommended for most production environments

**Windows:** ~80 operations including all Quick controls plus LSA Protection, SMB/RDP/NTLM hardening, network protocols, PowerShell security, Print Spooler hardening

### Maximum Level (60+ minutes)
**Use Case:** High-security environments, government/military, compliance requirements

**Windows:** ~150 operations - complete CISA/NSA baseline including boot security, certificate security, HVCI, Credential Guard, DMA protection, AppLocker, advanced network hardening

---

## 🔧 Requirements

### Windows
- ✅ Windows 10 or Windows 11 (build 14393+)
- ✅ PowerShell 5.1 or later
- ✅ Administrator privileges
- ✅ 1GB+ free disk space
- ⚠️ Windows Professional, Enterprise, or Education edition recommended (some features unavailable on Home)

---

## 📖 Usage Examples

### Windows

#### Enterprise Deployment
```powershell
# Silent execution for RMM tools
.\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Standard -EnterpriseMode -Silent

# Domain-joined systems with compliance report
.\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Maximum -EnterpriseMode -ComplianceReport

# Standalone workstation
.\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Standard -StandaloneMode
```

#### Rollback
```powershell
# Restore from most recent backup
.\Windows-Endpoint-Hardener-Complete.ps1 -RollbackMode
```

#### Custom Configuration
```powershell
# Use custom ASR rules
.\Windows-Endpoint-Hardener-Complete.ps1 -ASRRules "guid1,guid2,guid3"

# Disable IPv6
.\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Maximum -DisableIPv6

# Custom exploit protection XML
.\Windows-Endpoint-Hardener-Complete.ps1 -ExploitProtectionXml "C:\config\exploit-protection.xml"
```

---

## 📂 Output & Logs

### Windows
- **Logs:** `C:\HardeningLogs\`
- **Transcripts:** `C:\HardeningLogs\Transcript-YYYYMMDD-HHmmss.log`
- **Compliance Reports:** `C:\HardeningLogs\ComplianceReport-YYYYMMDD-HHmmss.json|.html`
- **Backups:** `C:\HardeningBackup\YYYYMMDD-HHmmss\`

---

## 🔄 Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success, no reboot required | Continue operations |
| 1 | Errors encountered | Review logs |
| 3010 | Success, reboot required | Schedule system reboot |
| 3011 | Rollback completed | Verify system state |
| 1601 | Invalid parameters | Check command syntax |
| 1603 | Incompatible system | Verify requirements |

---

## 🛡️ Security Considerations

### Testing Required
⚠️ **ALWAYS test in a non-production environment first!**

These scripts make significant system changes that can affect:
- Network connectivity
- Application compatibility
- Remote access capabilities
- System performance

### Backup Strategy
- Scripts automatically create backups before changes
- Manual VM snapshots recommended for critical systems
- Test rollback procedures before production deployment

### Known Impacts

**Windows:**
- Maximum level may disable legacy protocols (SMBv1, TLS 1.0/1.1)
- Some applications may require exceptions in AppLocker/Controlled Folder Access
- Remote management tools may need reconfiguration

---

## 📊 Compliance & Standards

### Frameworks Covered
- ✅ **CISA/NSA Security Guidelines**
- ✅ **CIS Benchmarks** (Level 1 & 2)
- ✅ **NIST Cybersecurity Framework**
- ✅ **DISA STIGs** (Security Technical Implementation Guides)
- ✅ **PCI DSS** (Payment Card Industry Data Security Standard)
- ✅ **HIPAA** (Health Insurance Portability and Accountability Act)
- ✅ **ISO 27001/27002** (Information Security Management)

### Compliance Reporting (Windows v2.2.0)

The Windows script generates comprehensive compliance reports including:
- **Security posture assessment** (13 checks across 6 categories)
- **Compliance scoring** (0-100% with ratings)
- **Detailed findings** by security control
- **Actionable recommendations**
- **Dual format:** JSON (automation) + HTML (executive review)

---

## 🔍 What's New

### Version 2.2.0 (Windows - 2025-10-27)
- ✨ Pre-flight system compatibility checks
- ✨ Real-time progress tracking with percentage
- ✨ Enhanced compliance reporting (JSON + HTML)
- ✨ Improved error handling (PSScriptAnalyzer compliant)
- ✨ Better initialization with visual separators
- 🐛 Fixed null comparison warnings
- 🐛 Enhanced reboot detection (added CBS check)

### Version 2.1.0 (Windows)
- Unified script (all CISA/NSA modules integrated)
- Three security levels (Quick/Standard/Maximum)
- Enterprise and Standalone modes

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on:
- Code of conduct
- Development process
- How to submit pull requests
- Coding standards

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**USE AT YOUR OWN RISK**

This software is provided "as is" without warranty of any kind. The authors are not responsible for any damage or data loss that may result from using these scripts. Always:

1. Test thoroughly in non-production environments
2. Create complete system backups before execution
3. Review all changes in preview mode first
4. Understand the security controls being implemented
5. Have a rollback plan ready

These scripts are designed for security professionals and system administrators who understand the implications of system hardening.

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/Br3thren-Org/Windows-Device-Hardener/issues)
- **Security Vulnerabilities:** See [SECURITY.md](SECURITY.md) for responsible disclosure
- **Documentation:** See [CLAUDE.md](CLAUDE.md) for developer guidance

---

## 🙏 Acknowledgments

- CISA/NSA for comprehensive security guidelines
- Microsoft Security Team for Windows hardening best practices
- CIS Benchmarks authors
- DISA STIG contributors

---

## 📚 Additional Resources

- [CISA Security Guidelines](https://www.cisa.gov/uscert/ncas/tips)
- [NSA Cybersecurity Advisories](https://www.nsa.gov/What-We-Do/Cybersecurity/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)

---

**Made with ❤️ for security professionals worldwide**
