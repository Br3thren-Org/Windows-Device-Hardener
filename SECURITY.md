# Security Policy

## Reporting Security Vulnerabilities

We take the security of the Endpoint Hardener project seriously. If you believe you have found a security vulnerability in any of our scripts or documentation, please report it to us as described below.

### 🔒 Responsible Disclosure

**Please do NOT:**
- Open public GitHub issues for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed
- Exploit the vulnerability beyond what is necessary to demonstrate it

**Please DO:**
- Report security issues privately (see contact methods below)
- Provide detailed information about the vulnerability
- Allow reasonable time for the issue to be addressed before public disclosure
- Follow coordinated disclosure practices

---

## 📧 How to Report

### Preferred Method: GitHub Security Advisory
1. Go to the [Security tab](https://github.com/Br3thren-Org/Windows-Device-Hardener/security) of this repository
2. Click "Report a vulnerability"
3. Fill out the security advisory form with details

### Alternative Method: Email
If you prefer not to use GitHub Security Advisories, you can email:
- **Email:** security@endpoint-hardener.example.com (update with your contact)
- **Subject:** "Security Vulnerability Report - [Brief Description]"

### Information to Include

Please provide as much of the following information as possible:

1. **Type of vulnerability** (e.g., code injection, privilege escalation, credential exposure)
2. **Affected component** (Windows script, specific function/line)
3. **Version affected** (script version number)
4. **Steps to reproduce** (detailed steps to trigger the vulnerability)
5. **Potential impact** (what an attacker could achieve)
6. **Suggested fix** (if you have one)
7. **Your contact information** (for follow-up questions)

### Example Report Format

```
Subject: Security Vulnerability Report - Potential Command Injection in Windows Script

Component: Windows-Endpoint-Hardener-Complete.ps1
Version: 2.2.0
Severity: High

Description:
The script accepts user input in the -CustomConfig parameter without proper
validation, which could allow command injection.

Steps to Reproduce:
1. Run script with malicious parameter: -CustomConfig "$(malicious-command)"
2. Script executes unvalidated command
3. Arbitrary code execution achieved

Potential Impact:
An attacker with local access could escalate privileges or execute arbitrary
commands in the context of the script (Administrator).

Suggested Fix:
Add input validation using [ValidateScript()] attribute to sanitize the
-CustomConfig parameter before processing.

Reporter: John Doe (john@example.com)
```

---

## 🕒 Response Timeline

We are committed to addressing security vulnerabilities promptly:

| Timeline | Action |
|----------|--------|
| **Within 48 hours** | Initial acknowledgment of your report |
| **Within 7 days** | Assessment of vulnerability and severity classification |
| **Within 30 days** | Fix development and testing (for confirmed vulnerabilities) |
| **Within 60 days** | Public disclosure after fix is released (coordinated with reporter) |

**Note:** Complex vulnerabilities may require additional time. We will keep you informed of progress throughout the remediation process.

---

## 🎯 Scope

### In Scope

Security vulnerabilities in the following components are in scope for reporting:

✅ **Windows-Endpoint-Hardener-Complete.ps1**
- Command injection vulnerabilities
- Privilege escalation issues
- Credential exposure risks
- Path traversal vulnerabilities
- XML/JSON parsing vulnerabilities
- Registry manipulation issues
- Logic flaws that weaken security posture

✅ **Documentation**
- Misleading security guidance
- Dangerous example configurations
- Incorrect usage instructions that could lead to vulnerabilities

### Out of Scope

The following are generally NOT considered security vulnerabilities:

❌ **Expected Behavior:**
- Scripts require administrator/root privileges (this is by design)
- Scripts modify system configurations (this is the intended purpose)
- Scripts can break systems if used incorrectly (addressed in documentation)
- Changes made by scripts affect system behavior (this is expected)

❌ **User Error:**
- Running scripts without reading documentation
- Bypassing safety checks intentionally
- Using scripts on unsupported systems
- Misconfiguring parameters

❌ **Third-Party Issues:**
- Vulnerabilities in PowerShell, or Windows themselves
- Issues with systems the scripts run on (unless caused by our code)
- Vulnerabilities in external tools or dependencies

❌ **Social Engineering:**
- Tricking users into running malicious versions of scripts
- Phishing attacks impersonating this project

---

## 🏆 Recognition

We believe in recognizing security researchers who help make our project safer:

### Hall of Fame

We maintain a security researchers Hall of Fame in our documentation. With your permission, we will:
- Credit you by name (or handle/alias if you prefer)
- Link to your website or social media (optional)
- Describe the vulnerability you found (after it's fixed)

### Responsible Disclosure Recognition

- Your name in CHANGELOG.md for the security fix release
- Acknowledgment in the GitHub release notes
- Optional blog post featuring your research (with your approval)

**Privacy:** If you prefer to remain anonymous, we will respect that completely.

---

## 🔐 Security Best Practices

### For Users

When using these hardening scripts:

1. ✅ **Always test in non-production first**
2. ✅ **Review the code before running** (it's open source for a reason)
3. ✅ **Use the latest version** (check for updates regularly)
4. ✅ **Create backups** before running scripts
5. ✅ **Use Preview mode** to see changes before applying
6. ✅ **Download from official sources** only (GitHub releases)
7. ✅ **Verify script integrity** (check hashes if provided)

### For Contributors

When contributing code:

1. ✅ **Validate all user input** (use PowerShell ValidateScript/ValidateSet)
2. ✅ **Avoid command injection** (use parameterized commands)
3. ✅ **Handle sensitive data carefully** (never log credentials)
4. ✅ **Follow least privilege** (don't request unnecessary permissions)
5. ✅ **Document security implications** of new features
6. ✅ **Test security controls** thoroughly

---

## 📋 Known Limitations

These are known limitations that are NOT security vulnerabilities but are important to understand:

### Windows Script
- ⚠️ Requires Administrator privileges to function
- ⚠️ Can disable networking if misconfigured
- ⚠️ May break legacy applications that depend on old protocols
- ⚠️ Rollback may not restore 100% of original configuration
- ⚠️ Some controls require reboot to take full effect

---

## 🔄 Security Update Process

### For Critical Vulnerabilities

1. **Immediate Action:** Pull vulnerable version if actively exploited
2. **Emergency Patch:** Release fix within 48-72 hours
3. **Security Advisory:** Publish GitHub Security Advisory
4. **User Notification:** Update README with security notice
5. **Post-Mortem:** Analyze how vulnerability was introduced

### For Non-Critical Vulnerabilities

1. **Assessment:** Evaluate severity and impact
2. **Fix Development:** Develop and test fix thoroughly
3. **Coordinated Release:** Release with regular version update
4. **Changelog Entry:** Document fix in CHANGELOG.md
5. **Advisory Publication:** Publish advisory after fix is available

---

## 📜 Vulnerability Severity Classification

We use the following severity levels:

| Severity | Description | Example |
|----------|-------------|---------|
| **CRITICAL** | Remote code execution, privilege escalation without user interaction | Command injection in default configuration |
| **HIGH** | Local privilege escalation, credential theft, data exfiltration | Insecure file operations with predictable paths |
| **MEDIUM** | Security control bypass, information disclosure | Weak validation allowing policy evasion |
| **LOW** | Minor security improvements, defense-in-depth enhancements | Missing input validation on non-critical path |

---

## 📞 Questions About Security?

If you have general questions about the security of these scripts (not vulnerability reports):

- **GitHub Discussions:** Use the [Security category](https://github.com/yourusername/endpoint-hardener/discussions)
- **Documentation:** Check [README.md](README.md) and [CLAUDE.md](CLAUDE.md)
- **Issues:** Open a public issue for non-sensitive security questions

---

## 🙏 Thank You

Thank you for helping keep the Endpoint Hardener project and its users safe!

Your efforts to responsibly disclose security vulnerabilities make this project better for everyone.

---

**Last Updated:** 2025-01-27
**Policy Version:** 1.0
