# Contributing to Endpoint Hardener

First off, thank you for considering contributing to Endpoint Hardener! 🎉

It's people like you that make this project a great tool for security professionals worldwide.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)

---

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. Please be respectful and constructive in all interactions.

### Our Standards

**Positive behavior includes:**
- ✅ Using welcoming and inclusive language
- ✅ Being respectful of differing viewpoints and experiences
- ✅ Gracefully accepting constructive criticism
- ✅ Focusing on what is best for the community
- ✅ Showing empathy towards other community members

**Unacceptable behavior includes:**
- ❌ Trolling, insulting/derogatory comments, and personal attacks
- ❌ Public or private harassment
- ❌ Publishing others' private information without permission
- ❌ Other conduct which could reasonably be considered inappropriate

---

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**When submitting a bug report, include:**

- **Script version** (Windows, version number)
- **Operating system** (Windows 10/11 build)
- **Expected behavior** vs **actual behavior**
- **Steps to reproduce**
- **Error messages or logs**
- **System configuration** (if relevant)

**Bug Report Template:**

```markdown
**Script:** Windows-Endpoint-Hardener-Complete.ps1 v2.2.0
**OS:** Windows 11 Pro 23H2 (Build 22631.3007)
**Security Level:** Standard

**Expected Behavior:**
BitLocker should enable with TPM protector

**Actual Behavior:**
Script fails with error "TPM not found" despite TPM being enabled in BIOS

**Steps to Reproduce:**
1. Run script with: .\Windows-Endpoint-Hardener-Complete.ps1 -SecurityLevel Standard
2. Script reaches BitLocker configuration step
3. Error occurs

**Error Messages:**
[Paste error messages here]

**Additional Context:**
TPM 2.0 is enabled in BIOS and shows as ready in Windows
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:

1. **Check existing feature requests** to avoid duplicates
2. **Provide clear use case** for the enhancement
3. **Explain how it benefits users**
4. **Consider security implications**

**Enhancement Template:**

```markdown
**Enhancement:** Add support for custom ASR rule exclusions

**Use Case:**
Organizations need to exclude specific paths or processes from ASR rules
for business-critical applications.

**Proposed Solution:**
Add -ASRExclusions parameter accepting JSON file with exclusion rules.

**Benefits:**
- Reduces false positives
- Improves enterprise adoption
- Maintains security while allowing necessary applications

**Security Considerations:**
- Validate exclusion paths to prevent abuse
- Log all exclusions for audit purposes
- Warn users about security impact
```

### Contributing Code

We love pull requests! Here's how to contribute code:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** following coding standards
4. **Test thoroughly** in multiple environments
5. **Commit with clear messages** (see commit guidelines)
6. **Push to your fork** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request** with detailed description

---

## 🛠️ Development Setup

### Windows Script Development

**Prerequisites:**
- Windows 10/11 with PowerShell 5.1+
- Administrator privileges
- VM or test environment (DO NOT test on production)

**Setup:**
```powershell
# Clone the repository
git clone https://github.com/Br3thren-Org/Windows-Device-Hardener.git
cd endpoint-hardener

# Create a test VM snapshot (if using VM)
# VMware: Take snapshot via GUI
# Hyper-V: Checkpoint-VM -Name "TestVM" -SnapshotName "PreHardening"

# Test syntax
powershell.exe -NoProfile -Command "`$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content '.\Windows-Endpoint-Hardener-Complete.ps1' -Raw), [ref]`$null)"

# Run in preview mode
.\Windows-Endpoint-Hardener-Complete.ps1 -Preview -SecurityLevel Quick
```

---

## 📏 Coding Standards

### PowerShell Standards

**General Guidelines:**
- ✅ Use **4 spaces** for indentation (no tabs)
- ✅ Maximum **120 characters** per line
- ✅ Use **PascalCase** for functions (e.g., `Set-FirewallConfiguration`)
- ✅ Use **camelCase** for variables (e.g., `$defenderStatus`)
- ✅ Use **meaningful names** (not $x, $temp, $foo)
- ✅ Add **comment-based help** for functions

**Code Style:**
```powershell
# GOOD
function Set-SecurityControl {
    param(
        [Parameter(Mandatory)]
        [string]$ControlName,

        [ValidateSet("Enabled", "Disabled")]
        [string]$State = "Enabled"
    )

    try {
        # Check current state
        $currentState = Get-SecurityControlState -Name $ControlName

        if ($currentState -eq $State) {
            Log "Control '$ControlName' already in state: $State" "INFO"
            return $true
        }

        # Apply change
        Set-ControlState -Name $ControlName -State $State
        Log "Successfully set '$ControlName' to: $State" "SUCCESS"
        return $true

    } catch {
        Log "Failed to set '$ControlName': $_" "ERROR"
        return $false
    }
}

# BAD
function dostuff {
$x=Get-Stuff
if($x-eq"foo"){Write-Host "bar"}else{Write-Host "baz"}
}
```

**PSScriptAnalyzer Compliance:**
```powershell
# Install PSScriptAnalyzer
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser

# Check your code
Invoke-ScriptAnalyzer -Path .\Windows-Endpoint-Hardener-Complete.ps1 -Severity Warning,Error

# Fix common issues automatically
Invoke-ScriptAnalyzer -Path .\script.ps1 -Fix
```

---

## 💬 Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring (no functional change)
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```
feat(windows): Add support for custom ASR exclusions

- Added -ASRExclusions parameter accepting JSON file
- Implemented validation for exclusion paths
- Added logging for all exclusions

Closes #123
```

```
docs(readme): Update compliance report examples

Added screenshots and detailed explanation of the new compliance
reporting feature introduced in v2.2.0.
```

---

## 🔄 Pull Request Process

### Before Submitting

1. ✅ **Test thoroughly** on multiple systems
2. ✅ **Run linters** (PSScriptAnalyzer, ShellCheck)
3. ✅ **Update documentation** if needed
4. ✅ **Add your changes** to CHANGELOG.md (if applicable)
5. ✅ **Ensure no conflicts** with main branch

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Testing Performed
- [ ] Tested on Windows 10
- [ ] Tested on Windows 11
- [ ] Tested Quick level
- [ ] Tested Standard level
- [ ] Tested Maximum level
- [ ] Tested Preview mode
- [ ] Tested Rollback functionality

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Commented code (particularly complex areas)
- [ ] Documentation updated
- [ ] No new warnings from linters
- [ ] Changes generate no new errors
- [ ] Added tests (if applicable)

## Related Issues
Closes #(issue number)
```

### Review Process

1. **Automated Checks:** CI/CD runs linters and basic tests
2. **Maintainer Review:** Code review for quality and security
3. **Testing:** Additional testing in various environments
4. **Approval:** At least one maintainer approval required
5. **Merge:** Squash and merge into main branch

---

## 🧪 Testing Requirements

### Manual Testing Checklist

**Windows:**
```powershell
# Test on clean VM/system
1. [ ] Preview mode works without errors
2. [ ] Quick level completes successfully
3. [ ] Standard level completes successfully
4. [ ] Maximum level completes successfully
5. [ ] Rollback restores previous state
6. [ ] Compliance report generates correctly
7. [ ] No unexpected system breakage
8. [ ] Logs are created properly
9. [ ] Exit codes are correct
10. [ ] Reboot detection works
```

### Automated Testing

**PowerShell (Pester):**
```powershell
# Install Pester
Install-Module -Name Pester -Force

# Run tests
Invoke-Pester -Path .\tests\
```

---

## 🔒 Security Considerations

When contributing, always consider:

1. **Input Validation:** Validate all user input
2. **Privilege Escalation:** Avoid unnecessary privilege requirements
3. **Credential Handling:** Never log sensitive data
4. **Command Injection:** Use parameterized commands
5. **Path Traversal:** Validate file paths
6. **Error Messages:** Don't expose sensitive info in errors

**Security Review Checklist:**
- [ ] No hardcoded credentials
- [ ] Input validation on all parameters
- [ ] Secure file operations (no predictable temp files)
- [ ] Proper error handling (no sensitive data leakage)
- [ ] Minimal privileges required
- [ ] No command injection vulnerabilities
- [ ] Security implications documented

---

## 📚 Additional Resources

- [PowerShell Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-development-guidelines)
- [CISA Security Guidelines](https://www.cisa.gov/uscert/ncas/tips)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

---

## ❓ Questions?

- **General Questions:** Open a [GitHub Discussion](https://github.com/Br3thren-Org/Windows-Device-Hardener/discussions)
- **Bug Reports:** Create an [Issue](https://github.com/Br3thren-Org/Windows-Device-Hardener/issues)
- **Security Issues:** See [SECURITY.md](SECURITY.md)

---

## 🎉 Recognition

Contributors will be:
- Listed in CHANGELOG.md for their contributions
- Mentioned in release notes
- Added to Contributors section (if desired)

Thank you for making Endpoint Hardener better! 🙏

---

**Last Updated:** 2025-10-27
