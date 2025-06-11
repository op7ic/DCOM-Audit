# DCOM-Audit

A comprehensive PowerShell-based security auditing tool for Windows DCOM (Distributed Component Object Model) permissions and configurations. DCOM-Audit provides deep analysis, vulnerability detection, attack scenario mapping, and actionable security recommendations for DCOM objects in Windows Environment.

## 🔥 Key Features

- **Comprehensive Permission Analysis**: Audits both Launch and Access permissions for all DCOM objects
- **Attack Scenario Detection**: Maps vulnerabilities to real-world attack techniques with examples
- **DLL Hijacking Detection**: Identifies writable DLL paths and phantom DLL opportunities
- **Service Security Analysis**: Checks permissions on DCOM-related Windows services
- **Interface Enumeration**: Identifies exposed COM interfaces and dangerous methods
- **Vulnerability Detection**: Identifies high-risk configurations and dangerous method exposures
- **Risk-Based Reporting**: Categorizes findings by severity (Critical, High, Medium, Low)
- **.NET Fallback Methods**: Ensures reliable auditing even when PowerShell methods fail
- **Performance Optimizations**: Significantly faster than v1.0 with parallel processing support
- **DCOM Hardening Verification**: Validates Windows DCOM security patches and configurations
- **Multiple Output Formats**: HTML reports, CSV exports, and console output
- **Mitigation Guidance**: Provides specific recommendations for each vulnerability
- **MITRE ATT&CK Mapping**: Links findings to specific adversary techniques

## 🛡️ Features

### Advanced Attack Surface Analysis
- **DLL Permission Checking**: Identifies DLL hijacking opportunities in DCOM server paths
- **Service Permission Auditing**: Finds privilege escalation vectors via weak service ACLs
- **Interface Analysis**: Enumerates COM interfaces to identify scriptable objects
- **Known Exploit Detection**: Flags DCOM objects with documented exploitation techniques
- **x86/x64 Compatibility**: Handles architecture mismatches gracefully
- **Method Detection**: Uses multiple techniques to enumerate methods

### Attack Scenario Mapping
- Real-world exploitation examples for each vulnerability
- MITRE ATT&CK technique mapping
- Detection and prevention guidance
- Sample attack code for security testing

### Enhanced Detection Capabilities
- SIEM/EDR detection rules in multiple formats (Sigma, Splunk, ELK, KQL)
- PowerShell logging recommendations
- Network-based detection strategies
- Behavioral indicators of compromise

## 📋 Requirements

- Windows 7/Server 2008 R2 or later
- PowerShell 4.0 or higher
- Administrative privileges (for complete audit)
- .NET Framework 4.5 or higher

## 🚀 Quick Start

```powershell
# Basic audit (permissions only)
.\DCOM-Auditor-Enhanced.ps1

# Full audit with method enumeration
.\DCOM-Auditor-Enhanced.ps1 -Audit

# Generate report with CSV export
.\DCOM-Auditor-Enhanced.ps1 -Audit -ExportCSV -OutputPath "C:\Reports"

# Check DCOM hardening status
.\DCOM-Auditor-Enhanced.ps1 -Audit -CheckMitigations

# Fast mode (skip method enumeration)
.\DCOM-Auditor-Enhanced.ps1 -FastMode
```

## 📊 Output Examples

### Console Output
```
[!] Critical Risk: Everyone has Launch permissions (LocalLaunch, RemoteLaunch) for {00020906-0000-0000-C000-000000000046}
    Application: Microsoft Word Document

[!] WARNING: Dangerous methods found in {00000300-0000-0000-C000-000000000046}
    Methods: Shell, Execute, Navigate
```

### HTML Report
The tool generates a comprehensive HTML report including:
- Executive summary with risk statistics
- DCOM hardening status
- Prioritized recommendations
- Detailed findings table with color-coded risk levels

## 🔍 Understanding DCOM Permissions

| Permission Type | Description | Risk Implications |
|-----------------|-------------|-------------------|
| **LocalLaunch** | Start COM server on local machine | Low risk if properly restricted |
| **RemoteLaunch** | Start COM server from remote machine | High risk if granted to broad groups |
| **LocalActivation** | Activate COM object locally | Medium risk depending on object |
| **RemoteActivation** | Activate COM object remotely | High risk for privileged objects |
| **LocalAccess** | Access running COM server locally | Low to medium risk |
| **RemoteAccess** | Access running COM server remotely | High risk if unrestricted |

## 🛡️ Risk Categories

### Critical Risk
- "Everyone" or "Authenticated Users" with remote permissions
- Non-admin users with access to dangerous methods
- Default permissions on sensitive DCOM objects

### High Risk
- Domain Users with launch/activation rights
- Remote access permissions for non-administrative groups
- Objects exposing dangerous methods without restrictions

### Medium Risk
- Local permissions for non-admin users
- Default permissions in use
- Missing DCOM hardening configurations

## 🔧 DCOM Security Hardening

### Apply KB5004442 Mitigations
The tool checks for and recommends the following hardening measures:

1. **Disable DCOM HTTP**
   ```
   HKLM\SOFTWARE\Microsoft\Ole\EnableDCOMHTTP = 0
   ```

2. **Increase Authentication Level**
   ```
   HKLM\SOFTWARE\Microsoft\Ole\DefaultAuthenticationLevel = 5 (Packet Integrity)
   ```

3. **Restrict Launch Permissions**
   ```
   HKLM\SOFTWARE\Microsoft\Ole\AllowLaunchActAsInteractiveUser = 0
   ```

### Additional Security Recommendations

1. **Remove Unnecessary Permissions**
   - Remove "Everyone" from all DCOM permissions
   - Restrict "Authenticated Users" to local access only
   - Limit remote access to specific administrative accounts

2. **Monitor High-Risk Objects**
   - MMC Application Class (MMC20.Application)
   - ShellWindows ({9BA05972-F6A8-11CF-A442-00A0C90A8F39})
   - ShellBrowserWindow ({C08AFD90-F2A1-11D1-8455-00A0C91F3880})

3. **Implement Defense in Depth**
   - Enable Windows Firewall rules for DCOM
   - Use IPSec for DCOM authentication
   - Implement network segmentation

## 📝 Report Contents

The generated reports include:

1. **Executive Summary**
   - Total objects analyzed
   - Risk distribution
   - Critical findings count

2. **DCOM Hardening Status**
   - Current security settings
   - Compliance with recommendations

3. **Detailed Findings**
   - Per-object permission analysis
   - Risk scoring
   - User/group mappings

4. **Recommendations**
   - Prioritized by severity
   - Specific remediation steps
   - References to Microsoft guidance

## 🔗 References

- [Microsoft DCOM Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [DCOM Authentication Hardening](https://techcommunity.microsoft.com/blog/windows-itpro-blog/dcom-authentication-hardening-what-you-need-to-know/3657154)
- [MS-DCOM Protocol Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0)
- [COM Security Best Practices](https://docs.microsoft.com/en-us/windows/win32/com/security-in-com)

## 🤝 Contributing

Contributions are welcome! Please submit issues and pull requests on GitHub.

## License

See LICENSE file

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.