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


# DCOM Security Monitoring Guide

## Overview

This guide provides security teams with actionable monitoring strategies for DCOM-based attacks, including dashboard configurations, alert rules, and response procedures.

## Key Indicators to Monitor

### 1. DCOM Process Indicators

| Indicator | Normal Behavior | Suspicious Behavior |
|-----------|-----------------|---------------------|
| dllhost.exe spawning | Local operations only | Remote IP connections |
| mmc.exe with -Embedding | Administrative tasks | Spawned by non-admin |
| iexplore.exe automation | User browsing | Hidden window + child processes |
| Excel/Word with /automation | Document processing | Network connections + exec |


### 2. Known Exploitation Targets:
```
┌─────────────────────────────────────────┬──────────────────────┬───────────┐
│ CLSID                                   │ Name                 │ Risk      │
├─────────────────────────────────────────┼──────────────────────┼───────────┤
│ {9BA05972-F6A8-11CF-A442-00A0C90A8F39} │ ShellWindows        │ CRITICAL  │
│ {49B2791A-B1AE-4C90-9B8E-E860BA07F889} │ MMC20.Application   │ CRITICAL  │
│ {00021401-0000-0000-C000-000000000046} │ ShellBrowserWindow  │ HIGH      │
│ {F5078F35-C551-11D3-89B9-0000F81FE221} │ Outlook.Application │ HIGH      │
└─────────────────────────────────────────┴──────────────────────┴───────────┘
```

### 2. Network Indicators

```
Critical Ports:
- TCP 135 (RPC Endpoint Mapper)
- Dynamic RPC ports (49152-65535)
- TCP 445 (SMB, often used with DCOM)

Suspicious Patterns:
- Multiple failed DCOM authentications
- DCOM connections from unusual sources
- High volume of RPC traffic to single host
- DCOM traffic outside business hours
```

### 3. SIEM Rules to Detect DCOM attacks

```
---
title: DCOM Lateral Movement via MMC20.Application
id: 51e47cc5-9e44-4c64-a819-7f8a8e3e3d1c
status: production
description: Detects usage of MMC20.Application COM object for remote command execution
author: DCOM Auditor Enhanced
date: 2024/01/15
tags:
    - attack.lateral_movement
    - attack.t1021.003
    - attack.execution
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith: '\mmc.exe'
        CommandLine|contains:
            - '-Embedding'
            - '/Embedding'
    remote_connection:
        EventID: 4624
        LogonType: 3
        TargetUserName|endswith: '$'
    timeframe: 5s
    condition: selection and remote_connection
falsepositives:
    - Legitimate remote administration
level: high

---
title: DCOM ShellWindows Object Abuse
id: 16d71e55-43fd-4ee1-9701-8e30cbb85ebe
status: production
description: Detects potential abuse of ShellWindows COM object for code execution
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains: '\AppData\Local\Temp\'
        Image|endswith: '\iexplore.exe'
    process_creation:
        EventID: 1
        ParentImage|endswith: '\iexplore.exe'
        CommandLine|contains:
            - 'powershell'
            - 'cmd.exe'
            - 'rundll32'
            - 'regsvr32'
    condition: selection or process_creation
falsepositives:
    - Legitimate IE automation
level: high

---
title: Suspicious DCOM Network Connection
id: 91a2625b-6e94-4736-b0e1-c42885f0d5cc
status: production
description: Detects DCOM connections that may indicate lateral movement
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image|endswith: '\dllhost.exe'
        DestinationPort: 
            - 135
            - 445
        Initiated: 'true'
    filter:
        DestinationIp|startswith:
            - '127.'
            - '::1'
    condition: selection and not filter
falsepositives:
    - Legitimate DCOM communication
level: medium

---
title: DCOM DLL Hijacking Attempt
id: e5c2b032-b4dc-4a47-bfea-f0614b3a1f8f
status: experimental
description: Detects potential DLL hijacking via DCOM by monitoring DLL loads
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image|endswith: '\dllhost.exe'
        ImageLoaded|contains:
            - '\Users\'
            - '\Temp\'
            - '\ProgramData\'
    filter:
        ImageLoaded|endswith:
            - '\System32\'
            - '\SysWOW64\'
        Signed: 'true'
    condition: selection and not filter
falsepositives:
    - Custom DCOM applications
level: high

---
title: Excel 4.0 Macro Execution via DCOM
id: 7c3e8e69-c4b6-48a0-abed-c0fbbaac7b0f
status: production
description: Detects Excel 4.0 macro execution potentially triggered via DCOM
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: security
detection:
    parent_process:
        EventID: 4688
        NewProcessName|endswith: '\excel.exe'
        CommandLine|contains:
            - '/automation'
            - '-Embedding'
    child_process:
        EventID: 4688
        ParentProcessName|endswith: '\excel.exe'
        NewProcessName|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    condition: parent_process and child_process
falsepositives:
    - Legitimate Excel automation
level: high

---
title: DCOM Service Permission Modification
id: 5f0e0877-296e-4d22-8bda-2a2e62814cf0
status: production
description: Detects modification of services associated with DCOM objects
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7040
        param1: 'auto start'
    service_modification:
        EventID: 4657
        ObjectName|contains: '\Services\'
        ProcessName|endswith:
            - '\sc.exe'
            - '\powershell.exe'
    condition: selection or service_modification
falsepositives:
    - Legitimate service configuration
level: medium

---
title: Outlook COM Object Abuse for Persistence
id: c3e76af4-d0cb-4588-81cf-ad5c45185aa8
status: production
description: Detects potential abuse of Outlook COM object for persistence
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: sysmon
detection:
    registry_set:
        EventID: 13
        TargetObject|contains:
            - '\Software\Microsoft\Office\Outlook\Rules'
            - '\Software\Microsoft\Office\Outlook\Security'
        Details|contains:
            - '.exe'
            - '.dll'
            - '.scr'
            - '.bat'
    process_creation:
        EventID: 1
        ParentImage|endswith: '\outlook.exe'
        Image|not_endswith:
            - '\outlook.exe'
            - '\EXCEL.EXE'
            - '\WINWORD.EXE'
    condition: registry_set or process_creation
falsepositives:
    - Legitimate Outlook add-ins
level: high

---
title: DCOM Authentication Bypass Attempt
id: bf9e1387-0040-4393-9bea-ac0a3d49f740
status: production
description: Detects attempts to bypass DCOM authentication
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 
            - 10028  # DCOM access denied
            - 10036  # DCOM authentication failure
        Message|contains:
            - 'The server did not register with DCOM'
            - 'Access is denied'
            - 'The authentication service is unknown'
    high_frequency:
        count: 5
        timeframe: 1m
    condition: selection and high_frequency
falsepositives:
    - Misconfigured applications
level: high

---
title: Remote WMI via DCOM
id: 056094ef-0e37-4da9-85a6-c69088ba146d
status: production
description: Detects remote WMI execution potentially using DCOM
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: wmi
detection:
    selection:
        EventID: 5857
        Type: 'Temporary'
    remote_connection:
        EventID: 5858
        Operation: 'Provider Started'
    dcom_connection:
        EventID: 11
        TargetFilename|contains: '\WBEM\Repository\'
    condition: (selection and remote_connection) or dcom_connection
falsepositives:
    - Legitimate remote management
level: medium

---
title: PowerShell DCOM Execution
id: 5cd72f0e-5aea-451c-b55e-2ee8042c8a91
status: production
description: Detects PowerShell commands used for DCOM lateral movement
author: DCOM Auditor Enhanced
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'GetTypeFromCLSID'
            - 'GetTypeFromProgID'
            - 'CreateInstance'
            - '::InternetExplorer.Application'
            - 'MMC20.Application'
            - 'ShellWindows'
            - '9BA05972-F6A8-11CF-A442-00A0C90A8F39'
    remote_indicator:
        ScriptBlockText|re: '\[activator\]::CreateInstance\([^,]+,["\'][^"\']+["\']\)'
    condition: selection and remote_indicator
falsepositives:
    - Administrative scripts
level: high

# Splunk Search Examples
splunk_searches:
    dcom_lateral_movement: |
        index=windows EventCode=4688 NewProcessName="*\\mmc.exe" CommandLine="*-Embedding*"
        | join type=inner host 
        [search index=windows EventCode=4624 LogonType=3 
        | eval jointime=_time 
        | eval starttime=jointime-5 
        | eval endtime=jointime+5] 
        | where _time>=starttime AND _time<=endtime
        | table _time host TargetUserName NewProcessName CommandLine

    dcom_network_connections: |
        index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
        Image="*\\dllhost.exe" (DestinationPort=135 OR DestinationPort=445) 
        NOT (DestinationIp="127.*" OR DestinationIp="::1")
        | stats count by SourceIp DestinationIp DestinationPort

    powershell_dcom_abuse: |
        index=windows EventCode=4104 
        (ScriptBlockText="*GetTypeFromCLSID*" OR ScriptBlockText="*GetTypeFromProgID*" OR 
         ScriptBlockText="*MMC20.Application*" OR ScriptBlockText="*ShellWindows*")
        | rex field=ScriptBlockText "(?<target_host>['\"][^'\"]+['\"])\s*\)"
        | table _time host User ScriptBlockText target_host

# ElasticSearch/ELK Queries
elasticsearch_queries:
    dcom_abuse_detection: |
        {
          "query": {
            "bool": {
              "must": [
                {"match": {"event.code": "4688"}},
                {"wildcard": {"process.name": "*\\dllhost.exe"}},
                {"match": {"process.command_line": "*-Embedding*"}}
              ],
              "filter": {
                "range": {
                  "@timestamp": {
                    "gte": "now-1h"
                  }
                }
              }
            }
          }
        }

# KQL (Azure Sentinel/Microsoft 365 Defender)
kql_queries:
    dcom_lateral_movement_kql: |
        union DeviceProcessEvents, DeviceNetworkEvents
        | where Timestamp > ago(24h)
        | where ProcessCommandLine contains "GetTypeFromCLSID" 
            or ProcessCommandLine contains "MMC20.Application"
            or ProcessCommandLine contains "ShellWindows"
        | join kind=inner (
            DeviceNetworkEvents
            | where RemotePort == 135
        ) on DeviceName
        | project Timestamp, DeviceName, InitiatingProcessAccountName, 
                  ProcessCommandLine, RemoteIP, RemotePort
```


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