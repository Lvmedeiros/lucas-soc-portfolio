# Investigation Report — Suspicious PowerShell Execution

## 1. Executive Summary

A suspicious PowerShell command was detected on a Windows endpoint.

The command included indicators commonly associated with suspicious or malicious activity, such as execution policy bypass, encoded content, hidden execution, web requests, or command execution through PowerShell.

At this stage, the activity should be treated as suspicious until the full command line, parent process, user context, and post-execution activity are reviewed.

---

## 2. Alert Details

| Field | Value |
|---|---|
| Alert Name | Suspicious PowerShell Execution |
| Initial Severity | Medium |
| Affected User | user01 |
| Hostname | WIN-WS-01 |
| Process | powershell.exe |
| Parent Process | winword.exe |
| Log Source | Sysmon / Windows Event Logs |
| Status | Under Investigation |

---

## 3. Observed Events

| Source | Event ID | Description | Relevance |
|---|---|---|---|
| Sysmon | 1 | Process creation | Shows PowerShell execution and command line |
| Sysmon | 3 | Network connection | Shows outbound connections from the process |
| Windows Security | 4688 | Process creation | Shows process execution details |
| PowerShell | 4104 | Script block logging | Shows executed PowerShell script content |
| PowerShell | 4103 | Module logging | Shows PowerShell module activity |

---

## 4. Timeline

| Time | Event |
|---|---|
| 14:21 | User opened a Microsoft Word document |
| 14:22 | winword.exe launched powershell.exe |
| 14:22 | PowerShell executed with suspicious command-line arguments |
| 14:23 | PowerShell attempted outbound connection |
| 14:24 | Additional process or file activity observed |

---

## 5. Analysis

The activity is suspicious because PowerShell was launched with indicators that are commonly associated with malicious behavior.

PowerShell is a legitimate administrative tool, but attackers frequently abuse it to execute commands, download payloads, bypass execution controls, or run obfuscated scripts.

The parent process is especially important. PowerShell launched by administrative tools may be normal, but PowerShell launched by Office applications, browsers, script interpreters, or unusual processes should be investigated carefully.

Key points for analysis:

- The full command line should be reviewed
- Encoded content should be decoded
- Parent and child processes should be identified
- External IPs or domains should be checked
- Created or modified files should be reviewed
- Similar activity should be searched across other endpoints

---

## 6. Indicators Observed

| Indicator Type | Value | Notes |
|---|---|---|
| Process | powershell.exe | PowerShell execution observed |
| Parent Process | winword.exe | Suspicious parent process |
| Command Line | powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand | Suspicious flags observed |
| Destination IP | 203.0.113.10 | Example external IP for documentation |
| User | user01 | User context for the execution |
| Host | WIN-WS-01 | Affected endpoint |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Execution | PowerShell |
| Defense Evasion | Obfuscated Files or Information |
| Command and Control | Application Layer Protocol |
| Ingress Tool Transfer | Ingress Tool Transfer |

---

## 8. Severity Assessment

| Criteria | Assessment |
|---|---|
| Likelihood | Medium |
| Impact | Medium to High |
| Final Severity | High |
| Escalation Required | Yes, if malicious behavior is confirmed |

The severity is considered higher when PowerShell is launched by an unusual parent process, uses encoded commands, downloads content, or connects to suspicious external infrastructure.

---

## 9. Recommended Actions

- Review the full PowerShell command line
- Decode Base64 or obfuscated content if present
- Identify the parent process and child processes
- Review network connections made by PowerShell
- Check destination IPs and domains using threat intelligence sources
- Review files created or modified after execution
- Search for the same command or indicators across other endpoints
- Isolate the host if malicious activity is confirmed
- Reset user credentials if compromise is suspected
- Escalate to Incident Response if additional suspicious activity is found

---

## 10. Conclusion

The PowerShell execution should be treated as suspicious until additional context is reviewed.

PowerShell activity must be analyzed based on command line, parent process, user context, network activity, and post-execution behavior.

In this scenario, the presence of suspicious flags and an unusual parent process increases the likelihood of malicious activity.
