# MITRE ATT&CK Mapping — Suspicious PowerShell Execution

## Overview

This document maps the suspicious PowerShell execution scenario to the MITRE ATT&CK framework.

The observed behavior involves PowerShell being executed with suspicious command-line arguments, potentially including encoded commands, execution policy bypass, hidden execution, web requests, or payload download activity.

---

## Related MITRE ATT&CK Tactics

| Tactic | Description |
|---|---|
| Execution | The attacker may use PowerShell to execute commands or scripts |
| Defense Evasion | The attacker may use encoded or obfuscated commands to avoid detection |
| Command and Control | PowerShell may be used to communicate with external infrastructure |
| Ingress Tool Transfer | PowerShell may be used to download payloads or tools |

---

## Related MITRE ATT&CK Techniques

| Technique | Description | Relevance |
|---|---|---|
| PowerShell | Use of PowerShell to execute commands and scripts | PowerShell is the primary process observed in this scenario |
| Obfuscated Files or Information | Use of encoding or obfuscation to hide command content | EncodedCommand or Base64 content may indicate obfuscation |
| Application Layer Protocol | Use of common protocols such as HTTP/HTTPS for communication | PowerShell may contact external domains or IPs |
| Ingress Tool Transfer | Transfer of tools or payloads into the environment | PowerShell may download content using Invoke-WebRequest or DownloadString |

---

## Why This Mapping Matters

Mapping PowerShell activity to MITRE ATT&CK helps the analyst understand the possible attacker behavior behind the alert.

PowerShell alone is not malicious, but certain command-line arguments, parent processes, and network behavior can indicate abuse.

This mapping helps connect the observed event to broader adversary tactics and techniques.

---

## Detection Opportunities

This behavior can be detected by monitoring:

- PowerShell execution with encoded commands
- PowerShell execution with execution policy bypass
- PowerShell launched by Office applications
- PowerShell launched by browsers
- PowerShell launched by script interpreters
- PowerShell making outbound network connections
- PowerShell downloading content from external sources
- PowerShell creating or launching child processes
- PowerShell activity from unusual users or hosts

---

## Enrichment Opportunities

The alert can be enriched with additional context, such as:

- User role and privilege level
- Parent process
- Full command line
- Decoded command content
- Destination IP or domain reputation
- File hashes
- Process tree
- Historical PowerShell activity for the host
- Related endpoint or network alerts

---

## Analyst Questions

During triage, the analyst should ask:

1. Who executed PowerShell?
2. What process launched PowerShell?
3. What was the full command line?
4. Was the command encoded or obfuscated?
5. Did PowerShell connect to an external IP or domain?
6. Did PowerShell download or create any files?
7. Were any child processes launched?
8. Is this activity normal for the user or host?
9. Are there similar events on other endpoints?
10. Are there related alerts involving the same host, user, IP, or domain?

---

## Response Considerations

If the activity is confirmed suspicious, recommended actions may include:

- Decoding the command content
- Reviewing the full process tree
- Checking destination IPs and domains
- Reviewing file creation and modification activity
- Searching for similar activity across the environment
- Isolating the endpoint if compromise is confirmed
- Resetting credentials if account compromise is suspected
- Escalating to Incident Response if malicious behavior is confirmed

---

## Conclusion

This detection aligns mainly with PowerShell abuse, defense evasion, and possible payload download behavior.

Mapping the alert to MITRE ATT&CK improves investigation quality, detection coverage, and communication with other security teams.
