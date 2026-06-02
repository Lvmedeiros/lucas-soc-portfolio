# Suspicious PowerShell Execution

## Scenario

A suspicious PowerShell command was detected on a Windows endpoint.

PowerShell is commonly used by administrators for legitimate automation tasks, but it can also be abused by attackers to execute commands, download payloads, bypass defenses, or run encoded scripts.

---

## Objective

Investigate the PowerShell execution and determine whether the activity is legitimate, suspicious, or related to malicious behavior.

---

## Data Sources

- Windows Event Logs
- Sysmon Logs
- PowerShell Operational Logs
- EDR telemetry, when available

---

## Relevant Events

| Source | Event ID | Description |
|---|---|---|
| Sysmon | Event ID 1 | Process creation |
| Sysmon | Event ID 3 | Network connection |
| Windows Security | Event ID 4688 | Process creation |
| PowerShell | Event ID 4104 | Script block logging |
| PowerShell | Event ID 4103 | Module logging |

---

## Suspicious Indicators

The activity should be considered suspicious if PowerShell is executed with indicators such as:

```text
-EncodedCommand
-ExecutionPolicy Bypass
-NoProfile
-WindowStyle Hidden
DownloadString
Invoke-WebRequest
Invoke-Expression
IEX
Base64-encoded content
Connection to external IP or domain
```

---

## Investigation Notes

During the investigation, the analyst should validate:

- Which user executed the command
- Parent process that launched PowerShell
- Full command line
- Whether the command is encoded or obfuscated
- Destination IPs or domains contacted
- Files created or modified after execution
- Whether the endpoint generated additional alerts
- Whether the behavior matches normal administrative activity

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Execution | PowerShell |
| Defense Evasion | Obfuscated Files or Information |
| Command and Control | Application Layer Protocol |
| Ingress Tool Transfer | Ingress Tool Transfer |

---

## Severity

Suggested severity: **Medium to High**

Severity may increase if:

- PowerShell was launched by Office, browser, or script interpreter
- Encoded or obfuscated commands were used
- The command downloaded content from the internet
- The process connected to suspicious infrastructure
- The activity happened on a privileged account
- Additional payloads were created or executed

---

## Recommended Response

- Review the full command line
- Decode Base64 content if present
- Identify the parent process
- Check destination IP/domain reputation
- Review created files and child processes
- Isolate the host if malicious behavior is confirmed
- Collect forensic evidence if needed
- Escalate to Incident Response if compromise is suspected

---

## Project Files

- [Detection Logic](./detection-logic.md)
- [Investigation Report](./investigation-report.md)
- [MITRE ATT&CK Mapping](./mitre-attack.md)

---

## Conclusion

Suspicious PowerShell execution is an important detection scenario for SOC monitoring because PowerShell is frequently used in both legitimate administration and malicious activity.

Context is essential to determine whether the activity is benign, suspicious, or malicious.
