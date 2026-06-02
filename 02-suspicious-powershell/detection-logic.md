# Detection Logic — Suspicious PowerShell Execution

## Detection Objective

Detect suspicious PowerShell execution patterns that may indicate malicious activity, defense evasion, payload download, command execution, or abuse of legitimate Windows tools.

PowerShell is commonly used for administration, but attackers often abuse it because it is available by default on Windows systems and can execute commands, download files, run scripts, and interact with the operating system.

---

## Log Sources

| Source | Event ID | Description |
|---|---|---|
| Sysmon | Event ID 1 | Process creation |
| Sysmon | Event ID 3 | Network connection |
| Windows Security Logs | Event ID 4688 | Process creation |
| PowerShell Operational Logs | Event ID 4104 | Script block logging |
| PowerShell Operational Logs | Event ID 4103 | Module logging |

---

## Detection Pattern

The alert should trigger when PowerShell is executed with suspicious command-line arguments or behavior.

Examples of suspicious indicators:

```text
powershell.exe -EncodedCommand
powershell.exe -ExecutionPolicy Bypass
powershell.exe -NoProfile
powershell.exe -WindowStyle Hidden
powershell.exe IEX
powershell.exe Invoke-Expression
powershell.exe Invoke-WebRequest
powershell.exe DownloadString
powershell.exe downloading content from external IP or domain
powershell.exe launched by Office, browser, or script interpreter
```

---

## Splunk SPL Example

```spl
index=windows (sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)
(EventCode=4688 OR EventCode=1)
| where like(CommandLine, "%powershell%")
| eval suspicious=case(
    like(CommandLine, "%EncodedCommand%"), "encoded_command",
    like(CommandLine, "%ExecutionPolicy Bypass%"), "execution_policy_bypass",
    like(CommandLine, "%NoProfile%"), "no_profile",
    like(CommandLine, "%WindowStyle Hidden%"), "hidden_window",
    like(CommandLine, "%Invoke-WebRequest%"), "web_request",
    like(CommandLine, "%Invoke-Expression%"), "invoke_expression",
    like(CommandLine, "%DownloadString%"), "download_string",
    like(CommandLine, "%IEX%"), "iex"
)
| where isnotnull(suspicious)
| table _time, host, User, ParentImage, Image, CommandLine, suspicious
| sort - _time
```

---

## Microsoft Sentinel KQL Example

```kql
SecurityEvent
| where EventID == 4688
| where Process has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any (
    "-EncodedCommand",
    "-ExecutionPolicy Bypass",
    "-NoProfile",
    "-WindowStyle Hidden",
    "Invoke-WebRequest",
    "Invoke-Expression",
    "DownloadString",
    "IEX"
)
| project TimeGenerated, Computer, Account, ParentProcessName, Process, CommandLine
| order by TimeGenerated desc
```

---

## Sysmon Detection Example

```text
Event ID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64>
ParentImage: winword.exe, excel.exe, outlook.exe, chrome.exe, cmd.exe, wscript.exe, cscript.exe
```

---

## Alert Fields

| Field | Description |
|---|---|
| User / Account | User account that executed PowerShell |
| Host / Computer | Endpoint where the command was executed |
| Image / Process | PowerShell process path |
| CommandLine | Full command executed |
| ParentImage / ParentProcessName | Process that launched PowerShell |
| Destination IP / Domain | External destination contacted by PowerShell |
| Hash | File hash, when available |
| TimeGenerated / _time | Timestamp of the event |

---

## Severity Logic

| Condition | Severity |
|---|---|
| PowerShell executed with normal administrative command | Low |
| PowerShell executed with suspicious flags | Medium |
| PowerShell launched by Office, browser, or script interpreter | High |
| Encoded or obfuscated command detected | High |
| PowerShell downloads content from the internet | High |
| PowerShell creates or executes additional payloads | High |
| Confirmed malicious activity or compromise | Critical |

---

## Possible False Positives

- Legitimate administrative scripts
- Software deployment tools
- IT automation tasks
- Security tools using PowerShell
- Login scripts
- Monitoring or inventory scripts
- Internal help desk troubleshooting

---

## Tuning Recommendations

To reduce false positives, consider tuning based on:

- Approved administrative scripts
- Known IT administrator accounts
- Expected management servers
- Signed scripts
- Internal repositories
- Known software deployment tools
- Business hours
- Parent process behavior
- Historical activity for the user and host

---

## Analyst Triage Questions

During triage, the analyst should answer:

1. Which user executed PowerShell?
2. What was the full command line?
3. Was the command encoded or obfuscated?
4. What process launched PowerShell?
5. Did PowerShell connect to an external IP or domain?
6. Were any files downloaded or created?
7. Did any child processes execute after PowerShell?
8. Is this behavior normal for the user or host?
9. Is the destination known, trusted, or suspicious?
10. Are there other alerts related to the same host or user?

---

## Recommended Response

- Review the full PowerShell command line
- Decode Base64 content if present
- Identify the parent process
- Review destination IPs and domains
- Check reputation of external indicators
- Review files created or modified after execution
- Search for similar activity across other hosts
- Isolate the endpoint if malicious behavior is confirmed
- Reset credentials if account compromise is suspected
- Escalate to Incident Response if further suspicious activity is found

---

## Conclusion

This detection helps identify suspicious PowerShell behavior commonly observed in malicious activity.

The presence of PowerShell alone does not confirm compromise. The analyst must review context such as command-line arguments, parent process, user behavior, destination connections, file activity, and related alerts before making a final decision.
