# Detection Logic — Brute Force Detection

## Detection Objective

Detect multiple failed login attempts against the same user account within a short period of time, followed by a successful login.

This behavior may indicate brute force activity, password spraying, or the use of compromised credentials.

---

## Log Sources

| Source | Event ID | Description |
|---|---|---|
| Windows Security Logs | 4625 | Failed logon |
| Windows Security Logs | 4624 | Successful logon |
| Windows Security Logs | 4740 | Account locked out |

---

## Detection Pattern

The alert should trigger when the following pattern is observed:

```text
More than 5 failed login attempts
for the same user account
within 10 minutes
followed by a successful login
from the same source IP or unusual location
Splunk SPL Example
index=windows sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval action=case(EventCode=4625, "failed_logon", EventCode=4624, "successful_logon")
| bin _time span=10m
| stats count(eval(action="failed_logon")) as failed_attempts,
        count(eval(action="successful_logon")) as successful_logons,
        values(Source_Network_Address) as source_ip
        by Account_Name, _time
| where failed_attempts > 5 AND successful_logons >= 1
Microsoft Sentinel KQL Example
SecurityEvent
| where EventID in (4625, 4624)
| summarize
    FailedAttempts = countif(EventID == 4625),
    SuccessfulLogons = countif(EventID == 4624),
    SourceIPs = make_set(IpAddress)
    by Account, bin(TimeGenerated, 10m)
| where FailedAttempts > 5 and SuccessfulLogons >= 1
Alert Fields
Field	Description
Account_Name / Account	User account involved in the authentication activity
Source_Network_Address / IpAddress	Source IP address of the login attempt
EventCode / EventID	Windows authentication event ID
_time / TimeGenerated	Timestamp of the event
Destination Host	Host where the authentication attempt occurred
Severity Logic
Condition	Severity
Multiple failures followed by success for a normal user	Medium
Activity from unusual location or external IP	High
Activity involving privileged account	High
Activity followed by access to sensitive systems	High
Same source targeting multiple users	High
Confirmed account compromise	Critical
Possible False Positives
User forgot password and retried several times
Password recently changed
Cached credentials on a device
Misconfigured application or service account
VPN or remote access authentication issue
User logging in from a new device
Tuning Recommendations

To reduce false positives, consider tuning based on:

Known internal IP ranges
Service accounts
VPN gateways
Expected business hours
Known administrative activity
Users with recent password changes
MFA status
Historical login behavior
Analyst Triage Questions

During triage, the analyst should answer:

Is the affected account privileged?
Is the source IP known or expected?
Did the login happen outside normal business hours?
Was MFA enabled and successfully completed?
Was there any suspicious activity after the successful login?
Are there similar attempts against other users?
Has the source IP appeared in threat intelligence sources?
Recommended Response
Validate the activity with the user
Review the source IP and geolocation
Check for additional failed logins
Review post-authentication activity
Reset the password if compromise is suspected
Enforce MFA if not enabled
Block malicious source IPs if confirmed
Escalate to Incident Response if suspicious activity continues
Conclusion

This detection is useful for SOC monitoring because it identifies a common authentication attack pattern.

The detection should not rely only on the number of failed logins. Context such as source IP, account privilege, time of activity, MFA status, and post-login behavior is essential to determine whether the alert is a false positive or a real security incident.


Depois clique em **Commit changes**.

Na mensagem do commit, coloque:

```text
Add brute force detection logic
