# Investigation Report — Brute Force Detection

## 1. Executive Summary

Multiple failed login attempts were identified for the same user within a short period of time, followed by a successful login.

This behavior may indicate a brute force attempt, password spraying, or the use of compromised credentials.

At this stage, the activity should be treated as suspicious until additional validation is completed.

---

## 2. Alert Details

| Field | Value |
|---|---|
| Alert Name | Multiple Failed Logons Followed by Success |
| Initial Severity | Medium |
| Affected User | user01 |
| Source IP | 192.168.1.50 |
| Destination Host | WIN-SRV-01 |
| Log Source | Windows Security Logs |
| Status | Under Investigation |

---

## 3. Observed Events

| Event ID | Description | Relevance |
|---|---|---|
| 4625 | Failed Logon | Indicates failed authentication attempts |
| 4624 | Successful Logon | Indicates a successful authentication |
| 4740 | Account Locked Out | May indicate repeated failed login attempts |

---

## 4. Timeline

| Time | Event |
|---|---|
| 10:01 | First failed login attempt |
| 10:02 | Second failed login attempt |
| 10:03 | Third failed login attempt |
| 10:04 | Fourth failed login attempt |
| 10:05 | Fifth failed login attempt |
| 10:06 | Successful login observed |

---

## 5. Analysis

The observed pattern is suspicious because multiple authentication failures occurred in a short time window and were followed by a successful login.

This may suggest that an attacker successfully guessed or used valid credentials after several failed attempts.

The severity would increase if one or more of the following conditions are true:

- The affected account is privileged
- The source IP is external or unusual
- The login occurred outside business hours
- MFA was not enabled
- The account accessed sensitive systems after login
- Similar attempts were observed against multiple users

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | Brute Force |
| Credential Access | Password Guessing |
| Initial Access | Valid Accounts |

---

## 7. Severity Assessment

| Criteria | Assessment |
|---|---|
| Likelihood | Medium |
| Impact | Medium |
| Final Severity | Medium |
| Escalation Required | Conditional |

The alert should be escalated if there is evidence of account compromise, suspicious post-login activity, or access to sensitive systems.

---

## 8. Recommended Actions

- Validate the activity with the affected user
- Review the source IP address and reputation
- Check for additional failed logins from the same source
- Review activity after the successful login
- Confirm whether MFA was enabled
- Reset the password if compromise is suspected
- Block the source IP if confirmed malicious
- Escalate to Incident Response if further suspicious activity is found

---

## 9. Conclusion

The alert should not be closed as a false positive without additional validation.

Multiple failed login attempts followed by a successful login represent a relevant detection scenario for SOC monitoring and may indicate brute force activity, password spraying, or compromised credentials.
