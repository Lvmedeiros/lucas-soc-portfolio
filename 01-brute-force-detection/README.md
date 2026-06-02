# Brute Force Detection

## Scenario

Multiple failed login attempts were detected for the same user within a short period of time, followed by a successful login.

This behavior may indicate a brute force attempt, password spraying, or the use of compromised credentials.

---

## Objective

Investigate authentication events and determine whether the activity is legitimate, suspicious, or related to a potential account compromise.

---

## Data Sources

- Windows Security Logs
- Event ID 4625 — Failed Logon
- Event ID 4624 — Successful Logon
- Event ID 4740 — Account Locked Out

---

## Detection Logic

The activity should be considered suspicious when the following pattern is observed:

```text
More than 5 failed login attempts for the same user
within 10 minutes
followed by a successful login
from the same source IP or an unusual location
```

---

## Investigation Notes

During the investigation, the analyst should validate:

- Whether the user recognizes the activity
- Source IP address and geolocation
- Time of the login attempt
- Whether the account is privileged
- Whether MFA was enabled
- Any activity after the successful login
- Access to critical systems or sensitive data

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | Brute Force |
| Credential Access | Password Guessing |
| Initial Access | Valid Accounts |

---

## Severity

Suggested severity: **Medium to High**

Severity may increase if:

- The account is privileged
- The login came from an external or unusual IP address
- The activity occurred outside business hours
- MFA was not enabled
- The user accessed sensitive systems after the login

---

## Recommended Response

- Validate the activity with the user
- Review source IP reputation
- Check for additional login attempts
- Review activity after successful authentication
- Reset the password if needed
- Enforce MFA
- Block malicious source IPs if confirmed
- Escalate to Incident Response if account compromise is suspected

---

## Project Files

- [Detection Logic](./detection-logic.md)
- [Investigation Report](./investigation-report.md)
- [MITRE ATT&CK Mapping](./mitre-attack.md)

---

## Conclusion

Multiple failed login attempts followed by a successful login should not be closed as a false positive without additional validation.

This pattern is important for SOC monitoring because it may indicate brute force activity, password spraying, or compromised credentials.
