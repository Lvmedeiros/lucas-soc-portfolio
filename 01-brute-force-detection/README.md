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
