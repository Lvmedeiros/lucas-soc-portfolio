# MITRE ATT&CK Mapping — Brute Force Detection

## Overview

This document maps the brute force detection scenario to the MITRE ATT&CK framework.

The observed behavior involves multiple failed login attempts followed by a successful login, which may indicate credential guessing, brute force activity, password spraying, or the use of valid credentials.

---

## Related MITRE ATT&CK Tactics

| Tactic | Description |
|---|---|
| Credential Access | The attacker attempts to steal, guess, or obtain valid credentials |
| Initial Access | The attacker may use valid credentials to gain access to the environment |
| Defense Evasion | The attacker may try to make the activity look like normal authentication behavior |

---

## Related MITRE ATT&CK Techniques

| Technique | Description | Relevance |
|---|---|---|
| Brute Force | Attempts to guess passwords through repeated authentication attempts | Multiple failed logins may indicate brute force activity |
| Password Guessing | Attempts to authenticate using guessed passwords | Several failed attempts against the same user can indicate password guessing |
| Password Spraying | Attempts one or a few common passwords against multiple accounts | Relevant if the same source IP targets multiple users |
| Valid Accounts | Use of legitimate credentials to access systems | A successful login after multiple failures may indicate valid credentials were obtained or used |

---

## Why This Mapping Matters

Mapping detections to MITRE ATT&CK helps the analyst understand the attacker behavior behind the alert.

Instead of looking only at isolated events, the analyst can connect the activity to possible adversary tactics and techniques.

In this case, failed authentication attempts followed by a successful login may represent an attempt to gain access using stolen, guessed, or weak credentials.

---

## Detection Opportunities

This behavior can be detected by monitoring:

- Multiple failed login attempts for the same user
- Multiple failed login attempts from the same source IP
- Failed logins followed by a successful login
- Login attempts outside normal business hours
- Authentication from unusual locations
- Authentication attempts against privileged accounts
- Similar activity across multiple users

---

## Enrichment Opportunities

The alert can be enriched with additional context, such as:

- User role and privilege level
- Source IP reputation
- Geolocation
- Historical login behavior
- MFA status
- Asset criticality
- Threat intelligence results
- Previous alerts related to the same user or IP address

---

## Analyst Questions

During triage, the analyst should ask:

1. Is the account privileged?
2. Is the source IP known or expected?
3. Is the login location normal for this user?
4. Did the login happen outside business hours?
5. Was MFA enabled and completed successfully?
6. Was there suspicious activity after the successful login?
7. Are other users being targeted by the same source?

---

## Response Considerations

If the activity is confirmed suspicious, recommended actions may include:

- Resetting the affected user's password
- Enforcing MFA
- Blocking the malicious source IP
- Reviewing recent activity from the affected account
- Checking for lateral movement
- Searching for similar authentication patterns
- Escalating to Incident Response if compromise is suspected

---

## Conclusion

This detection aligns mainly with credential-based attack behavior.

Mapping the alert to MITRE ATT&CK helps improve investigation quality, detection coverage, and communication with other security teams.
