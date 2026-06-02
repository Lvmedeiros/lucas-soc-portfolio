# Investigation Report — Phishing Investigation

## 1. Executive Summary

A suspicious email was reported by a user and submitted for security review.

The email contained multiple phishing indicators, including urgent language, a suspicious sender domain, failed email authentication checks, and a link requesting password verification.

At this stage, the email should be treated as malicious unless additional evidence proves otherwise.

---

## 2. Alert Details

| Field | Value |
|---|---|
| Alert Name | Reported Phishing Email |
| Initial Severity | Medium |
| Reported By | user01 |
| Recipient | user01@company.com |
| Sender Display Name | IT Support |
| Sender Email Address | support@example-security.com |
| Subject | Urgent Password Verification Required |
| Attachment Present | No |
| URLs Present | Yes |
| Status | Under Investigation |

---

## 3. Observed Indicators

| Indicator Type | Value | Assessment |
|---|---|---|
| Sender Domain | example-security.com | Suspicious |
| URL | hxxps[:]//example-security-login[.]com/verify | Suspicious |
| Subject | Urgent Password Verification Required | Suspicious |
| SPF | Fail | Suspicious |
| DKIM | None | Suspicious |
| DMARC | Fail | Suspicious |

---

## 4. Timeline

| Time | Event |
|---|---|
| 09:15 | User received suspicious email |
| 09:20 | User reported the email to security team |
| 09:25 | Analyst reviewed sender and email headers |
| 09:30 | Analyst extracted and defanged URL |
| 09:35 | Analyst checked authentication results and indicators |
| 09:45 | Email classified as phishing attempt |

---

## 5. Analysis

The email shows several characteristics commonly associated with phishing attacks.

The sender appears to impersonate IT support and attempts to create urgency by claiming that the user's account will be disabled unless password verification is completed.

The presence of a suspicious external URL, failed SPF and DMARC checks, and urgent language increases the likelihood that the email is malicious.

Key points observed:

- The email attempts to impersonate IT support
- The subject line creates urgency
- The message requests password verification
- The URL leads to an external domain
- Email authentication checks failed
- No legitimate business context was identified

---

## 6. User Impact Review

The analyst should determine whether the user interacted with the email.

| Question | Status |
|---|---|
| Did the user click the link? | Unknown |
| Did the user submit credentials? | Unknown |
| Did the user download any file? | No attachment observed |
| Did other users receive the same email? | Needs search |
| Were there unusual logins after delivery? | Needs review |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | Phishing |
| Initial Access | Spearphishing Link |
| Credential Access | Input Capture |
| Execution | User Execution |

---

## 8. Severity Assessment

| Criteria | Assessment |
|---|---|
| Likelihood | High |
| Impact | Medium to High |
| Final Severity | High |
| Escalation Required | Conditional |

The alert should be escalated if the user clicked the link, submitted credentials, or if similar emails were delivered to multiple users.

---

## 9. Recommended Actions

- Search for similar emails across the environment
- Remove the phishing email from affected mailboxes
- Block the sender domain
- Block the suspicious URL
- Check whether the user clicked the link
- Review sign-in logs for the affected user
- Reset credentials if the user submitted information
- Enforce MFA if not already enabled
- Notify affected users if the campaign was widespread
- Escalate to Incident Response if account compromise is suspected

---

## 10. Conclusion

The reported email contains multiple phishing indicators and should be classified as malicious.

The most important next step is to determine whether the user interacted with the link or submitted credentials.

If user interaction is confirmed, the incident should be escalated for account compromise investigation.
