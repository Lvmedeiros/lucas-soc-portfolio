# Email Analysis — Phishing Investigation

## Analysis Objective

Analyze the reported email to identify phishing indicators, suspicious metadata, malicious links, attachments, spoofing attempts, and potential user impact.

---

## Email Metadata

| Field | Value |
|---|---|
| Reported By | user01 |
| Sender Display Name | IT Support |
| Sender Email Address | support@example-security.com |
| Reply-To Address | helpdesk@example-security.com |
| Recipient | user01@company.com |
| Subject | Urgent Password Verification Required |
| Date/Time Received | 2026-XX-XX 09:15 |
| Attachment Present | No |
| URLs Present | Yes |

---

## Header Review

Key email header fields to review:

| Header Field | Purpose |
|---|---|
| From | Shows the visible sender address |
| Reply-To | Shows where replies will be sent |
| Return-Path | Shows the bounce address |
| Received | Shows mail transfer path |
| SPF | Validates whether the sending server is authorized |
| DKIM | Validates message integrity and domain signing |
| DMARC | Validates domain alignment and policy |

---

## Authentication Results

| Control | Result | Notes |
|---|---|---|
| SPF | Fail | Sending server may not be authorized |
| DKIM | None | No valid DKIM signature observed |
| DMARC | Fail | Domain alignment failed |

---

## Body Analysis

The email body contains several phishing characteristics:

- Urgent language
- Request for password verification
- Link to an external website
- Generic greeting
- Sender pretending to be IT support
- Attempt to pressure the user into taking action quickly

Example suspicious message:

```text
Your account will be disabled today unless you verify your password immediately.
Click the link below to keep your mailbox active.
```

---

## URL Analysis

| URL | Defanged URL | Notes |
|---|---|---|
| https://example-security-login.com/verify | hxxps[:]//example-security-login[.]com/verify | Suspicious login page |

Things to validate:

- Does the domain match the legitimate organization?
- Is the domain newly registered?
- Does the URL use HTTPS only to look trustworthy?
- Does the page ask for credentials?
- Is the domain similar to a legitimate brand?
- Is the URL shortened or obfuscated?

---

## Attachment Analysis

No attachment was observed in this scenario.

If an attachment is present, the analyst should review:

- File name
- File extension
- File hash
- Macro presence
- Embedded scripts
- Archive contents
- Reputation results
- Sandbox behavior

---

## Indicators Identified

| Indicator Type | Value | Assessment |
|---|---|---|
| Sender Domain | example-security.com | Suspicious |
| URL | hxxps[:]//example-security-login[.]com/verify | Suspicious |
| Subject | Urgent Password Verification Required | Suspicious |
| SPF | Fail | Suspicious |
| DMARC | Fail | Suspicious |

---

## User Impact Review

The analyst should determine:

- Did the user click the link?
- Did the user enter credentials?
- Did the user download any file?
- Did the user forward the email to others?
- Did other users receive the same email?
- Were any mailbox rules created after the event?
- Were there unusual logins after the email was received?

---

## Assessment

Based on the suspicious sender, failed authentication checks, urgent language, and external credential verification link, this email should be treated as a phishing attempt.

---

## Recommended Next Steps

- Block the sender domain
- Block the suspicious URL
- Search for similar emails across the environment
- Remove the email from affected mailboxes
- Check whether any user clicked the link
- Reset credentials if any user submitted information
- Review sign-in logs for affected users
- Escalate if account compromise is suspected

---

## Conclusion

The email contains multiple phishing indicators and should be classified as malicious unless further evidence proves otherwise.

The most important follow-up action is to determine whether any user interacted with the link or submitted credentials.
