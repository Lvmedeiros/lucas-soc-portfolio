# Indicators of Compromise — Phishing Investigation

## Overview

This document lists the indicators identified during the phishing investigation.

Indicators of Compromise (IOCs) help analysts search for related activity, block malicious infrastructure, and determine whether other users or systems were affected.

---

## Identified Indicators

| Indicator Type | Value | Assessment | Notes |
|---|---|---|---|
| Sender Email | support@example-security.com | Suspicious | Sender impersonates IT support |
| Sender Domain | example-security.com | Suspicious | Domain does not match the legitimate organization |
| Reply-To Address | helpdesk@example-security.com | Suspicious | Reply-To should be reviewed for mismatch |
| URL | hxxps[:]//example-security-login[.]com/verify | Suspicious | Possible credential harvesting page |
| Domain | example-security-login[.]com | Suspicious | Lookalike login domain |
| Subject | Urgent Password Verification Required | Suspicious | Uses urgency to pressure the user |

---

## Defanged Indicators

Defanging prevents accidental clicks or access to suspicious indicators.

| Original | Defanged |
|---|---|
| https://example-security-login.com/verify | hxxps[:]//example-security-login[.]com/verify |
| example-security-login.com | example-security-login[.]com |

---

## Reputation Checks

| Indicator | Source | Result |
|---|---|---|
| example-security-login[.]com | VirusTotal | Pending review |
| hxxps[:]//example-security-login[.]com/verify | URL reputation tool | Pending review |
| support@example-security.com | Email security gateway | Pending review |

---

## Hunt Queries

These indicators can be used to search across email, proxy, DNS, and SIEM logs.

### Email Search

```text
sender: support@example-security.com
subject: "Urgent Password Verification Required"
url: example-security-login.com
```

### DNS Search

```text
example-security-login.com
```

### Proxy / Web Logs Search

```text
example-security-login.com
/verify
```

### SIEM Search Keywords

```text
example-security-login
support@example-security.com
Urgent Password Verification Required
```

---

## Blocking Recommendations

If the indicators are confirmed malicious, the following actions are recommended:

- Block the sender email address
- Block the sender domain
- Block the phishing URL
- Block the phishing domain
- Add the indicators to email security controls
- Search for similar emails across the environment
- Monitor for attempted access to the phishing domain

---

## User Impact Checks

The analyst should validate whether users interacted with any of the indicators.

Questions to answer:

- Did any user click the phishing URL?
- Did any user submit credentials?
- Did any endpoint access the suspicious domain?
- Did the email reach multiple mailboxes?
- Was the email forwarded internally?
- Were there unusual sign-ins after the email was received?

---

## Conclusion

The identified indicators should be used for containment, blocking, and environment-wide searches.

Even if only one user reported the email, the analyst should search for related messages and activity to determine whether the phishing attempt affected additional users.
