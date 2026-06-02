# Phishing Investigation

## Scenario

A suspicious email was reported by a user and submitted for security review.

The email contains indicators that may suggest phishing activity, such as an unusual sender, suspicious links, urgent language, unexpected attachments, or a request for credentials or sensitive information.

---

## Objective

Investigate the reported email and determine whether it is legitimate, suspicious, or malicious.

The goal is to identify phishing indicators, extract relevant indicators of compromise, assess risk, and recommend appropriate response actions.

---

## Data Sources

- Reported email
- Email headers
- Email body
- URLs and domains
- Attachments
- Sender information
- Mail security gateway logs
- Threat intelligence sources
- VirusTotal or similar reputation tools

---

## Phishing Indicators

The email should be considered suspicious if it contains indicators such as:

```text
Unknown or spoofed sender
Urgent or threatening language
Unexpected attachment
Credential request
Suspicious URL
Mismatched display name and email address
External sender pretending to be internal
Shortened links
Lookalike domain
Poor grammar or unusual formatting
```

---

## Investigation Notes

During the investigation, the analyst should validate:

- Who reported the email
- Sender email address and display name
- Reply-To address
- Sending domain
- SPF, DKIM, and DMARC results
- URLs present in the email
- Attachment names and file types
- Attachment hashes, when available
- Whether other users received the same email
- Whether any user clicked the link or opened the attachment
- Reputation of URLs, domains, IPs, and hashes

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | Phishing |
| Initial Access | Spearphishing Link |
| Initial Access | Spearphishing Attachment |
| Credential Access | Input Capture |
| Execution | User Execution |

---

## Severity

Suggested severity: **Medium to High**

Severity may increase if:

- Multiple users received the same email
- A user clicked the link
- A user submitted credentials
- The attachment contains malware
- The sender domain is spoofed or malicious
- The email targets privileged users
- The link leads to a credential harvesting page

---

## Recommended Response

- Analyze the email headers
- Review sender, Reply-To, and return-path fields
- Check SPF, DKIM, and DMARC results
- Extract and defang URLs
- Check URL and domain reputation
- Analyze attachments in a safe environment
- Search for similar emails across the environment
- Remove malicious emails from user mailboxes
- Block malicious sender, domain, URL, or hash
- Reset credentials if a user submitted information
- Escalate to Incident Response if compromise is suspected

---

## Project Files

- [Email Analysis](./email-analysis.md)
- [Investigation Report](./investigation-report.md)
- [Indicators of Compromise](./iocs.md)

---

## Conclusion

Phishing investigation is a common SOC activity and requires careful analysis of email metadata, content, links, attachments, and user interaction.

A reported email should not be classified based only on appearance. The analyst must review technical indicators, authentication results, threat intelligence, and potential user impact before making a final decision.
