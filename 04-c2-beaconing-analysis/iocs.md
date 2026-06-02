# Indicators of Compromise — C2 Beaconing Analysis

## Overview

This document lists the indicators identified during the C2 beaconing investigation.

Indicators of Compromise (IOCs) help analysts search for related network activity, identify affected hosts, block malicious infrastructure, and support incident response actions.

---

## Identified Indicators

| Indicator Type | Value | Assessment | Notes |
|---|---|---|---|
| Source Host | WIN-WS-01 | Internal asset | Host generating repeated outbound connections |
| Source IP | 10.10.20.15 | Internal IP | Source of suspicious traffic |
| Destination IP | 203.0.113.50 | Suspicious | External destination contacted repeatedly |
| Destination Domain | example-update-check[.]com | Suspicious | Domain associated with repeated outbound traffic |
| Destination Port | 443 | Suspicious in context | HTTPS traffic to unknown destination |
| Beacon Interval | 60 seconds | Suspicious | Repeated communication at a consistent interval |

---

## Defanged Indicators

Defanging prevents accidental clicks or access to suspicious indicators.

| Original | Defanged |
|---|---|
| example-update-check.com | example-update-check[.]com |
| https://example-update-check.com | hxxps[:]//example-update-check[.]com |
| 203.0.113.50 | 203.0.113[.]50 |

---

## Reputation Checks

| Indicator | Source | Result |
|---|---|---|
| 203.0.113[.]50 | Threat intelligence platform | Pending review |
| example-update-check[.]com | Domain reputation tool | Pending review |
| hxxps[:]//example-update-check[.]com | URL reputation tool | Pending review |

---

## Hunt Queries

These indicators can be used to search across firewall, proxy, DNS, EDR, and SIEM logs.

### Firewall / Proxy Search

```text
203.0.113.50
example-update-check.com
```

### DNS Search

```text
example-update-check.com
```

### SIEM Search Keywords

```text
203.0.113.50
example-update-check
WIN-WS-01
10.10.20.15
```

### Endpoint Search

```text
Processes connecting to 203.0.113.50
Processes resolving example-update-check.com
Outbound connections from WIN-WS-01
```

---

## Blocking Recommendations

If the indicators are confirmed malicious, the following actions are recommended:

- Block the destination IP
- Block the destination domain
- Add the indicators to firewall and proxy controls
- Search for other hosts communicating with the same destination
- Monitor for attempted connections after blocking
- Review endpoint activity on affected hosts
- Isolate compromised hosts if needed

---

## Environment-Wide Search

The analyst should search for related activity across the environment.

Questions to answer:

- Are other hosts communicating with the same destination?
- Did the source host contact other suspicious destinations?
- Did the destination appear in DNS logs?
- Did the traffic happen outside business hours?
- Is the interval consistent across multiple connections?
- Is there related malware or PowerShell activity on the host?
- Was any data transferred from the host to the destination?

---

## Conclusion

The identified indicators should be used for containment, blocking, and environment-wide hunting.

Even if only one host is currently observed communicating with the destination, the analyst should search across the environment to determine whether the activity is isolated or part of a broader compromise.
