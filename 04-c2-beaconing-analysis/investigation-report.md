# Investigation Report — C2 Beaconing Analysis

## 1. Executive Summary

A workstation was observed making repeated outbound connections to the same external destination at regular time intervals.

This behavior may indicate command and control beaconing, where a compromised host periodically communicates with external infrastructure controlled by an attacker.

At this stage, the activity should be treated as suspicious until destination reputation, endpoint telemetry, DNS activity, and process context are reviewed.

---

## 2. Alert Details

| Field | Value |
|---|---|
| Alert Name | Possible C2 Beaconing Activity |
| Initial Severity | High |
| Source Host | WIN-WS-01 |
| Source IP | 10.10.20.15 |
| Destination IP | 203.0.113.50 |
| Destination Domain | example-update-check.com |
| Destination Port | 443 |
| Protocol | HTTPS |
| Frequency | Every 60 seconds |
| Status | Under Investigation |

---

## 3. Observed Indicators

| Indicator Type | Value | Assessment |
|---|---|---|
| Source Host | WIN-WS-01 | Internal endpoint |
| Source IP | 10.10.20.15 | Internal address |
| Destination IP | 203.0.113.50 | Suspicious |
| Destination Domain | example-update-check[.]com | Suspicious |
| Destination Port | 443 | Common outbound protocol |
| Beacon Interval | 60 seconds | Suspicious pattern |
| Traffic Volume | Low and consistent | Suspicious |

---

## 4. Timeline

| Time | Event |
|---|---|
| 02:00 | First outbound connection observed |
| 02:01 | Second outbound connection observed |
| 02:02 | Third outbound connection observed |
| 02:03 | Fourth outbound connection observed |
| 02:04 | Fifth outbound connection observed |
| 02:10 | Pattern confirmed as repeated communication |

---

## 5. Analysis

The observed activity is suspicious because the host repeatedly communicated with the same external destination at a consistent interval.

Beaconing behavior is commonly associated with command and control communication. Attackers often use periodic outbound connections to maintain access, receive commands, or send status updates from a compromised host.

Key points observed:

- The same destination was contacted repeatedly
- The connection interval was consistent
- The traffic volume was low and steady
- The activity occurred outside business hours
- The destination was not immediately recognized as a trusted service
- Further endpoint correlation is required

The traffic should not be confirmed as malicious based only on timing. Additional validation is required, including reputation checks, DNS review, endpoint process analysis, and comparison with normal host behavior.

---

## 6. Endpoint Correlation

The analyst should review endpoint telemetry to determine which process initiated the outbound connections.

| Question | Status |
|---|---|
| Which process initiated the connection? | Needs review |
| Was the process expected? | Needs review |
| Was the process recently created? | Needs review |
| Did the process have a suspicious parent process? | Needs review |
| Were files created before the network activity? | Needs review |
| Were related endpoint alerts generated? | Needs review |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Command and Control | Application Layer Protocol |
| Command and Control | Web Service |
| Command and Control | Ingress Tool Transfer |
| Exfiltration | Exfiltration Over Web Service |

---

## 8. Severity Assessment

| Criteria | Assessment |
|---|---|
| Likelihood | Medium to High |
| Impact | High |
| Final Severity | High |
| Escalation Required | Yes, if destination or endpoint activity is confirmed malicious |

The alert should be escalated if the destination is confirmed malicious, if malware is found on the endpoint, or if similar traffic is observed across multiple hosts.

---

## 9. Recommended Actions

- Review firewall, proxy, DNS, and NetFlow logs
- Check destination IP and domain reputation
- Review DNS history for the suspicious domain
- Search for the same destination across other hosts
- Identify the process responsible for the connection
- Review endpoint telemetry and related alerts
- Analyze packet capture if available
- Block the destination if confirmed malicious
- Isolate the affected host if compromise is suspected
- Escalate to Incident Response if C2 activity is confirmed

---

## 10. Conclusion

The repeated outbound communication pattern is consistent with possible C2 beaconing behavior.

The activity should be treated as suspicious until additional context confirms whether the traffic is benign, suspicious, or malicious.

The most important next steps are endpoint correlation, destination reputation review, and environment-wide search for similar communication patterns.
