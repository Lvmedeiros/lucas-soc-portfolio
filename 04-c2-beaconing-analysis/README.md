# C2 Beaconing Analysis

## Scenario

A workstation was observed making repeated outbound connections to the same external IP address at regular time intervals.

This type of behavior may indicate command and control beaconing, where a compromised host periodically communicates with attacker-controlled infrastructure.

---

## Objective

Investigate the network activity and determine whether the communication is legitimate, suspicious, or related to command and control behavior.

The goal is to identify suspicious patterns, extract indicators, assess risk, and recommend response actions.

---

## Data Sources

- Firewall logs
- Proxy logs
- DNS logs
- NetFlow data
- EDR telemetry
- SIEM alerts
- Wireshark packet captures
- Threat intelligence sources

---

## Suspicious Indicators

The activity should be considered suspicious if it contains indicators such as:

```text
Repeated outbound connections to the same external IP
Regular time intervals between connections
Low-volume but consistent traffic
Connections to unknown or suspicious domains
Traffic outside business hours
Unusual user agent
DNS queries for suspicious domains
Encrypted traffic to rare destinations
Communication from a host that does not normally make outbound connections
```

---

## Investigation Notes

During the investigation, the analyst should validate:

- Source host involved
- Source user, if available
- Destination IP address
- Destination domain
- Destination port and protocol
- Frequency of connections
- Time interval between connections
- Amount of data transferred
- Whether the destination is known or trusted
- Whether other hosts contacted the same destination
- Whether the host generated related endpoint alerts

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Command and Control | Application Layer Protocol |
| Command and Control | Web Service |
| Command and Control | Ingress Tool Transfer |
| Exfiltration | Exfiltration Over Web Service |

---

## Severity

Suggested severity: **Medium to High**

Severity may increase if:

- The destination IP or domain is known malicious
- Multiple internal hosts communicate with the same destination
- The traffic follows a consistent beaconing interval
- The host shows signs of malware execution
- Data transfer volume increases over time
- The communication occurs outside normal business hours
- The endpoint is a critical asset

---

## Recommended Response

- Review network logs and connection frequency
- Check destination IP and domain reputation
- Review DNS history for the destination domain
- Search for the same destination across other hosts
- Analyze packet capture if available
- Review endpoint telemetry for related process activity
- Isolate the host if compromise is suspected
- Block malicious IPs, domains, or URLs if confirmed
- Escalate to Incident Response if command and control activity is confirmed

---

## Project Files

- [Network Analysis](./network-analysis.md)
- [Investigation Report](./investigation-report.md)
- [Indicators of Compromise](./iocs.md)

---

## Conclusion

C2 beaconing analysis is an important SOC investigation scenario because compromised hosts often communicate with external infrastructure on a repeated schedule.

The analyst should focus on communication patterns, destination reputation, endpoint context, and related activity before determining whether the traffic is benign or malicious.
