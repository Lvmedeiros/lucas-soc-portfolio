# Network Analysis — C2 Beaconing

## Analysis Objective

Analyze repeated outbound network connections from an internal host to an external destination and determine whether the behavior may indicate command and control beaconing.

---

## Scenario Summary

A workstation was observed communicating with the same external IP address at regular intervals.

The traffic pattern is suspicious because beaconing activity often involves low-volume, repeated communication from a compromised host to attacker-controlled infrastructure.

---

## Network Data Reviewed

| Data Source | Purpose |
|---|---|
| Firewall Logs | Identify outbound connections, destination IPs, ports, and timestamps |
| Proxy Logs | Review HTTP/HTTPS requests and user-agent strings |
| DNS Logs | Identify domain lookups related to the destination |
| NetFlow | Analyze traffic volume, frequency, and direction |
| Wireshark PCAP | Inspect packet-level details when available |
| EDR Telemetry | Correlate network activity with endpoint process activity |

---

## Observed Traffic Pattern

| Field | Value |
|---|---|
| Source Host | WIN-WS-01 |
| Source IP | 10.10.20.15 |
| Destination IP | 203.0.113.50 |
| Destination Port | 443 |
| Protocol | HTTPS |
| Frequency | Every 60 seconds |
| Traffic Volume | Low |
| Time Window | 02:00 - 04:00 |
| Direction | Outbound |

---

## Beaconing Indicators

The following indicators may suggest beaconing behavior:

```text
Repeated outbound connections
Consistent time interval
Same destination IP or domain
Low and steady traffic volume
Traffic outside business hours
Rare destination for the environment
Encrypted traffic to unknown infrastructure
No clear business justification
```

---

## Timing Analysis

Beaconing often follows a repeated interval.

Example observed pattern:

| Time | Destination | Notes |
|---|---|---|
| 02:00:00 | 203.0.113.50:443 | Outbound connection |
| 02:01:00 | 203.0.113.50:443 | Outbound connection |
| 02:02:00 | 203.0.113.50:443 | Outbound connection |
| 02:03:00 | 203.0.113.50:443 | Outbound connection |
| 02:04:00 | 203.0.113.50:443 | Outbound connection |

The consistent 60-second interval increases suspicion of automated communication.

---

## DNS Analysis

| Domain | Resolved IP | Assessment |
|---|---|---|
| example-update-check.com | 203.0.113.50 | Suspicious |

DNS review should answer:

- Was the domain recently registered?
- Is the domain rare in the environment?
- Did other hosts query the same domain?
- Does the domain imitate a legitimate service?
- Is the domain associated with known malicious activity?

---

## HTTP/HTTPS Analysis

For HTTP or HTTPS traffic, the analyst should review:

- User-Agent string
- URI path
- HTTP method
- Response size
- Request frequency
- TLS certificate details
- JA3/JA3S fingerprint, if available
- Whether the destination is expected for the host

---

## Endpoint Correlation

Network activity should be correlated with endpoint telemetry.

Questions to answer:

- Which process initiated the connection?
- Was the process expected?
- Was the process recently created?
- Did the process have a suspicious parent process?
- Were any files created before the network activity started?
- Did the endpoint generate malware, PowerShell, or persistence alerts?

---

## Threat Intelligence Review

| Indicator | Type | Result |
|---|---|---|
| 203.0.113.50 | IP Address | Pending review |
| example-update-check.com | Domain | Pending review |

Threat intelligence checks should include:

- IP reputation
- Domain reputation
- Passive DNS
- WHOIS information
- Known malware associations
- Reports from security vendors

---

## Assessment

The repeated outbound connections at a consistent interval, combined with low-volume traffic and communication outside business hours, make this activity suspicious.

However, the traffic should not be classified as malicious without additional context, such as destination reputation, process correlation, and endpoint behavior.

---

## Recommended Next Steps

- Review destination IP and domain reputation
- Search for the destination across other hosts
- Review DNS logs for related queries
- Identify the process responsible for the connection
- Check endpoint alerts on the source host
- Analyze packet capture if available
- Block the destination if confirmed malicious
- Isolate the host if compromise is suspected
- Escalate to Incident Response if C2 activity is confirmed

---

## Conclusion

The observed traffic pattern is consistent with possible C2 beaconing behavior.

Further validation is required to determine whether the activity is benign, suspicious, or malicious.
