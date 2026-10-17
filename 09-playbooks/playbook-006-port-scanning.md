# Playbook — Detection 006: Port Scanning

**Rules:** 100401 (Windows, Sysmon-based), 100621 (Linux, UFW-based follow-up)
**MITRE:** T1046
**Severity:** High (level 12)
**Platform:** Windows and Linux

## 1. What triggered

A single source IP made connection attempts to 15+ distinct destination ports on the monitored host within 60 seconds.

## 2. Immediate triage

1. Identify `srcip` — is it internal (another asset you manage) or external?
2. Check whether the source IP is a **known vulnerability scanner** (Nessus, Qualys, internal red-team tooling) on a scheduled scan window.
3. Check how many ports were actually touched and whether any connection fully completed (vs. all being dropped/filtered) — full completions suggest open services were found, which raises the stakes.

## 3. True Positive indicators

- Source IP is external and unrecognized.
- Source IP is internal but not on the approved scanner/asset list.
- The scan is followed by a connection attempt to a specific discovered port (i.e., reconnaissance followed by exploitation attempt).
- Multiple internal hosts show scans from the same source IP in a similar time window (sweep pattern across the environment, not just one host).
- Timing doesn't match your organization's documented vulnerability-scanning schedule.

## 4. False Positive indicators

- Source IP matches your documented, scheduled vulnerability scanner (check the scanning tool's own logs/schedule to confirm).
- Internal network monitoring/asset-discovery tools (e.g., network mapping software) running a legitimate inventory sweep.
- A misconfigured internal service repeatedly retrying connections to many ports due to a bug, not malicious intent (check if the "scan" is always the exact same port sequence, repeating — a bug signature, not reconnaissance).

## 5. Investigation steps

```bash
sudo grep -a "100401" /var/ossec/logs/alerts/alerts.json | tail -n 5
sudo grep -a "<srcip>" /var/ossec/logs/alerts/alerts.json | grep -a "100400" | wc -l
```

Check which ports were targeted and whether any had a listening service:
```bash
sudo grep -a "<srcip>" /var/ossec/logs/archives/archives.json | grep -a "destinationPort"
```

Dashboard: Threat Hunting → `data.srcip: "<ip>"`, widen time range to check for prior/subsequent activity from the same source (other hosts scanned, other alert types).

## 6. Containment (if confirmed malicious)

1. Block the source IP at the firewall.
2. If any scanned port had an active/vulnerable service, prioritize patching or restricting access to it immediately.
3. Check if the scan was followed by any successful connection or authentication attempt (correlate with Detection 002 brute force on the same host/timeframe).
4. If internal source: identify and isolate/investigate that host — it may itself be compromised and performing reconnaissance as part of lateral movement.

## 7. Escalation criteria

Escalate if:
- Source is external and the scan found open/listening services.
- Source is an internal host not on the known-scanner list (possible compromised pivot point).
- Scan activity correlates with other alerts from the same source.

## 8. Platform limitation to account for

- **Windows:** detection relies on Sysmon Event ID 3, which only logs connections that complete at the OS level. A firewalled host scanned with a stealth SYN scan (`nmap -sS`) may generate **no alert at all**, since packets are dropped before Sysmon sees them — absence of an alert does not guarantee absence of scanning; cross-reference actual firewall/network logs if available.
- **Linux:** the auditd-based `connect()` detection (100610-series) only sees **outbound** connections initiated by the host itself — it cannot detect inbound scans against that host. Inbound scan detection on Linux requires the separate UFW-log-based rule (100620/100621); confirm which detection path is actually deployed before assuming scan coverage exists.

## 9. Closing the alert

Document: source IP, ports targeted, whether any connection completed, scanner-list cross-check result, verdict, and action taken.
