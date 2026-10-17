# Playbook — Detection 010: Suspicious Network Activity / C2 Hunting

**Rules:** 100600–100605 (Windows), 100610–100613 (Linux)
**MITRE:** T1071, T1571, T1568, T1105
**Severity:** Low (base/context) to Critical (100605/100613 composite, level 14)
**Platform:** Windows and Linux

## 1. What triggered

- **100601/100611** — a process running from a suspicious location (Temp/AppData/Downloads on Windows; /tmp, /dev/shm, /var/tmp on Linux) made a network connection.
- **100602** — connection to a commonly-abused C2 port (4444, 1337, 8080, 8443, 9001, 6666, 31337, 5555).
- **100603/100612** — the same process repeatedly connected to the same destination (Windows) or made repeated outbound connections (Linux) — possible beaconing.
- **100604** — DNS query to a low-reputation TLD (.xyz, .top, .tk, .club, .gq, .ml, .cf, .biz).
- **100605/100613** — composite: suspicious location AND beaconing confirmed together. Highest confidence.

## 2. Immediate triage

1. Always start with the **composite** alert (100605/100613) if present — it's the highest-signal event and should drive the investigation; the individual contributing alerts (100601, 100602, 100603, etc.) provide supporting detail.
2. Identify the process (`image`/`exe`), its full path, and its hash (Windows only — `win.eventdata.hashes`).
3. Identify the destination IP/port (Windows) or just the process (Linux — destination not reliably available, see limitation below).
4. Check whether the process is a known, legitimate application that happens to run from an unusual location (rare, but verify before assuming malice).

## 3. True Positive indicators

- Process path is in Temp/AppData/Downloads/tmp and the binary name doesn't match its actual hash/signature (e.g., `powershell.exe` renamed).
- Repeated connections to the same destination at regular intervals (classic beaconing cadence).
- Destination port is in the known C2-associated list, especially combined with an unusual source process.
- DNS queries to freshly-registered-looking or low-reputation domains, especially many distinct subdomains from the same process (possible DGA pattern).
- No parent process or user-initiated action explains why this process is running (not launched from a known application, not part of a documented workflow).
- Correlated with a recent suspicious PowerShell/encoded command (Detections 003/004) or suspicious parent-child spawn (Detection 005) on the same host.

## 4. False Positive indicators

- Process is legitimate software that happens to install/run from AppData or Temp by design (some installers, update mechanisms, and browser helper components do this normally) — verify against your software inventory and the binary's hash/signature.
- Destination port match is coincidental — e.g., an internal service genuinely listening on 8080 for legitimate reasons (common for web dev/test servers). Check if the destination IP is internal and known.
- DNS query to a low-reputation TLD that is nonetheless a known, legitimate internal or vendor domain (some vendors do use less-common TLDs) — verify the specific domain's reputation and ownership before dismissing, but also before escalating.
- "Beaconing" pattern is actually a known legitimate check-in (software update checker, license validation, telemetry) — confirm against documented software behavior for that specific application.

## 5. Investigation steps

```bash
# Windows
sudo grep -a "100601\|100602\|100603\|100604\|100605" /var/ossec/logs/alerts/alerts.json | tail -n 20

# Linux
sudo grep -a "100611\|100612\|100613" /var/ossec/logs/alerts/alerts.json | tail -n 20
```

Pull the full connection history for the process to establish a beaconing timeline:
```bash
sudo grep -a "<image or exe path>" /var/ossec/logs/archives/archives.json | grep -a "destinationIp\|destinationPort"
```

(Windows) Verify the binary's actual identity via hash, not just filename:
```bash
sudo grep -a "<processGuid>" /var/ossec/logs/archives/archives.json | grep -a "hashes"
```

Check what else this process/host did around the same time — correlate across all other detections (new persistence, new account, suspicious PowerShell).

## 6. Containment (if confirmed malicious)

1. Isolate the host from the network immediately — this detection targets active C2 communication.
2. Preserve the binary (copy, do not delete) for malware analysis.
3. Block the destination IP/domain at the firewall/DNS layer across the environment, not just the affected host.
4. Hunt for the same hash/IP/domain across all other monitored endpoints.
5. Kill the process.
6. Investigate for persistence mechanisms that would allow the malware to survive a reboot (Detection 009) and any credential access attempts made during its runtime.

## 7. Escalation criteria

Escalate immediately for any composite alert (100605/100613). Escalate individual-layer alerts (100601–100604, 100611–100612) when the process/binary cannot be verified as legitimate, or when correlated with other suspicious activity.

## 8. Platform limitation to account for during triage

**Linux detection is intentionally scoped to process-identity-based beaconing only** — destination IP/port and DNS visibility are not reliably available via this lab's auditd-based implementation (the raw `connect()` socket address is hex-encoded and not parsed into structured fields by the Wazuh decoder in use, and no Linux DNS query logging was built). This means a Linux alert tells you **which process is beaconing**, but not **where to**, without manual follow-up (e.g., checking active connections directly on the host: `ss -tnp` or reviewing firewall/NAT logs for the actual destination). Do not assume parity with the Windows investigation workflow when triaging a Linux alert from this detection.

## 9. Closing the alert

Document: process/binary identity (with hash if available), destination (if known), beaconing interval (if established), correlated alerts, verdict, and remediation action.
