# Detection 008 — DNS & Network Connection Hunting

**Status:** Detection validated; contextual review required  
**Verdict:** Suspicious DNS indicators detected; C2 not confirmed  
**Date:** 17 October 2026  
**Wazuh manager:** `vm1`  
**Endpoint:** `window10`, agent `002`  
**IPs shown:** `192.168.34.148` and `192.168.34.152`  
**Telemetry:** Sysmon DNS Event ID 22 and network-connection events

## 1. Executive Summary
Wazuh was used to hunt DNS-query and network-connection activity. The dashboard search included rules `100600`–`100605`, `100610`–`100613`, and `100400`. It displayed **395 hits** over the selected last-week range, with **0 alerts at Level 12 or above**.

The supplied records include two Level 10 alerts from rule `100604` for DNS queries to `suspicious-test-domain.xyz` and `another-test.top`. The records associate the queries with `powershell.exe` (PID `1696`) under `DESKTOP-0P32A1N\\vipin`. The custom detection fired as intended, but DNS lookup alone does not prove a successful connection or C2 activity.

## 2. Environment

| Field | Value |
|---|---|
| SIEM | Wazuh |
| Manager | `vm1` |
| Endpoint | `window10` |
| Agent ID | `002` |
| IPs in evidence | `192.168.34.148`, `192.168.34.152` |
| Source | `Microsoft-Windows-Sysmon/Operational` |
| DNS event | Sysmon Event ID `22` |
| Dashboard query | `100600–100605`, `100610–100613`, `100400` |
| Selected range | Last week, 10–17 October 2026 |

## 3. Detection Rules

| Rule | Description observed | Level |
|---|---|---:|
| `100400` | Sysmon - Network connection event | 3 |
| `100600` | Sysmon - DNS query event | 3 |
| `100604` | DNS query to a low-reputation TLD commonly used for C2 | 10 |
| `100601–100603`, `100605`, `100610–100613` | Included in dashboard query; no rule details supplied | Unverified |

The exact custom rule XML was not provided. Only the observed alert descriptions are documented here.

## 4. Finding 1 — DNS Query to `suspicious-test-domain.xyz`
- **Wazuh rule:** `100604`
- **Level:** 10
- **MITRE ATT&CK:** `T1568 — Dynamic Resolution`
- **Indexed alert time:** `2026-10-17 12:45:31.312 UTC` (approximately `18:15:31.312 UTC+05:30`)
- **Endpoint/agent:** `window10`, agent `002`; alert record IP `192.168.34.152`
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **PID:** `1696`
- **User:** `DESKTOP-0P32A1N\\vipin`
- **Sysmon embedded event time:** `2026-10-17 08:40:40.186`
- **Query status:** `9003`
- **Query results shown:** `ns0.centralnic.net`

The custom rule classified the queried `.xyz` domain as a low-reputation TLD commonly used for C2. The supplied evidence proves the detection fired on a DNS query; it does not prove the domain is malicious, that a remote connection occurred, or that the host was compromised.

## 5. Finding 2 — DNS Query to `another-test.top`
- **Wazuh rule:** `100604`
- **Level:** 10
- **MITRE ATT&CK:** `T1568 — Dynamic Resolution`
- **Indexed alert time:** `2026-10-17 12:45:31.354 UTC` (approximately `18:15:31.354 UTC+05:30`)
- **Endpoint/agent:** `window10`, agent `002`; alert record IP `192.168.34.152`
- **Process:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **PID:** `1696`
- **User:** `DESKTOP-0P32A1N\\vipin`
- **Sysmon embedded event time:** `2026-10-17 08:40:40.321`
- **Query status:** `9003`
- **Query results shown:** `a.zdnscloud.com`

This second custom alert occurred alongside the `.xyz` query. Its proximity is worth investigating, especially by examining the PowerShell command line, parent process, and any network connections around the time. It is still not proof of C2.

## 6. Baseline DNS and Network Events
The alert samples also show queries from ordinary Windows components or test destinations:
- `my.microsoftpersonalcontent.com` and `api.onedrive.com` from `OneDrive.exe`
- `onedriveclucproddm20048.blob.core.windows.net` from `OneDrive.exe`
- `microsoft.com` and `example.com`
- `wpad` from Microsoft Copilot and Microsoft Edge
- `localdomain` and `DESKTOP-0P32A1N` from Windows system services

The presence of these events demonstrates telemetry coverage, not inherently suspicious behavior. `wpad` and local-name lookups can be part of local discovery/configuration; investigate their process and resolution status before drawing conclusions.

## 7. Dashboard Summary
- **Search:** `rule.id:(100600 OR 100601 OR 100602 OR 100603 OR 100604 OR 100605 OR 100610 OR 100611 OR 100612 OR 100613 OR 100400)`
- **Selected range:** Last week
- **Total hits:** 395
- **Alerts at Level 12+:** 0
- **Visible rule levels:** standard DNS/network telemetry at Level 3; custom suspicious-domain matches at Level 10
- **Visible endpoint:** `window10`

The 395 figure is the number of matching alert documents in the selected window, not 395 unique connections or incidents.

## 8. Timeline

| Indexed time (UTC+05:30) | Observed event | Rule |
|---|---|---|
| 17 Oct 2026, approx. 14:56–14:57 | DNS and network events for `wpad`, Microsoft/OneDrive domains and local names | `100600`, `100400` |
| 17 Oct 2026, approx. 18:15:31 | PowerShell queries `suspicious-test-domain.xyz` | `100604` |
| 17 Oct 2026, approx. 18:15:31 | PowerShell queries `another-test.top` | `100604` |
| 17 Oct 2026, approx. 18:16:44 | PowerShell queries `example.com` | `100600` |
| 17 Oct 2026, approx. 18:17:39 | DNS query for `microsoft.com` | `100600` |

**Timestamp caution:** The embedded Sysmon `eventdata.utcTime` for some records differs significantly from Sysmon `systemTime` and Wazuh's indexed `timestamp`. The timeline above uses indexed time for the approximate sequence where available. Verify time synchronization and timestamp parsing before treating this as definitive event chronology.

## 9. MITRE ATT&CK
- **T1568 — Dynamic Resolution:** mapped by custom rule `100604`.
- The supplied ordinary DNS-query and network-event rules do not show ATT&CK mappings in their example alerts.

This mapping supports investigation context, not a conclusion that a command-and-control session exists.

## 10. Analyst Verdict
**DNS/network monitoring detections validated; possible suspicious DNS activity requires contextual review; C2 not confirmed.**

Rule `100604` successfully alerted on two test-like domain lookups generated by PowerShell. The broader dashboard confirms collection of DNS and network telemetry. The samples do not show a confirmed outbound connection to either suspicious domain, nor evidence of malicious payload delivery or compromise.

## 11. Recommended Investigation
1. Confirm whether the two domain queries were generated intentionally for the lab.
2. Retrieve the full process-creation Event ID 1 for PID `1696`, including command line, parent process, hashes, and user.
3. Correlate around the query with Sysmon Event ID 3 network connections and endpoint firewall/proxy logs.
4. Inspect raw DNS resolver responses; note `queryStatus` `9003` and the name-server results as recorded, without assuming successful resolution.
5. Validate the domains using reputable threat-intelligence or passive-DNS sources before labelling them malicious.
6. Check the endpoint IP discrepancy (`192.168.34.148` vs `192.168.34.152`) and verify DHCP/agent metadata.
7. Reconcile `eventdata.utcTime`, `systemTime`, and Wazuh `timestamp` fields.
8. Review custom rule `100604` XML and test expected benign vs suspicious DNS queries to evaluate false positives.
9. Review IDs `100601`–`100603`, `100605`, and `100610`–`100613` only after their rule XML or sample alerts are available.

## 12. Limitations
The exact rule XML was not supplied. The meanings of IDs `100601`–`100603`, `100605`, and `100610`–`100613` are not established by the supplied alert examples. DNS queries are not equivalent to successful network sessions. The record timestamps are inconsistent, and the endpoint IP differs across examples. No evidence supplied here proves C2, malware execution, or compromise.

## 13. Conclusion
Wazuh and Sysmon telemetry successfully captured DNS queries and network-connection events, and the custom rule `100604` generated two Level 10 alerts for selected low-reputation-TLD test domains queried by PowerShell. This is a useful detection-engineering and threat-hunting result. The correct disposition is suspicious DNS activity requiring correlation, not confirmed command and control.

## 14. Evidence Index
- `evidence/E01-network-dns-dashboard.png` — dashboard overview (395 hits)
- `evidence/E02-network-dns-alert-results.png` — DNS/network rule search results
- `evidence/E03-example-com-dns-event-details.png` — Sysmon DNS event details
- `evidence/E04-system-dns-event-details.png` — Windows system DNS event details
