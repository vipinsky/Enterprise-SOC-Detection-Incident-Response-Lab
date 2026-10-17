# Detection 004 — Suspicious Parent–Child Process Lineage

**Status:** Lab detection validation  
**Verdict:** Suspicious process lineage observed; no compromise confirmed  
**Endpoint:** `window10` (`192.168.34.148`), Wazuh agent `002`  
**Telemetry:** Sysmon Event ID 1 — Process Create  
**Wazuh manager:** `vm1`  
**Date:** 17 October 2026

## 1. Executive Summary
Wazuh generated alerts for three process-lineage patterns on the Windows lab endpoint: Office spawning PowerShell (rule `100302`), a browser spawning PowerShell (rule `100303`), and a PDF reader spawning PowerShell (rule `100304`). The selected dashboard search displayed seven alert hits for these rules.

The detailed events show simulated parent executable paths under `C:\\FakeOffice\\`, `C:\\FakeBrowser\\`, and `C:\\FakePDF\\`, with PowerShell launched using the test command `Write-Host test`. These findings demonstrate detection behavior in the lab. They do not prove that a malicious document, browser session, or PDF compromised the endpoint.

## 2. Environment
| Field | Observed value |
|---|---|
| SIEM | Wazuh |
| Manager | `vm1` |
| Endpoint | `window10` |
| Agent ID | `002` |
| Endpoint IP | `192.168.34.148` |
| Sysmon computer | `DESKTOP-0P32A1N` |
| User | `DESKTOP-0P32A1N\\vipin` |
| Log channel | `Microsoft-Windows-Sysmon/Operational` |
| Event ID | `1` — Process Create |
| Input location | `EventChannel` |

## 3. Detection Rules

| Rule | Alert | Level | ATT&CK mapping |
|---|---|---:|---|
| `100302` | Office application spawned a scripting/shell process | 13 | `T1566.001`, `T1059` |
| `100303` | Browser spawned a scripting/shell process | 12 | `T1059` |
| `100304` | PDF reader spawned a scripting/shell process | 12 | `T1059` |

Rule `100302` was configured to map to Spearphishing Attachment (`T1566.001`) and Command and Scripting Interpreter (`T1059`). The rule mapping provides investigative context; it is not proof of phishing.

## 4. Observed Events

### Event A — Office spawns PowerShell
- **Rule:** `100302` · **Level:** 13 · **Alert time:** approximately `13:28:48` local
- **Parent:** `C:\\FakeOffice\\Office16\\WINWORD.EXE`
- **Child:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **PowerShell PID:** `11572`; parent PID: `5488`
- **Sysmon event time:** `2026-10-17 07:58:47.016 UTC` (`13:28:47.016` UTC+05:30)
- **Observed command:** `powershell.exe -command Write-Host test`
- **User:** `DESKTOP-0P32A1N\\vipin`
- **Event record ID:** `16391`

The parent command line shows a test-like `Start-Process powershell.exe` invocation. Because the path is under `C:\\FakeOffice\\`, this appears consistent with simulated lab telemetry, but the analyst should confirm it was intentional.

### Event B — Browser spawns PowerShell
- **Rule:** `100303` · **Level:** 12 · **Alert time:** approximately `13:30:12` local
- **Parent:** `C:\\FakeBrowser\\chrome.exe`
- **Child:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **PowerShell PID:** `7852`; parent PID: `13128`
- **Sysmon event time:** `2026-10-17 08:00:10.696 UTC` (`13:30:10.696` UTC+05:30)
- **Observed command:** `powershell.exe -command Write-Host test`
- **User:** `DESKTOP-0P32A1N\\vipin`
- **Event record ID:** `16400`

A browser spawning PowerShell is a useful triage signal. In this evidence, the parent path is a simulated `FakeBrowser` location and the child command is a test command. Malicious browser activity is not established.

### Event C — PDF reader spawns PowerShell
- **Rule:** `100304` · **Level:** 12 · **Alert time:** approximately `13:30:24` local
- **Parent:** `C:\\FakePDF\\AcroRd32.exe`
- **Child:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **PowerShell PID:** `8908`; parent PID: `13056`
- **Sysmon event time:** `2026-10-17 08:00:23.236 UTC` (`13:30:23.236` UTC+05:30)
- **Observed command:** `powershell.exe -command Write-Host test`
- **User:** `DESKTOP-0P32A1N\\vipin`
- **Event record ID:** `16409`

A PDF reader launching a shell may indicate suspicious document behavior in a real environment. Here, the `FakePDF` path and benign-looking command suggest a controlled test, pending confirmation.

## 5. Timeline

| Time (UTC+05:30) | Event |
|---|---|
| 17 Oct 2026, 13:28:47 | Sysmon records PowerShell created by `WINWORD.EXE`; Wazuh rule `100302` fires at about 13:28:48 |
| 17 Oct 2026, 13:30:10 | Sysmon records PowerShell created by `chrome.exe`; Wazuh rule `100303` fires at about 13:30:12 |
| 17 Oct 2026, 13:30:23 | Sysmon records PowerShell created by `AcroRd32.exe`; Wazuh rule `100304` fires at about 13:30:24 |

Additional Office-related alerts were visible on 15 October 2026. The screenshots show seven results in the selected combined search; event counts should be deduplicated before reporting unique executions.

## 6. Analysis and Impact
- **Confirmed:** Sysmon recorded the process creations, and Wazuh generated alerts for all three parent-child categories.
- **Confirmed:** The displayed child command was `Write-Host test`, a test-like command.
- **Observed context:** Parent image paths use `C:\\FakeOffice\\`, `C:\\FakeBrowser\\`, and `C:\\FakePDF\\`.
- **Not established:** Malicious document content, drive-by download, payload execution beyond the visible command, persistence, data exfiltration, or endpoint compromise.

## 7. MITRE ATT&CK
- **T1059 — Command and Scripting Interpreter:** PowerShell was launched as a child process.
- **T1566.001 — Spearphishing Attachment:** Mapped by rule `100302` as a potential Office-related threat context. The event alone does not prove a phishing attachment was involved.

## 8. Analyst Verdict
**Lab detection validation — suspicious process lineage observed; no compromise confirmed.**

Office, browser, and PDF-reader processes spawning PowerShell can warrant investigation. The observed paths and test payloads are consistent with lab simulations. If this pattern appears on a real endpoint without an approved explanation, investigate promptly.

## 9. Recommended Response
1. Confirm these parent processes were deliberately simulated.
2. Review complete Sysmon records using the process GUIDs and event record IDs shown above.
3. Correlate PowerShell Operational Event IDs 4103/4104 if enabled.
4. Review nearby network connections, downloaded files, script blocks, and additional child processes if activity is unexplained.
5. Check whether the parent executables and their locations are expected and legitimate.
6. Run benign baseline tests to understand false positives and tune detections.
7. Preserve event records and document whether each alert was an expected test or required escalation.

## 10. Limitations
The custom rule XML was not supplied, so the exact matching conditions for `100302`, `100303`, and `100304` were not independently verified. The screenshots show alert results and metadata, but do not prove that a malicious payload executed or that the endpoint was compromised.

## 11. Conclusion
The Wazuh/Sysmon lab successfully alerted on Office-, browser-, and PDF-reader-to-PowerShell process chains. The available commands are test-like, and the parent paths appear simulated. Record the outcome as detection validation and avoid labeling the endpoint compromised without corroborating evidence.

## 12. Evidence Index
- `evidence/E01-process-lineage-alert-results.png` — combined rule search
- `evidence/E02-process-lineage-dashboard.png` — summary dashboard and alert totals
- `evidence/E03-suspicious-powershell-alerts.png` — rule `100300` alert list
- `evidence/E04-suspicious-powershell-dashboard.png` — rule `100300` dashboard
- `evidence/E05-office-spawn-alert-details.png` — parent and child process details
