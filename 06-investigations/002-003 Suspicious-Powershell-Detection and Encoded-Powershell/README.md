# Windows SOC Detection Lab: Suspicious and Encoded PowerShell

## Overview
This project documents two custom Wazuh detections on a Windows 10 endpoint using Sysmon process-creation telemetry.

- **Detection 003 — Suspicious PowerShell**: Wazuh rule `100300`, Level 10.
- **Detection 004 — Encoded PowerShell**: Wazuh rule `100301`, Level 12.
- **Related detection**: Rule `100302` detects an Office application spawning a scripting/shell process (Level 13).

**MITRE ATT&CK:** `T1059.001 — PowerShell`. Encoded PowerShell also maps to `T1027 — Obfuscated Files or Information`.

## Lab environment
| Component | Observed value |
|---|---|
| SIEM / manager | Wazuh / `vm1` |
| Windows endpoint | `window10` |
| Wazuh agent ID | `002` |
| Endpoint IP | `192.168.34.148` |
| Windows computer name in Sysmon | `DESKTOP-0P32A1N` |
| Telemetry | Sysmon Operational, Event ID 1 (Process Create) |
| Wazuh input location | `EventChannel` |

## Detection 003 — Suspicious PowerShell

### Objective
Identify PowerShell process creation with suspicious execution characteristics, rather than alerting on every PowerShell launch.

### Observed alert
- Rule: `100300`
- Severity: Level 10
- Description: `Suspicious PowerShell execution`
- Group: `sysmon`, `powershell`, `suspicious_powershell`
- MITRE: `T1059.001` — Execution / PowerShell
- Event: Sysmon Event ID 1
- Observed command line:
  ```text
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -windowstyle hidden -command "Write-Host test"
  ```
- User: `DESKTOP-0P32A1N\vipin`
- Process ID: `13156`
- Parent process: `powershell.exe`, parent PID `10780`
- Event time: `2026-10-17 07:25:56.216 UTC` (approximately `12:55:56.216` India time)
- Wazuh indexed timestamp: `2026-10-17 12:55:57.895` (displayed in Wazuh)
- Wazuh event reports the Microsoft-signed Windows PowerShell executable path and a SHA-256 hash. A file hash alone does not establish that the command was benign or malicious.

### Interpretation
The `-windowstyle hidden` option is a suspicious execution characteristic because it can conceal a PowerShell window. However, the observed payload `Write-Host test` is a harmless-looking test command. Based on this event alone, classify it as **a detection test / suspicious characteristic observed**, not a confirmed malicious execution. Confirm the activity was intentional and correlate with nearby events.

The screenshots show six alerts for rule `100300` in the selected time range. Repeated hits may reflect multiple test executions or duplicate/related events; review event IDs, timestamps, process GUIDs, and raw logs before counting unique executions.

## Detection 004 — Encoded PowerShell

### Objective
Detect PowerShell launched with an encoded command indicator, then inspect the decoded content and surrounding process context. Encoding is not proof of maliciousness by itself.

### Observed alert
- Rule: `100301`
- Severity: Level 12
- Description: `Encoded PowerShell command detected`
- Groups: `sysmon`, `powershell`, `suspicious_powershell`, `encoded_command`
- MITRE: `T1059.001` — PowerShell; `T1027` — Obfuscated Files or Information
- Event: Sysmon Event ID 1
- User: `DESKTOP-0P32A1N\vipin`
- Process ID: `8008`
- Parent process: `powershell.exe`, parent PID `1696`
- Event time: `2026-10-17 07:30:58.306 UTC` (approximately `13:00:58.306` India time)
- Wazuh indexed timestamp: `2026-10-17 13:00:59.474` (displayed in Wazuh)
- Alert email setting: `true` in the supplied alert record.

### Observed encoded argument
```text
VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABoAGkAcwAgAGkAcwAgAGEAbgAgAGUAbgBjAG8AZABlAGQAIAB0AGUAcwB0ACAAYwBvAG0AbQBhAG4AZAAnAA==
```

### Decoded meaning
The Base64 value represents UTF-16LE text equivalent to:
```powershell
Write-Host 'This is an encoded test command'
```
This is a benign test payload. The detection correctly identifies the encoded-command pattern in the process command line, but the payload shown here does not establish malicious behavior.

### Interpretation
The encoded command alert is **a successful detection test** for the `-enc` indicator. In production, investigate the decoded content, parent process, user, execution time, network connections, file activity, and related alerts. Avoid treating every `-EncodedCommand` use as malicious.

## Related Detection — Office spawning PowerShell
The supplied Wazuh results also show rule `100302`, Level 13, for an Office application (`WINWORD.EXE` under `C:\FakeOffice\Office16\`) spawning PowerShell. This is a separate high-priority behavior worth investigating because Office-to-script process chains can occur in malicious document activity. The path `C:\FakeOffice\Office16\` suggests a lab/test path, but verify whether it was deliberately created for testing. Do not conclude that a malicious document ran without additional evidence.

## Evidence summary
The supplied screenshots show:
- 11 combined results when searching rules `100302` OR `100301`.
- 6 results for rule `100300`.
- 3 results for rule `100301` in the combined view, with visible timestamps across October 15 and October 17.
- 4 visible rule `100302` events in the combined view.
- A Wazuh dashboard filtered to rule `100300`, displaying six total events.

Counts reflect the selected Wazuh search range and screenshots, not necessarily unique executions or the total count across all logs.

## Investigation questions and findings
1. **Was PowerShell executed?** Yes. Sysmon Event ID 1 records process creation.
2. **Which endpoint?** `window10`, agent `002`, IP `192.168.34.148`.
3. **Which account?** `DESKTOP-0P32A1N\vipin`.
4. **Was suspicious PowerShell detected?** Yes, rule `100300` generated Level 10 alerts.
5. **Was encoded PowerShell detected?** Yes, rule `100301` generated a Level 12 alert.
6. **Was the encoded payload malicious?** The supplied encoded test decodes to a `Write-Host` test string; malicious intent is not indicated by that payload.
7. **Was compromise confirmed?** No. The evidence shows detection behavior and test-like commands, not confirmed compromise.
8. **Was Office-to-PowerShell activity observed?** Yes, rule `100302` alerts were visible. The process chain and test context need validation.

## Recommended analyst response
1. Confirm the commands were deliberately executed as part of the lab.
2. Review complete Sysmon Event ID 1 details and correlate process GUIDs, parent processes, user, and timestamps.
3. Inspect PowerShell Operational events (4103/4104) if script-block/module logging is enabled.
4. Review network and file activity around the events, especially for commands that download or execute remote content.
5. Validate rule thresholds and false-positive behavior with benign and suspicious controlled tests.
6. Tune detection logic to combine command-line indicators with context, rather than alerting on all PowerShell executions.
7. Investigate rule `100302` Office-to-PowerShell events separately.
8. Keep the incident as **lab detection validation / suspicious behavior requiring context** unless other evidence confirms malicious activity.

## Detection logic and limitations
The rule XML was not included in the supplied evidence, so this report documents observed alert behavior and metadata rather than claiming to validate every matching condition. To complete the detection engineering record, add the exact rule XML and test results (including benign baseline tests). Event counts should be deduplicated using process GUID, event record ID, host, and time.

## Evidence files
- `evidence/E01-suspicious-powershell-dashboard.png`
- `evidence/E02-suspicious-powershell-alerts.png`
- `evidence/E03-encoded-powershell-alert.png`

## Disclaimer
This is an isolated lab exercise using a Windows endpoint and Wazuh. Do not publish secrets, access tokens, internal production hostnames, or sensitive log data. Review the evidence images before making the repository public.
