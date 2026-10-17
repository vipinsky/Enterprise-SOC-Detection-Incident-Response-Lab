# Detection 002 — Suspicious PowerShell

**Status:** Detection observed; context review required  
**Wazuh rule:** `100300` · **Level:** 10  
**Endpoint:** `window10` (`192.168.34.148`), agent `002`  
**MITRE ATT&CK:** `T1059.001 — PowerShell`

## Objective
Detect PowerShell execution with suspicious characteristics without alerting on every PowerShell process.

## Evidence
Sysmon Event ID 1 recorded PowerShell process creation under user `DESKTOP-0P32A1N\vipin`.

```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -windowstyle hidden -command "Write-Host test"
```

- Process ID: `13156`
- Parent image: `powershell.exe`
- Parent PID: `10780`
- Event time: `2026-10-17 07:25:56.216 UTC` (`12:55:56.216` UTC+05:30)
- Wazuh alert timestamp: `2026-10-17 12:55:57.895`
- Rule groups: `sysmon`, `powershell`, `suspicious_powershell`

## Analysis
The hidden-window option can be used to conceal script execution and is a useful suspicious indicator. The observed `Write-Host test` command appears test-oriented and does not, by itself, demonstrate malicious behavior.

The Wazuh screenshots show six events for rule `100300` in the selected time range. Validate unique executions using process GUID, event record ID, timestamp, and raw event data.

## Verdict
**Detection test / suspicious characteristic observed; no compromise confirmed.**

## Recommended follow-up
- Confirm the command was intentionally run for testing.
- Correlate parent and child process activity.
- Review PowerShell Operational logs (4103/4104) if enabled.
- Check related network/file activity and adjacent Wazuh alerts.
- Tune rules to avoid alerting on all PowerShell execution.

## Evidence
See `../evidence/E02-suspicious-powershell-alerts.png` and `../evidence/E01-suspicious-powershell-dashboard.png`.
