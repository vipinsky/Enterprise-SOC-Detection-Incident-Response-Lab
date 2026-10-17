# Detection 004 — Suspicious Parent–Child Process Lineage

A Windows SOC detection-engineering lab using Wazuh and Sysmon. The detections identify scripting/shell execution initiated by Office, browser, and PDF-reader parent processes.

## Summary
Wazuh alerts were observed on Windows endpoint `window10` (`192.168.34.148`, agent ID `002`) for three process-lineage rules:

| Rule ID | Detection | Wazuh level | MITRE ATT&CK mapping |
|---|---|---:|---|
| `100302` | Office application spawned a scripting/shell process | 13 | `T1566.001`, `T1059` |
| `100303` | Browser spawned a scripting/shell process | 12 | `T1059` |
| `100304` | PDF reader spawned a scripting/shell process | 12 | `T1059` |

The supplied alerts show PowerShell launched with a test command (`Write-Host test`) by simulated parent executable paths under `C:\FakeOffice\`, `C:\FakeBrowser\`, and `C:\FakePDF\`. This is consistent with controlled lab validation. The alert behavior is confirmed; malicious intent or compromise is not.

## Lab environment
- **SIEM / manager:** Wazuh, manager `vm1`
- **Endpoint:** `window10`, agent ID `002`, IP `192.168.34.148`
- **Sysmon computer name:** `DESKTOP-0P32A1N`
- **Telemetry:** `Microsoft-Windows-Sysmon/Operational`, Event ID `1` (Process Create)
- **Wazuh input location:** `EventChannel`
- **Investigation date:** 17 October 2026
- **Account observed:** `DESKTOP-0P32A1N\vipin`

## Key observations
- Search results displayed **7 hits** for rules `100302 OR 100303 OR 100304` in the selected time range.
- The visible results contain Office-to-PowerShell events, one browser-to-PowerShell event, and one PDF-reader-to-PowerShell event.
- The three detailed 17 October events occurred at approximately:
  - `13:28:47` local time — `WINWORD.EXE` → `powershell.exe` (rule `100302`, level 13)
  - `13:30:10` local time — `chrome.exe` → `powershell.exe` (rule `100303`, level 12)
  - `13:30:23` local time — `AcroRd32.exe` → `powershell.exe` (rule `100304`, level 12)
- The shown PowerShell command was `-command Write-Host test`.
- These paths are lab-like (`C:\FakeOffice\`, `C:\FakeBrowser\`, `C:\FakePDF\`). Confirm whether they were intentionally created for the exercise.

Counts are from the supplied Wazuh UI results and selected time range. They should not be treated as unique incidents without deduplication.

## Analyst verdict
**Lab detection validation — suspicious process lineage observed; no compromise confirmed.**

Office, browser, and PDF-reader processes spawning PowerShell can be suspicious because these parent-child chains are common investigation pivots. Here, the sample commands are benign-looking test commands and the paths appear to be simulated. The alerts prove that Wazuh matched the configured detections, not that a real malicious document, web page, or PDF compromised the endpoint.

## Suggested triage
1. Confirm the three events were deliberately generated in the lab and validate the parent executables/paths.
2. Review Sysmon Event ID 1 using process GUIDs, parent process GUIDs, PID, username, command line, and event time.
3. Correlate PowerShell Operational Event IDs 4103/4104 if those logs are enabled.
4. Check nearby network, file-write, script-block, and child-process events if a real incident is suspected.
5. Investigate any real Office/browser/PDF process spawning PowerShell, especially if the command downloads content, launches hidden execution, or modifies the system.
6. Test benign baseline activity and tune rule conditions to balance coverage and noise.

## Report files
- `Detection-004-Process-Lineage-Report.pdf` — shareable report with screenshots
- `Detection-004-Process-Lineage-Report.docx` — editable report
- `Detection-004-Suspicious-Process-Lineage.md` — Markdown report
- `timeline.csv` — observed-event timeline
- `evidence/` — supplied screenshots

## Evidence limitations
The exact XML for rules `100302`–`100304` was not supplied. This report documents observed alert descriptions and telemetry, but does not claim to validate every condition in the rules. The supplied evidence does not include independent proof of network downloads, malicious payload execution, persistence, or compromise.


