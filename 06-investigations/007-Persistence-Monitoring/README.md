# Detection 007 — Persistence Monitoring with Wazuh

## Overview
This project documents a cross-platform persistence detection lab with Wazuh, Linux File Integrity Monitoring (FIM), Linux cron telemetry, and Windows scheduled-task auditing.

The supplied Wazuh dashboard searched:
`rule.id:(100530 OR 100531 OR 100532 OR 100533)`

The dashboard displayed **13 hits** in the selected last-week range, including **2 alerts at Level 12 or above**.

## Lab environment
| Component | Value |
|---|---|
| SIEM / manager | Wazuh / `vm1` |
| Linux endpoint | `ubuntu_vm2`, agent `001`, `192.168.34.143` |
| Windows endpoint | `window10`, agent `002`, `192.168.34.148` |
| Linux telemetry | Wazuh FIM (`syscheck`) for cron-related paths |
| Windows telemetry | Windows Security Event ID `4698` (scheduled task created) |
| Investigation date | 17 October 2026 |

## Detection rules observed
| Rule | Description | Level | ATT&CK |
|---|---|---:|---|
| `100530` | Linux cron job file added, modified, or deleted | 10 | `T1053.003` — Cron |
| `100531` | Included in dashboard filter; no specific alert detail supplied | Not confirmed | Not confirmed |
| `100532` | Windows scheduled task created | 10 | `T1053.005` — Scheduled Task |
| `100533` | Scheduled task runs a scripting engine; command visible in task content | 12 | `T1053.005`, `T1059` |

The exact XML for the custom rules was not included, so this report documents observed alert behavior rather than claiming to validate every condition.

## Key findings
- Linux FIM alerted when `/etc/cron.d/test_persist` and `/etc/cron.d/test_persist1` were added; `test_persist1` was then modified.
- A temporary file under `/var/spool/cron/crontabs/` was created and deleted, and `/var/spool/cron/crontabs/vm2` was added. Such files can occur during crontab updates, but the content and originating action should be checked.
- Windows Security Event ID `4698` detected creation of a OneDrive-named scheduled task, plus lab tasks `TestPersist1` and `TestPersist2`.
- Rule `100533` flagged `\TestPersist1`, whose task content runs `powershell.exe -command Write-Host persistence_test` and is configured with a repeating one-minute trigger.
- The OneDrive-named task points to `%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe`; validate the binary path, signature, and whether the task was expected before deciding whether it is benign.
- The dashboard showed 13 matching alert documents, not necessarily 13 unique persistence incidents.

## Analyst verdict
**Persistence detections validated; intent requires context.**

The evidence shows that Wazuh detects Linux cron file changes and Windows scheduled-task creation, including a task that launches PowerShell. The `TestPersist1` contents look explicitly test-oriented, while the OneDrive-named task needs baseline validation. The supplied evidence does not prove malicious persistence or host compromise.

## MITRE ATT&CK
- `T1053.003 — Scheduled Task/Job: Cron`
- `T1053.005 — Scheduled Task/Job: Scheduled Task`
- `T1059 — Command and Scripting Interpreter`

These mappings classify the behavior being monitored; they do not prove malicious intent.

## Investigation recommendations
1. Confirm the cron files and scheduled tasks were intentionally created for the lab.
2. Inspect the complete contents of `/etc/cron.d/test_persist` and `/etc/cron.d/test_persist1`, plus `crontab -l` for the relevant user.
3. Review FIM change metadata and hashes. Compare the old/new SHA-256 for modified files.
4. For Windows tasks, review task XML, triggers, action/command, run-as identity, and task history.
5. Validate the OneDrive updater executable's actual path, digital signature, and expected software installation.
6. Correlate task creation with process creation and PowerShell events.
7. Validate rule `100531` from its XML or an example alert before documenting its behavior.
8. After evidence is preserved, remove only test persistence artifacts that are no longer required.

## Repository contents
- `Detection-007-Persistence-Report.pdf` — shareable report with screenshots
- `Detection-007-Persistence-Report.docx` — editable report
- `Detection-007-Persistence.md` — Markdown report
- `timeline.csv` — event timeline
- `evidence/` — screenshots supplied for this investigation

## Limitations
The custom rule XML and actual cron file contents were not supplied. Linux FIM records show file events and hashes but not the cron command content. Windows logs confirm scheduled-task creation, but task execution after creation is not proven by Event ID 4698 alone. The dashboard count may include repeated events.

