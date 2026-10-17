# Detection 007 — Persistence Monitoring with Wazuh

**Status:** Detection validated; analyst review required  
**Verdict:** Persistence-related events detected; malicious persistence not confirmed  
**Date:** 17 October 2026  
**Manager:** `vm1`  
**Linux endpoint:** `ubuntu_vm2` (`192.168.34.143`, agent `001`)  
**Windows endpoint:** `window10` (`192.168.34.148`, agent `002`)

## 1. Executive Summary
Wazuh was queried for rules `100530`, `100531`, `100532`, and `100533`. The dashboard showed 13 hits in the selected last-week range and two alerts at Level 12 or above.

Evidence includes Linux cron-related file creation, modification, and deletion detected by FIM, and Windows scheduled-task creation events. Most relevant is rule `100533` for task `\\TestPersist1`, which launches PowerShell with the argument `-command Write-Host persistence_test` on a repeating one-minute trigger. This is consistent with a lab detection test. A OneDrive-named scheduled task was also detected and should be validated against the endpoint baseline.

The evidence confirms persistence-related telemetry and rule matches. It does not establish malicious intent or compromise.

## 2. Environment

| Field | Value |
|---|---|
| SIEM | Wazuh |
| Manager | `vm1` |
| Linux endpoint | `ubuntu_vm2` — `192.168.34.143`, agent `001` |
| Windows endpoint | `window10` — `192.168.34.148`, agent `002` |
| Linux data source | Wazuh FIM / `syscheck` |
| Windows data source | Security Event ID `4698` |
| Query | `rule.id:(100530 OR 100531 OR 100532 OR 100533)` |
| Selected range | Last week, 10–17 October 2026 |

## 3. Detection Rules

| Rule | Observed description | Level | ATT&CK |
|---|---|---:|---|
| `100530` | Cron job file modified (alerts also show add/delete events) | 10 | `T1053.003` |
| `100531` | Included in the query; specific alert details not supplied | Unverified | Unverified |
| `100532` | Windows scheduled task created | 10 | `T1053.005` |
| `100533` | Scheduled task runs a scripting engine; command visible in task content | 12 | `T1053.005`, `T1059` |

The custom XML was not provided, so the report describes only the behavior visible in the supplied records.

## 4. Linux Finding — Cron File Changes

Wazuh FIM detected these events on `ubuntu_vm2` (`192.168.34.143`):

| Time (UTC+05:30) | Path | Event | Evidence |
|---|---|---|---|
| 14:50:20.836 | `/etc/cron.d/test_persist` | Added | Size 74 bytes; owner/group root; SHA-256 `2da5023deafd4da57132d2d8c52332b0063e4eb658f837b84e0d92be126a99df` |
| 14:52:14.167 | `/etc/cron.d/test_persist1` | Added | Size 74 bytes; owner/group root; SHA-256 `2da5023deafd4da57132d2d8c52332b0063e4eb658f837b84e0d92be126a99df` |
| 14:53:46.524 | `/etc/cron.d/test_persist1` | Modified | Size grew from 74 to 143 bytes; SHA-256 changed |
| 14:53:56.862 | `/var/spool/cron/crontabs/tmp.96btvJ` | Added | Size 241 bytes; owner `vm2`; group `crontab` |
| 14:53:56.900 | `/var/spool/cron/crontabs/vm2` | Added | Size 241 bytes; owner `vm2`; group `crontab` |
| 14:53:56.899 | `/var/spool/cron/crontabs/tmp.96btvJ` | Deleted | Temporary file deleted shortly after creation |

For `/etc/cron.d/test_persist1`, the recorded SHA-256 changed from:
- **Before:** `2da5023deafd4da57132d2d8c52332b0063e4eb658f837b84e0d92be126a99df`
- **After:** `0912ef515f64685158cba92fbd028a9942928dfab90e587ef1bae1b5af76d1b2`

This change is strong evidence that file content changed. The actual cron commands were not included in the supplied logs, so their behavior cannot be assessed here.

The temporary file activity under `/var/spool/cron/crontabs` may relate to a normal crontab update workflow, but the sequence and content should be validated against the lab actions.

## 5. Windows Finding — Scheduled Task Creation

### Event A — OneDrive-named task
- **Rule:** `100532`, Level 10
- **Task:** `\\OneDrive Standalone Update Task-S-1-5-21-...-1001`
- **Creator:** `vipin`
- **Windows event:** Security Event ID `4698`
- **Event time:** `2026-10-17 07:34:34.094 UTC` (approximately `13:04:34.094` UTC+05:30)
- **Event record ID:** `45525`
- **Task action:** `%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe`
- **Schedule:** daily time trigger; enabled; runs with least privilege.

The task name and action resemble an updater task, but names alone do not establish legitimacy. Validate the actual executable path, digital signature, and installed OneDrive status.

### Event B — `\\TestPersist1`
- **Rule:** `100533`, Level 12
- **Task creator:** `vipin`
- **Windows event:** Security Event ID `4698`
- **Event time:** `2026-10-17 09:29:05.198 UTC` (approximately `14:59:05.198` UTC+05:30)
- **Event record ID:** `46761`
- **Trigger:** repeats every minute
- **Action:** `powershell.exe`
- **Arguments:** `-command Write-Host persistence_test`
- **Run level:** `LeastPrivilege`
- **Alert email flag:** `true`

This is a clear detection test: the task content explicitly runs a test string through PowerShell. The detection shows that Wazuh can inspect scheduled-task content and raise a higher-level alert when a scripting engine is present.

### Event C — `\\TestPersist2`
- **Rule:** `100532`, Level 10 (from dashboard results)
- **Creator:** `vipin`
- **Windows event:** Security Event ID `4698`
- **Event time:** approximately `2026-10-17 09:29:15.204 UTC` (`14:59:15.204` UTC+05:30)
- **Task name:** `\\TestPersist2`

The supplied details confirm task creation and the rule match. Its complete action/content should be reviewed before drawing conclusions about its behavior.

A separate Windows alert in the dashboard also references `\\Microsoft\\Windows\\UpdateOrchestrator\\MusUx_LogonUpdateResults`; verify this against the endpoint baseline rather than automatically classifying it as malicious.

## 6. Timeline

| Time (UTC+05:30) | Endpoint | Event |
|---|---|---|
| 13:04:34 | `window10` | OneDrive-named scheduled task created; rule `100532` |
| 14:50:20 | `ubuntu_vm2` | `/etc/cron.d/test_persist` added; rule `100530` |
| 14:52:14 | `ubuntu_vm2` | `/etc/cron.d/test_persist1` added; rule `100530` |
| 14:53:46 | `ubuntu_vm2` | `/etc/cron.d/test_persist1` modified; hashes changed; rule `100530` |
| 14:53:56 | `ubuntu_vm2` | Crontab spool temporary file and `vm2` crontab observed; temporary file later deleted; rule `100530` |
| 14:59:05 | `window10` | `\\TestPersist1` created with PowerShell test command; rule `100533` |
| 14:59:15 | `window10` | `\\TestPersist2` created; rule `100532` |

Times are converted to UTC+05:30 for readability from the supplied event/system timestamps. Some dashboard dates may reflect indexed time rather than original event time.

## 7. Dashboard Summary
- **Query:** `rule.id:(100530 OR 100531 OR 100532 OR 100533)`
- **Selected range:** Last week
- **Total hits:** 13
- **Level 12 or above:** 2
- **Visible endpoint coverage:** Linux `ubuntu_vm2` and Windows `window10`
- **ATT&CK categories shown:** Cron, Scheduled Task, Command and Scripting Interpreter

These are alert-document counts in the selected range, not necessarily unique persistence mechanisms.

## 8. MITRE ATT&CK
- **T1053.003 — Scheduled Task/Job: Cron**
- **T1053.005 — Scheduled Task/Job: Scheduled Task**
- **T1059 — Command and Scripting Interpreter**

The technique mappings align with cron file changes and scheduled tasks launching a scripting engine. They do not independently prove malicious activity.

## 9. Impact Assessment
**Confirmed**
- Linux cron-related files were added, modified, or deleted and Wazuh FIM generated alerts.
- Windows Security Event ID 4698 records confirmed scheduled-task creation.
- A task named `TestPersist1` contains a PowerShell `Write-Host persistence_test` command and a repeating minute trigger.
- Wazuh dashboard returned 13 hits, including two Level 12+ alerts.

**Not confirmed**
- That any cron job or task executed successfully.
- Malicious intent, unauthorized persistence, or endpoint compromise.
- Whether the OneDrive-named task is legitimate without validation of its executable and software baseline.
- The exact behavior of rule `100531`.

## 10. Analyst Verdict
**Persistence detection validated; lab test behavior observed; malicious persistence not confirmed.**

The `TestPersist1` task and the `test_persist*` cron paths are consistent with controlled test artifacts. Nevertheless, unexpected cron changes and scheduled-task creation are important persistence indicators. The OneDrive-named task should be validated against its executable path and known endpoint baseline. Keep the investigation as detection validation until task/file ownership and authorization are confirmed.

## 11. Recommended Response
1. Confirm the test cron files and `TestPersist1`/`TestPersist2` tasks were intentionally created.
2. Save the cron file contents and task XML before cleanup.
3. Verify the OneDrive updater executable exists at the recorded path and has the expected signer.
4. Correlate scheduled-task creation with process creation, PowerShell logs, and task execution history.
5. Review cron file commands, owners, permissions, hashes, and user crontab contents.
6. Check whether any of these jobs launched external commands, created files, or established network connections.
7. Remove only known test artifacts after preserving evidence.
8. Validate rule `100531` and test false-positive behavior with legitimate cron/task updates.

## 12. Limitations
The custom rule XML, full cron file contents, and complete `TestPersist2` task content were not supplied. FIM proves that files changed, but not what cron commands they contained. Security Event ID 4698 proves task creation, not subsequent execution. The dashboard count may include repeat or related alerts.

## 13. Conclusion
The Wazuh/Sysmon-style endpoint telemetry validated cross-platform monitoring of Linux cron changes and Windows scheduled-task creation. A scheduled task with a PowerShell test command was detected at Level 12. The available evidence supports a lab detection validation outcome, not a confirmed intrusion. Preserve the evidence, verify authorization and task content, then document cleanup and final disposition.

## 14. Evidence Index
- `evidence/E01-persistence-alert-results.png` — alert results for rules 100530–100533
- `evidence/E02-persistence-dashboard.png` — dashboard summary, counts, and ATT&CK chart
- `evidence/E03-linux-cron-file-alert-details.png` — Linux FIM cron file change details
- `evidence/E04-windows-scheduled-task-alert-details.png` — Windows task XML and task-creation alert
