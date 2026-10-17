# Playbook — Detection 009: Persistence (Cron / Scheduled Task)

**Rules:** 100530/100531 (Linux cron), 100532/100533 (Windows scheduled task)
**MITRE:** T1053.003, T1053.005, T1059
**Severity:** Medium–High (10–12)
**Platform:** Linux and Windows

## 1. What triggered

- **100530** — a cron job file (`/etc/cron.d`, `/etc/crontab`, or a per-user crontab) was modified.
- **100531** — specifically a **new** cron file was created (stronger signal than a modification).
- **100532** — a Windows scheduled task was created.
- **100533** — the created task's content includes a scripting engine (PowerShell, cmd, wscript, cscript, mshta).

## 2. Immediate triage

1. Identify the mechanism (`syscheck.path` / `taskName`), the creator (`audit.user.name` / `subjectUserName`), and the command it runs.
2. Check whether this matches a known, documented scheduled job (backup script, log rotation, monitoring check-in, patch deployment).
3. If **100531** or **100533** fired specifically, prioritize — new creation and scripting-engine content are both stronger signals than routine modification of existing jobs.

## 3. True Positive indicators

- Creator account has no legitimate reason to be scheduling jobs (not an admin/automation identity).
- The command references an external URL/IP, or is encoded/obfuscated.
- The job runs at a very short interval (every minute) — common in test/malicious persistence, less common in legitimate production scheduling.
- The job was created shortly after another suspicious event on the same host (suspicious PowerShell, privilege escalation, new user account).
- No corresponding change ticket or deployment record exists.
- (Windows) The task's "Run As" account is privileged but the creating user normally has no business creating privileged tasks.

## 4. False Positive indicators

- Matches a known backup, monitoring, patch-management, or log-rotation job documented in your change/configuration records.
- Created by a known configuration-management tool (Ansible, Puppet, Chef, SCCM, Intune) as part of a routine deployment.
- Creator is a system/service account with an established pattern of legitimate scheduled-job creation.

## 5. Investigation steps

```bash
# Linux
sudo grep -a "100530\|100531" /var/ossec/logs/alerts/alerts.json | tail -n 10
cat /etc/cron.d/<filename>   # inspect the actual job content directly on the host

# Windows (on vm1, searching alerts)
sudo grep -a "100532\|100533" /var/ossec/logs/alerts/alerts.json | tail -n 10
```

On Windows, inspect the task directly on the endpoint:
```powershell
schtasks /query /tn "<taskName>" /v /fo LIST
Get-ScheduledTask -TaskName "<taskName>" | Get-ScheduledTaskInfo
```

**Confirm actual execution** — don't stop at "job was created," verify whether it has run:
```bash
# Linux: check for output/side-effects of the job
# Windows:
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 | Where-Object {$_.Id -eq 1 -and $_.Message -match "<task command>"}
```

## 6. Containment (if confirmed malicious)

1. Disable/remove the cron job or scheduled task immediately: `sudo rm /etc/cron.d/<file>` or `schtasks /delete /tn "<task>" /f`.
2. Preserve the job's content (copy before deleting) for analysis.
3. Investigate the creator's full session for how they gained the access to schedule it (correlate with Detections 002, 007, 008).
4. Check for other persistence mechanisms planted around the same time (new accounts, new services, registry Run keys, SSH keys).
5. Rotate credentials for the creating account.

## 7. Escalation criteria

Escalate if:
- 100531/100533 fired (new creation / scripting content) with no matching change record.
- The job references external infrastructure or runs at suspiciously short intervals.
- Correlated with other suspicious activity on the same host in the surrounding time window.

## 8. Closing the alert

Document: mechanism (cron file path or task name), creator, full command/content, confirmed execution (yes/no), change-record match (yes/no), verdict, and remediation.
