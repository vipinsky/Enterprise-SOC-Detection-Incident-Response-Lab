# Detection 009 — Persistence (Cron and Scheduled Task)

**Rules:** 100530/100531 (Linux cron), 100532/100533 (Windows scheduled task)
**MITRE:** T1053.003 (Scheduled Task/Job: Cron), T1053.005 (Scheduled Task), T1059
**Platform:** Linux (vm2) and Windows (window10)

## Investigation chain

```
Persistence mechanism → Creator → Command → Execution → Associated account
```

## Linux — Cron Persistence

### Prerequisite
```bash
sudo grep -n "cron" /var/ossec/etc/ossec.conf
```
Should show `/etc/cron.d`, `/etc/crontab`, and `/var/spool/cron/crontabs` watched with `whodata="yes"`.

### Test Case 1: New cron file (expect 100530 + 100531)

```bash
echo "* * * * * root /bin/bash -c 'echo persistence_test >> /tmp/cron_test.log'" | sudo tee /etc/cron.d/test_persist1
```
**Expected:** both **100530** (file modified) and **100531** (specifically new).

### Test Case 2: Modifying an existing cron file (expect 100530 only)

```bash
echo "*/5 * * * * root /bin/bash -c 'echo heartbeat >> /tmp/cron_test.log'" | sudo tee -a /etc/cron.d/test_persist1
```
**Expected:** only **100530** this time — confirms the "added vs. modified" distinction in 100531 works.

### Test Case 3: Per-user crontab (realistic attacker path, no root needed)

```bash
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'echo user_persist >> /tmp/cron_test2.log'") | crontab -
```
**Expected:** fires if `/var/spool/cron/crontabs` is in the watched paths.

### Test Case 4: Confirm actual execution

Wait 1–2 minutes after Test Case 1, then:
```bash
cat /tmp/cron_test.log
```
**Expected:** file fills with `persistence_test` entries — proves the "Execution" link in the chain, not just file creation.

### Clean up
```bash
sudo rm /etc/cron.d/test_persist1 /tmp/cron_test.log /tmp/cron_test2.log 2>/dev/null
crontab -r
```

### Verify
```bash
sudo grep -a "100530\|100531" /var/ossec/logs/alerts/alerts.json | tail -n 10
```

## Windows — Scheduled Task Persistence

### Prerequisite
```powershell
auditpol /get /subcategory:"Other Object Access Events"
```
Enable if not already:
```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

### Test Case 5: Task running PowerShell (expect 100532 + 100533)

```powershell
schtasks /create /tn "TestPersist1" /tr "powershell.exe -command Write-Host persistence_test" /sc minute /mo 1
```
**Expected:** both **100532** (task created) and **100533** (scripting engine in task content).

### Test Case 6: Task running a non-scripting binary (expect 100532 only)

```powershell
schtasks /create /tn "TestPersist2" /tr "C:\Windows\System32\calc.exe" /sc daily /st 09:00
```
**Expected:** only **100532** — confirms 100533 correctly distinguishes "any task" from "task running something scriptable."

### Test Case 7: Confirm actual execution

Wait at least 1 minute, then:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 30 | Where-Object {$_.Id -eq 1 -and $_.Message -match "powershell"} | Select-Object -First 3 TimeCreated, Message
```
**Expected:** `powershell.exe` process creation with `ParentImage` showing `svchost.exe` (Task Scheduler's host) — proves the task actually ran.

### Clean up
```powershell
schtasks /delete /tn "TestPersist1" /f
schtasks /delete /tn "TestPersist2" /f
```

### Verify

```bash
sudo grep -a "100532\|100533" /var/ossec/logs/alerts/alerts.json | tail -n 10
```

## Investigation chain mapped to fields

| Chain step | Linux evidence | Windows evidence |
|---|---|---|
| Mechanism | `/etc/cron.d/test_persist1` created | `TestPersist1` task registered |
| Creator | `syscheck.audit.user.name` (whodata) | `subjectUserName` (Event 4698) |
| Command | Cron line content | `taskContent` field |
| Execution | `/tmp/cron_test.log` filling with entries | Sysmon Event 1: `powershell.exe` spawned by `svchost.exe` |
| Associated account | Cron line's specified user (`root`) | `subjectUserName` or task's Run As account |

## Notes for writeup

Test Case 2 (modify vs. create) and Test Case 6 (scripting vs. non-scripting binary) are the key discrimination tests — they show the rules distinguish genuinely suspicious persistence patterns from routine scheduled-task usage, paired with Test Case 4/7 as proof the full mechanism → creator → command → execution → account chain was actually traced, not just the initial creation event.
