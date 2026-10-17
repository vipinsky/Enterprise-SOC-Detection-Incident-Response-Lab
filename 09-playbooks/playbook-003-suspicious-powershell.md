# Playbook — Detection 003: Suspicious PowerShell

**Rule:** 100300
**MITRE:** T1059.001
**Severity:** Medium (level 10)
**Platform:** Windows

## 1. What triggered

`powershell.exe`/`powershell_ise.exe` executed with at least one evasion/download indicator in the command line: `-nop`, `-w hidden`, `-ep bypass`, `downloadstring`, `downloadfile`, `iex`/`invoke-expression`, `-sta`, `iwr`.

## 2. Immediate triage

1. Pull the full `data.win.eventdata.commandLine` — this is the single most important field.
2. Check `data.win.eventdata.user` and `data.win.eventdata.parentImage`.
3. Ask: does this command line read like routine IT automation (a known deployment/config script), or does it read like an attempt to hide/retrieve something?

## 3. True Positive indicators

- Command line references an external URL, especially an IP address or an unfamiliar/freshly-registered domain.
- `-w hidden` combined with anything else (hidden window + any other flag is rarely legitimate for interactive admin work).
- Parent process is unusual: Office app, browser, `mshta.exe`, `wscript.exe`, a scheduled-task host (`svchost.exe` running a task not in your known task inventory), rather than `explorer.exe`/`cmd.exe`/an admin's RDP session.
- The command was not initiated by IT/automation accounts (check `user`).
- Timing is off-hours or inconsistent with the user's normal activity.
- Followed shortly after by network connections to unfamiliar destinations (correlate with Detection 010 alerts on the same host/time).

## 4. False Positive indicators

- Known deployment tooling (SCCM, Intune, Ansible, Chef/Puppet agents) legitimately uses `-nop`/`-w hidden` as standard invocation flags — check against your organization's known automation account list.
- `downloadstring`/`iwr` pointing to an internal, known-good URL (internal package repo, internal wiki).
- Command run interactively by a known admin during a documented maintenance window, visible in change-management records.
- Security tooling itself (EDR agents, vulnerability scanners) sometimes uses these flags for their own legitimate scripted checks — confirm against your asset inventory of installed security agents.

## 5. Investigation steps

```bash
sudo grep -a "100300" /var/ossec/logs/alerts/alerts.json | tail -n 5
```

Pull the full process tree around the event:
```bash
sudo grep -a "<processGuid>" /var/ossec/logs/archives/archives.json
```

Check what the same host did in the surrounding time window — did this PowerShell command lead to further suspicious activity (Detection 005 parent-child, Detection 010 network)?

Dashboard: Threat Hunting → `rule.id: 100300`, then pivot to `agent.name` + the same time range to see all other alerts from that host.

## 6. Containment (if confirmed malicious)

1. Isolate the host from the network if active C2/beaconing is suspected.
2. Capture the full command line and any downloaded payload for analysis (if the script is still accessible on disk).
3. Kill the PowerShell process if still running: `Stop-Process -Id <pid> -Force`.
4. Check for persistence artifacts created by the script (scheduled tasks, registry Run keys, new services) — cross-reference Detection 009.
5. Reset credentials for the user context the process ran under.

## 7. Escalation criteria

Escalate if:
- The command references an external, non-corporate URL/IP.
- The parent process is Office, a browser, or another document/scripting-abuse vector.
- Correlated alerts exist on the same host (network beaconing, new scheduled task, new local account).

## 8. Closing the alert

Document: full command line, user context, parent process, verdict (TP/FP), and — if FP — which known-tool/automation pattern it matched, so it can be tuned into an allowlist exception rather than re-triaged each time.
