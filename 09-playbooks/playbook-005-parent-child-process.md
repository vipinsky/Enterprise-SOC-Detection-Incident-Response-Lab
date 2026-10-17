# Playbook — Detection 005: Suspicious Parent → Child Process

**Rules:** 100302 (Office → shell), 100303 (Browser → shell), 100304 (PDF reader → shell)
**MITRE:** T1566.001, T1059
**Severity:** High (level 12–13)
**Platform:** Windows

## 1. What triggered

An Office application, browser, or PDF reader spawned a shell/scripting engine (`powershell`, `cmd`, `wscript`, `cscript`, `mshta`, `regsvr32`, `rundll32`, `certutil`).

## 2. Immediate triage

1. Identify the exact parent (`parentImage`) and child (`image`) + the child's `commandLine`.
2. Check if the parent document/file that launched the chain is known — was the user expecting to open this file? Check email/download history around the event time.
3. Check the child's command line for a download cradle or encoded payload (cross-reference Detections 003/004).

## 3. True Positive indicators

- The document was received via email moments before the event (classic phishing-macro timing).
- The child process's command line references an external URL/IP.
- `parentImage`'s **hash** (`win.eventdata.hashes` from the Office/browser/PDF process) does not match the known-good hash for that application — this is the strongest signal, since filenames can be spoofed (see note below).
- The user has no legitimate reason to be running macros/scripts from this document (not part of their normal workflow).
- Chain continues: child process spawns further children, creates files, or makes network connections shortly after.

## 4. False Positive indicators

- Legitimate internal macro-enabled workbooks/templates that are a known, documented part of business workflow (e.g., a finance team's VBA-driven reporting macro that shells out to a PowerShell helper script) — confirm against your organization's known-macro inventory.
- A PDF reader plugin or browser extension that legitimately launches a helper script as part of normal operation — rare, but check your software inventory before assuming malice.
- Testing/development activity by IT staff deliberately exercising macro functionality in a sandboxed or documented context.

## 5. Investigation steps

```bash
sudo grep -a "100302\|100303\|100304" /var/ossec/logs/alerts/alerts.json | tail -n 5
```

**Critical:** verify the parent process's actual identity, not just its path:
```bash
sudo grep -a "<parentProcessGuid>" /var/ossec/logs/archives/archives.json
```
Check the `hashes` field (MD5/SHA256) against known-good hashes for the legitimate application (Office, Chrome, Acrobat). A mismatch, or a hash belonging to a different binary entirely (e.g., `powershell.exe` renamed to `WINWORD.EXE`), confirms malicious spoofing rather than a genuine Office macro.

Trace the full process lineage from the original document to any child processes, network connections, or file drops.

## 6. Containment (if confirmed malicious)

1. Isolate the host.
2. Preserve the original document/attachment for analysis — do not delete, it's the initial access artifact.
3. Identify and notify other recipients if this arrived via a phishing email (check for similar emails sent to other users).
4. Kill any still-running child processes.
5. Hunt for persistence and lateral movement originating from this host.
6. Block the sender/source if email-delivered.

## 7. Escalation criteria

Escalate immediately — this pattern has very few legitimate explanations and directly maps to an active initial-access attempt.

## 8. Detection limitation to account for during triage

This rule matches on the `Image`/`parentImage` **path string** (e.g., containing `winword.exe`), not a verified digital signature or hash. A binary can be renamed to spoof this match (confirmed during lab testing — renaming `powershell.exe` to `WINWORD.EXE` successfully triggers the rule). **Always verify the hash field during investigation**, since the same weakness that lets testers simulate this detection could let a real attacker name a dropped payload to blend in or, conversely, evade a naive hash-based tool by avoiding the exact legitimate filename.

## 9. Closing the alert

Document: original file/attachment, verified parent hash, child command line, verdict, and whether other users/hosts were affected.
