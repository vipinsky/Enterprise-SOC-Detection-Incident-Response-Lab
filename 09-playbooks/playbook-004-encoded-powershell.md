# Playbook — Detection 004: Encoded PowerShell

**Rule:** 100301
**MITRE:** T1059.001, T1027
**Severity:** High (level 12)
**Platform:** Windows

## 1. What triggered

`powershell.exe` executed with `-enc`/`-encodedcommand`, or `-e` followed by a 20+ character base64-like string.

## 2. Immediate triage

1. **Decode the payload first** — this is the single most important triage step. In an isolated analysis environment (not production):
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<encoded string>"))
   ```
2. Read the decoded command. Does it reference a URL, create a scheduled task, modify registry Run keys, or spawn another process?
3. Check `data.win.eventdata.user` and `parentImage`.

## 3. True Positive indicators

- Decoded content includes a download cradle (`Net.WebClient`, `Invoke-WebRequest`, `Invoke-RestMethod` to an external host).
- Decoded content references obfuscated variable names, string concatenation tricks, or reflection (`[Reflection.Assembly]::Load`) — common in loader/dropper scripts.
- Decoded content attempts persistence (new scheduled task, registry Run key, WMI event subscription) — cross-reference Detection 009.
- The account running it is not a known automation/admin account.
- No legitimate business reason for encoding is apparent (encoding is almost always used specifically to evade string-based detection or logging, not for routine administration).

## 4. False Positive indicators

- Rare but real: some legitimate deployment frameworks encode commands to safely pass multi-line scripts or special characters through remote execution layers (e.g., certain remote management tools). Confirm against your known tooling inventory — if so, the decoded content will be clearly benign, readable configuration/deployment logic.
- Decoded content is a simple, harmless one-liner used by an admin to avoid shell quoting issues (rare but possible) — verify the decoded content directly rather than assuming malice from encoding alone.

## 5. Investigation steps

```bash
sudo grep -a "100301" /var/ossec/logs/alerts/alerts.json | tail -n 5
```

Extract and decode the command line from the alert's `data.win.eventdata.commandLine` field (see triage step 1).

Check for related activity on the same host/time window:
```bash
sudo grep -a "<agent.name>" /var/ossec/logs/alerts/alerts.json | grep -a "100400\|100600\|100532"
```
(network connections, DNS queries, scheduled task creation — common follow-on behavior)

## 6. Containment (if confirmed malicious)

1. Isolate the host immediately — encoded PowerShell is a strong, low-false-positive signal of intentional evasion.
2. Capture the decoded payload for malware analysis / IOC extraction.
3. Kill the process if still active.
4. Hunt across the environment for the same encoded string or decoded URL/IP (likely present on other hosts if this is a broader campaign).
5. Check for persistence created by the decoded script.
6. Reset credentials for the executing user context.

## 7. Escalation criteria

Escalate immediately — this detection is high-confidence by design (level 12). Any confirmed malicious decode should go to incident response, not stay at analyst-only triage.

## 8. Closing the alert

Document: the full encoded string, the decoded content, verdict, and any IOCs extracted (URLs, IPs, file hashes referenced in the decoded script) for threat-intel tracking.
