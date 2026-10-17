# Playbook — Detection 008: Privilege Escalation / Sudo Abuse

**Rules:** 100520 (baseline, Tier 1), 100521 (watchlist, Tier 2), 100522–100524 (high-confidence, Tier 3), 100525 (repeated failures)
**MITRE:** T1548.003, T1078, T1059.004, T1105
**Severity:** Tier 1 = Low (5) · Tier 2 = Medium (9) · Tier 3 = High (12–13) · 100525 = High (10)
**Platform:** Linux

## 1. What triggered

Sudo command execution, tiered by risk:
- **100520** — any sudo command (baseline visibility only).
- **100521** — sudo used with a sensitive command (passwd, sudoers, crontab, systemctl, etc.).
- **100522/100523/100524** — sudo used to spawn an interactive shell, a GTFOBins-style escape, or a download-and-execute/reverse-shell pattern.
- **100525** — 3+ failed sudo password attempts from the same source within 2 minutes.

## 2. Immediate triage

**Tier 1 (100520) alone:** no action needed — this is baseline audit trail, not an incident signal. Do not investigate individually; use only for later correlation if a Tier 2/3 alert fires on the same host.

**Tier 2 (100521):** check whether the command matches the user's normal job function. A sysadmin editing crontab is routine; a developer account doing the same is worth a second look.

**Tier 3 (100522–100524):** treat as a likely incident from the start — pull the full command line and user context immediately.

**100525:** check if this is the account owner struggling with a forgotten password, or a different actor attempting escalation on an account they don't fully control.

## 3. True Positive indicators

- Tier 3 fired from an account with no legitimate reason to spawn a root shell or use a GTFOBins escape (e.g., a service account, a junior support account).
- The command line in 100524 references an external IP/domain.
- Tier 3 activity follows shortly after a suspicious login (correlate with Detection 002) or a suspicious process (correlate with Detections 003–005).
- 100525 fired alongside a later Tier 2/3 event — someone struggled to authenticate, then succeeded and immediately did something sensitive.
- The user's session (TTY, source) doesn't match their normal working pattern (unusual terminal, unusual hours, unfamiliar source IP for remote sessions).

## 4. False Positive indicators

- Tier 2 command matches a routine, documented administrative task (confirmed against change records or the admin's normal duties).
- Tier 3 `sudo su`/`sudo bash` used by a system administrator during a documented maintenance window — common and often legitimate for admins who prefer a root shell over prefixing every command with `sudo`.
- 100525 caused by the legitimate account owner simply mistyping their password, confirmed by a normal successful login shortly after from the same source and no suspicious follow-on activity.

## 5. Investigation steps

```bash
# Full tier-by-tier picture for the user/session
sudo grep -a "100520\|100521\|100522\|100523\|100524\|100525" /var/ossec/logs/alerts/alerts.json | grep -a "<dstuser or srcuser>"
```

Reconstruct the full command history for the session:
```bash
sudo grep -a "<srcuser>" /var/ossec/logs/alerts/alerts.json | tail -n 50
```

Check `full_log`/`data.command` for every Tier 2/3 alert — the actual command text is the most important evidence here.

## 6. Containment (if confirmed malicious)

1. Disable or lock the account used for escalation.
2. If a reverse shell or download-and-execute pattern (100524) fired: isolate the host immediately, assume compromise.
3. Review what the elevated session accessed or modified (file changes via syscheck, new accounts via Detection 007, new persistence via Detection 009).
4. Rotate credentials for the account and any accounts it could have accessed while escalated.
5. Review `sudoers` configuration for overly broad permissions that enabled the escalation path.

## 7. Escalation criteria

Escalate immediately for any Tier 3 alert (100522–100524) unless conclusively matched to a documented, routine admin action. Tier 2 escalates only when paired with other suspicious context. Tier 1 never escalates on its own.

## 8. Closing the alert

Document: tier, exact command, user, session context, matched to change record (yes/no), verdict, and action taken. For Tier 1/2 false positives that recur legitimately and frequently, consider whether an allowlist exception is warranted to reduce analyst load — but do this deliberately, not by raising the detection's threshold broadly.
