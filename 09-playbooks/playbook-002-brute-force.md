# Playbook — Detection 002: SSH Brute Force & Successful Login After Brute Force

**Rules:** 100200 (brute force), 100201 (success after brute force)
**MITRE:** T1110 (Brute Force), T1078 (Valid Accounts)
**Severity:** 100200 = Medium (level 10) · 100201 = Critical (level 14)
**Platform:** Linux

## 1. What triggered

- **100200** — 5+ failed SSH authentications from the same source IP within 180 seconds.
- **100201** — A *successful* SSH login from an IP that triggered 100200 within the prior 300 seconds.

## 2. Immediate triage (first 5 minutes)

1. Open the alert in Threat Hunting / Discover. Note: `data.srcip`, `data.dstuser`, `agent.name`, `timestamp`.
2. Check whether `srcip` is:
   - An internal/known IP (admin workstation, jump box, CI system) → more likely benign.
   - An external/unknown IP → treat as hostile by default until proven otherwise.
3. If **100201** fired (successful login after brute force), treat as **high priority** regardless of source — this means a login succeeded during or immediately after a failure burst.

## 3. True Positive indicators

- `srcip` is external (not in your known IP allowlist).
- `dstuser` is a privileged or service account (root, admin, svc-*, backup).
- Failures use varied usernames (user enumeration pattern), not just one typo'd login.
- 100201 fired — a login succeeded shortly after the failure burst.
- Timing has no human pattern (e.g., precisely-spaced attempts, off-hours, weekend).
- The source IP also appears in other recent alerts (port scan, other brute-force attempts) — correlated campaign.

## 4. False Positive indicators

- `srcip` is a known internal host (e.g., a monitoring tool, backup agent, or a user who mistyped a password a few times).
- A single legitimate user is the *only* `dstuser` targeted, and the eventual successful login (if any) matches that same user's normal login hours/location.
- The failures stopped and no 100201 followed — consistent with a user simply forgetting their password and then not logging in at all, or giving up.
- A known automated job (cron/script) misconfigured with a bad password, reconnecting on a fixed interval — check `data.srcport` and interval regularity; scripted retries are often perfectly periodic (every N seconds exactly), which real attackers rarely are.

## 5. Investigation steps

```bash
# Full picture of the failure burst and any follow-on success
sudo grep -a "<srcip>" /var/ossec/logs/alerts/alerts.json | grep -a "5760\|5715\|100200\|100201"

# Confirm what account(s) were targeted
sudo grep -a "<srcip>" /var/ossec/logs/archives/archives.json | grep -a "Failed password\|Accepted password"
```

Dashboard: Threat Hunting → search `data.srcip: "<ip>"`, time range covering the full incident window, sort by time ascending to reconstruct the sequence.

Check for lateral activity if 100201 fired — what did the session do after logging in?
```bash
sudo grep -a "\"srcuser\":\"<dstuser>\"" /var/ossec/logs/alerts/alerts.json | tail -n 30
```

## 6. Containment (if confirmed malicious)

1. Block the source IP at the firewall / `ufw deny from <ip>`.
2. If 100201 fired (successful compromise): force-expire the compromised account's password immediately, and review `sudo` history (`data.dstuser` in rule 100520 group) for that account's session.
3. Check `~/.ssh/authorized_keys` for the compromised account for any added keys.
4. Review `last` / `lastlog` on the target host for session duration and any concurrent logins.
5. Consider disabling password authentication in favor of key-based SSH if not already enforced.

## 7. Escalation criteria

Escalate immediately if:
- 100201 fired (successful login after brute force).
- The targeted account has elevated privileges.
- The source IP is linked to other active alerts (scan, malware, etc.) in the same time window.

## 8. Closing the alert

Document: source IP, targeted account(s), whether login succeeded, action taken, and whether the IP was blocked. If false positive, note the reason (known host, known job) so future analysts can recognize the pattern without re-investigating from scratch — consider adding the IP to an allowlist/exception if it's a legitimate recurring source.
