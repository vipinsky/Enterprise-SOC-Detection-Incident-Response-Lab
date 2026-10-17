# Detection 005 — Suspicious Account Creation

**Status:** Detection observed; authorization review required  
**Verdict:** Account-creation detections validated; unauthorized persistence not confirmed  
**Investigation date:** 17 October 2026  
**Analyst:** Vipin Kumar

## 1. Executive Summary
Wazuh detected local account creation activity on both Linux and Windows endpoints. The dashboard search `rule.id:(100501 OR 100510 OR 100511)` showed 20 hits in the selected last-week time range.

The supplied evidence identifies Linux accounts `testuser_basic` and `testuser_sudo`, and Windows accounts `testuser_win` and `testuser_ps`. The events were matched by custom rules `100510`, `100511`, and `100501` and mapped to MITRE ATT&CK `T1136.001 — Create Account: Local Account`.

The available evidence confirms account-creation events and alert generation. It does not prove that the accounts were unauthorized. In particular, the raw Linux `useradd` event for `testuser_sudo` does not show its group memberships or sudoers rights.

## 2. Lab Environment

| Field | Value |
|---|---|
| SIEM | Wazuh |
| Wazuh manager | `vm1` |
| Windows endpoint | `window10` — `192.168.34.148`, agent `002` |
| Linux endpoint | `ubuntu_vm2` — `192.168.34.143`, agent `001` |
| Windows event source | Security log, Event ID `4720` |
| Linux event source | `/var/log/auth.log`, `useradd` |
| Investigation date | 17 October 2026 |

## 3. Detection Rules

| Rule ID | Description | Alert level | Group/context |
|---|---|---:|---|
| `100501` | Windows local user account created | 10 | Windows account management / persistence |
| `100510` | Linux user account created | 8 | Linux account management / account creation |
| `100511` | Linux user account created with elevated privileges | 10 | Linux account management / account creation / persistence |

All three rules carry the MITRE ATT&CK mapping `T1136.001 — Create Account: Local Account`.

## 4. Findings

### Finding 1 — Linux account `testuser_basic`
- **Endpoint:** `ubuntu_vm2` — `192.168.34.143`, agent `001`
- **Rule:** `100510`, Level 8
- **Event time:** `2026-10-17 13:58:12.255546` (UTC+05:30)
- **Log:** `/var/log/auth.log`
- **UID/GID:** `1001` / `1001`
- **Home directory:** `/home/testuser_basic`
- **Shell:** `/bin/sh`
- **Raw event summary:** `useradd`: new user `testuser_basic`

**Assessment:** Linux account creation is confirmed. Authorization, subsequent login, group membership, and use are not established by this event.

### Finding 2 — Linux account `testuser_sudo`
- **Endpoint:** `ubuntu_vm2` — `192.168.34.143`, agent `001`
- **Rule:** `100511`, Level 10
- **Event time:** `2026-10-17 13:59:24.485296` (UTC+05:30)
- **Log:** `/var/log/auth.log`
- **UID/GID:** `1002` / `1002`
- **Home directory:** `/home/testuser_sudo`
- **Shell:** `/bin/bash`
- **Raw event summary:** `useradd`: new user `testuser_sudo`

**Assessment:** Account creation is confirmed, and rule `100511` classified it as account creation with elevated privileges. However, the raw event shown only proves that the account was created; it does not show sudo group membership or sudoers permissions. Verify actual privileges before describing this as confirmed privilege assignment.

### Finding 3 — Windows account `testuser_win`
- **Endpoint:** `window10` — `192.168.34.148`, agent `002`
- **Rule:** `100501`, Level 10
- **Windows event:** Security Event ID `4720` — A user account was created
- **Event time:** `2026-10-17 08:33:08.872 UTC` (approximately `14:03:08.872` UTC+05:30)
- **Wazuh alert timestamp:** `2026-10-17 08:33:10.667 UTC` (approximately `14:03:10.667` UTC+05:30)
- **Creator:** `vipin`
- **Created account:** `testuser_win`
- **Target SID:** ends in `-1006`
- **Event record ID:** `46579`

The supplied event text reports the account as disabled and includes a “Password Not Required” flag. Verify this state on the endpoint. A disabled account is not evidence of successful access, but “Password Not Required” is a setting that should be reviewed before the account is enabled.

### Finding 4 — Windows account `testuser_ps`
- **Endpoint:** `window10` — `192.168.34.148`, agent `002`
- **Rule:** `100501`, Level 10
- **Wazuh alert timestamp:** `2026-10-17 08:34:00.947 UTC` (approximately `14:04:00.947` UTC+05:30)
- **Creator:** `vipin`
- **Created account:** `testuser_ps`
- **Target SID:** ends in `-1007`
- **Windows event:** Security Event ID `4720`
- **Event record ID:** `46585` (from event details)

**Assessment:** Account creation is confirmed. Its authorization, enabled status, and group memberships have not been supplied.

## 5. Timeline

| Time (UTC+05:30) | Event | Rule |
|---|---|---|
| 17 Oct 2026, 13:58:12.255 | Linux account `testuser_basic` created | `100510` |
| 17 Oct 2026, 13:59:24.485 | Linux account `testuser_sudo` created | `100511` |
| 17 Oct 2026, 14:03:08.872 | Windows account `testuser_win` created | `100501` |
| 17 Oct 2026, 14:03:59.299 | Windows account `testuser_ps` created | `100501` |

Times above are event times where supplied. Wazuh indexed timestamps are slightly later and are retained in the raw alert data.

## 6. Dashboard Summary
- **Search expression:** `rule.id:(100501 OR 100510 OR 100511)`
- **Selected time range:** Last week
- **Displayed results:** 20 hits
- **MITRE chart:** Local Account
- **Agents in view:** `ubuntu_vm2`, `window10`, and `vm1`

The 20 hits are alert documents for the selected search, not necessarily 20 unique accounts. The screenshots show repeat account-creation detections, especially Linux account-creation events. Deduplicate before making unique-incident claims.

## 7. MITRE ATT&CK
**T1136.001 — Create Account: Local Account (Persistence)**

Adversaries may create local accounts to maintain access. This technique is relevant to investigating unexpected account creation, but routine administration and lab exercises can produce the same event. The ATT&CK mapping does not itself prove malicious intent.

## 8. Impact Assessment
**Confirmed**
- Account-creation telemetry was collected on Linux and Windows.
- Wazuh rules `100501`, `100510`, and `100511` generated alerts.
- Four specific account names are visible in the supplied alert evidence.

**Not confirmed**
- Whether the account creations were authorized.
- Whether `testuser_sudo` was actually granted sudo privileges.
- Whether any new account was subsequently used to log in.
- Whether the Windows accounts were enabled or added to privileged groups.
- Persistence, lateral movement, data theft, or full endpoint compromise.

## 9. Analyst Verdict
**Account-creation detections validated; authorization and privilege assignment require review.**

This is a useful SOC detection result because it identifies local account creation across Windows and Linux. Keep the case as “investigation required” until each account is matched to an approved administrative or lab action. Do not claim confirmed malicious persistence from these records alone.

## 10. Recommended Investigation
1. Confirm whether all four accounts were intentionally created during the lab.
2. On Linux, verify `testuser_sudo` group memberships and sudoers access; also review `/etc/passwd`, `/etc/group`, and subsequent SSH/authentication activity.
3. On Windows, check enabled status, local group membership, and related Security events for account enablement, password reset, and group membership changes.
4. Check the creator’s session and commands around each timestamp.
5. If an account is unauthorized, preserve relevant logs before disabling/removing it and follow your lab incident-response procedure.
6. Validate the custom Wazuh rule XML and test both authorized account creation and unexpected account creation.
7. Tune severity based on account name, creator, host role, group membership, and whether account creation was expected.

## 11. Limitations
The custom Wazuh rule XML was not supplied. The report therefore documents observed alerts rather than independently verifying the exact rule matching conditions. The Linux `useradd` log does not expose group membership. The Windows event text contains account-control labels that should be verified against the current endpoint state. The dashboard count covers selected search results and may include repeated events.

## 12. Conclusion
Wazuh detected account-creation activity on the Windows and Linux lab endpoints and produced alerts mapped to `T1136.001`. The available records confirm creation of `testuser_basic`, `testuser_sudo`, `testuser_win`, and `testuser_ps`, but they do not establish unauthorized access. Next, verify whether the accounts were expected, confirm actual group/privilege membership, and review subsequent account usage before closing the investigation.

## 13. Evidence Index
- `evidence/E01-account-creation-dashboard.png` — dashboard overview
- `evidence/E02-account-creation-alerts.png` — account-creation alert results
- `evidence/E03-linux-user-creation-elevated-rule.png` — Linux account creation with elevated-privilege rule description
- `evidence/E04-windows-user-creation-details.png` — Windows Security Event 4720 details
