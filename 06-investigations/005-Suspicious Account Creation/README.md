# Detection 005 — Suspicious Account Creation

## Overview
This SOC lab documents Wazuh detections for account creation on Linux and Windows endpoints. Account creation can be legitimate administration, but unexpected accounts may be used for persistence or unauthorized access.

**Observed result:** The Wazuh dashboard search for rules `100501`, `100510`, and `100511` displayed 20 hits in the selected last-week range.

## Environment
| Component | Value |
|---|---|
| SIEM | Wazuh |
| Manager | `vm1` |
| Windows endpoint | `window10`, agent `002`, `192.168.34.148` |
| Linux endpoint | `ubuntu_vm2`, agent `001`, `192.168.34.143` |
| Windows telemetry | Security Event ID `4720` (user account created) |
| Linux telemetry | `/var/log/auth.log`, `useradd` records |
| Investigation date | 17 October 2026 |

## Detection rules
| Rule ID | Description | Level in supplied evidence | MITRE |
|---|---|---:|---|
| `100501` | Windows local user account created | 10 | `T1136.001` — Local Account |
| `100510` | Linux user account created | 8 | `T1136.001` — Local Account |
| `100511` | Linux user account created with elevated privileges | 10 | `T1136.001` — Local Account |

## Confirmed observations
- Linux account `testuser_basic` was created with UID/GID `1001`, home `/home/testuser_basic`, and shell `/bin/sh`. Rule `100510` generated a Level 8 alert.
- Linux account `testuser_sudo` was created with UID/GID `1002`, home `/home/testuser_sudo`, and shell `/bin/bash`. Rule `100511` generated a Level 10 alert with a description indicating elevated privileges. The underlying `useradd` event does **not** show group membership or sudoers configuration, so elevated privileges must be independently verified.
- Windows account `testuser_win` was created by `vipin`; rule `100501` generated a Level 10 alert based on Security Event ID `4720`.
- Windows account `testuser_ps` was also created by `vipin`; a further rule `100501` alert was observed.
- The supplied Windows Event 4720 for `testuser_win` reports the account as disabled and includes a “Password Not Required” flag. This is a security-relevant configuration to validate, but the supplied evidence does not prove the account was enabled or used.
- The dashboard shows 20 search hits in the selected time range. Treat this as matching alert documents, not automatically 20 unique users or incidents.

## MITRE ATT&CK
- `T1136.001 — Create Account: Local Account` (Persistence).

The mapping categorizes the behavior. Account creation itself is not proof of malicious persistence.

## Analyst verdict
**Account-creation detections validated; authorization and account configuration require review.**

The telemetry confirms that Linux and Windows account-creation events were collected and matched by Wazuh rules. The evidence does not establish that the accounts were unauthorized. It also does not independently prove that `testuser_sudo` had sudo privileges.

## Investigation checklist
1. Confirm that `testuser_basic`, `testuser_sudo`, `testuser_win`, and `testuser_ps` were deliberately created for the lab.
2. On Linux, verify groups and privileges for `testuser_sudo` (for example, `id testuser_sudo`, `getent group sudo`, and the relevant sudoers configuration).
3. On Windows, check whether each account is enabled and whether it belongs to local Administrators or other sensitive groups. Review related Security events for account enablement, password changes, and group membership changes.
4. Review who created each account, the session/terminal, surrounding authentication events, and any commands executed afterward.
5. Disable or remove only accounts confirmed to be unauthorized, after preserving evidence and following the lab response process.
6. Test expected admin account creation to identify false positives and tune rule severity using account context and group membership where available.

## Evidence files
- `evidence/E01-account-creation-dashboard.png`
- `evidence/E02-account-creation-alerts.png`
- `evidence/E03-linux-user-creation-elevated-rule.png`
- `evidence/E04-windows-user-creation-details.png`

## Limitations
The custom rule XML was not supplied. The report records observed Wazuh alerts and source event fields but does not independently validate every rule condition. The Linux `useradd` event alone cannot prove elevated privileges. The Windows event shows account creation attributes but not later use, enablement, or group membership. The dashboard count reflects its selected time range and search expression.

