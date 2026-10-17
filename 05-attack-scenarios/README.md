# Detection Test Cases — Index

Test cases for each custom Wazuh detection built in this lab (Windows 10 + Ubuntu endpoints, Kali as attacker).

| File | Detection | Platform | Rule IDs |
|---|---|---|---|
| `detection-002-brute-force.md` | SSH Brute Force + Successful Login After Brute Force | Linux | 100200, 100201 |
| `detection-003-suspicious-powershell.md` | Suspicious PowerShell | Windows | 100300 |
| `detection-004-encoded-powershell.md` | Encoded PowerShell | Windows | 100301 |
| `detection-005-parent-child-process.md` | Suspicious Parent → Child Process | Windows | 100302, 100303, 100304 |
| `detection-006-port-scanning.md` | Port Scanning | Windows + Linux | 100400, 100401, 100620*, 100621* |
| `detection-007-user-creation.md` | New User Creation / Deletion | Windows + Linux | 100501, 100503, 100510–100513 |
| `detection-008-privilege-escalation.md` | Privilege Escalation / Sudo Abuse (tiered) | Linux | 100520–100525 |
| `detection-009-persistence.md` | Persistence (cron / scheduled task) | Linux + Windows | 100530, 100531, 100532, 100533 |
| `detection-010-network-activity.md` | Suspicious Network Activity / C2 Hunting | Windows + Linux | 100600–100605, 100610–100613 |

\* follow-up rules sketched but not yet fully validated — see file for details.

Each file includes: rule logic, step-by-step test commands, expected results, at least one negative test (proving the rule doesn't over-alert), verification commands, dashboard search queries, and notes for the project writeup.
