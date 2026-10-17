# SOC Triage Playbooks — Index

Analyst-facing playbooks for each custom detection built in this lab. Each playbook follows the same structure so any analyst can pick one up and triage an alert consistently:

1. **What triggered** — rule logic in plain language
2. **Immediate triage** — first checks, under 5 minutes
3. **True Positive indicators** — concrete signals that this is real
4. **False Positive indicators** — concrete signals that this is benign, and why
5. **Investigation steps** — exact commands/dashboard queries to run
6. **Containment** — response actions if confirmed malicious
7. **Escalation criteria** — when to hand off beyond analyst-level triage
8. **Closing the alert** — what to document regardless of verdict

| File | Detection | Severity range |
|---|---|---|
| `playbook-002-brute-force.md` | SSH Brute Force + Success After Brute Force | Medium → Critical |
| `playbook-003-suspicious-powershell.md` | Suspicious PowerShell | Medium |
| `playbook-004-encoded-powershell.md` | Encoded PowerShell | High |
| `playbook-005-parent-child-process.md` | Suspicious Parent → Child Process | High |
| `playbook-006-port-scanning.md` | Port Scanning | High |
| `playbook-007-user-creation.md` | New User Creation / Deletion | Medium → Critical |
| `playbook-008-privilege-escalation.md` | Privilege Escalation / Sudo Abuse (tiered) | Low → High |
| `playbook-009-persistence.md` | Persistence (cron / scheduled task) | Medium → High |
| `playbook-010-network-activity.md` | Suspicious Network Activity / C2 Hunting | Low → Critical |

## How to use these

- Every playbook separates **True Positive** and **False Positive** indicators as parallel lists — an analyst should check both before reaching a verdict, not just look for reasons to confirm their first impression.
- Several playbooks flag a **known platform limitation** discovered during this lab's testing (e.g., Windows path-string spoofing in Detection 005, Linux's lack of destination-IP visibility in Detection 010). These are not bugs to "fix away" during triage — they are structural facts about what the detection can and cannot tell you, and should shape how much weight an analyst puts on an alert's absence as well as its presence.
- "Closing the alert" sections intentionally ask for the *reason* behind a false-positive verdict, not just the verdict itself — this is what allows future tuning (allowlisting a known source, adjusting a threshold) to be done deliberately rather than by gradually loosening detections out of alert fatigue.
