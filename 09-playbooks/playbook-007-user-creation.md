# Playbook — Detection 007: New User Creation / Deletion

**Rules:** 100501 (Win create), 100503 (Win delete), 100510/100511 (Linux create), 100512 (Linux delete), 100513 (Linux create+delete anti-forensic)
**MITRE:** T1136.001, T1531
**Severity:** Medium–Critical depending on rule (100513 = Critical, level 13)
**Platform:** Windows and Linux

## 1. What triggered

A local user account was created and/or deleted; or the same account was created and deleted within a 10-minute window (100513 — anti-forensic pattern).

## 2. Immediate triage

1. Identify `subjectUserName`/creator and `targetUserName`/new account name.
2. Check against your change-management/ticketing system — was this account creation approved and documented?
3. If **100513** fired, treat as high priority immediately — legitimate account provisioning is essentially never followed by deletion within minutes.

## 3. True Positive indicators

- No corresponding change ticket/approval for the new account.
- Account created outside business hours.
- Account name follows a suspicious pattern (mimics a system account, uses a generic/throwaway name, or closely resembles an existing privileged account).
- Account immediately added to privileged groups (admin/sudo) after creation.
- 100513 fired — create+delete within 10 minutes, a classic anti-forensic/backdoor-testing pattern.
- Creator account itself was involved in a recent suspicious event (e.g., recent brute-force success, suspicious PowerShell).

## 4. False Positive indicators

- Creation matches an approved onboarding/provisioning ticket.
- Creator is a known identity-management service account (AD provisioning tool, HR system integration, Ansible/configuration-management run).
- Deletion (without rapid re-creation) matches an approved offboarding ticket.
- Account creation/deletion pair with a legitimate explanation — e.g., a documented test account cycle used by QA/IT for routine testing (confirm this is a known, recurring, approved pattern before closing as FP).

## 5. Investigation steps

```bash
# Linux
sudo grep -a "100510\|100511\|100512\|100513" /var/ossec/logs/alerts/alerts.json | tail -n 10

# Windows
sudo grep -a "100501\|100503" /var/ossec/logs/alerts/alerts.json | tail -n 10
```

Check what the creator account did immediately before and after:
```bash
sudo grep -a "<subjectUserName or srcuser>" /var/ossec/logs/alerts/alerts.json | tail -n 30
```

Check whether the new account was used to log in at all before deletion (if 100513 fired):
```bash
sudo grep -a "<targetUserName>" /var/ossec/logs/alerts/alerts.json | grep -a "authentication_success\|4624"
```

## 6. Containment (if confirmed malicious)

1. If the account still exists: disable it immediately (don't delete yet — preserve for forensics).
2. If already deleted: check backup/AD recycle bin for recovery of account details and any group memberships it held.
3. Investigate the creator account's full session — how did they gain the privilege to create an account? (Correlate with Detection 008 sudo abuse or a recent privilege escalation event.)
4. Check for any data access or further account creation by the suspicious new account during its lifetime.
5. Reset credentials for the creator account.

## 7. Escalation criteria

Escalate immediately if:
- 100513 fired (create+delete anti-forensic pattern).
- The new account was granted privileged access.
- No matching change-ticket exists and the creator is not a known automation identity.

## 8. Closing the alert

Document: creator identity, new account name, privileges granted (if any), change-ticket reference (if found), verdict, and remediation action (disabled/deleted/confirmed legitimate).
