# Detection 007 — New User Creation (and Deletion)

**Rules:** 100510/100511 (Linux create), 100512 (Linux delete), 100513 (Linux create+delete anti-forensic), 100501 (Windows create, Event 4720), 100503 (Windows delete, Event 4726)
**MITRE:** T1136.001 (Create Account: Local Account), T1531 (Account Access Removal)
**Platform:** Linux (vm2) and Windows (window10)

## Linux — User Creation (100510, 100511)

### Test Case 1: Basic user creation

```bash
sudo useradd testuser_basic
```
**Expected:** rule **100510** fires.

### Test Case 2: Creation with elevated/sudo context

```bash
sudo useradd -m -s /bin/bash testuser_sudo
```
**Expected:** **100510** + **100511** fire together (100511 matches "sudo" in the log line).

### Negative Test: Group modification is not account creation

```bash
sudo usermod -aG sudo testuser_basic
```
**Expected:** does not trigger 100510/100511 — falls under a different built-in rule group (`addgroup_groupmod`), confirming creation-specific scoping.

Clean up:
```bash
sudo userdel testuser_basic
sudo userdel testuser_sudo
```

## Linux — User Deletion and Anti-Forensic Pattern (100512, 100513)

### Test Case 3: Deletion

```bash
sudo userdel testuser_basic
```
**Expected:** rule **100512** fires.

### Test Case 4: Create + delete within 10 minutes (anti-forensic signal)

```bash
sudo useradd testuser_temp
sleep 2
sudo userdel testuser_temp
```
**Expected:** **100510** fires on creation, **100512** on deletion, and **100513** fires as the composite — "Suspicious: Linux account created and deleted within 10 minutes."

## Windows — User Creation (100501, Event 4720)

### Prerequisite

```powershell
auditpol /get /subcategory:"User Account Management"
```
Enable if not already:
```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```

### Test Case 5: Basic account creation

```powershell
net user testuser_win Passw0rd123! /add
```
**Expected:** rule **100501** fires.

### Test Case 6: Creation via PowerShell cmdlet (alternate tooling, same event)

```powershell
New-LocalUser -Name "testuser_ps" -Password (ConvertTo-SecureString "Passw0rd123!" -AsPlainText -Force) -FullName "Test PS User"
```
**Expected:** also fires **100501** — confirms detection catches the underlying Security event (4720) regardless of which tool created the account.

### Negative Test: Account state change is not creation

```powershell
net user testuser_win /active:no
```
**Expected:** no 100501 alert — this generates a different event (account disabled), not 4720.

## Windows — User Deletion (100503, Event 4726)

### Test Case 7: Deletion

```powershell
net user testuser_win /delete
net user testuser_ps /delete
```
**Expected:** rule **100503** fires for each.

## Verification

```bash
sudo grep -a "100501\|100503\|100510\|100511\|100512\|100513" /var/ossec/logs/alerts/alerts.json | tail -n 20
```

## Dashboard check

```
rule.id: (100501 OR 100503 OR 100510 OR 100511 OR 100512 OR 100513)
```

## Notes for writeup

Test Case 6 (PowerShell cmdlet vs. `net user`) is deliberate validation that the detection is tied to the underlying security event, not one specific command-line syntax — a real attacker might use any of several tools (PowerShell, `net.exe`, direct API calls) to create an account, and a rule tied to one tool's syntax would miss the others.
