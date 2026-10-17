# Detection 002 — SSH Brute Force & Successful Login After Brute Force

**Rules:** 100200 (brute force), 100201 (successful login after brute force)
**MITRE:** T1110 (Brute Force), T1078 (Valid Accounts)
**Platform:** Linux (vm2)

## Logic

```
Failed authentication
       ↓
5+ failures in 180s, same source IP
       ↓
Successful authentication from same IP within 300s
       ↓
Rule 100201 — HIGH SEVERITY (level 14)
```

## Prerequisite

Base SSH-failure rule confirmed as **5760** (not the assumed 5716) via `wazuh-logtest` — always confirm your own base rule ID before testing, since it varies by Wazuh version.

## Test Case 1: Brute force simulation with Hydra

From the attacking machine (Kali), **not** vm2 itself:

```bash
printf "wrongpass1\nwrongpass2\nwrongpass3\nwrongpass4\nwrongpass5\n" > passwords.txt
hydra -l youruser -P passwords.txt ssh://<vm2-ip> -t 1 -V
```

- `-l youruser`: real or fake username on vm2
- `-P passwords.txt`: wordlist of wrong passwords
- `-t 1`: one thread (realistic, avoids SSH throttling)
- `-V`: verbose, shows each attempt

**Expected:** rule **100200** fires after the 5th failed attempt within 180 seconds, same source IP.

## Test Case 2: Successful login after brute force (the escalation)

Immediately after Test Case 1, from the **same machine**:

```bash
ssh youruser@<vm2-ip>
```
Enter the correct password this time.

**Expected:** rule **100201** fires (level 14) — "Successful SSH login after brute force attempt - possible compromised credential."

## Negative Test: Failures below threshold should not escalate

```bash
ssh wronguser@<vm2-ip>
# wrong password, 2 attempts only
```

**Expected:** base failure alerts (5760) fire, but **100200 does not** — confirms the frequency/timeframe threshold (5 in 180s) is respected, not a hair-trigger.

## Verification

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -a --line-buffered -E "100200|100201"
```

```bash
sudo grep -a "100200\|100201" /var/ossec/logs/alerts/alerts.json | tail -n 10
```

## Dashboard check

Threat Hunting → Events, agent vm2, search:
```
rule.id: (100200 OR 100201)
```

## Notes for writeup

- `same_source_ip` ties the failures and the eventual success together — a failed attempt from attacker A does not combine with a legitimate login from user B.
- The composite rule (100201) is deliberately much higher severity than the raw brute-force alert (100200), since a successful login after a brute force is far more serious than failed attempts alone.
- Common pitfalls hit during testing: using the wrong base rule ID (5716 assumed vs. 5760 actual — always confirm via logtest), and forgetting `timeframe` must be placed as a rule *attribute*, not a child XML tag.
