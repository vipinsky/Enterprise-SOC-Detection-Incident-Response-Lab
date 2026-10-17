# Kali Linux — Attack Simulation Machine

**Role:** Attacker-simulation host used to generate realistic test traffic against the Windows and Ubuntu endpoints
**OS:** Kali Linux
**Not a Wazuh agent** — no Wazuh software installed here; this machine exists purely to drive attack scenarios that the monitored endpoints (and Wazuh) then detect.

## 1. Tools used in this project

Kali ships with `nmap` and `hydra` pre-installed by default. If missing on a minimal install:

```bash
sudo apt update
sudo apt install nmap hydra netcat-traditional -y
```

## 2. nmap — used for port-scan detection testing (Detection 006)

```bash
nmap -sS -T4 -p 1-1000 <target-ip> -v
```

- `-sS` — SYN stealth scan
- `-T4` — aggressive timing (ensures 15+ ports are probed well within the detection's 60-second correlation window)
- `-p 1-1000` — scans the first 1000 ports
- `-v` — verbose output

**Note:** against a fully firewalled target, this generates no completed connections and therefore no detectable events on the endpoint side (see `detection-006-port-scanning.md` for the full discussion and workaround).

## 3. hydra — used for SSH brute-force testing (Detection 002)

```bash
printf "wrongpass1\nwrongpass2\nwrongpass3\nwrongpass4\nwrongpass5\n" > passwords.txt
hydra -l <username> -P passwords.txt ssh://<vm2-ip> -t 1 -V
```

- `-l <username>` — target username (real or fake)
- `-P passwords.txt` — wordlist of (intentionally wrong) passwords
- `-t 1` — single thread, keeps timing realistic and avoids SSH connection throttling
- `-V` — verbose, shows each attempt

## 4. Manual SSH testing (Detection 002 — successful login after brute force)

```bash
ssh <username>@<vm2-ip>
```
Run immediately after a hydra run, from the same source IP, entering the correct password — this is what triggers the "successful login after brute force" escalation rule.

## 5. netcat — used for raw TCP connection testing (Detection 010 follow-up)

```bash
nc -w 2 -z <target-ip> <port>
```
Used to generate controlled outbound connection attempts for beaconing/frequency rule validation when testing Linux-side detections that don't depend on Kali directly (most of this testing was actually run from the endpoints themselves acting as the "compromised" host — see `detection-010-network-activity.md`).

## Summary of Kali's role per detection

| Detection | Kali's role |
|---|---|
| 002 — Brute Force | `hydra` generates failed SSH logins; manual `ssh` generates the subsequent successful login |
| 006 — Port Scanning | `nmap` generates the scan traffic against both Windows and Linux endpoints |
| Others (003–005, 007–010) | Simulated directly on the endpoints themselves (PowerShell abuse, user management, sudo abuse, persistence, network beaconing) rather than from Kali, since those behaviors represent post-compromise activity on a host, not externally-driven attacks |

## Notes for writeup

Kali's role in this project is deliberately narrow — it represents the external attacker for the two detections that are genuinely network-facing (brute force, port scanning). The remaining eight detections simulate **post-compromise** attacker behavior (what an attacker does *after* gaining a foothold: PowerShell abuse, privilege escalation, persistence, C2 beaconing), which is realistically generated on the endpoint itself rather than from an external scanning host.
