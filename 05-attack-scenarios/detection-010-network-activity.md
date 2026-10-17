# Detection 010 — Suspicious Network Activity (C2 Hunting Foundation)

**Rules:** 100600–100605 (Windows), 100610–100613 (Linux)
**MITRE:** T1071 (Application Layer Protocol), T1571 (Non-Standard Port), T1568 (Dynamic Resolution), T1105 (Ingress Tool Transfer)
**Platform:** Windows (window10) and Linux (vm2)

## Investigation chain

```
Process → Destination → Port → Frequency → DNS
```

## Windows

### Prerequisite: netcat listener on vm1

```bash
nc -lvnk -p 4444
```
Leave running throughout testing (the `-k` flag is required to keep accepting connections — a plain `nc -lvnp` only accepts one and exits).

### Test Case W1: Suspicious location + port + frequency + composite (100601, 100602, 100603, 100605)

```powershell
Copy-Item "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" "$env:TEMP\svcupdate.exe"

1..6 | ForEach-Object {
    $client = New-Object System.Net.Sockets.TcpClient
    try { $client.Connect("192.168.34.145", 4444) } catch {}
    $client.Close()
    Start-Sleep -Seconds 10
}
```

**Expected sequence:**
- **100400** fires 6x (base connection events)
- **100601** fires (process in `%TEMP%`)
- **100602** fires (destination port 4444 — known C2-associated port)
- **100603** fires once 6 connections to the same IP land within 300 seconds (beaconing)
- **100605** fires as the composite (suspicious location AND beaconing together) — highest confidence

### Test Case W2: DNS to a low-reputation TLD (100600, 100604)

```powershell
Resolve-DnsName "suspicious-test-domain.xyz" -ErrorAction SilentlyContinue
Resolve-DnsName "another-test.top" -ErrorAction SilentlyContinue
```
**Expected:** **100604** fires for each (matches `.xyz`/`.top`).

### Negative Test W3: Normal process, normal destination

```powershell
Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing | Out-Null
```
**Expected:** only **100400** (base event) — no suspicious-location, port, or composite alert.

### Negative Test W4: Legitimate TLD

```powershell
Resolve-DnsName "microsoft.com" -ErrorAction SilentlyContinue
```
**Expected:** **100600** fires (base DNS event), but **100604** does not.

### Clean up
```powershell
Remove-Item "$env:TEMP\svcupdate.exe" -Force
```

## Linux

### Prerequisite

Confirm rule 100610 uses `<decoded_as>auditd</decoded_as>`, not `<if_group>audit_command</if_group>` — the latter silently fails for bare `connect()` events, which carry no EXECVE block.

### Test Case L1: Suspicious location + frequency + composite (100611, 100612, 100613)

```bash
cp /bin/nc /tmp/svcupdate
chmod +x /tmp/svcupdate
for i in {1..6}; do /tmp/svcupdate -w 2 -z 192.168.34.145 4444; sleep 10; done
```
**Expected:** **100610** (base, 6x), **100611** (suspicious `/tmp/` location), **100612** (frequency/beaconing by process), **100613** (composite).

### Negative Test L2: Normal process, normal location

```bash
curl -s http://example.com > /dev/null
```
**Expected:** only **100610** fires (if at all — `curl`'s connect behavior was unreliable in testing; re-confirm). No suspicious-location or composite alert.

### Clean up
```bash
rm /tmp/svcupdate
```

## Verification

```bash
sudo grep -a "100600\|100601\|100602\|100603\|100604\|100605\|100610\|100611\|100612\|100613" /var/ossec/logs/alerts/alerts.json | tail -n 25
```

## Dashboard check

```
rule.id: (100600 OR 100601 OR 100602 OR 100603 OR 100604 OR 100605 OR 100610 OR 100611 OR 100612 OR 100613)
```

## Summary table

| Test | Platform | Rules expected | Proves |
|---|---|---|---|
| W1 | Windows | 100400, 100601, 100602, 100603, 100605 | Full chain: process + port + frequency + composite |
| W2 | Windows | 100600, 100604 | DNS/TLD heuristic |
| W3 | Windows | 100400 only | Negative — normal traffic doesn't over-trigger |
| W4 | Windows | 100600 only | Negative — legitimate TLD doesn't trigger DNS rule |
| L1 | Linux | 100610, 100611, 100612, 100613 | Process + frequency + composite (no destination/port — documented gap) |
| L2 | Linux | 100610 only (if base fires) | Negative — normal process doesn't escalate |

## IMPORTANT — documented cross-platform gap

Linux achieves only **Process → Frequency** of the full chain. Destination IP and port are **not** reliably available from auditd's `connect()` syscall in this Wazuh version — the raw `SOCKADDR` record is hex-encoded and not parsed into structured fields (`daddr`/`dport` do not appear in the decoded event). DNS query logging was never built for Linux (no equivalent to Sysmon Event ID 22). This asymmetry — Windows via Sysmon offering clean structured network/DNS telemetry versus Linux via auditd requiring more effort for less precision — is a genuine, worthwhile finding for the writeup, not a flaw to hide.
