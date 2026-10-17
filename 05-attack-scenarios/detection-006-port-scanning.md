# Detection 006 — Port Scanning

**Rules:** 100400/100401 (Windows), 100620/100621 (Linux, UFW-based follow-up)
**MITRE:** T1046 (Network Service Discovery)
**Platform:** Windows (window10) and Linux (vm2)

## Logic

```
One source
  +
Many destination ports
  +
Short time period
  =
Possible port scan
```

Windows: `frequency="15" timeframe="60"` + `same_source_ip` + `different_dst_port` on top of Sysmon Event ID 3 (network connection).

## Test Case A: Scan the Windows endpoint

### Step 1 — temporarily disable the Windows Firewall (Administrator)

```powershell
netsh advfirewall set allprofiles state off
```

### Step 2 — scan from Kali

```bash
nmap -sS -T4 -p 1-1000 192.168.34.139 -v
```

### Step 3 — re-enable the firewall immediately

```powershell
netsh advfirewall set allprofiles state on
```

### Step 4 — verify

```bash
sudo grep -a "100401" /var/ossec/logs/alerts/alerts.json | tail -n 3
sudo grep -a "100400" /var/ossec/logs/alerts/alerts.json | wc -l
```

**Expected:** rule **100401** fires once 15+ distinct destination ports are hit within 60 seconds from the same source IP.

## IMPORTANT — why a firewall-off step is needed

A stealth SYN scan (`-sS`) against a properly firewalled host is **silently dropped** before Sysmon/auditd ever logs it ("All 1000 scanned ports... filtered, no-response" in nmap's own output). No TCP handshake completes, so no Event ID 3 is generated. Disabling the firewall for the test is what makes the traffic visible to the detection layer at all — this is a genuine constraint of host-based (not firewall-log-based) scan detection.

## Test Case B: Scan the Linux endpoint (vm2) — documents a real coverage gap

### Step 1 — check UFW status

```bash
sudo ufw status
```
If active, disable for the test:
```bash
sudo ufw disable
```

### Step 2 — scan from Kali

```bash
nmap -sS -T4 -p 1-1000 192.168.34.143 -v
```

### Step 3 — re-enable UFW

```bash
sudo ufw enable
```

### Step 4 — confirm the gap

```bash
sudo grep -a "100610\|100611\|100612\|100613" /var/ossec/logs/alerts/alerts.json | tail -n 5
```

**Expected result: no match.** This is a legitimate finding, not a test failure — the existing Linux network rules (100610–100613) are built on auditd's `connect()` syscall, which only captures **outbound** connections initiated by vm2 itself. An inbound scan from Kali is never seen by that detection path.

## Fix: inbound scan detection via UFW logging (follow-up build)

```bash
sudo ufw logging on
```

Add a localfile block if missing:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ufw.log</location>
</localfile>
```

Candidate rules (decoder name must be confirmed via `wazuh-logtest` with a real UFW log line before trusting):
```xml
<group name="linux,ufw,port_scan,">
  <rule id="100620" level="5">
    <decoded_as>ufw</decoded_as>
    <match>BLOCK</match>
    <description>UFW blocked an inbound connection attempt</description>
    <group>ufw_block,</group>
  </rule>

  <rule id="100621" level="12" frequency="15" timeframe="60">
    <if_matched_sid>100620</if_matched_sid>
    <same_source_ip />
    <different_dst_port />
    <description>Possible inbound port scan detected via UFW: multiple ports blocked from same source</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>port_scan,recon,</group>
  </rule>
</group>
```

Re-run the scan with UFW **enabled** this time to validate.

## Summary table

| Target | Method | Result | Demonstrates |
|---|---|---|---|
| Windows | Firewall off + nmap | 100401 fires | Sysmon-based detection works once traffic reaches the OS |
| Linux (current rules) | nmap with firewall active or inactive | No alert | Documented gap: outbound-only auditd visibility |
| Linux (UFW fix) | UFW enabled + logging, nmap scan | 100621 fires (pending decoder confirmation) | Correct inbound detection via firewall logs |
