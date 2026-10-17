# Detection 07 — Sudo & Privilege Escalation

Sudo activity visibility, command watchlists, root-shell patterns, shell escapes, download/execute indicators, and repeated sudo failures.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100520`, `100521`, `100522`, `100523`, `100524`, `100525`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100520` — group `linux,sudo,privilege_escalation,`

```xml
<group name="linux,sudo,privilege_escalation,">
  <rule id="100520" level="5">
    <if_sid>5402</if_sid>
    <description>Sudo command executed: user=$(dstuser) command=$(full_log)</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
    <group>sudo_activity,</group>
  </rule>
</group>
```

### Rule `100521` — group `linux,sudo,privilege_escalation,`

```xml
<group name="linux,sudo,privilege_escalation,">
  <rule id="100521" level="9">
    <if_sid>100520</if_sid>
    <match>visudo|passwd|/etc/shadow|/etc/sudoers|usermod|chmod 777|chown root|crontab|systemctl|/etc/passwd</match>
    <description>Sudo used with a sensitive/high-risk command: $(full_log)</description>
    <mitre>
      <id>T1548.003</id>
      <id>T1078</id>
    </mitre>
    <group>sudo_watchlist,</group>
  </rule>
</group>
```

### Rule `100522` — group `linux,sudo,privilege_escalation,`

```xml
<group name="linux,sudo,privilege_escalation,">
  <rule id="100522" level="12">
    <if_sid>100520</if_sid>
    <match>sudo su|sudo bash|sudo sh |sudo -i|sudo -s|/bin/bash$|/bin/sh$</match>
    <description>Sudo used to spawn interactive root shell - review for legitimacy: $(full_log)</description>
    <mitre>
      <id>T1548.003</id>
      <id>T1059.004</id>
    </mitre>
    <group>sudo_shell_spawn,</group>
  </rule>
</group>
```

### Rule `100523` — group `linux,sudo,privilege_escalation,`

```xml
<group name="linux,sudo,privilege_escalation,">
  <rule id="100523" level="12">
    <if_sid>100520</if_sid>
    <match>vim -c|awk 'BEGIN|perl -e|python -c|find / -exec|nmap --interactive</match>
    <description>Sudo used with a known shell-escape pattern (GTFOBins-style): $(full_log)</description>
    <mitre>
      <id>T1548.003</id>
      <id>T1059</id>
    </mitre>
    <group>sudo_gtfobins,</group>
  </rule>
</group>
```

### Rule `100524` — group `linux,sudo,privilege_escalation,`

```xml
<group name="linux,sudo,privilege_escalation,">
  <rule id="100524" level="13">
    <if_sid>100520</if_sid>
    <match>curl.*\|.*sh|wget.*\|.*sh|curl.*-o.*&amp;&amp;|nc -e|/dev/tcp/</match>
    <description>Sudo used with download-and-execute or reverse shell pattern: $(full_log)</description>
    <mitre>
      <id>T1548.003</id>
      <id>T1105</id>
    </mitre>
    <group>sudo_download_exec,</group>
  </rule>
</group>
```

### Rule `100525` — group `linux,sudo,privilege_escalation,`

```xml
<group name="linux,sudo,privilege_escalation,">
  <rule id="100525" level="10" frequency="3" timeframe="120">
    <if_matched_sid>5403</if_matched_sid>
    <same_source_ip />
    <description>Multiple sudo authentication failures from same source - possible privilege escalation attempt</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
    <group>sudo_failures,</group>
</rule>
</group>
```

## Validation notes

Rule `100525` uses `<same_source_ip />` for sudo authentication failures. Check that the source event has a meaningful source IP and test the correlation using actual decoded events.
