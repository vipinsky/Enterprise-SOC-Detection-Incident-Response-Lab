# Detection 09 — DNS, Network & C2 Hunting

Windows DNS/network heuristics and Linux audit-based outbound-connect telemetry.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100600`, `100601`, `100602`, `100603`, `100604`, `100605`, `100610`, `100611`, `100612`, `100613`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100600` — group `windows,sysmon,c2_hunting,`

```xml
<group name="windows,sysmon,c2_hunting,">
  <rule id="100600" level="3">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^22$</field>
    <description>Sysmon - DNS query event: $(win.eventdata.queryName)</description>
    <group>sysmon_dns,</group>
</rule>
</group>
```

### Rule `100601` — group `windows,sysmon,c2_hunting,`

```xml
<group name="windows,sysmon,c2_hunting,">
  <rule id="100601" level="11">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\|\\Users\\Public\\)</field>
    <description>Process in suspicious location initiated network connection: $(win.eventdata.image) -&gt; $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>suspicious_network_process,</group>
  </rule>
</group>
```

### Rule `100602` — group `windows,sysmon,c2_hunting,`

```xml
<group name="windows,sysmon,c2_hunting,">
  <rule id="100602" level="11">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.destinationPort" type="pcre2">^(4444|1337|8080|8443|9001|6666|31337|5555)$</field>
    <description>Network connection to known C2-associated port: $(win.eventdata.image) -&gt; $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
    <mitre>
      <id>T1571</id>
    </mitre>
    <group>suspicious_port,</group>
  </rule>
</group>
```

### Rule `100603` — group `windows,sysmon,c2_hunting,`

```xml
<group name="windows,sysmon,c2_hunting,">
  <rule id="100603" level="12" frequency="6" timeframe="300">
    <if_matched_sid>100400</if_matched_sid>
    <same_field>win.eventdata.image</same_field>
    <same_field>win.eventdata.destinationIp</same_field>
    <description>Possible C2 beaconing: repeated connections from $(win.eventdata.image) to $(win.eventdata.destinationIp)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>possible_beaconing,</group>
  </rule>
</group>
```

### Rule `100604` — group `windows,sysmon,c2_hunting,`

```xml
<group name="windows,sysmon,c2_hunting,">
  <rule id="100604" level="10">
    <if_sid>100600</if_sid>
    <field name="win.eventdata.queryName" type="pcre2">(?i)\.(top|xyz|tk|club|gq|ml|cf|biz)$</field>
    <description>DNS query to a low-reputation TLD commonly used for C2: $(win.eventdata.queryName)</description>
    <mitre>
      <id>T1568</id>
    </mitre>
    <group>suspicious_dns,</group>
</rule>
</group>
```

### Rule `100605` — group `windows,sysmon,c2_hunting,`

```xml
<group name="windows,sysmon,c2_hunting,">
  <rule id="100605" level="14" timeframe="300">
    <if_sid>100601</if_sid>
    <if_matched_sid>100603</if_matched_sid>
    <description>High confidence: suspicious process exhibiting beaconing behavior - likely C2</description>
    <mitre>
      <id>T1071</id>
      <id>T1105</id>
    </mitre>
    <group>c2_high_confidence,</group>
  </rule>
</group>
```

### Rule `100610` — group `linux,audit,c2_hunting,`

```xml
<group name="linux,audit,c2_hunting,">
  <rule id="100610" level="3">
    <if_group>audit_command</if_group>
    <field name="audit.key">audit-wazuh-net</field>
    <field name="audit.exe" type="pcre2">(?i)^(?!.*(wazuh-logcollector|sudo|systemd|gnome|sshd)).*$</field>
    <description>Linux - outbound connect() syscall: $(audit.exe)</description>
    <group>linux_network,</group>
  </rule>
</group>
```

### Rule `100611` — group `linux,audit,c2_hunting,`

```xml
<group name="linux,audit,c2_hunting,">
  <rule id="100611" level="11">
    <if_sid>100610</if_sid>
    <field name="audit.exe" type="pcre2">(?i)(/tmp/|/dev/shm/|/var/tmp/)</field>
    <description>Process in suspicious location initiated network connection: $(audit.exe)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>suspicious_network_process,</group>
  </rule>
</group>
```

### Rule `100612` — group `linux,audit,c2_hunting,`

```xml
<group name="linux,audit,c2_hunting,">
  <rule id="100612" level="12" frequency="6" timeframe="300">
    <if_matched_sid>100610</if_matched_sid>
    <same_field>audit.exe</same_field>
    <description>Possible C2 beaconing: repeated outbound connections from $(audit.exe)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>possible_beaconing,</group>
  </rule>
</group>
```

### Rule `100613` — group `linux,audit,c2_hunting,`

```xml
<group name="linux,audit,c2_hunting,">
  <rule id="100613" level="14" timeframe="300">
    <if_sid>100611</if_sid>
    <if_matched_sid>100612</if_matched_sid>
    <description>High confidence: suspicious Linux process exhibiting beaconing behavior - likely C2</description>
    <mitre>
      <id>T1071</id>
      <id>T1105</id>
    </mitre>
    <group>c2_high_confidence,</group>
  </rule>
</group>
```

## Validation notes

These rules use heuristic indicators (selected ports, file paths, TLDs, event frequency). Validate decoded fields and correlation behavior against your actual Sysmon and audit telemetry. A DNS query or repeated connection pattern is not, by itself, proof of command and control.
