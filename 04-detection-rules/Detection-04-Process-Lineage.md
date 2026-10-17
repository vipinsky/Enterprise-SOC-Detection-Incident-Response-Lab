# Detection 04 — Suspicious Parent–Child Process Lineage

Office, browser, or PDF reader spawning a shell or scripting engine.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100302`, `100303`, `100304`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100302` — group `sysmon,process_lineage,`

```xml
<group name="sysmon,process_lineage,">
  <rule id="100302" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)(winword|excel|powerpnt|outlook|mspub|visio)\.exe</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32|certutil)\.exe</field>
    <description>Office application spawned a scripting/shell process: $(win.eventdata.parentImage) -&gt; $(win.eventdata.image)</description>
    <mitre>
      <id>T1566.001</id>
      <id>T1059</id>
    </mitre>
    <group>suspicious_lineage,office_spawn,</group>
  </rule>
</group>
```

### Rule `100303` — group `sysmon,process_lineage,`

```xml
<group name="sysmon,process_lineage,">
  <rule id="100303" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)(chrome|firefox|msedge|iexplore)\.exe</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(powershell|cmd|wscript|cscript|mshta)\.exe</field>
    <description>Browser spawned a scripting/shell process: $(win.eventdata.parentImage) -&gt; $(win.eventdata.image)</description>
    <mitre>
      <id>T1059</id>
    </mitre>
    <group>suspicious_lineage,browser_spawn,</group>
  </rule>
</group>
```

### Rule `100304` — group `sysmon,process_lineage,`

```xml
<group name="sysmon,process_lineage,">
  <rule id="100304" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)(acrord32|acrobat|foxitreader)\.exe</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(powershell|cmd|wscript|cscript|mshta)\.exe</field>
    <description>PDF reader spawned a scripting/shell process: $(win.eventdata.parentImage) -&gt; $(win.eventdata.image)</description>
    <mitre>
      <id>T1059</id>
    </mitre>
    <group>suspicious_lineage,pdf_spawn,</group>
  </rule>
</group>
```
