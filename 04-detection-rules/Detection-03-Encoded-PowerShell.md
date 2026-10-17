# Detection 03 — Encoded PowerShell

PowerShell encoded-command indicators.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100301`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100301` — group `sysmon,powershell,`

```xml
<group name="sysmon,powershell,">
  <rule id="100301" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell(_ise)?\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc(odedcommand)?\s|-e\s+[a-z0-9+/=]{20,})</field>
    <description>Encoded PowerShell command detected: $(win.eventdata.commandLine)</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
    <group>suspicious_powershell,encoded_command,</group>
  </rule>
</group>
```
