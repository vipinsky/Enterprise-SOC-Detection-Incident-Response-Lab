# Detection 02 — Suspicious PowerShell

Command-line indicators for suspicious PowerShell execution.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100300`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100300` — group `sysmon,powershell,`

```xml
<group name="sysmon,powershell,">
  <rule id="100300" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell(_ise)?\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-nop\b|-noprofile|-w(indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass|downloadstring|downloadfile|invoke-expression|\biex\b|-sta\b|iwr\b)</field>
    <description>Suspicious PowerShell execution: $(win.eventdata.commandLine)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>suspicious_powershell,</group>
  </rule>
</group>
```
