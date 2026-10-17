# Detection 10 — Windows Process Visibility

Notepad, Microsoft Store/UWP application launch telemetry, and general Sysmon process creation.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100120`, `100100`, `100101`, `100102`, `100700`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100120` — group `local,windows,sysmon,`

```xml
<group name="local,windows,sysmon,">
  <rule id="100120" level="5">
    <decoded_as>windows_eventchannel</decoded_as>
    <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.originalFileName">^NOTEPAD\.EXE$</field>
    <description>Sysmon: Notepad process created on Windows endpoint</description>
  </rule>
</group>
```

### Rule `100100` — group `local,windows,sysmon,`

```xml
<group name="local,windows,sysmon,">
<rule id="100100" level="8">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)notepad\.exe</field>
    <description>Notepad executed</description>
  </rule>
</group>
```

### Rule `100101` — group `local,windows,sysmon,`

```xml
<group name="local,windows,sysmon,">
  <rule id="100101" level="5">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)WindowsApps</field>
    <description>Windows Store app opened: $(win.eventdata.originalFileName)</description>
  </rule>
</group>
```

### Rule `100102` — group `local,windows,sysmon,`

```xml
<group name="local,windows,sysmon,">
  <rule id="100102" level="5">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)WinStore\.App\.exe</field>
    <description>Microsoft Store application opened</description>
  </rule>
</group>
```

### Rule `100700` — group `windows,sysmon,process_visibility,`

```xml
<group name="windows,sysmon,process_visibility,">
  <rule id="100700" level="3">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^1$</field>
    <description>Sysmon - Process creation event: $(win.eventdata.image)</description>
    <group>sysmon_process,</group>
  </rule>
</group>
```
