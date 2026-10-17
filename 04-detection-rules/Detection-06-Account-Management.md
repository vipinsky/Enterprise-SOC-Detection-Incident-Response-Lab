# Detection 06 — Account Management & Lifecycle

Windows/Linux account creation, account deletion, and account lifecycle correlation.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100501`, `100503`, `100510`, `100511`, `100512`, `100513`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100501` — group `windows,account_management,`

```xml
<group name="windows,account_management,">
  <rule id="100501" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4720$</field>
    <description>Windows local user account created: $(win.eventdata.targetUserName) by $(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
    <group>account_creation,persistence,</group>
  </rule>
</group>
```

### Rule `100503` — group `windows,account_management,`

```xml
<group name="windows,account_management,">
  <rule id="100503" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4726$</field>
    <description>Windows local user account deleted: $(win.eventdata.targetUserName) by $(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1531</id>
    </mitre>
    <group>account_deletion,anti_forensics,</group>
  </rule>
</group>
```

### Rule `100510` — group `linux,account_management,`

```xml
<group name="linux,account_management,">
  <rule id="100510" level="8">
    <if_sid>5902</if_sid>
    <description>Linux user account created: $(full_log)</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
    <group>account_creation,</group>
  </rule>
</group>
```

### Rule `100511` — group `linux,account_management,`

```xml
<group name="linux,account_management,">
  <rule id="100511" level="10">
    <if_sid>5902</if_sid>
    <match>sudo</match>
    <description>Linux user account created with elevated privileges: $(full_log)</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
    <group>account_creation,persistence,</group>
  </rule>
</group>
```

### Rule `100512` — group `linux,account_management,`

```xml
<group name="linux,account_management,">
  <rule id="100512" level="8">
    <if_sid>5903</if_sid>
    <description>Linux user account deleted: $(full_log)</description>
    <mitre>
      <id>T1531</id>
    </mitre>
    <group>account_deletion,</group>
  </rule>
</group>
```

### Rule `100513` — group `linux,account_management,`

```xml
<group name="linux,account_management,">
  <rule id="100513" level="13" timeframe="600">
    <if_sid>100512</if_sid>
    <if_matched_sid>100510</if_matched_sid>
    <description>Suspicious: Linux account created and deleted within 10 minutes - possible anti-forensic activity</description>
    <mitre>
      <id>T1531</id>
      <id>T1136.001</id>
    </mitre>
    <group>anti_forensics,account_lifecycle,</group>
  </rule>
</group>
```

## Source-rule note

Rule `100511` is labelled as account creation with elevated privileges, but the source XML matches text `sudo` after parent SID `5902`; validate with actual account-creation events before interpreting the alert as proof of sudo-group membership.

Rule `100513` is described as same-account creation/deletion within 10 minutes, but the supplied XML does not explicitly compare the account identity across events. Validate correlation behavior before relying on the description.
