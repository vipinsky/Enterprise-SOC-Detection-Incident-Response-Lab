# Detection 08 — Persistence: Cron & Scheduled Tasks

Linux cron-file changes and Windows scheduled-task creation/content.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100530`, `100531`, `100532`, `100533`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100530` — group `linux,persistence,cron,`

```xml
<group name="linux,persistence,cron,">
  <rule id="100530" level="10">
    <if_group>syscheck</if_group>
    <field name="file" type="pcre2">(?i)(/etc/cron\.d/|/etc/crontab|/var/spool/cron/crontabs/)</field>
    <description>Persistence: cron job file modified - path=$(file) user=$(audit.user.name)</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
    <group>persistence_cron,</group>
  </rule>
</group>
```

### Rule `100531` — group `linux,persistence,cron,`

```xml
<group name="linux,persistence,cron,">
  <rule id="100531" level="12">
    <if_sid>100530</if_sid>
    <field name="changed_attributes" type="pcre2">(?i)added|new</field>
    <description>Persistence: NEW cron job created - path=$(file) user=$(audit.user.name)</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
    <group>persistence_cron,new_cron,</group>
  </rule>
</group>
```

### Rule `100532` — group `windows,persistence,scheduled_task,`

```xml
<group name="windows,persistence,scheduled_task,">
  <rule id="100532" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4698$</field>
    <description>Persistence: Windows scheduled task created - task=$(win.eventdata.taskName) creator=$(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
    <group>persistence_scheduled_task,</group>
  </rule>
</group>
```

### Rule `100533` — group `windows,persistence,scheduled_task,`

```xml
<group name="windows,persistence,scheduled_task,">
  <rule id="100533" level="12">
    <if_sid>100532</if_sid>
    <field name="win.eventdata.taskContent" type="pcre2">(?i)(powershell|cmd\.exe|wscript|cscript|mshta)</field>
    <description>Persistence: scheduled task runs a scripting engine - task=$(win.eventdata.taskName) command visible in task content</description>
    <mitre>
      <id>T1053.005</id>
      <id>T1059</id>
    </mitre>
    <group>persistence_scheduled_task,suspicious_task_content,</group>
  </rule>
</group>
```

## Validation notes

Rule `100531` depends on the `changed_attributes` field matching `added` or `new`; check that your Wazuh syscheck alert exposes the field with these values.
