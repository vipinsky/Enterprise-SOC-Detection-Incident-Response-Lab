# Detection 01 — SSH Authentication & Brute Force

SSH authentication failure examples, repeated SSH failures, and a successful login following a brute-force alert.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100001`, `100200`, `100201`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100001` — group `local,syslog,sshd,`

```xml
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
```

### Rule `100200` — group `syslog,sshd,`

```xml
<group name="syslog,sshd,">
  <rule id="100200" level="10" frequency="5" timeframe="180" ignore="180">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>Multiple SSH authentication failures from same source - possible brute force</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>
</group>
```

### Rule `100201` — group `syslog,sshd,`

```xml
<group name="syslog,sshd,">
      <rule id="100201" level="14" timeframe="300">
    <if_sid>5715</if_sid>
    <if_matched_sid>100200</if_matched_sid>
    <same_source_ip />
    <description>Successful SSH login after brute force attempt - possible compromised credential</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,brute_force_success,</group>
  </rule>
</group>
```

## Source-specific note

Rule `100001` is the supplied example rule for source IP `1.1.1.1`; it is not a generic rule for all SSH sources unless that IP condition is changed.
