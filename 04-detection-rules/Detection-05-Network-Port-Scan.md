# Detection 05 — Network Connection & Port Scan

Base Sysmon network-connection telemetry and repeated connections across destination ports.

> The XML rule blocks below are copied from the supplied `local_rules.xml` text. The inner `<rule>...</rule>` blocks are preserved; each is shown within its original `<group name="...">` context so it can be identified and reused.

## Rule IDs

`100400`, `100401`

## Manual Wazuh Rules

Copy the required block into your Wazuh rules file. If several blocks use the same group, preserve valid XML group structure when combining them. Back up `local_rules.xml` and validate before restarting the manager.

### Rule `100400` — group `sysmon,network,`

```xml
<group name="sysmon,network,">
  <rule id="100400" level="3">
    <if_group>sysmon_event3</if_group>
    <description>Sysmon - Network connection event</description>
    <group>sysmon_network,</group>
  </rule>
</group>
```

### Rule `100401` — group `sysmon,network,`

```xml
<group name="sysmon,network,">
  <rule id="100401" level="12" frequency="15" timeframe="60">
    <if_matched_sid>100400</if_matched_sid>
    <same_source_ip />
    <different_dst_port />
    <description>Possible port scan: multiple destination ports from $(srcip) in short time</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>port_scan,recon,</group>
  </rule>
</group>
```
