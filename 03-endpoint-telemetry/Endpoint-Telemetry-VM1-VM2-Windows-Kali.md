# Endpoint Telemetry Plan — Wazuh SOC Home Lab

**Project:** Enterprise SOC Detection & Incident Response Lab  
**SIEM:** Wazuh  
**Systems covered:** VM1 (Wazuh server), VM2 (Ubuntu endpoint), Windows endpoint, Kali Linux (lab test/source host)  
**Purpose:** Document what telemetry each system should generate, how Wazuh collects it, how to verify collection, and how the data supports the custom detections in this repository.

> **Evidence note:** Items marked **Observed in supplied alerts** were visible in the Wazuh screenshots/logs shared for this project. Items marked **Recommended / verify** are suggested telemetry or configuration and should not be claimed as enabled until checked on the live VMs.

---

## 1. Lab Topology

| System | Role | Wazuh status from supplied evidence | IP / Agent ID seen |
|---|---|---|---|
| **VM1 — Ubuntu** | Wazuh manager, indexer, dashboard; central alerting and search | Manager name `vm1` appears in Wazuh alert records. The user previously reported manager, indexer, and dashboard installed. | Manager IP not provided; do not publish a guessed value |
| **VM2 — Ubuntu** | Linux endpoint for authentication, sudo, account-management, and cron/FIM tests | **Observed in supplied alerts** | `ubuntu_vm2`, agent `001`, `192.168.34.143` |
| **Windows 10** | Windows endpoint for Sysmon, PowerShell, account and scheduled-task detections | **Observed in supplied alerts** | `window10`, agent `002`; IPs `192.168.34.148` and `192.168.34.152` appear in different records |
| **Kali Linux** | Authorized lab testing/source host for generating controlled activity | Kali is used in the lab. The evidence does not confirm that a Wazuh agent is installed on Kali. | `192.168.34.138` appeared as an SSH source in VM2 logs; confirm this is still Kali’s IP |

### IP-address note

Windows was recorded with both `192.168.34.148` and `192.168.34.152`. This may reflect DHCP changes, a network-interface change, or older events. Verify the current IP and retain timestamps when correlating events.

---

## 2. Telemetry Summary

| Source / system | Telemetry | Main fields / evidence | Detection categories supported |
|---|---|---|---|
| VM1 Wazuh server | Wazuh manager service logs and alert processing | `ossec.log`, agent status, rule ID, level, groups, timestamps | Platform health, ingestion troubleshooting, alert review |
| VM2 Ubuntu | `/var/log/auth.log` | SSH failed/successful logins, sudo commands, user creation events | Brute force, sudo activity, account management |
| VM2 Ubuntu | Wazuh FIM (`syscheck`) on cron paths | File path, event (added/modified/deleted), file size, owner, hashes | Cron persistence |
| VM2 Ubuntu | `auditd` / audit events, if configured | Executable, syscall/action, UID, audit key | Optional outbound-connection/process auditing |
| Windows | Sysmon Event ID 1 | Process image, command line, parent image, process GUID/PID, user, hashes | Suspicious PowerShell, encoded PowerShell, process lineage |
| Windows | Sysmon Event ID 3 | Network connection, destination address/port, image, process GUID | Network telemetry, possible scanning/beaconing |
| Windows | Sysmon Event ID 22 | DNS query name, process image, query status/results, process GUID | DNS hunting, suspicious-domain detections |
| Windows | Security Event ID 4720 / 4726 | Local account created / deleted | Account lifecycle |
| Windows | Security Event ID 4698 | Scheduled task created, task name/content, creator | Scheduled-task persistence |
| Windows | PowerShell Operational, e.g. 4103/4104 if enabled | Module/script-block logging content | Script investigation and PowerShell triage |
| Kali | Test activity and endpoint logs; Wazuh collection only if agent is installed | Source commands and timing, auth/syslog/audit logs where present | Validate source activity and correlate against target telemetry |

---

## 3. VM1 — Wazuh Server Telemetry

### Role

VM1 is the central Wazuh server in this lab. It receives endpoint events, evaluates the custom rules, stores/searches alerts through the indexer, and presents them in the dashboard.

### Important local telemetry

| Source | What to check |
|---|---|
| Wazuh manager | `/var/ossec/logs/ossec.log` |
| Manager service | `wazuh-manager` |
| Indexer service | `wazuh-indexer` |
| Dashboard service | `wazuh-dashboard` |
| Alert index | Wazuh alert records such as `wazuh-alerts-4.x-*` in the dashboard |

### Verification commands

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
sudo tail -n 100 /var/ossec/logs/ossec.log
sudo grep -Ei 'error|warning|critical' /var/ossec/logs/ossec.log | tail -n 50
```

### Optional manager-local log collection

If VM1 itself should forward local Linux logs into Wazuh analysis, add only the paths that actually exist to `/var/ossec/etc/ossec.conf` inside the appropriate `<ossec_config>` block. Back up the file first.

```xml
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/syslog</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/ossec/logs/ossec.log</location>
  <log_format>syslog</log_format>
</localfile>
```

**Caution:** Do not add paths blindly. Confirm the file exists and decide whether manager-local ingestion is useful; avoid ingesting a stream in a way that creates duplicate or recursive noise.

### Verification checklist

- [ ] Manager, indexer, and dashboard services are active.
- [ ] VM2 and Windows agents show as connected/active in Wazuh.
- [ ] New endpoint events arrive with expected timestamps and agent names.
- [ ] Custom rule IDs appear only when the event matches their logic.
- [ ] Manager logs show no rule syntax or ingestion errors after changes.

---

## 4. VM2 — Ubuntu Linux Endpoint Telemetry

**Observed endpoint:** `ubuntu_vm2`, agent `001`, `192.168.34.143`.

### A. Authentication and sudo logs

Primary source: `/var/log/auth.log`.

The supplied records show:
- Repeated SSH authentication failures for user `vm2` from `192.168.34.138`.
- A later successful SSH login from the same source.
- Sudo events including `ls /root`, `visudo -c`, `cat /etc/shadow`, `systemctl status ssh`, `su -c whoami`, Python running `whoami` through sudo, and `crontab -l`.
- Linux user creation and deletion events for test accounts.

### Suggested Wazuh `localfile` blocks

Check whether equivalent blocks already exist before adding duplicates.

```xml
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/syslog</location>
  <log_format>syslog</log_format>
</localfile>
```

If `/var/log/syslog` does not exist on this installation, do not add it as a working source. Review the system’s journal/syslog configuration instead.

### B. File Integrity Monitoring for cron persistence

The supplied alerts showed Wazuh FIM events for:
- `/etc/cron.d/test_persist`
- `/etc/cron.d/test_persist1`
- `/var/spool/cron/crontabs/vm2`
- Temporary crontab files created/deleted during the test

Example `<syscheck>` configuration, to merge with the existing section rather than create duplicate/conflicting settings:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/etc/cron.d</directories>
  <directories check_all="yes">/etc/crontab</directories>
  <directories check_all="yes" realtime="yes">/var/spool/cron/crontabs</directories>
</syscheck>
```

**Note:** Real-time FIM is supported for directories, not individual files. Monitoring `/var/spool/cron/crontabs` may generate events for temporary files used during normal crontab updates. Tune after observing normal behavior.

### C. Auditd — optional additional telemetry

If `auditd` is installed and configured, it can provide audit records useful for process and syscall investigations. The custom Linux network rules in this lab refer to an audit key named `audit-wazuh-net`; the evidence supplied here does **not** establish that the corresponding audit rules are currently enabled.

Verify:

```bash
sudo systemctl status auditd
sudo auditctl -l
sudo test -f /var/log/audit/audit.log && sudo tail -n 30 /var/log/audit/audit.log
```

If collecting the audit log with the Wazuh agent, use the correct log format and make sure `auditd` is already configured to create the log:

```xml
<localfile>
  <location>/var/log/audit/audit.log</location>
  <log_format>audit</log_format>
</localfile>
```

### D. VM2 verification commands

```bash
sudo systemctl status wazuh-agent
sudo tail -n 50 /var/log/auth.log
sudo grep -E 'Failed password|Accepted password|useradd|userdel|sudo:' /var/log/auth.log | tail -n 100
sudo find /etc/cron.d /var/spool/cron/crontabs -maxdepth 2 -type f -ls 2>/dev/null
```

Use care when sharing the output publicly; authentication logs can contain usernames, internal IPs, and sensitive operational context.

---

## 5. Windows 10 Endpoint Telemetry

**Observed endpoint:** `window10`, agent `002`, computer name `DESKTOP-0P32A1N`. The endpoint IP appears as both `192.168.34.148` and `192.168.34.152` in supplied records.

### A. Sysmon Operational channel

The supplied alerts show Sysmon events in `Microsoft-Windows-Sysmon/Operational`:

| Sysmon ID | Telemetry | Used by this lab for |
|---:|---|---|
| 1 | Process creation | PowerShell command line, parent-child lineage, hashes and process IDs |
| 3 | Network connection | Outbound/other process network connections |
| 22 | DNS query | DNS name, query status/results, process image and PID/GUID |

Wazuh agent configuration path on a typical 64-bit Windows installation:

`C:\Program Files (x86)\ossec-agent\ossec.conf`

Add the following block inside the existing `<ossec_config>` structure if it is not already present:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Sysmon must itself be installed and configured to generate the desired event types. Wazuh collecting the channel cannot recover event types that Sysmon was never configured to record.

### B. Windows Security events

Relevant observed/target event IDs:

| Windows Security Event ID | Meaning | Detection category |
|---:|---|---|
| 4720 | A user account was created | Account management |
| 4726 | A user account was deleted | Account management |
| 4698 | A scheduled task was created | Persistence |

Example filtered Security channel collection:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[(EventID=4720 or EventID=4726 or EventID=4698)]</query>
</localfile>
```

Ensure Windows audit policy produces the required events. If you need additional account/group-change context, decide which additional Security events to collect and document them separately.

### C. PowerShell logging

The following channel is useful **if PowerShell logging is enabled**:

`Microsoft-Windows-PowerShell/Operational`

Optional Wazuh collection block:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Useful events in this channel can include Event ID 4103 (module logging) and Event ID 4104 (script-block logging), depending on the policy/configuration. Their presence is **not confirmed** solely by the Sysmon alerts supplied for this project.

### D. Windows verification commands

Run PowerShell as Administrator where required:

```powershell
Get-Service -Name Wazuh
Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 |
  Select-Object TimeCreated, Id, ProviderName, Message

Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1,3,22
  StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 50 |
  Select-Object TimeCreated, Id, Message
```

PowerShell Security/Operational events can be checked with:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 10 |
  Select-Object TimeCreated, Id, Message

Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id = 4720,4726,4698
  StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 50 |
  Select-Object TimeCreated, Id, Message
```

### E. Windows telemetry verification checklist

- [ ] Wazuh service is running.
- [ ] Sysmon Operational channel exists and records Event IDs 1, 3, and 22 as required.
- [ ] Wazuh is collecting the Sysmon channel.
- [ ] Security Event IDs 4720/4726/4698 are generated when relevant lab actions occur.
- [ ] PowerShell Operational channel is available if script logging is part of the lab.
- [ ] Current Windows IP address and Wazuh agent metadata agree; investigate `.148` versus `.152`.

---

## 6. Kali Linux — Lab Source / Testing Endpoint

**Role:** Kali is used as the authorized source/test system in this lab. VM2’s SSH logs show source IP `192.168.34.138`; confirm this address belongs to Kali before describing it as a verified Kali IP.

### What to collect

| Telemetry | Why it helps |
|---|---|
| `/var/log/auth.log`, if present | Authentication and SSH-client/system authentication context |
| `/var/log/syslog`, if present | System/service messages |
| `journalctl` | System and service logs where file-based logs are absent |
| Wazuh agent logs, if an agent is installed | Confirms agent connectivity and collection |
| Test activity timeline | Records what was intentionally run, from which host, and when |
| Optional audit/process telemetry | Helps corroborate commands run locally on Kali |

The evidence supplied for this project does not confirm that Kali is enrolled as a Wazuh agent. If Kali is not enrolled, Wazuh will still see the **target-side evidence** generated on VM2/Windows, but it will not automatically receive Kali’s local logs.

### Verify Kali’s current IP and log files

```bash
ip -brief address
hostnamectl
sudo test -f /var/log/auth.log && sudo tail -n 20 /var/log/auth.log
sudo test -f /var/log/syslog && sudo tail -n 20 /var/log/syslog
sudo journalctl -n 50 --no-pager
sudo systemctl status wazuh-agent
```

The final command is only expected to work if the Wazuh agent is installed.

### Optional Wazuh agent collection

If you choose to enroll Kali as an agent, configure its Wazuh agent in `/var/ossec/etc/ossec.conf` with the manager address and the log sources that actually exist on the Kali installation. For example, add only available file-based logs:

```xml
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/syslog</location>
  <log_format>syslog</log_format>
</localfile>
```

Do not copy a manager address from an example or guess the IP. Use VM1’s actual reachable address. If neither log file exists, use the supported journal/log collection method for the installed Wazuh version or keep Kali as a test source and document its actions separately.

### Safe test evidence

For each authorized lab test, record:
- Start/end time and timezone.
- Source host and current IP.
- Target host and service.
- The test objective.
- The relevant target-side log/alert.
- Whether the test succeeded, failed, or returned an error.

Do not publish raw shell history, passwords, tokens, keys, or unredacted sensitive logs.

---

## 7. Data Flow

```text
Kali (authorized test/source) ───────► VM2 Ubuntu services / Windows endpoint
       │                                      │
       │ optional Wazuh agent                 │ Wazuh agent
       ▼                                      ▼
   Wazuh manager (VM1) ◄──────────────── endpoint telemetry
       │
       ├── Rule matching and alert generation
       ├── Indexing/search in Wazuh indexer
       └── Investigation in Wazuh dashboard
```

Kali’s local telemetry reaches Wazuh only if Kali is enrolled and configured to send it. Target-side logs are still essential for validating what the target observed.

---

## 8. Endpoint-to-Detection Coverage

| Detection category | Required telemetry | Main endpoint |
|---|---|---|
| SSH brute force | Failed/successful SSH records in `auth.log` | VM2 |
| Suspicious PowerShell | Sysmon Event ID 1 command line/process metadata | Windows |
| Encoded PowerShell | Sysmon Event ID 1 command line | Windows |
| Suspicious process lineage | Sysmon Event ID 1 parent and child process fields | Windows |
| Network connection / port scan | Sysmon Event ID 3 | Windows; optional audit telemetry on Linux |
| Account lifecycle | Linux `useradd`/`userdel` records and Windows Security 4720/4726 | VM2 + Windows |
| Sudo / high-risk command | Linux sudo records in `auth.log` | VM2 |
| Cron persistence | FIM/syscheck on cron directories and files | VM2 |
| Windows scheduled-task persistence | Windows Security Event ID 4698 with task XML/content | Windows |
| DNS hunting | Sysmon Event ID 22 | Windows |
| Wazuh health | Manager/agent service logs and status | VM1 + endpoints |

---

## 9. Final Validation Checklist

- [ ] Every host’s current hostname and IP have been recorded.
- [ ] Wazuh agent IDs are recorded correctly: VM2 `001`, Windows `002`; Kali agent status is not assumed.
- [ ] Log paths/channels in `ossec.conf` exist and are not duplicated.
- [ ] Wazuh agent and manager services are healthy after any config change.
- [ ] Sysmon is configured to generate the Windows events the detections depend on.
- [ ] Linux FIM watches the intended cron paths.
- [ ] Optional `auditd` rules exist before claiming audit-based network telemetry.
- [ ] Positive and negative test cases have been run and observed.
- [ ] Source event time, UTC time, local time, and Wazuh indexed timestamp are reconciled.
- [ ] Screenshots and alert JSON are stored with secrets and sensitive details redacted.
- [ ] Rules that rely on specific fields or correlations are tested using actual decoded events and `wazuh-logtest`.

---

## 10. References

Use the documentation matching the Wazuh version installed in the lab:

- Wazuh local log collection configuration: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- Wazuh log data collection: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html
- Wazuh File Integrity Monitoring configuration: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
- Wazuh Windows Sysmon log collection example: https://documentation.wazuh.com/current/user-manual/manager/event-logging.html
- Microsoft Sysmon event reference: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events

**Publication note:** The IPs and usernames in this document come from the supplied lab evidence. Before making this repository public, replace any internal values you do not wish to expose with generic placeholders.
