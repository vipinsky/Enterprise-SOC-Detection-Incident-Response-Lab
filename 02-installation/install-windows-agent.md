# Windows 10 — Wazuh Agent & Sysmon Installation and Configuration

**Role:** Monitored Windows endpoint
**OS:** Windows 10
**Wazuh Agent version:** 4.14.x

## 1. Wazuh agent installation

Run in an elevated PowerShell:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.x-1.msi -OutFile $env:tmp\wazuh-agent.msi
msiexec.exe /i $env:tmp\wazuh-agent.msi /q WAZUH_MANAGER='<vm1-ip>'
```

Start the service:
```powershell
NET START WazuhSvc
```

Confirm connection:
```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```
Look for `Connected to the server`.

## 2. Sysmon installation

```powershell
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:tmp\Sysmon.zip
Expand-Archive $env:tmp\Sysmon.zip -DestinationPath $env:tmp\Sysmon
cd $env:tmp\Sysmon
.\Sysmon64.exe -accepteula -i
```

## 3. Sysmon configuration — enable the event types used in this project

Create a config XML (e.g. `C:\sysmonconfig.xml`) enabling:
- **Event ID 1** — Process creation
- **Event ID 3** — Network connection
- **Event ID 5** — Process termination
- **Event ID 11** — File creation
- **Event ID 22** — DNS query

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="exclude">
    </ProcessCreate>

    <NetworkConnect onmatch="exclude">
      <!-- Excludes to reduce noise; everything else is logged -->
      <Image condition="begin with">C:\ProgramData\Microsoft\Windows Defender\Platform\</Image>
      <DestinationHostname condition="end with">.microsoft.com</DestinationHostname>
      <DestinationIp condition="is">127.0.0.1</DestinationIp>
    </NetworkConnect>

    <FileCreate onmatch="exclude">
    </FileCreate>

    <DnsQuery onmatch="exclude">
      <QueryName condition="end with">.microsoft.com</QueryName>
      <QueryName condition="end with">.windowsupdate.com</QueryName>
      <QueryName condition="end with">.events.data.microsoft.com</QueryName>
    </DnsQuery>
  </EventFiltering>
</Sysmon>
```

Apply it:
```powershell
sysmon.exe -c C:\sysmonconfig.xml
```

Verify an event type is firing, e.g. DNS:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 22} | Select-Object -First 3
```

## 4. Wazuh agent — read the Sysmon channel

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf`, inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

This single `<localfile>` block covers **all** Sysmon event IDs on that channel (no separate block needed per event type).

## 5. Wazuh agent — read the Security event log (for account/task events)

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent service after any `ossec.conf` change:
```powershell
Restart-Service -Name wazuh
```

## 6. Windows audit policies — enable the Security events used in this project

```powershell
# User account management (Event IDs 4720 create, 4726 delete)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Scheduled task creation (Event ID 4698)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Confirm:
```powershell
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Other Object Access Events"
```

## 7. Key diagnostic commands used throughout the project

```powershell
# Confirm a Sysmon event type is firing locally, before troubleshooting the Wazuh side
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq <EventID>} | Select-Object -First 5

# Check the current Sysmon config
sysmon.exe -c

# Tail the agent's own operational log
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

## Summary of what the Windows endpoint contributes to this project

| Telemetry | Source | Event ID |
|---|---|---|
| Process creation (command line, parent, hashes) | Sysmon | 1 |
| Network connections (IP/port, initiating process) | Sysmon | 3 |
| Process termination | Sysmon | 5 |
| File creation | Sysmon | 11 |
| DNS queries | Sysmon | 22 |
| Scheduled task creation | Security log | 4698 |
| Local user account created | Security log | 4720 |
| Local user account deleted | Security log | 4726 |

## Known limitation discovered during testing

The Windows Firewall will silently drop unsolicited inbound connections (e.g. a port scan from Kali) before Sysmon ever logs them, since no TCP handshake completes. Port-scan testing against this endpoint required temporarily disabling the firewall (`netsh advfirewall set allprofiles state off`) to validate the detection logic — see `detection-006-port-scanning.md` for the full test case and discussion.
