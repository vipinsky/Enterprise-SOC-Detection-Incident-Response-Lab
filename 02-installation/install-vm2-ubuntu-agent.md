# VM2 — Ubuntu Wazuh Agent Installation & Telemetry Configuration

**Role:** Monitored Linux endpoint
**OS:** Ubuntu 22.04
**Wazuh Agent version:** 4.14.x

## 1. Wazuh agent installation

```bash
curl -o wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.x-1_amd64.deb
sudo WAZUH_MANAGER='<vm1-ip>' dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Confirm connection to the manager:
```bash
sudo tail -n 20 /var/ossec/logs/ossec.log
```
Look for `Connected to the server`.

## 2. Ensure base logging is available

Minimal installs may lack `rsyslog`, which produces `/var/log/auth.log` and `/var/log/syslog`:

```bash
sudo apt install rsyslog -y
sudo systemctl enable --now rsyslog
```

## 3. Install auditd

```bash
sudo apt install auditd audispd-plugins -y
sudo systemctl enable --now auditd
```

## 4. Custom audit rules — `/etc/audit/rules.d/wazuh.rules`

```
# Identity: user and group creation/modification
-w /etc/passwd -p wa -k audit-wazuh-w
-w /etc/shadow -p wa -k audit-wazuh-w
-w /etc/group -p wa -k audit-wazuh-w
-w /etc/gshadow -p wa -k audit-wazuh-w

# Sudo and SSH configuration
-w /etc/sudoers -p wa -k audit-wazuh-w
-w /etc/sudoers.d/ -p wa -k audit-wazuh-w
-w /etc/ssh/sshd_config -p wa -k audit-wazuh-w

# Service creation (systemd units) and scheduled jobs
-w /etc/systemd/system/ -p wa -k audit-wazuh-w
-w /lib/systemd/system/ -p wa -k audit-wazuh-w
-w /etc/crontab -p wa -k audit-wazuh-w
-w /etc/cron.d/ -p wa -k audit-wazuh-w

# Process execution
-a always,exit -F arch=b64 -S execve -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -k audit-wazuh-c

# Network: outbound connect() syscall (AF_INET only — excludes local Unix sockets)
-a always,exit -F arch=b64 -S connect -F a2=0x10 -F success=1 -F key=audit-wazuh-net
-a always,exit -F arch=b32 -S connect -F a2=0x10 -F success=1 -F key=audit-wazuh-net
```

Load:
```bash
sudo augenrules --load
sudo auditctl -l
```

**Note:** `a2=0x10` restricts the `connect` rule to socket address structures matching IPv4 (`sockaddr_in`), significantly reducing noise from local Unix domain sockets (`systemd`, `sudo`, `wazuh-logcollector` itself all generate heavy `connect()` traffic to local IPC sockets otherwise).

## 5. Wazuh agent `ossec.conf` — log collection

Edit `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/dpkg.log</location>
</localfile>

<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Optional (only if the relevant service is installed):
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ufw.log</location>
</localfile>
```

Restart the agent after any `ossec.conf` change:
```bash
sudo systemctl restart wazuh-agent
```

## 6. File Integrity Monitoring (FIM) — `<syscheck>` block

Inside `/var/ossec/etc/ossec.conf`:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/etc/ssh,/etc/sudoers.d</directories>
  <directories check_all="yes" whodata="yes">/etc/systemd/system</directories>
  <directories check_all="yes" realtime="yes">/home</directories>
  <directories check_all="yes" whodata="yes">/etc/cron.d,/etc/crontab,/var/spool/cron/crontabs</directories>
</syscheck>
```

`whodata="yes"` additionally records which user/process made a change (requires auditd, already installed above).

## 7. UFW (used for inbound port-scan detection follow-up)

```bash
sudo ufw enable
sudo ufw logging on
```

## 8. Key diagnostic commands used throughout the project

```bash
# Confirm auditd captured an event locally, by key
sudo ausearch -k audit-wazuh-net -ts recent

# Confirm FIM directories are actively watched
sudo grep "Directory set for" /var/ossec/logs/ossec.log

# Confirm audit rules are loaded
sudo auditctl -l
```

## Summary of what vm2 contributes to this project

| Telemetry | Source |
|---|---|
| SSH logins (success/failure) | `/var/log/auth.log` |
| sudo usage | `/var/log/auth.log` |
| User/group creation & deletion | `/var/log/auth.log` |
| Process execution | auditd (`execve`, key `audit-wazuh-c`) |
| Outbound network connections | auditd (`connect`, key `audit-wazuh-net`) — outbound only, see Detection 010 notes |
| File integrity (cron, SSH config, sudoers, /home, systemd units) | syscheck (FIM) with whodata |
