# VM1 — Wazuh Manager, Indexer & Dashboard Installation

**Role:** Wazuh Manager + Indexer + Dashboard (all-in-one node)
**OS:** Ubuntu (24.04)
**Wazuh version:** 4.14.x

## 1. All-in-one installation

Wazuh provides a single installation script that deploys the Manager, Indexer, and Dashboard together on one node — this is what this lab used.

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

This installs and starts:
- `wazuh-manager`
- `wazuh-indexer` (OpenSearch-based)
- `wazuh-dashboard` (OpenSearch Dashboards-based)

The script prints the auto-generated `admin` password for the Indexer/Dashboard at the end — save it, it's required for `curl` API checks and dashboard login.

## 2. Verify services

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

## 3. Manager configuration — enable full event archiving

By default, Wazuh only logs *alerts* (events that matched a rule). To also capture every raw event for dashboards/forensics, edit `/var/ossec/etc/ossec.conf`:

```xml
<global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    ...
</global>
```

Restart:
```bash
sudo systemctl restart wazuh-manager
```

## 4. Enable Filebeat archive shipping

By default Filebeat only ships alerts to the Indexer, not the full archive. Edit `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: true
```

Restart:
```bash
sudo systemctl restart filebeat
```

Verify:
```bash
filebeat test output
```

## 5. Create the `wazuh-archives-*` index pattern (Dashboard)

1. Menu → Dashboards Management → Index Patterns → Create index pattern
2. Name: `wazuh-archives-*`
3. Time field: `timestamp`
4. Create

(`wazuh-alerts-*` is created automatically by the install script.)

## 6. Verify indices exist

```bash
curl -k -u admin:<password> "https://localhost:9200/_cat/indices?v" | grep wazuh
```

## 7. Supporting tools installed on vm1

```bash
sudo apt install netcat-traditional -y
```
Used as a throwaway TCP listener (`nc -lvnk -p 4444`) during network/beaconing detection testing — simulates a C2 listener so outbound test connections from endpoints actually complete (rather than being dropped, which prevents some event types from being logged at all).

## 8. Key diagnostic commands used throughout the project

```bash
# Test a rule against a single log line interactively
sudo /var/ossec/bin/wazuh-logtest

# Validate rule syntax before restarting the manager
sudo /var/ossec/bin/wazuh-analysisd -t

# Tail raw collected events (requires logall_json: yes)
sudo tail -f /var/ossec/logs/archives/archives.json

# Tail matched alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json

# Manager's own operational log
sudo tail -f /var/ossec/logs/ossec.log
```

**Note:** binary-file warnings from `grep` on `alerts.json`/`archives.json` (caused by occasional non-UTF8 bytes, e.g. from Windows event messages containing special characters) require the `-a` flag to force text search:
```bash
sudo grep -a "<pattern>" /var/ossec/logs/alerts/alerts.json
```

## 9. Custom detection rules

All custom rules for this project live in:
```
/var/ossec/etc/rules/local_rules.xml
```

See the project's `test-cases/` directory for the full rule set and corresponding test cases per detection.
