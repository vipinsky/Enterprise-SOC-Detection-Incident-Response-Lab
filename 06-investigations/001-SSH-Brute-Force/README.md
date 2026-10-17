# IR-001 — SSH Brute Force Investigation

A portfolio-ready SOC incident report based on a Wazuh lab investigation.

## Scenario
Wazuh rule `100200` (Level 10) detected repeated SSH authentication failures against `ubuntu_vm2` (`192.168.34.143`) from `192.168.34.138`. Endpoint logs also show a successful password-based login for `vm2` at `12:11:35.546` (UTC+05:30), followed by a sudo session at `12:12:09`.

## Verdict
**Suspicious activity — investigation required.** Successful authentication is confirmed, but unauthorized access or compromise is not proven. Validate whether the source and login were authorized before closing the case.

## Environment
- SIEM: Wazuh
- Manager: `vm1`
- Endpoint: Ubuntu Linux, `ubuntu_vm2` (`192.168.34.143`)
- Source: `192.168.34.138`
- Log: `/var/log/auth.log`
- Rule `100200`: repeated SSH failures; Level 10; frequency 5; timeframe 180 seconds; ignore 180 seconds
- Rule `100201`: intended successful-login-after-brute-force correlation; requires validation

## Repository contents
- `IR-001-SSH-Brute-Force-Investigation.pdf` — shareable report
- `IR-001-SSH-Brute-Force-Investigation.docx` — editable report
- `timeline.csv` — concise event timeline
- `evidence/` — supplied Wazuh screenshots

## Key findings
1. Repeated SSH password failures from `192.168.34.138` against account `vm2`.
2. Wazuh generated a Level 10 alert under custom rule `100200`.
3. A successful SSH password login from the same source was recorded at `12:11:35.546`.
4. A sudo session followed at `12:12:09` to read `/var/log/auth.log`.
5. Evidence does not currently prove malicious intent, unauthorized access, or compromise.

## MITRE ATT&CK
- `T1110 — Brute Force` (Credential Access): behavior is consistent with repeated password attempts.
- `T1078 — Valid Accounts`: successful authentication occurred, but unauthorized use is not established.

## Next steps
- Confirm whether the source VM and successful login were authorized.
- Review process/command activity, account changes, SSH keys, cron jobs, services, and later logins.
- Validate rules `100200` and `100201` with `wazuh-logtest` and controlled lab events.
- Preserve relevant raw logs and record the final disposition.

## Evidence handling
Screenshots are supplied as visual evidence. Add raw log exports and actual `wazuh-logtest` output if collected. Do not claim tests or containment actions that were not performed. Private IPs and usernames in this repository describe a lab environment; redact any sensitive details before public publication.

## Report note
Wazuh event time (`full_log` / `predecoder.timestamp`) and indexed timestamp may differ. Correlate using event time and validate ingestion delay from raw records before drawing conclusions.
