# MITRE ATT&CK Mapping — Wazuh SOC Detection Rules

**Project:** Enterprise SOC Detection & Incident Response Lab  
**Source:** Custom Wazuh `local_rules.xml` supplied for this project  
**Purpose:** Central reference for MITRE ATT&CK mappings declared by the custom rules, grouped by detection category.

> **How to read this document:** Rule-to-technique mappings below reflect the `<mitre><id>...</id></mitre>` entries present in the supplied rule file. Rules without a MITRE entry are explicitly marked **No mapping declared in the supplied XML**. The presence of a mapping is a detection-design label; it does not prove that an adversary used that technique.

---

## 1. Executive Summary

The supplied custom rules contain the following MITRE ATT&CK technique IDs:

| ATT&CK ID | Technique name | Tactic(s) | Wazuh rule IDs in supplied XML |
|---|---|---|---|
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access | `100200`, `100201` |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion | `100201`, `100521` |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | `100300`, `100301` |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion | `100301` |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access | `100302` |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution | `100302`, `100303`, `100304`, `100523`, `100533` |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Discovery | `100401` |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Persistence | `100501`, `100510`, `100511`, `100513` |
| [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | Impact | `100503`, `100512`, `100513` |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation, Defense Evasion | `100520`–`100525` |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | Execution | `100522` |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command and Control | `100524`, `100605`, `100613` |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Scheduled Task/Job: Cron | Execution, Persistence, Privilege Escalation | `100530`, `100531` |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Execution, Persistence, Privilege Escalation | `100532`, `100533` |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Command and Control | `100601`, `100603`, `100605`, `100611`, `100612`, `100613` |
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | Command and Control | `100602` |
| [T1568](https://attack.mitre.org/techniques/T1568/) | Dynamic Resolution | Command and Control | `100604` |

---

## 2. Mapping by Detection Category

### Detection 01 — SSH Authentication & Brute Force

| Wazuh rule | Rule purpose from supplied XML | ATT&CK ID | Technique |
|---|---|---|---|
| `100001` | SSH authentication failed from a specific hard-coded IP | — | No mapping declared in the supplied XML |
| `100200` | Multiple SSH authentication failures from the same source | `T1110` | [Brute Force](https://attack.mitre.org/techniques/T1110/) |
| `100201` | Successful SSH login after a brute-force alert | `T1110`, `T1078` | [Brute Force](https://attack.mitre.org/techniques/T1110/); [Valid Accounts](https://attack.mitre.org/techniques/T1078/) |

**Mapping note:** The successful-login correlation is suspicious context, not proof that the credential was compromised. Verify authorization and activity after the login.

### Detection 02 — Suspicious PowerShell

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100300` | Suspicious PowerShell command-line characteristics | `T1059.001` | [PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

### Detection 03 — Encoded PowerShell

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100301` | Encoded PowerShell command line | `T1059.001`, `T1027` | [PowerShell](https://attack.mitre.org/techniques/T1059/001/); [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) |

**Mapping note:** `-EncodedCommand` is an indicator, not proof of malware. Decode the argument safely as text and inspect process ancestry and surrounding telemetry.

### Detection 04 — Suspicious Parent–Child Process Lineage

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100302` | Office application spawns a scripting/shell process | `T1566.001`, `T1059` | [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/); [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| `100303` | Browser spawns a scripting/shell process | `T1059` | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| `100304` | PDF reader spawns a scripting/shell process | `T1059` | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |

**Mapping note:** An Office process spawning PowerShell does not independently prove a phishing attachment. These mappings are investigative pivots that need command-line, document/download, and process evidence.

### Detection 05 — Network Connection & Possible Port Scan

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100400` | Base Sysmon network-connection event | — | No mapping declared in the supplied XML |
| `100401` | Multiple destination ports from one source in a short interval | `T1046` | [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |

**Mapping note:** A multi-port connection pattern can indicate discovery, but approved scanners and normal application traffic should be excluded by context.

### Detection 06 — Account Management & Lifecycle

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100501` | Windows local account created | `T1136.001` | [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| `100503` | Windows local account deleted | `T1531` | [Account Access Removal](https://attack.mitre.org/techniques/T1531/) |
| `100510` | Linux user account created | `T1136.001` | [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| `100511` | Linux user account creation labelled as elevated | `T1136.001` | [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| `100512` | Linux user account deleted | `T1531` | [Account Access Removal](https://attack.mitre.org/techniques/T1531/) |
| `100513` | Linux account created and deleted within 10 minutes | `T1531`, `T1136.001` | [Account Access Removal](https://attack.mitre.org/techniques/T1531/); [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) |

**Mapping notes:**
- The `T1136.001` mapping denotes local-account creation as a possible persistence behavior. Legitimate account administration produces similar events.
- `T1531` is an account-access removal technique. An account-deletion alert alone does not prove adversarial intent.
- Rule `100511`'s label says “elevated privileges,” but validate the actual event fields and group membership before concluding that sudo access was granted.
- Rule `100513` should be tested to ensure it correlates the same account across create/delete events.

### Detection 07 — Sudo & Privilege Escalation

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100520` | Base sudo command executed as root | `T1548.003` | [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) |
| `100521` | Sudo used with a sensitive/high-risk command | `T1548.003`, `T1078` | [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/); [Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| `100522` | Sudo used to spawn an interactive root shell | `T1548.003`, `T1059.004` | [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/); [Unix Shell](https://attack.mitre.org/techniques/T1059/004/) |
| `100523` | Sudo used with a shell-escape pattern | `T1548.003`, `T1059` | [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/); [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| `100524` | Sudo used with download/execute or reverse-shell-like patterns | `T1548.003`, `T1105` | [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/); [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| `100525` | Multiple sudo authentication failures | `T1548.003` | [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) |

**Mapping note:** The presence of `sudo` is not automatically abuse. Consider user, command, TTY, host role, approved administration, and actual command outcome. A failed authentication sequence should be validated against the real event fields, as local sudo events may not provide a meaningful source IP.

### Detection 08 — Persistence: Cron & Windows Scheduled Tasks

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100530` | Linux cron-related file modification | `T1053.003` | [Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) |
| `100531` | New Linux cron job created | `T1053.003` | [Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) |
| `100532` | Windows scheduled task created | `T1053.005` | [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| `100533` | Scheduled task contains a scripting-engine command | `T1053.005`, `T1059` | [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/); [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |

**Mapping note:** File changes and task creation are persistence-relevant events, but Event ID 4698 confirms scheduled-task creation rather than successful task execution. Validate cron/task content, run-as identity, trigger, and process telemetry.

### Detection 09 — DNS, Network & Possible C2 Hunting

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100600` | Base Sysmon DNS-query event | — | No mapping declared in the supplied XML |
| `100601` | Network connection from a suspicious executable path | `T1071` | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| `100602` | Connection to a selected C2-associated port | `T1571` | [Non-Standard Port](https://attack.mitre.org/techniques/T1571/) |
| `100603` | Repeated network connections by the same image to the same destination | `T1071` | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| `100604` | DNS query to selected uncommon/high-risk TLDs | `T1568` | [Dynamic Resolution](https://attack.mitre.org/techniques/T1568/) |
| `100605` | High-confidence suspicious process/beaconing composite | `T1071`, `T1105` | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/); [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| `100610` | Base Linux outbound `connect()` audit event | — | No mapping declared in the supplied XML |
| `100611` | Linux outbound connection by executable in a suspicious path | `T1071` | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| `100612` | Repeated Linux outbound connections from the same executable | `T1071` | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| `100613` | High-confidence suspicious Linux process/beaconing composite | `T1071`, `T1105` | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/); [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |

**Mapping notes:**
- A suspicious TLD, uncommon port, or repeated connection pattern is a heuristic. These indicators do not prove C2 on their own.
- `T1071` is a broad application-layer communication technique. For a stronger mapping, confirm the protocol used and how the connection fits the technique.
- The `T1568` mapping is declared by the XML for selected TLDs, but a TLD match alone does not establish dynamic resolution behavior.
- The Linux network rules depend on the expected audit key and decoded fields being present.

### Detection 10 — Windows Process Visibility

| Wazuh rule | Rule purpose | ATT&CK ID | Technique |
|---|---|---|---|
| `100120` | Sysmon Notepad process-created event | — | No mapping declared in the supplied XML |
| `100100` | Notepad execution | — | No mapping declared in the supplied XML |
| `100101` | Windows Store/UWP application opened | — | No mapping declared in the supplied XML |
| `100102` | Microsoft Store application opened | — | No mapping declared in the supplied XML |
| `100700` | General Sysmon process-creation event | — | No mapping declared in the supplied XML |

These are process visibility or baseline rules in the supplied file. No ATT&CK IDs are declared for them, so none have been added here.

---

## 3. Techniques by Tactic — Quick Reference

| Tactic | Techniques declared by this rule set |
|---|---|
| **Initial Access** | `T1566.001` Spearphishing Attachment; `T1078` Valid Accounts |
| **Execution** | `T1059` Command and Scripting Interpreter; `T1059.001` PowerShell; `T1059.004` Unix Shell; `T1053.003` Cron; `T1053.005` Scheduled Task |
| **Credential Access** | `T1110` Brute Force |
| **Defense Evasion** | `T1027` Obfuscated Files or Information; `T1078` Valid Accounts; `T1548.003` Sudo and Sudo Caching |
| **Persistence** | `T1136.001` Create Account: Local Account; `T1053.003` Cron; `T1053.005` Scheduled Task; `T1078` Valid Accounts |
| **Privilege Escalation** | `T1548.003` Sudo and Sudo Caching; `T1078` Valid Accounts; `T1053.003` Cron; `T1053.005` Scheduled Task |
| **Discovery** | `T1046` Network Service Discovery |
| **Command and Control** | `T1071` Application Layer Protocol; `T1571` Non-Standard Port; `T1568` Dynamic Resolution; `T1105` Ingress Tool Transfer |
| **Impact** | `T1531` Account Access Removal |

Tactics listed above describe the official ATT&CK classification for the technique IDs, not a claim that every alert demonstrates that tactic.

---

## 4. Rules with No Explicit ATT&CK Mapping in the Supplied XML

The following rules were present in the supplied source but did not contain a `<mitre>` mapping:

| Rule ID | Description in supplied XML |
|---|---|
| `100001` | SSH authentication failed from IP `1.1.1.1` |
| `100120` | Sysmon: Notepad process created on Windows endpoint |
| `100100` | Notepad executed |
| `100101` | Windows Store app opened |
| `100102` | Microsoft Store application opened |
| `100400` | Sysmon network connection event |
| `100600` | Sysmon DNS query event |
| `100610` | Linux outbound `connect()` syscall event |
| `100700` | Sysmon process-creation event |

No mapping has been invented for these rules. A future version could add mappings after reviewing each rule’s exact detection scope and evidence requirements.

---

## 5. Mapping Quality and Validation Notes

A rule’s ATT&CK tag should describe the behavior the rule detects, not merely the name of a suspicious command. Review these points before publishing or deploying the rules:

1. **Detection is not attribution.** A technique tag is a classification, not proof of adversary activity.
2. **Separate event telemetry from behavior analytics.** Base Sysmon DNS/network/process events provide visibility and may not need an ATT&CK mapping unless the rule identifies a specific behavior.
3. **Review broad mappings.** For example, a selected port or TLD is only a heuristic for `T1571` or `T1568`; validate the behavioral context.
4. **Review account deletions.** `T1531` specifically describes account access removal. An ordinary deletion event can be administrative and should not automatically be treated as adversarial.
5. **Validate parent/child process mappings.** An Office-to-PowerShell chain can be consistent with `T1059` and may merit investigation for `T1566.001`, but does not prove a malicious attachment.
6. **Validate rule correlation fields.** Repeated-event rules should be tested using real decoded events, especially fields such as source IP, destination IP, destination port, image path, and audit executable.
7. **Validate custom rules with the installed Wazuh version.** Use `wazuh-logtest`, sample positive/negative events, and alert JSON before using the mapping for reporting.

---

## 6. Official MITRE ATT&CK References

The following MITRE ATT&CK pages were used to verify technique names and tactics for this reference:

- [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [T1531 — Account Access Removal](https://attack.mitre.org/techniques/T1531/)
- [T1548.003 — Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/)
- [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1053.003 — Cron](https://attack.mitre.org/techniques/T1053/003/)
- [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1571 — Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [T1568 — Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)

---

## 7. Publication Checklist

- [ ] Compare every rule ID and `<mitre>` block with the current live `local_rules.xml`.
- [ ] Confirm the rules are syntactically valid and IDs are unique.
- [ ] Confirm MITRE mappings fit the actual detection behavior.
- [ ] Remove any mappings that are too broad or not supported by the rule.
- [ ] Keep rule-level evidence and investigation outcomes separate from ATT&CK taxonomy labels.
- [ ] Redact internal IP addresses, hostnames, usernames, and sensitive event content if required before making the repository public.

