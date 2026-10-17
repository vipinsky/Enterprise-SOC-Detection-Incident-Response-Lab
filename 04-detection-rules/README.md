# Wazuh Manual Rules — Organized by Detection Category

This repository contains the **actual Wazuh XML rule blocks** from the supplied `local_rules.xml` text, grouped into separate Markdown (`.md`) files by category.

These files are rule collections, not incident reports. The `<rule>...</rule>` logic is copied from the source text; the original enclosing `<group name="...">` is shown for context.

## Category index

| Detection | Category | Rule IDs | File |
|---|---|---|---|
| Detection 01 | SSH Authentication & Brute Force | 100001, 100200, 100201 | [Detection-01-Brute-Force.md ](Detection-01-Brute-Force.md) |
| Detection 02 | Suspicious PowerShell | 100300 | [Detection-02-Suspicious-PowerShell.md ](Detection-02-Suspicious-PowerShell.md) |
| Detection 03 | Encoded PowerShell | 100301 | [Detection-03-Encoded-PowerShell.md ](Detection-03-Encoded-PowerShell.md) |
| Detection 04 | Suspicious Parent–Child Process Lineage | 100302, 100303, 100304 | [Detection-04-Process-Lineage.md ](Detection-04-Process-Lineage.md) |
| Detection 05 | Network Connection & Port Scan | 100400, 100401 | [Detection-05-Network-Port-Scan.md ](Detection-05-Network-Port-Scan.md) |
| Detection 06 | Account Management & Lifecycle | 100501, 100503, 100510, 100511, 100512, 100513 | [Detection-06-Account-Management.md ](Detection-06-Account-Management.md) |
| Detection 07 | Sudo & Privilege Escalation | 100520, 100521, 100522, 100523, 100524, 100525 | [Detection-07-Sudo-Privilege-Escalation.md ](Detection-07-Sudo-Privilege-Escalation.md) |
| Detection 08 | Persistence: Cron & Scheduled Tasks | 100530, 100531, 100532, 100533 | [Detection-08-Persistence.md ](Detection-08-Persistence.md) |
| Detection 09 | DNS, Network & C2 Hunting | 100600, 100601, 100602, 100603, 100604, 100605, 100610, 100611, 100612, 100613 | [Detection-09-DNS-Network-C2.md ](Detection-09-DNS-Network-C2.md) |
| Detection 10 | Windows Process Visibility | 100120, 100100, 100101, 100102, 100700 | [Detection-10-Windows-Process-Visibility.md ](Detection-10-Windows-Process-Visibility.md) |

## How to use

1. Open the `.md` file for the category you need.
2. Copy the relevant XML block (including its `<group name="...">` wrapper or merge it into the original matching group carefully).
3. Avoid accidentally duplicating rule IDs in `local_rules.xml`.
4. Validate rule syntax with the Wazuh tools available in your installed version (for example, `wazuh-logtest` and the rule-analysis test workflow).
5. Test both matching and non-matching events before relying on the rules.

## Rule coverage

- Total rules extracted from source: **41**
- Rules assigned to categories: **41**
- Original rule IDs are preserved.
- No PDF/Word incident reports are included in this package.

## Important

The file that was supplied was terminal output from `cat /var/ossec/etc/rules/local_rules.xml`, not necessarily a raw XML file. The Markdown contains XML rule snippets extracted from that output. Always compare with the live configuration and validate on your Wazuh version before deployment.
