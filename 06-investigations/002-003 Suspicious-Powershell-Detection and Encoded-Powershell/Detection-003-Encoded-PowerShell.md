# Detection 003 — Encoded PowerShell

**Status:** Detection test observed; context review required  
**Wazuh rule:** `100301` · **Level:** 12  
**Endpoint:** `window10` (`192.168.34.148`), agent `002`  
**MITRE ATT&CK:** `T1059.001 — PowerShell`; `T1027 — Obfuscated Files or Information`

## Objective
Detect PowerShell launched with an encoded command indicator and support triage using decoded content and process context.

## Evidence
Sysmon Event ID 1 recorded PowerShell process creation under `DESKTOP-0P32A1N\vipin`.

```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABoAGkAcwAgAGkAcwAgAGEAbgAgAGUAbgBjAG8AZABlAGQAIAB0AGUAcwB0ACAAYwBvAG0AbQBhAG4AZAAnAA==
```

- Process ID: `8008`
- Parent image: `powershell.exe`
- Parent PID: `1696`
- Event time: `2026-10-17 07:30:58.306 UTC` (`13:00:58.306` UTC+05:30)
- Wazuh alert timestamp: `2026-10-17 13:00:59.474`
- Rule groups: `sysmon`, `powershell`, `suspicious_powershell`, `encoded_command`
- Alert record: `mail: true`

## Decoded payload
The encoded value decodes as UTF-16LE to:

```powershell
Write-Host 'This is an encoded test command'
```

This is a benign test string. The alert confirms that the encoded-command indicator was detected; it does not prove malicious behavior.

## Verdict
**Encoded PowerShell detection test passed based on the supplied alert evidence; no compromise confirmed.**

## Recommended follow-up
- Confirm the test was intentional.
- Decode suspicious content safely and inspect it before execution.
- Review process ancestry, user, network connections, file changes, and surrounding alerts.
- Correlate with PowerShell Operational events (4103/4104), if enabled.
- Use `-EncodedCommand` as one indicator among others, not as a standalone proof of malware.

## Evidence
See `../evidence/E03-encoded-powershell-alert.png` and `../evidence/E02-suspicious-powershell-alerts.png`.
