# Detection 004 — Encoded PowerShell

**Rule:** 100301
**MITRE:** T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)
**Platform:** Windows (window10)

## Logic

Fires on `-enc`/`-encodedcommand`, or `-e` followed by a base64-looking string of 20+ characters. Base64-encoded commands are almost always used specifically to obscure what's actually running, making this a stronger and more targeted signal than Detection 003's general suspicious-flag matching.

## Test Case 1: Standard `-enc` with a real encoded payload

```powershell
$cmd = "Write-Host 'This is an encoded test command'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -enc $encodedCommand
```

**Expected:** rule **100301** fires (level 12).

## Test Case 2: Short-form `-e` flag

```powershell
powershell.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA
```

**Expected:** rule **100301** fires.

## Negative Test: Short base64-like string below the length threshold

```powershell
powershell.exe -e short
```

**Expected:** no alert — the string is under the 20-character threshold the regex requires, confirming the rule isn't matching any `-e` flag indiscriminately (which would catch unrelated short arguments).

## Verification

```bash
sudo grep -a "100301" /var/ossec/logs/alerts/alerts.json | tail -n 5
```

Live:
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -a --line-buffered "100301"
```

## Dashboard check

```
rule.id: 100301
```

## Notes for writeup

Severity (level 12) is deliberately higher than Detection 003 (level 10) since an encoded payload is a stronger signal than a readable suspicious flag — the attacker is actively hiding the command content, not just using an evasive option in plain sight.
