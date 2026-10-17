# Detection 005 — Suspicious Parent → Child Process

**Rules:** 100302 (Office → shell), 100303 (Browser → shell), 100304 (PDF reader → shell)
**MITRE:** T1566.001 (Phishing: Spearphishing Attachment), T1059 (Command and Scripting Interpreter)
**Platform:** Windows (window10)

## Logic

Flags process lineage where a document/browser/PDF application unexpectedly spawns a shell or scripting engine (`powershell`, `cmd`, `wscript`, `cscript`, `mshta`, `regsvr32`, `rundll32`, `certutil`) — a classic phishing-macro / exploit pattern.

## Lab constraint: no MS Office installed

Since the rule matches on the **path string** containing e.g. `winword.exe` (not a digital signature), simulation is done by renaming a copy of `powershell.exe` into a fake Office-like path and using it as the "parent" process.

## Test Case 1: Office → PowerShell (rule 100302)

```powershell
New-Item -ItemType Directory -Path "C:\FakeOffice\Office16" -Force
Copy-Item "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\FakeOffice\Office16\WINWORD.EXE"

Start-Process "C:\FakeOffice\Office16\WINWORD.EXE" -ArgumentList "-command `"Start-Process powershell.exe -ArgumentList '-command Write-Host test'`""
```

Clean up:
```powershell
Remove-Item "C:\FakeOffice" -Recurse -Force
```

**Expected:** rule **100302** fires, `parentImage` = fake WINWORD.EXE path, `image` = `powershell.exe`.

## Test Case 2: Browser → PowerShell (rule 100303)

```powershell
New-Item -ItemType Directory -Path "C:\FakeBrowser" -Force
Copy-Item "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\FakeBrowser\chrome.exe"

Start-Process "C:\FakeBrowser\chrome.exe" -ArgumentList "-command `"Start-Process powershell.exe -ArgumentList '-command Write-Host test'`""
```

Clean up:
```powershell
Remove-Item "C:\FakeBrowser" -Recurse -Force
```

**Expected:** rule **100303** fires.

## Test Case 3: PDF reader → PowerShell (rule 100304)

```powershell
New-Item -ItemType Directory -Path "C:\FakePDF" -Force
Copy-Item "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\FakePDF\AcroRd32.exe"

Start-Process "C:\FakePDF\AcroRd32.exe" -ArgumentList "-command `"Start-Process powershell.exe -ArgumentList '-command Write-Host test'`""
```

Clean up:
```powershell
Remove-Item "C:\FakePDF" -Recurse -Force
```

**Expected:** rule **100304** fires.

## Negative Test: Normal, unrelated parent process

```powershell
powershell.exe -command "Write-Host test"
```
Run directly from a terminal (parent = `explorer.exe`/`cmd.exe`, not Office/browser/PDF).

**Expected:** no 100302/100303/100304 alert — confirms the rule is lineage-specific, not a general PowerShell trigger.

## Verification

```bash
sudo grep -a "100302\|100303\|100304" /var/ossec/logs/alerts/alerts.json | tail -n 5
```

Live:
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -a --line-buffered -E "100302|100303|100304"
```

## Dashboard check

```
rule.id: (100302 OR 100303 OR 100304)
```

## IMPORTANT — documented limitation

Successfully triggering the "Office" rule by renaming `powershell.exe` to `WINWORD.EXE` reveals a genuine detection gap: the rule matches on filename/path string alone, not digital signature or binary hash. A real attacker could exploit this same weakness in reverse (renaming a malicious binary to evade a blocklist). A production-grade version of this rule should additionally validate `Hashes`/`OriginalFileName` (both captured by Sysmon) rather than trusting the `Image` path alone.
