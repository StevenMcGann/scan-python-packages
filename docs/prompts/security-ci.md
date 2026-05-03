# Task: Add Nightly Security Scanning CI Workflow

Add a GitHub Actions workflow that performs nightly security checks against the project's own code and dependencies. This is a new workflow file — do not modify any existing workflows.

## Context

This project is a PowerShell 5.1 static security scanner for Python packages. It lives at `src/Scan-PythonPackages.ps1` with a Python helper at `src/inspect_binary.py`. The scanner depends on several Python packages (`bandit`, `pip-audit`, `detect-secrets`, `pefile`, `pyelftools`) that are installed into a virtual environment at runtime.

The project already has two CI workflows:

- `.github/workflows/test.yml` — runs Pester tests on push/PR (Windows runner, Python 3.11)
- `.github/workflows/smoke.yml` — runs the full smoke suite nightly at 06:00 UTC (Windows runner, Python 3.11)

Both use `actions/checkout@v4` and `actions/setup-python@v5`.

## What to Create

### File: `.github/workflows/security.yml`

Create a single new workflow file with the following exact specification.

### Workflow Metadata

```yaml
name: Security
on:
  workflow_dispatch:
  schedule:
    # Nightly at 07:00 UTC (one hour after smoke suite)
    - cron: '0 7 * * *'
```

### Job 1: `dependency-audit`

**Purpose:** Check the project's own Python dependencies for known CVEs.

**Runner:** `windows-latest`

**Steps (in this exact order):**

1. **Checkout** — `actions/checkout@v4`

2. **Set up Python** — `actions/setup-python@v5` with `python-version: '3.11'`

3. **Create scanner venv and install dependencies** — shell: `powershell`
   ```powershell
   python -m venv .scan-venv
   .\.scan-venv\Scripts\python.exe -m pip install --upgrade pip
   .\.scan-venv\Scripts\python.exe -m pip install bandit pip-audit detect-secrets pefile pyelftools
   ```

4. **Run pip-audit against scanner dependencies** — shell: `powershell`
   ```powershell
   $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
   $auditOutput = .\.scan-venv\Scripts\pip-audit.exe --strict --desc on 2>&1
   $exitCode = $LASTEXITCODE
   $ErrorActionPreference = $prevEAP

   $textOutput = ($auditOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
   $textOutput | Out-File -FilePath pip-audit-results.txt -Encoding utf8

   Write-Host $textOutput

   if ($exitCode -ne 0) {
       Write-Host "::error::pip-audit found vulnerabilities in scanner dependencies"
       exit 1
   }
   ```
   **Important:** The `$ErrorActionPreference` save/restore pattern is required for PowerShell 5.1 compatibility when capturing native command stderr with `2>&1`. Without it, PS 5.1 wraps stderr lines as `NativeCommandError` objects, which can cause the step to fail before reaching the exit-code check.

5. **Upload pip-audit results** — `actions/upload-artifact@v4`, condition: `if: always()`
   ```yaml
   with:
     name: pip-audit-results
     path: pip-audit-results.txt
     retention-days: 30
   ```

### Job 2: `secret-scan`

**Purpose:** Scan the repository for accidentally committed secrets, tokens, or credentials.

**Runner:** `windows-latest`

**Steps (in this exact order):**

1. **Checkout** — `actions/checkout@v4`

2. **Set up Python** — `actions/setup-python@v5` with `python-version: '3.11'`

3. **Install detect-secrets** — shell: `powershell`
   ```powershell
   python -m pip install detect-secrets
   ```

4. **Run detect-secrets scan** — shell: `powershell`
   ```powershell
   $prevEAP = $ErrorActionPreference
   $ErrorActionPreference = 'Continue'
   $output = python -m detect_secrets scan --all-files --no-verify --exclude-files 'tests[\\/]fixtures[\\/]' --exclude-files '\.git[\\/]' 2>&1
   $ErrorActionPreference = $prevEAP

   $jsonText = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
   $jsonText | Out-File -FilePath detect-secrets-results.json -Encoding utf8

   $parsed = $jsonText | ConvertFrom-Json
   $resultMembers = $parsed.results.PSObject.Properties
   $fileCount = @($resultMembers).Count

   if ($fileCount -gt 0) {
       Write-Host "::warning::detect-secrets found potential secrets in $fileCount file(s)"
       foreach ($member in $resultMembers) {
           $filePath = $member.Name
           foreach ($finding in @($member.Value)) {
               Write-Host "::warning file=$filePath,line=$($finding.line_number)::$($finding.type)"
           }
       }
       # Exit 0 — secrets are warnings, not failures, to avoid false positives
       # blocking the pipeline. Review the uploaded artifact.
   } else {
       Write-Host "No secrets detected."
   }
   ```
   **Important:** This step must NOT fail the workflow. Secret detection has a high false-positive rate (test fixtures contain intentional fake secrets). The step writes GitHub Actions warning annotations so findings are visible in the workflow summary, but the exit code is always 0.

5. **Upload detect-secrets results** — `actions/upload-artifact@v4`, condition: `if: always()`
   ```yaml
   with:
     name: detect-secrets-results
     path: detect-secrets-results.json
     retention-days: 30
   ```

### Job 3: `powershell-analysis`

**Purpose:** Run PSScriptAnalyzer against all PowerShell files for security and code quality findings.

**Runner:** `windows-latest`

**Steps (in this exact order):**

1. **Checkout** — `actions/checkout@v4`

2. **Install PSScriptAnalyzer** — shell: `powershell`
   ```powershell
   Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck -Scope CurrentUser
   ```

3. **Run PSScriptAnalyzer** — shell: `powershell`
   ```powershell
   $results = @()
   $psFiles = Get-ChildItem -Path . -Include '*.ps1','*.psm1','*.psd1' -Recurse -File |
       Where-Object { $_.FullName -notmatch '[\\/]\.scan-venv[\\/]' -and
                      $_.FullName -notmatch '[\\/]test-results[\\/]' }

   foreach ($file in $psFiles) {
       $findings = Invoke-ScriptAnalyzer -Path $file.FullName -Severity Warning,Error -Recurse:$false `
           -ExcludeRule @('PSAvoidUsingWriteHost', 'PSUseSingularNouns')
       if ($findings) {
           $results += $findings
       }
   }

   if ($results.Count -gt 0) {
       Write-Host "PSScriptAnalyzer found $($results.Count) finding(s):"
       Write-Host ""

       $results | Format-Table -Property Severity,RuleName,ScriptName,Line,Message -AutoSize -Wrap

       # Write GitHub Actions annotations
       foreach ($r in $results) {
           $level = if ($r.Severity -eq 'Error') { 'error' } else { 'warning' }
           Write-Host "::${level} file=$($r.ScriptPath),line=$($r.Line)::[$($r.RuleName)] $($r.Message)"
       }

       # Export results
       $results | Select-Object Severity,RuleName,ScriptName,Line,Column,Message |
           ConvertTo-Json -Depth 3 | Out-File -FilePath psscriptanalyzer-results.json -Encoding utf8

       # Fail only on Error-severity findings
       $errors = @($results | Where-Object { $_.Severity -eq 'Error' })
       if ($errors.Count -gt 0) {
           Write-Host "::error::PSScriptAnalyzer found $($errors.Count) Error-severity finding(s)"
           exit 1
       }
   } else {
       Write-Host "PSScriptAnalyzer: no findings."
       '[]' | Out-File -FilePath psscriptanalyzer-results.json -Encoding utf8
   }
   ```

4. **Upload PSScriptAnalyzer results** — `actions/upload-artifact@v4`, condition: `if: always()`
   ```yaml
   with:
     name: psscriptanalyzer-results
     path: psscriptanalyzer-results.json
     retention-days: 30
   ```

### Job 4: `python-analysis`

**Purpose:** Run Bandit against the project's own Python code (inspect_binary.py, build_fixtures.py).

**Runner:** `windows-latest`

**Steps (in this exact order):**

1. **Checkout** — `actions/checkout@v4`

2. **Set up Python** — `actions/setup-python@v5` with `python-version: '3.11'`

3. **Install Bandit** — shell: `powershell`
   ```powershell
   python -m pip install bandit
   ```

4. **Run Bandit against project Python files** — shell: `powershell`
   ```powershell
   $pyFiles = @(
       'src/inspect_binary.py',
       'tests/fixtures/build_fixtures.py'
   )

   $banditTargets = ($pyFiles | Where-Object { Test-Path $_ }) -join ' '

   if (-not $banditTargets) {
       Write-Host "No Python files found to scan."
       '[]' | Out-File -FilePath bandit-results.json -Encoding utf8
       exit 0
   }

   $prevEAP = $ErrorActionPreference
   $ErrorActionPreference = 'Continue'
   $output = python -m bandit -f json -ll $banditTargets 2>&1
   $exitCode = $LASTEXITCODE
   $ErrorActionPreference = $prevEAP

   $jsonLines = @()
   $stderrLines = @()
   foreach ($line in $output) {
       $s = [string]$line
       if ($s.TrimStart().StartsWith('{') -or $s.TrimStart().StartsWith('"') -or
           $s.TrimStart().StartsWith('[') -or $s.TrimStart().StartsWith(']') -or
           $jsonLines.Count -gt 0) {
           $jsonLines += $s
       } else {
           $stderrLines += $s
       }
   }

   foreach ($line in $stderrLines) { Write-Host "bandit-stderr: $line" }

   $jsonText = $jsonLines -join [Environment]::NewLine
   $jsonText | Out-File -FilePath bandit-results.json -Encoding utf8

   if ($exitCode -ne 0) {
       $parsed = $jsonText | ConvertFrom-Json
       $count = @($parsed.results).Count
       if ($count -gt 0) {
           Write-Host "::warning::Bandit found $count finding(s) in project Python code"
           foreach ($r in @($parsed.results)) {
               Write-Host "::warning file=$($r.filename),line=$($r.line_number)::[$($r.test_id)] $($r.issue_text) (severity: $($r.issue_severity), confidence: $($r.issue_confidence))"
           }
       }
       # Warning only — do not fail the workflow.
       # Bandit exits non-zero when it finds any issues, even LOW/LOW.
       exit 0
   } else {
       Write-Host "Bandit: no findings."
   }
   ```

5. **Upload Bandit results** — `actions/upload-artifact@v4`, condition: `if: always()`
   ```yaml
   with:
     name: bandit-results
     path: bandit-results.json
     retention-days: 30
   ```

## Failure Policy Summary

The workflow should fail (block the green checkmark) only for clear, actionable security issues:

| Job | Fails on | Warns on |
|---|---|---|
| `dependency-audit` | Any known CVE in scanner dependencies | — |
| `secret-scan` | Never (too many false positives from test fixtures) | Any detected secret |
| `powershell-analysis` | Error-severity PSScriptAnalyzer findings | Warning-severity findings |
| `python-analysis` | Never (Bandit findings in our code are informational) | Any Bandit finding |

## All Four Jobs Are Independent

All four jobs run in parallel. They have no dependencies on each other. Use this structure:

```yaml
jobs:
  dependency-audit:
    runs-on: windows-latest
    steps: [...]
  secret-scan:
    runs-on: windows-latest
    steps: [...]
  powershell-analysis:
    runs-on: windows-latest
    steps: [...]
  python-analysis:
    runs-on: windows-latest
    steps: [...]
```

## Files to Create

- `.github/workflows/security.yml` — the complete workflow described above

## Files to NOT Modify

- `.github/workflows/test.yml` — do not touch
- `.github/workflows/smoke.yml` — do not touch
- `src/Scan-PythonPackages.ps1` — do not touch
- `src/inspect_binary.py` — do not touch
- `tests/` — do not touch
- `CHANGELOG.md` — do not touch
- `README.md` — do not touch

## Verification

After creating the workflow file, verify by reading it back and confirming:

1. The file is valid YAML (proper indentation, no tabs — use 2-space indent throughout).
2. All four jobs are present: `dependency-audit`, `secret-scan`, `powershell-analysis`, `python-analysis`.
3. Each job uses `runs-on: windows-latest`.
4. Each job has an `Upload` step with `if: always()` and `retention-days: 30`.
5. The `schedule` cron is `'0 7 * * *'` (07:00 UTC).
6. The `on` trigger includes both `workflow_dispatch` and `schedule`.
7. Every `shell: powershell` directive is present on steps that contain PowerShell code.
8. The `$ErrorActionPreference` save/restore pattern is used in the `secret-scan` and `python-analysis` jobs (required for PowerShell 5.1 compatibility when capturing native command output with `2>&1`).
