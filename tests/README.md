# Scan-PythonPackages — Automated Test Suite

Pester v5 integration and unit tests for `src\Scan-PythonPackages.ps1`.

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell 5.1 | Minimum runtime — no PowerShell 7+ idioms used |
| Pester 5.x | `Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser` |
| Python 3.x on PATH | Required only for `Compare-Versions` tests (see below) |

## How to run

From any PowerShell 5.1 prompt, with the repo root as working directory:

```powershell
.\tests\Run-Tests.ps1
```

Or invoke Pester directly for more control:

```powershell
Invoke-Pester .\tests\Scan-PythonPackages.Tests.ps1 -Output Detailed
```

## Test coverage

| Describe block | Type | What it exercises |
|---|---|---|
| `Compare-Versions` | Integration | 16 cases: exact match, semver above/below, PEP 440 pre-releases (`rc1`, `a1`, `b2`, `.dev0`), post-releases (`.post1`), local-version (`+local.1`), epochs (`2!1.0.0`), empty inputs, garbage strings, missing executable |
| `Get-RiskLevel` | Unit | HIGH / MEDIUM / LOW / CLEAN ladder; HIGH-wins-over-MEDIUM in mixed array; empty-array returns CLEAN |
| `Get-PackageUnits archive-extension classification` | Unit | `.whl`, `.egg`, `.zip`, `.tgz` land in `simpleArchiveExts`; `.tar.gz` lands in `compoundArchiveSuffs`; counts verified |
| `Find-Python` | Unit (mocked) | All three candidates fail → returns `$null`; `py` succeeds with "Python 3.11.4" → returns `'py'` |

## Tests that skip when Python is unavailable

All tests inside `Describe 'Compare-Versions'` (except the "Python not available" context itself) call `Set-ItResult -Skipped` with a clear message when no Python 3 interpreter is found on PATH. The rest of the suite runs unconditionally.

The `Compare-Versions` tests create a small throw-away venv under `$TestDrive` (Pester's temporary filesystem) so they do not touch `<script-dir>\.scan-venv` or any other production path.
