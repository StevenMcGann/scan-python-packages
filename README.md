# Scan-PythonPackages

[![Smoke Tests](https://github.com/StevenMcGann/scan-python-packages/actions/workflows/smoke.yml/badge.svg)](https://github.com/StevenMcGann/scan-python-packages/actions/workflows/smoke.yml)
[![Security](https://github.com/StevenMcGann/scan-python-packages/actions/workflows/security.yml/badge.svg)](https://github.com/StevenMcGann/scan-python-packages/actions/workflows/security.yml)

`Scan-PythonPackages.ps1` is a Windows PowerShell 5.1 static security scanner for Python packages submitted through a media transfer review workflow. It is designed for operator-driven inspection o[...]

## What This Is

- A static-analysis wrapper around Bandit, detect-secrets, pip-audit, and native binary inspection (PE/ELF triage).
- An operator-host tool: reviewers run it against a submission folder and keep the generated report with that submission.
- A developer-host project: maintainers can regenerate deterministic fixtures, run Pester tests, and run smoke checks before cutting a release.

## What This Is Not

- It is not a sandbox, detonation chamber, runtime monitor, or malware analysis platform.
- It does not execute submitted package code.
- It does not install or import submitted packages; dependency checks use submitted metadata such as `Requires-Dist`.

## Operator Quickstart

Download the GitHub Release zip for the current version and extract it to a writable tools folder. The runtime package must contain both files below in the same directory:

```text
Scan-PythonPackages.ps1
inspect_binary.py
```

`inspect_binary.py` is required for v1.5+ native binary inspection. If it is missing, the scanner still runs, but PE/ELF binary triage is skipped and the log contains `Binary inspection helper not[...]

From a Windows PowerShell 5.1 prompt:

```powershell
# Interactive release-package usage: prompts for a submission folder
.\Scan-PythonPackages.ps1

# Non-interactive release-package usage: scan a specific folder
.\Scan-PythonPackages.ps1 -Path "D:\incoming\submission_2026-04-30"

# Unattended release-package usage: install missing scanner tools without prompting
.\Scan-PythonPackages.ps1 -Path "D:\incoming\submission_2026-04-30" -AutoInstall
```

When running from a developer checkout instead of the release zip, use `.\src\Scan-PythonPackages.ps1`; the required helper is already beside it at `.\src\inspect_binary.py`.

Reports are written to the scanned folder's `.reports\` directory. Runtime logs and the scanner virtual environment live beside the script directory.

## Developer Quickstart

```powershell
git clone <repo-url>
cd scan-python-packages

# Generate deterministic fixtures consumed by Pester
python tests\fixtures\build_fixtures.py

# Run the fast test suite
.\tests\Run-Tests.ps1

# Run the full local regression smoke harness
.\tests\Run-Smoke.ps1
```

`Run-Smoke.ps1` writes timestamped review artifacts under `test-results\`; that directory is intentionally ignored by git.

## Documentation

- Current release notes and operator documentation: [docs/release-notes/v1.5.2.md](docs/release-notes/v1.5.2.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)

## Versioning And Releases

The scanner version is set in the `.NOTES` block of `src\Scan-PythonPackages.ps1`, marked with an annotated git tag such as `v1.5`, and shipped through a GitHub Release. Future backlog items shoul[...]

## License

This project is licensed under the [MIT License](LICENSE).
