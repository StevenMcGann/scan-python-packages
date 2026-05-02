# Scan-PythonPackages

`Scan-PythonPackages.ps1` is a Windows PowerShell 5.1 static security scanner for Python packages submitted through a media transfer review workflow. It is designed for operator-driven inspection of untrusted Python artifacts before they are admitted to a trusted environment.

## What This Is

- A static-analysis wrapper around Bandit, detect-secrets, pip-audit, and native binary inspection (PE/ELF triage).
- An operator-host tool: reviewers run it against a submission folder and keep the generated report with that submission.
- A developer-host project: maintainers can regenerate deterministic fixtures, run Pester tests, and run smoke checks before cutting a release.

## What This Is Not

- It is not a sandbox, detonation chamber, runtime monitor, or malware analysis platform.
- It does not execute submitted package code.
- It does not install or import submitted packages; dependency checks use submitted metadata such as `Requires-Dist`.

## Operator Quickstart

From a Windows PowerShell 5.1 prompt:

```powershell
# Interactive: prompts for a submission folder
.\src\Scan-PythonPackages.ps1

# Non-interactive: scan a specific folder
.\src\Scan-PythonPackages.ps1 -Path "D:\incoming\submission_2026-04-30"

# Unattended: install missing scanner tools without prompting
.\src\Scan-PythonPackages.ps1 -Path "D:\incoming\submission_2026-04-30" -AutoInstall
```

Reports are written to the scanned folder's `.reports\` directory. Runtime logs and the scanner virtual environment live beside the repository root when the script is run from this checkout.

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

- Current release notes: [docs/release-notes/v1.5.md](docs/release-notes/v1.5.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)

## Versioning And Releases

The scanner version is set in the `.NOTES` block of `src\Scan-PythonPackages.ps1`, marked with an annotated git tag such as `v1.5`, and shipped through a GitHub Release. Future backlog items should be developed on feature branches and merged into the canonical file instead of creating new version-suffixed script filenames.

## License

This project is licensed under the [MIT License](LICENSE).
