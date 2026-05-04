# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.5.2] - 2026-05-03

### Changed

- Documented the v1.5+ runtime package layout: `Scan-PythonPackages.ps1` and `inspect_binary.py` must be distributed together in the same directory.
- Restored release-note/operator-documentation detail about package contents, install layout, binary-inspection prerequisites, troubleshooting, and release zip usage.
- Updated release packaging expectation from a single script asset to a zip containing both required runtime files.

### Fixed

- Prevented operators from unknowingly downloading only `Scan-PythonPackages.ps1` and losing native binary inspection coverage because `inspect_binary.py` was absent.

## [1.5.1] - 2026-05-03

### Changed

- Added explicit read-only GitHub Actions token permissions to CI workflows.
- Published nightly smoke `INDEX.md` content into the GitHub Actions job summary so results can be reviewed without downloading artifacts.
- Bumped scanner patch version to `1.5.1` for the cleanup release.

### Fixed

- Removed generated Python bytecode from source control and ignored future `__pycache__` / `.pyc` artifacts.
- Corrected the canonical scanner synopsis to use `Scan-PythonPackages.ps1` instead of a version-suffixed filename.
- Made scanner venv bootstrap upgrades use `python -m pip` so pip/setuptools/wheel updates are not rejected by the `pip.exe` wrapper.

## [1.5] - 2026-05-01

### Added

- Triage-level binary inspection for `.pyd`, `.so`, and `.dll` artifacts using `pefile` and `pyelftools`. The scanner now analyzes format validity, digital signatures, import tables, and section entropy.

### Changed

- Project layout migrated to git with `src/`, `tests/`, `docs/`, and `.github/workflows/`. Versioned filenames (`Scan-PythonPackages_v1_3`, `_v1_4`) replaced by a single canonical `src/Scan-PythonPackages.ps1` with version tracked via `.NOTES` and git tags.
- `Find-NativeBinaries` replaced by `Invoke-BinaryInspection`. Native binaries now produce specific, actionable findings instead of generic presence warnings. Tool name in findings changed from `NativeBinaryCheck` to `BinaryInspection`.
- `$SCANNER_PACKAGES` expanded with `pefile` and `pyelftools` dependencies.

### Fixed

- Binary inspection writes JSON to a temp file instead of stdout, preventing stderr pollution from corrupting results (matches Bandit/pip-audit pattern).
- Shannon entropy function no longer returns `-0.0` for single-byte data.

## [1.4] - 2026-04-30

### Added

- Unsupported-file detection pass that reports non-scannable files in text and JSON summaries.
- `mixed\` fixture coverage and manifest `expectedUnsupportedFiles` expectations.
- `tests\Run-Smoke.ps1` full smoke/regression harness with timestamped review artifacts.

### Changed

- Unsupported-only folders now produce a CLEAN report with a warning block instead of exiting without artifacts.
- Fixture manifest schema bumped to `1.4`.

### Fixed

- Re-scan behavior excludes scanner-owned `.reports\` artifacts from unsupported-file warnings.

### Removed

- Operator visibility into skipped files removed from backlog because v1.4 implements it.

## [1.3] - 2026-04-29

### Added

- Pester 5 test harness under `tests/`.
- Deterministic fixture corpus generator and manifest contract for scanner expectations.
- Machine-readable JSON summary report written beside the operator `.txt` report.
- Per-archive CycloneDX SBOM output for archives with `Requires-Dist` metadata.

### Changed

- Scanner main execution guarded so Pester can dot-source functions without launching a scan.
- pip-audit uses static `Requires-Dist` declarations with `--no-deps --disable-pip`.

### Fixed

- PowerShell 5.1 native-command stderr capture is wrapped with the established EAP restore pattern.
- detect-secrets JSON capture avoids stderr pollution and uses defensive strict-mode property checks.

### Removed

- Legacy scan-root workspace behavior; staging and scanner venv are outside submitted folders.

## [1.2] - earlier

### Added

- GA scanner layout with shared `.scan-venv`, central `logs`, temp extraction staging, and scan-root `.reports`.
- Static analyzer orchestration for Bandit, detect-secrets, pip-audit, and native binary checks.

### Changed

- Installation layout separated runtime dependencies, run logs, extraction staging, and operator reports by lifecycle.

### Fixed

- PEP 440 version comparison replaced fragile `[System.Version]` parsing.

### Removed

- Pre-GA `.scan_workspace` layout from scan targets.
