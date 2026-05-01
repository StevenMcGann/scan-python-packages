# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Project layout migrated to git with `src/`, `tests/`, `docs/`, and `.github/workflows/`. Versioned filenames (`Scan-PythonPackages_v1_3`, `_v1_4`) replaced by a single canonical `src/Scan-PythonPackages.ps1` with version tracked via `.NOTES` and git tags.

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
