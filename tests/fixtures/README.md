# Deterministic Scanner Fixture Corpus

This directory contains the source generator for the `src\Scan-PythonPackages.ps1` v1.6 test corpus. The generated files live under `tests/fixtures/corpus/` and are used by the Pester suite to validate the fixture manifest schema and declared scanner expectations, including findings, JSON summaries, SBOMs, binary inspection, notebook parsing, and unsupported files for folder fixtures.

Regenerate the corpus from any working directory:

```powershell
python tests\fixtures\build_fixtures.py
```

The generator wipes `corpus/` before rebuilding it, then writes archives, loose Python files, Jupyter notebooks, negative folders, malformed inputs, and `manifest.json`.

## Determinism

Fixtures are deterministic by design: generated random values use fixed seeds, ZIP and TAR members use fixed timestamps, archive members are added in sorted order, and native-binary fixtures are generated from deterministic PE/ELF builders. Running the generator twice without source changes should produce byte-identical corpus contents.

## Safety Notes

The AWS access key string is the public documented test value `AKIAIOSFODNN7EXAMPLE`; it is not a real credential.

The vulnerable `Requires-Dist` values reference real CVE-bearing dependency versions so `pip-audit` has stable targets to report. The wheels themselves contain no vulnerable package code. These dependency declarations are stub metadata strings and do not install or vendor the referenced packages.

All analyzer triggers are syntactic fixtures only. The corpus contains no real malware, exploit payloads, or credentials. Notebook fixtures are static `.ipynb` JSON files used to validate code-cell projection, saved-output/attachment warnings, and malformed-notebook failure behavior.

## Manifest Schema

The manifest schema is versioned. The current `manifest.json` uses:

```json
{
  "schemaVersion": "1.6",
  "scannerVersionTarget": "1.6.0"
}
```

Pester tests assert this schema version when loading the manifest. Fixture entries include expected text findings, JSON-summary expectations, SBOM presence/component-count expectations, binary-inspection expectations, notebook-parser expectations, and optional `expectedUnsupportedFiles` arrays for v1.6.0 scanner expectations.
