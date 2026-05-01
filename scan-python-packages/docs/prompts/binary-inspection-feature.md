# Feature: Triage-Level Binary Inspection for Native Artifacts

## Context

`scan-python-packages` is a PowerShell 5.1 static security scanner for Python packages. The main script is `src/Scan-PythonPackages.ps1` (~1425 lines). It orchestrates external Python-based tools (Bandit, detect-secrets, pip-audit) installed in an isolated venv at `<script-dir>/.scan-venv/`, plus a native binary presence check.

Currently, the `Find-NativeBinaries` function (line ~898) only detects the *presence* of `.pyd`, `.so`, and `.dll` files and reports `NATIVE-BINARY` findings at MEDIUM severity. It gives operators no information about what those binaries actually contain. This feature replaces that shallow check with triage-level binary inspection that tells operators whether a binary looks routine or suspicious.

## What to Build

A Python analysis script (`src/inspect_binary.py`) that the PowerShell scanner calls for each native binary found during extraction. The script analyzes PE files (`.pyd`, `.dll`) and ELF files (`.so`) and outputs structured JSON findings.

### Analysis Capabilities

For **PE files** (`.pyd`, `.dll`) using the `pefile` library:

1. **Format validation** — confirm the file is a valid PE. If it isn't (corrupt/truncated), emit a HIGH finding.
2. **Digital signature check** — report whether the PE has an Authenticode signature present in the security directory. Do NOT attempt signature chain validation (that requires Windows APIs and network access). Just report signed vs unsigned as an informational attribute, not a finding.
3. **Import table analysis** — extract imported DLLs and API functions. Flag suspicious imports at HIGH severity using a curated list:
   - **Process manipulation**: `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `OpenProcess`, `NtCreateThreadEx`
   - **Code injection**: `SetWindowsHookEx`, `QueueUserAPC`, `RtlCreateUserThread`
   - **Evasion/anti-analysis**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`
   - **Network (unexpected in Python extensions)**: Imports from `ws2_32.dll`, `winhttp.dll`, `wininet.dll` — flag at MEDIUM
   - **Registry/credential access**: `RegOpenKeyEx`, `CredRead`, `CryptUnprotectData` — flag at MEDIUM
4. **Section analysis** — iterate PE sections and calculate Shannon entropy for each. Flag sections with entropy > 7.0 at MEDIUM severity (suggests packing/encryption). Also flag unusual section names (anything other than `.text`, `.data`, `.rdata`, `.bss`, `.rsrc`, `.reloc`, `.edata`, `.idata`, `.pdata`, `.tls`, `.CRT`).

For **ELF files** (`.so`) using `pyelftools`:

1. **Format validation** — confirm valid ELF. If corrupt, emit HIGH finding.
2. **Dynamic imports** — extract needed shared libraries from `.dynamic` section. Flag suspicious libraries at MEDIUM:
   - `libcurl`, `libssl` (unexpected for pure Python C extensions)
   - `libpthread` alone is fine, but combined with network libraries raise severity
3. **Section analysis** — same entropy check (> 7.0) and unusual section name flagging as PE, adapted for ELF conventions (normal: `.text`, `.data`, `.bss`, `.rodata`, `.symtab`, `.strtab`, `.dynsym`, `.dynstr`, `.rel.*`, `.rela.*`, `.plt`, `.got`, `.init`, `.fini`, `.note.*`, `.eh_frame`).
4. **Symbol table** — if `.symtab` is stripped (common for release builds), note it as informational. Not a finding on its own.

### Output Format

The Python script receives a single file path as argument and writes JSON to stdout:

```json
{
  "file": "/path/to/extension.pyd",
  "format": "PE",
  "valid": true,
  "signed": false,
  "sections": [
    {"name": ".text", "entropy": 6.2, "suspicious": false},
    {"name": ".packed", "entropy": 7.8, "suspicious": true}
  ],
  "imports": {
    "kernel32.dll": ["LoadLibraryA", "GetProcAddress"],
    "python311.dll": ["PyInit_extension"]
  },
  "findings": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "testId": "BINARY-SUSPICIOUS-IMPORT",
      "issue": "Suspicious import: CreateRemoteThread from kernel32.dll (process injection capability)"
    },
    {
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "testId": "BINARY-HIGH-ENTROPY",
      "issue": "Section '.packed' has entropy 7.8 (threshold 7.0) — possible packing or encryption"
    }
  ]
}
```

When the file is not a valid PE/ELF:

```json
{
  "file": "/path/to/garbage.pyd",
  "format": "UNKNOWN",
  "valid": false,
  "findings": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "testId": "BINARY-INVALID-FORMAT",
      "issue": "File has .pyd extension but is not a valid PE binary — may be disguised or corrupt"
    }
  ]
}
```

### TestID Values

Use these exact test IDs for consistency in reports and test expectations:

- `BINARY-INVALID-FORMAT` — file doesn't match expected PE/ELF format (HIGH)
- `BINARY-SUSPICIOUS-IMPORT` — known-bad API import detected (HIGH)
- `BINARY-NETWORK-IMPORT` — unexpected network library import (MEDIUM)
- `BINARY-SENSITIVE-IMPORT` — registry/credential API import (MEDIUM)
- `BINARY-HIGH-ENTROPY` — section entropy > 7.0 (MEDIUM)
- `BINARY-UNUSUAL-SECTION` — non-standard section name (LOW)
- `BINARY-STRIPPED-SYMBOLS` — ELF symbol table stripped (informational, LOW)

## Integration into PowerShell Scanner

### 1. New dependencies

Add `pefile` and `pyelftools` to the `$SCANNER_PACKAGES` array and `$SCANNER_MIN_VERSIONS` hashtable in the CONFIGURATION block (line ~63):

```powershell
$SCANNER_PACKAGES = @(
    'bandit',
    'pip-audit',
    'detect-secrets',
    'pefile',
    'pyelftools'
)

$SCANNER_MIN_VERSIONS = @{
    'bandit'         = '1.7.0'
    'pip-audit'      = '2.0.0'
    'detect-secrets' = '1.4.0'
    'pefile'         = '2023.2.7'
    'pyelftools'     = '0.29'
}
```

### 2. Replace Find-NativeBinaries

Replace the existing `Find-NativeBinaries` function (line ~898) with a new `Invoke-BinaryInspection` function. Follow the same pattern as `Invoke-BanditScan`:

- Accept `$ScriptsDir` (for the venv Python) and `$TargetPath`.
- Find all `.pyd`, `.so`, `.dll` files in `$TargetPath` recursively.
- For each file, call the Python script: `& $venvPython src/inspect_binary.py <filepath>`
- Capture JSON from stdout, parse with `ConvertFrom-Json`.
- Map each entry in the `findings` array to the standard finding PSCustomObject shape:

```powershell
[PSCustomObject]@{
    Tool       = 'BinaryInspection'
    Severity   = $finding.severity
    Confidence = $finding.confidence
    File       = $binaryPath
    Line       = 0
    Issue      = $finding.issue
    TestID     = $finding.testId
}
```

- Use the established PS 5.1 ErrorActionPreference save/restore pattern for the native command call (the `$prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'` pattern used throughout the script).
- If the Python script is not found or fails, log a WARN and return `@()` — graceful degradation, same as all other scanners.

### 3. Update the scan loop

In the main scan loop (line ~1371), replace:

```powershell
foreach ($f in (Find-NativeBinaries  -TargetPath $scanTarget)) { $findings.Add($f) }
```

with:

```powershell
foreach ($f in (Invoke-BinaryInspection -ScriptsDir $venv.Scripts -TargetPath $scanTarget -PythonExe $venv.Python)) { $findings.Add($f) }
```

### 4. Update report TOOL COVERAGE block

In `Write-SummaryReport` (line ~1084), update the NativeBinaryChk line:

```
  BinaryInspect : Native binary triage (format validation, imports, entropy, signatures)
```

## Test Fixtures

### Update `tests/fixtures/build_fixtures.py`

The existing native binary fixtures use `seeded_bytes("pyd", 64)` — just random bytes. These need to be replaced with minimal but structurally valid PE and ELF binaries so the inspection script has something real to analyze.

Create helper functions that build minimal valid binaries:

1. **`make_minimal_pe(imports=None)`** — build a minimal valid PE (MZ header, PE signature, COFF header, optional header, `.text` section). If `imports` is provided, add an import directory with the specified DLL/function entries. This doesn't need to be executable — it just needs valid structure that `pefile` can parse.

2. **`make_minimal_elf(needed_libs=None)`** — build a minimal valid ELF (ELF header, `.text` section, optionally `.dynamic` section with `DT_NEEDED` entries). Same principle — valid enough for `pyelftools` to parse.

3. **`make_packed_pe_section()`** — build a PE with a section named `.packed` filled with high-entropy (compressed/random) data.

Update the existing native binary wheel specs to use real binaries:

```python
# Clean native binary — valid PE, no suspicious imports
("native_pyd_pkg-1.0-py3-none-any.whl", "native_pyd_pkg",
 {"native_pyd_pkg/__init__.py": "pass\n",
  "native_pyd_pkg/extension.pyd": make_minimal_pe()}, [], True),

# Clean .so — valid ELF, no suspicious imports
("native_so_pkg-1.0-py3-none-any.whl", "native_so_pkg",
 {"native_so_pkg/__init__.py": "pass\n",
  "native_so_pkg/extension.so": make_minimal_elf()}, [], True),

# Clean .dll — valid PE, normal imports only
("native_dll_pkg-1.0-py3-none-any.whl", "native_dll_pkg",
 {"native_dll_pkg/__init__.py": "pass\n",
  "native_dll_pkg/helper.dll": make_minimal_pe(imports={"kernel32.dll": ["GetModuleHandleA"]})}, [], True),
```

Add NEW fixture wheels for suspicious binaries:

```python
# Suspicious imports — PE with process injection APIs
("suspicious_imports_pkg-1.0-py3-none-any.whl", "suspicious_imports_pkg",
 {"suspicious_imports_pkg/__init__.py": "pass\n",
  "suspicious_imports_pkg/payload.pyd": make_minimal_pe(
      imports={"kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]})},
 [], True),

# Network imports — PE importing ws2_32.dll
("network_native_pkg-1.0-py3-none-any.whl", "network_native_pkg",
 {"network_native_pkg/__init__.py": "pass\n",
  "network_native_pkg/net.pyd": make_minimal_pe(
      imports={"ws2_32.dll": ["connect", "send", "recv"]})},
 [], True),

# High entropy section — packed/encrypted PE
("packed_native_pkg-1.0-py3-none-any.whl", "packed_native_pkg",
 {"packed_native_pkg/__init__.py": "pass\n",
  "packed_native_pkg/packed.pyd": make_packed_pe_section()},
 [], True),

# Invalid binary — .pyd extension but not a PE
("fake_native_pkg-1.0-py3-none-any.whl", "fake_native_pkg",
 {"fake_native_pkg/__init__.py": "pass\n",
  "fake_native_pkg/fake.pyd": seeded_bytes("fake-pyd", 64)},
 [], True),
```

Update the manifest `fixtures` list with corresponding expectations:

- `native_pyd_pkg`: expectedRisk `CLEAN` (valid PE, no suspicious imports — the `NativeBinaryCheck` MEDIUM findings go away since we now inspect rather than just flag presence)
- `native_so_pkg`: expectedRisk `CLEAN`
- `native_dll_pkg`: expectedRisk `CLEAN`
- `suspicious_imports_pkg`: expectedRisk `HIGH`, expectedFindings with tool `BinaryInspection`, testId `BINARY-SUSPICIOUS-IMPORT`
- `network_native_pkg`: expectedRisk `MEDIUM`, expectedFindings with tool `BinaryInspection`, testId `BINARY-NETWORK-IMPORT`
- `packed_native_pkg`: expectedRisk `MEDIUM`, expectedFindings with tool `BinaryInspection`, testId `BINARY-HIGH-ENTROPY`
- `fake_native_pkg`: expectedRisk `HIGH`, expectedFindings with tool `BinaryInspection`, testId `BINARY-INVALID-FORMAT`

**Important**: All binary generation must remain deterministic. Use `seeded_bytes()` for any random/entropy data. All timestamps and metadata must use fixed values from the existing constants (`FIXED_ZIP_DT`, `FIXED_EPOCH`, `RANDOM_SEED`).

## Pester Tests

Add test coverage in `tests/Scan-PythonPackages.Tests.ps1`:

### Fixture manifest tests

Update the existing `'Includes analyzer expectations for all scanner tools'` test to include `BinaryInspection` in the expected tools list:

```powershell
$tools | Should -Contain 'BinaryInspection'
```

Update the fixture count assertion to match the new total (was 27, will increase by the number of new fixtures added).

### Unit tests for Invoke-BinaryInspection

Add a `Describe 'Invoke-BinaryInspection'` block with:

- **Valid PE with no findings** — run against the `native_pyd_pkg` fixture's extracted `.pyd`, verify it returns 0 findings (or only informational ones).
- **Suspicious imports** — run against the `suspicious_imports_pkg` fixture's extracted `.pyd`, verify HIGH findings with testId `BINARY-SUSPICIOUS-IMPORT`.
- **Invalid format** — run against the `fake_native_pkg` fixture's `.pyd` (random bytes), verify HIGH finding with testId `BINARY-INVALID-FORMAT`.
- **Missing script graceful degradation** — pass a nonexistent `$ScriptsDir`, verify it returns `@()` and doesn't throw.

These are integration tests that require Python + pefile/pyelftools. Use the same skip pattern as Compare-Versions: `if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }`.

## CI Changes

Update `.github/workflows/test.yml` to install `pefile` and `pyelftools` in the test runner after the fixture generation step (or include them in the fixture builder's requirements if used there).

Update `.github/workflows/smoke.yml` similarly — the scanner's `Install-ScannerDependencies` should handle this automatically during smoke runs since the new packages are in `$SCANNER_PACKAGES`, but verify this works.

## Version and Changelog

- Bump the version in the `.NOTES` block of `src/Scan-PythonPackages.ps1` from `1.4` to `1.5`.
- Update `CHANGELOG.md` with a `## [Unreleased]` section (or `## [1.5]` if we're releasing immediately) documenting:
  - **Added**: Triage-level binary inspection for `.pyd`, `.so`, `.dll` artifacts using `pefile` and `pyelftools`. Analyzes format validity, digital signatures, import tables, and section entropy.
  - **Changed**: `Find-NativeBinaries` replaced by `Invoke-BinaryInspection`. Native binaries now produce specific, actionable findings instead of generic presence warnings. Tool name in findings changed from `NativeBinaryCheck` to `BinaryInspection`.
  - **Changed**: `$SCANNER_PACKAGES` expanded with `pefile` and `pyelftools` dependencies.
- Update the fixture manifest `schemaVersion` and `scannerVersionTarget` to `1.5`.
- Update the JSON report `scannerVersion` to `1.5`.

## Files to Create or Modify

**Create:**
- `src/inspect_binary.py` — the Python analysis script

**Modify:**
- `src/Scan-PythonPackages.ps1` — new function, updated config, updated scan loop, updated report text
- `tests/fixtures/build_fixtures.py` — PE/ELF builder helpers, new fixture wheels, updated manifest
- `tests/Scan-PythonPackages.Tests.ps1` — new test blocks, updated manifest assertions
- `CHANGELOG.md` — release notes for v1.5

**Do NOT modify:**
- `tests/Run-Smoke.ps1` — should work without changes since it validates via the JSON report shape
- `.github/workflows/smoke.yml` — scanner auto-installs deps during smoke runs
- `README.md` — update separately after feature is validated

## Design Constraints

1. **PowerShell 5.1 compatibility** — all PS code must work under PS 5.1. Use the `$prevEAP` save/restore pattern for all native command calls with `2>&1`.
2. **Deterministic fixtures** — all generated test binaries must produce identical bytes across runs. Use the existing `seeded_bytes()`, `FIXED_ZIP_DT`, `FIXED_EPOCH`, and `RANDOM_SEED` constants.
3. **Graceful degradation** — if `pefile`/`pyelftools` aren't installed or the script fails, log a warning and return empty findings. Never crash the scan.
4. **No code execution** — the inspector must never execute or load the binary. Pure static parsing only.
5. **Finding object shape** — all findings must use the exact PSCustomObject shape with `Tool`, `Severity`, `Confidence`, `File`, `Line`, `Issue`, `TestID` properties, matching all other scanners.
6. **The Python script must work when called from the venv Python** — it imports `pefile` and `pyelftools` which are installed in the scanner venv. The PowerShell function calls it via `& $venv.Python src/inspect_binary.py <path>`.
