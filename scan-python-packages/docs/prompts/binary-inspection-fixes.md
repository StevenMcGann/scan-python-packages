# Fix: Binary Inspection Review Items

Three fixes from code review of the binary inspection feature. All are small and localized.

## Fix 1 — Write JSON to temp file instead of stdout (robustness)

### Problem

`Invoke-BinaryInspection` in `src/Scan-PythonPackages.ps1` (around line 940) captures Python output with `2>&1` and parses the entire captured output as JSON:

```powershell
$inspectOut = & $PythonExe $inspector $binaryPath 2>&1
# ...
$jsonText = ($inspectOut | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
$raw = $jsonText | ConvertFrom-Json
```

If Python or its libraries write anything to stderr (deprecation warnings, import warnings), that text gets mixed into `$inspectOut` and corrupts the JSON parsing. The binary gets silently skipped. The other scanners (Bandit, detect-secrets, pip-audit) all avoid this by writing output to a temp file.

### Fix

**In `src/inspect_binary.py`:** Change `main()` to accept an optional second argument for the output file path. If provided, write JSON there instead of stdout. If not provided, still write to stdout for backward compatibility and manual testing.

```python
def main(argv: list[str]) -> int:
    if len(argv) < 2 or len(argv) > 3:
        print(json.dumps({"error": "usage: inspect_binary.py <path> [output_json]"}))
        return 2
    path = Path(argv[1]).resolve()
    result = json.dumps(inspect(path), sort_keys=True)
    if len(argv) == 3:
        Path(argv[2]).write_text(result, encoding="utf-8")
    else:
        print(result)
    return 0
```

**In `src/Scan-PythonPackages.ps1`:** Update `Invoke-BinaryInspection` to pass a temp file path and read from it, matching the Bandit/pip-audit pattern:

```powershell
$tmpJson = Join-Path $env:TEMP "binary_$([IO.Path]::GetRandomFileName()).json"
try {
    $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $inspectOut = & $PythonExe $inspector $binaryPath $tmpJson 2>&1
    $ErrorActionPreference = $prevEAP
    foreach ($line in $inspectOut) { Write-Log -Level DEBUG -Msg "binary-inspect: $([string]$line)" }

    if (Test-Path $tmpJson) {
        $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
        foreach ($finding in @($raw.findings)) {
            # ... same finding mapping as now ...
        }
    } else {
        Write-Log -Level WARN -Msg "Binary inspection produced no output file for $binaryPath."
    }
} catch {
    Write-Log -Level WARN -Msg "Binary inspection error for ${binaryPath}: $_"
} finally {
    Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
}
```

Note the use of `finally` for cleanup (matching Bandit's pattern) and that `$ErrorActionPreference` is restored immediately after the native call on the very next line (also matching Bandit's pattern). The separate `if ($prevEAP)` restore in the old catch block is no longer needed.

## Fix 2 — Eliminate `-0.0` entropy values (cosmetic)

### Problem

In `src/inspect_binary.py`, the `entropy()` function returns `-0.0` instead of `0.0` for single-byte data. This is a floating point artifact: when a section has exactly one byte, the Shannon entropy formula computes `-(1.0 * log2(1.0))` = `-(1.0 * 0.0)` = `-0.0`. This shows up in JSON reports as `-0.0`.

### Fix

In `src/inspect_binary.py`, add a single line at the end of the `entropy()` function to clamp negative zero:

```python
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    ent = -sum((count / total) * math.log(count / total, 2) for count in counts if count)
    return ent if ent > 0.0 else 0.0
```

The change: assign to `ent` instead of returning directly, then return `ent if ent > 0.0 else 0.0`. This turns `-0.0` into `0.0` while leaving all positive entropy values unchanged.

## Files to modify

- `src/inspect_binary.py` — both fixes (temp file output + entropy clamp)
- `src/Scan-PythonPackages.ps1` — `Invoke-BinaryInspection` function only (temp file pattern + finally block)

## What NOT to change

- Test fixtures, manifest, changelog, version — no changes needed for these fixes.
- The Pester tests for `Invoke-BinaryInspection` should continue to pass without modification since the function's external behavior (input parameters and return shape) is unchanged.
