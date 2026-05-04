#Requires -Version 5.1
<#
.SYNOPSIS
    Scan-PythonPackages.ps1 - Static security scanner for submitted Python packages.

.DESCRIPTION
    Designed for media transfer review workflows where untrusted Python packages
    are submitted for inspection before use. This script:

      1. Checks and installs required scanning tools (Bandit, pip-audit, detect-secrets, pefile, pyelftools).
      2. Prompts the operator for a folder containing Python packages to scan.
      3. Extracts archives (.whl, .egg, .zip, .tar.gz, .tgz) into a staging workspace.
      4. Scans all Python source code for:
           - Risky code patterns (Bandit)
           - Hardcoded secrets / credentials (detect-secrets)
           - Known CVE vulnerabilities in dependencies (pip-audit)
           - Native binary triage (.pyd, .so, .dll)
      5. Surfaces unsupported files in the scan root so operators can review skipped content.
      6. Writes a flat human-readable summary report for operator review.
      7. Writes a timestamped run log for troubleshooting and audit purposes.

    All analysis is STATIC — no package code is executed at any point.

.PARAMETER Path
    Optional. Path to the folder containing packages to scan.
    If omitted, the operator is prompted interactively.

.PARAMETER AutoInstall
    Optional switch. If provided, scanner tools are installed automatically
    without prompting. Useful for unattended/scheduled runs.

.NOTES
    Author      : Generated for media transfer security review workflow
    Version     : 1.5.2
    Requires    : PowerShell 5.1+, Python 3.x (with pip), internet access for tool install
    Output      : <scan-root>\.reports\summary_<timestamp>.txt           (operator report)
                  <scan-root>\.reports\summary_<timestamp>.json          (machine-readable, same timestamp)
                  <scan-root>\.reports\sbom_<timestamp>_<unit>.cdx.json  (CycloneDX SBOM, one per archive with metadata)
    Venv        : <script-dir>\.scan-venv\  (created once, reused for all scans)
    Logs        : <script-dir>\logs\run_<timestamp>.log
    Staging     : %TEMP%\python-scanner-<timestamp>\  (extraction staging, deleted after each run)
    PS 5.1 note : Native-command stderr captured via 2>&1 produces ErrorRecord objects
                  that trigger $ErrorActionPreference = 'Stop'. All native-command calls
                  in this script temporarily set EAP to 'Continue' before capturing output
                  and restore it immediately after.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$Path,

    [switch]$AutoInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# CONFIGURATION
# ============================================================

# Scanner pip packages to install/verify
$SCANNER_PACKAGES = @(
    'bandit',
    'pip-audit',
    'detect-secrets',
    'pefile',
    'pyelftools'
)

# Minimum acceptable versions (empty string = no version check)
$SCANNER_MIN_VERSIONS = @{
    'bandit'         = '1.7.0'
    'pip-audit'      = '2.0.0'
    'detect-secrets' = '1.4.0'
    'pefile'         = '2023.2.7'
    'pyelftools'     = '0.29'
}

# File extensions treated as extractable archives
$ARCHIVE_EXTENSIONS = @('.whl', '.egg', '.zip', '.tar.gz', '.tgz')

# File extensions treated as direct Python source
$PYTHON_SOURCE_EXTENSIONS = @('.py', '.pyw')

# ============================================================
# LOGGING SETUP
# Will be fully initialized after Path is confirmed.
# ============================================================

$Script:LogPath = $null

function Write-Log {
    <#
    .SYNOPSIS
        Write a timestamped entry to both the console and the run log file.
    .PARAMETER Level
        INFO | WARN | ERROR | DEBUG
    .PARAMETER Msg
        Message text to record.
    #>
    param(
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO',
        [string]$Msg
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry     = "[$timestamp] [$Level] $Msg"

    # Write to log file if initialized
    if ($Script:LogPath) {
        Add-Content -LiteralPath $Script:LogPath -Value $entry -Encoding UTF8
    }

    # Console color by level
    switch ($Level) {
        'INFO'  { Write-Host $entry -ForegroundColor Cyan }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
        'DEBUG' { Write-Host $entry -ForegroundColor DarkGray }
    }
}

# ============================================================
# OPERATOR STATUS MESSAGES
# Separate from logging — these are the operator-facing messages
# that appear on screen during the run (progress indicators).
# ============================================================

function Show-Status {
    <#
    .SYNOPSIS
        Display a short operator-facing status line on the console.
        Not written to the log (log has its own detail).
    #>
    param([string]$Msg)
    Write-Host ""
    Write-Host "  >> $Msg" -ForegroundColor White
}

function Show-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host "   Python Package Security Scanner — Media Transfer Review" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-Done {
    param([string]$ReportPath)
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkGreen
    Write-Host "   SCAN COMPLETE" -ForegroundColor Green
    Write-Host "   Report saved to:" -ForegroundColor Green
    Write-Host "   $ReportPath" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor DarkGreen
    Write-Host ""
}

# ============================================================
# DEPENDENCY FUNCTIONS
# ============================================================

function Find-Python {
    <#
    .SYNOPSIS
        Locate a usable Python 3 executable on the system.
        Tries the Windows py launcher first, then 'python', then 'python3'.
    .OUTPUTS
        String path/command for Python, or $null if not found.
    #>
    Write-Log -Level DEBUG -Msg "Searching for Python executable..."

    foreach ($candidate in @('py', 'python', 'python3')) {
        try {
            Get-Command $candidate -ErrorAction Stop | Out-Null
            # Verify it's Python 3
            $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
            try {
                $ver = & $candidate --version 2>&1
            } finally {
                $ErrorActionPreference = $prevEAP
            }
            if ($ver -match 'Python 3\.') {
                Write-Log -Level INFO -Msg "Found Python: $candidate -> $ver"
                return $candidate
            } else {
                Write-Log -Level DEBUG -Msg "$candidate returned '$ver' — not Python 3, skipping."
            }
        } catch {
            Write-Log -Level DEBUG -Msg "$candidate not found on PATH."
        }
    }

    return $null
}

function Get-VenvPaths {
    <#
    .SYNOPSIS
        Return a hashtable of paths inside the scanner virtual environment.
    .PARAMETER VenvDir
        Root directory of the venv.
    #>
    param([string]$VenvDir)

    return @{
        Root    = $VenvDir
        Pip     = Join-Path $VenvDir 'Scripts\pip.exe'
        Python  = Join-Path $VenvDir 'Scripts\python.exe'
        Scripts = Join-Path $VenvDir 'Scripts'
    }
}

function Initialize-ScannerVenv {
    <#
    .SYNOPSIS
        Create (or reuse) an isolated virtual environment for scanner tools.
        Avoids polluting the system Python installation.
    .PARAMETER PythonCmd
        The Python command to use (e.g. 'py', 'python').
    .PARAMETER VenvDir
        Full path to the venv directory. Created on first run; reused thereafter.
        Intentionally lives next to the script, not in the scan target folder,
        so tools are installed once and shared across all scans.
    #>
    param(
        [string]$PythonCmd,
        [string]$VenvDir
    )

    if (Test-Path $VenvDir) {
        Write-Log -Level INFO -Msg "Reusing existing scanner venv: $VenvDir"
    } else {
        Write-Log -Level INFO -Msg "Creating scanner venv at: $VenvDir"
        try {
            # PS 5.1: set Continue so stderr-as-ErrorRecord from 2>&1 does not trigger Stop
            $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
            $venvOut = & $PythonCmd -m venv $VenvDir 2>&1
            $ErrorActionPreference = $prevEAP
            foreach ($line in $venvOut) { Write-Log -Level DEBUG -Msg ([string]$line) }
        } catch {
            Write-Log -Level ERROR -Msg "Failed to create venv: $_"
            throw
        }
    }

    $paths = Get-VenvPaths -VenvDir $VenvDir

    if (-not (Test-Path $paths.Pip)) {
        Write-Log -Level ERROR -Msg "pip not found in venv at $($paths.Pip). Venv may be corrupt."
        throw "pip missing from venv"
    }

    return $paths
}

function Get-InstalledPackageVersion {
    <#
    .SYNOPSIS
        Query pip for the installed version of a package.
    .OUTPUTS
        Version string, or $null if not installed.
    #>
    param(
        [string]$PipExe,
        [string]$PackageName
    )

    try {
        $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
        try {
            $output = & $PipExe show $PackageName 2>&1
        } finally {
            $ErrorActionPreference = $prevEAP
        }
        $verLine = $output | Where-Object { $_ -match '^Version:' }
        if ($verLine) {
            return ($verLine -replace '^Version:\s*', '').Trim()
        }
    } catch {
        # Package not installed
    }
    return $null
}

function Compare-Versions {
    <#
    .SYNOPSIS
        PEP 440-compliant version comparison. Returns $true if $Installed >= $Minimum.
    .DESCRIPTION
        Delegates to Python's packaging.version.Version — using the standalone
        'packaging' module if installed, falling back to the vendored copy at
        pip._vendor.packaging.version (which is bundled inside pip itself and is
        therefore present in any venv created via 'python -m venv'). This means
        pre-releases (1.7.0rc1), post-releases (1.7.0.post1), dev releases
        (1.7.0.dev0), local version identifiers (1.7.0+local.1), and epochs
        (2!1.0.0) are all ordered correctly per PEP 440 instead of silently
        failing through [System.Version].
    .PARAMETER PythonExe
        Path to the venv Python executable. Required — the comparison runs there.
    .PARAMETER Installed
        The currently installed version string.
    .PARAMETER Minimum
        The minimum acceptable version string. Empty/null means no check.
    .OUTPUTS
        Boolean. $true when Installed >= Minimum (or when no minimum is set).
        $false when Installed < Minimum, when either version is unparseable, or
        when the comparison cannot be run — i.e. the function fails closed so
        an unparseable version forces a reinstall rather than silently passing.
    #>
    param(
        [string]$PythonExe,
        [string]$Installed,
        [string]$Minimum
    )

    if (-not $Minimum)   { return $true  }
    if (-not $Installed) { return $false }

    if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
        Write-Log -Level WARN -Msg "Compare-Versions: Python executable not available — cannot perform PEP 440 comparison. Treating as below minimum."
        return $false
    }

    # Tiny Python program: exit 0 if Installed >= Minimum, 1 if <, 2 on parse error,
    # 3 if 'packaging' is missing. packaging.version is shipped as a transitive
    # dependency of pip itself, so it is present in any venv created with -m venv.
    # Try standalone 'packaging' first; fall back to pip's vendored copy which is
    # always present in any venv that has pip (even before standalone packaging is installed).
    $pyScript = @"
import sys
try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    try:
        from pip._vendor.packaging.version import Version, InvalidVersion
    except ImportError as e:
        print(f'ImportError: {e}', file=sys.stderr)
        sys.exit(3)
try:
    a = Version(sys.argv[1])
    b = Version(sys.argv[2])
except InvalidVersion as e:
    print(f'InvalidVersion: {e}', file=sys.stderr)
    sys.exit(2)
sys.exit(0 if a >= b else 1)
"@

    try {
        # PS 5.1: Python may write to stderr; Continue prevents false termination
        $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
        $output = & $PythonExe -c $pyScript $Installed $Minimum 2>&1
        $ErrorActionPreference = $prevEAP
        $code   = $LASTEXITCODE

        if ($output) {
            foreach ($line in $output) { Write-Log -Level DEBUG -Msg "version-compare: $([string]$line)" }
        }

        switch ($code) {
            0 { return $true }
            1 { return $false }
            2 {
                Write-Log -Level WARN -Msg "Compare-Versions: '$Installed' or '$Minimum' is not a valid PEP 440 version. Treating as below minimum."
                return $false
            }
            3 {
                Write-Log -Level WARN -Msg "Compare-Versions: 'packaging' module not importable from $PythonExe. Treating as below minimum."
                return $false
            }
            default {
                Write-Log -Level WARN -Msg "Compare-Versions: unexpected exit code $code from version compare. Treating as below minimum."
                return $false
            }
        }
    } catch {
        Write-Log -Level WARN -Msg "Compare-Versions: comparison failed for '$Installed' vs '${Minimum}': $_. Treating as below minimum."
        return $false
    }
}

function Install-ScannerDependencies {
    <#
    .SYNOPSIS
        Check each required scanner tool. Install or update as needed.
        Requires internet access to reach PyPI.
    .PARAMETER PipExe
        Path to pip inside the scanner venv.
    .PARAMETER PythonExe
        Path to python.exe inside the scanner venv. Used by Compare-Versions
        to perform PEP 440-compliant version checks against the minimum-version
        floors in $SCANNER_MIN_VERSIONS.
    .PARAMETER AutoInstall
        If $true, install without prompting. Otherwise prompt operator.
    #>
    param(
        [string]$PipExe,
        [string]$PythonExe,
        [bool]$AutoInstall
    )

    Write-Log -Level INFO -Msg "Upgrading pip/setuptools/wheel in scanner venv..."
    Show-Status "Updating pip..."
    # Use python -m pip for bootstrap upgrades because pip refuses to
    # replace itself when launched through the generated pip.exe wrapper.
    $upgradeOut = @()
    $upgradeExit = 0
    $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
    try {
        $upgradeOut = & $PythonExe -m pip install --upgrade pip setuptools wheel 2>&1
        $upgradeExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    foreach ($line in $upgradeOut) { Write-Log -Level DEBUG -Msg ([string]$line) }
    if ($upgradeExit -ne 0) {
        Write-Log -Level WARN -Msg "Bootstrap package upgrade exited with code $upgradeExit; continuing with per-tool verification."
    }

    foreach ($pkg in $SCANNER_PACKAGES) {
        $installedVer = Get-InstalledPackageVersion -PipExe $PipExe -PackageName $pkg
        $minVer       = $SCANNER_MIN_VERSIONS[$pkg]

        if ($installedVer -and (Compare-Versions -PythonExe $PythonExe -Installed $installedVer -Minimum $minVer)) {
            Write-Log -Level INFO -Msg "$pkg is installed (version $installedVer) — OK."
        } else {
            if ($installedVer) {
                Write-Log -Level WARN -Msg "$pkg installed ($installedVer) is below minimum ($minVer). Updating..."
            } else {
                Write-Log -Level WARN -Msg "$pkg is not installed."
            }

            $doInstall = $AutoInstall
            if (-not $doInstall) {
                $response = Read-Host "  Install/update '$pkg' now? (Y/N)"
                $doInstall = $response -match '^[Yy]'
            }

            if ($doInstall) {
                Show-Status "Installing $pkg..."
                Write-Log -Level INFO -Msg "Installing/updating $pkg via pip..."
                try {
                    # PS 5.1: Continue prevents pip's stderr warnings from falsely terminating
                    $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
                    try {
                        $installOut = & $PythonExe -m pip install --upgrade $pkg 2>&1
                    } finally {
                        $ErrorActionPreference = $prevEAP
                    }
                    foreach ($line in $installOut) { Write-Log -Level DEBUG -Msg ([string]$line) }
                } catch {
                    Write-Log -Level WARN -Msg "pip emitted errors during install of ${pkg}: $_"
                }
                # Confirm success by re-querying version — pip exit code is not reliable here
                $newVer = Get-InstalledPackageVersion -PipExe $PipExe -PackageName $pkg
                if (-not ($newVer -and (Compare-Versions -PythonExe $PythonExe -Installed $newVer -Minimum $SCANNER_MIN_VERSIONS[$pkg]))) {
                    Write-Log -Level ERROR -Msg "Failed to install ${pkg} (version check failed)."
                    throw "Dependency installation failed for $pkg. Check internet connectivity and try again."
                }
                Write-Log -Level INFO -Msg "$pkg installed successfully (version $newVer)."
            } else {
                Write-Log -Level WARN -Msg "Skipping $pkg — some scan capabilities will be unavailable."
            }
        }
    }
}

# ============================================================
# FILE COLLECTION & EXTRACTION
# ============================================================

function Get-PackageUnits {
    <#
    .SYNOPSIS
        Discover all Python packages and source files in the scan root folder.
        Returns a list of objects with Kind (archive|pyfile) and Path.
    #>
    param([string]$ScanRoot)

    Write-Log -Level INFO -Msg "Collecting package units from: $ScanRoot"
    $units = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Find archives — uses $ARCHIVE_EXTENSIONS from the configuration block above.
    # Extensions with one dot segment (.whl, .zip, .tgz) match via $ext comparison.
    # Compound suffixes with two dot segments (.tar.gz) must match via EndsWith on the
    # full filename because Get-Item .Extension only returns the final segment (.gz).
    $simpleArchiveExts    = $ARCHIVE_EXTENSIONS | Where-Object { ($_ -split '\.').Count -le 2 }
    $compoundArchiveSuffs = $ARCHIVE_EXTENSIONS | Where-Object { ($_ -split '\.').Count -gt 2 }

    $archiveFiles = @(Get-ChildItem -LiteralPath $ScanRoot -Recurse -File |
        Where-Object {
            $name = $_.Name.ToLower()
            $ext  = $_.Extension.ToLower()
            ($ext -in $simpleArchiveExts) -or
            ($compoundArchiveSuffs | Where-Object { $name.EndsWith($_) })
        })

    foreach ($f in $archiveFiles) {
        $units.Add([PSCustomObject]@{ Kind = 'archive'; Path = $f.FullName; Name = $f.Name })
        Write-Log -Level DEBUG -Msg "Found archive: $($f.FullName)"
    }

    # Find loose Python source files (not inside archives)
    $pyFiles = @(Get-ChildItem -LiteralPath $ScanRoot -Recurse -File |
        Where-Object { $_.Extension.ToLower() -in $PYTHON_SOURCE_EXTENSIONS })

    $pyFilesAdded = 0
    foreach ($f in $pyFiles) {
        $pyFilesAdded++
        $units.Add([PSCustomObject]@{ Kind = 'pyfile'; Path = $f.FullName; Name = $f.Name })
        Write-Log -Level DEBUG -Msg "Found Python source: $($f.FullName)"
    }

    Write-Log -Level INFO -Msg "Total units found: $($units.Count) ($($archiveFiles.Count) archives, $pyFilesAdded source files)"
    return $units
}

function Find-UnsupportedFiles {
    <#
    .SYNOPSIS
        Identify files in the scan root that are not supported scanner inputs.
    .PARAMETER ScanRoot
        Root folder being scanned. The function walks this folder recursively,
        excluding the scanner-owned .reports directory.
    .OUTPUTS
        Array of PSCustomObject entries with Path, RelativePath, Extension,
        and SizeBytes for each unsupported file.
    #>
    param([string]$ScanRoot)

    Write-Log -Level INFO -Msg "Checking for unsupported files in: $ScanRoot"
    $unsupported = [System.Collections.Generic.List[PSCustomObject]]::new()

    $scanRootFull = (Resolve-Path -LiteralPath $ScanRoot).Path.TrimEnd('\')

    # Exclude the scanner's own report directory so re-scanning a folder does
    # not flag prior summary, JSON, SBOM, or log artifacts as operator input.
    $reportsRoot   = Join-Path $scanRootFull '.reports'
    $reportsPrefix = ([System.IO.Path]::GetFullPath($reportsRoot)).TrimEnd('\') + '\'

    # Reuse the same simple-extension and compound-suffix split as
    # Get-PackageUnits so supported archives like pkg.tar.gz are not mistaken
    # for unsupported .gz files.
    $simpleArchiveExts    = $ARCHIVE_EXTENSIONS | Where-Object { ($_ -split '\.').Count -le 2 }
    $compoundArchiveSuffs = $ARCHIVE_EXTENSIONS | Where-Object { ($_ -split '\.').Count -gt 2 }

    foreach ($f in @(Get-ChildItem -LiteralPath $ScanRoot -Recurse -File -ErrorAction SilentlyContinue)) {
        $fullPath = $f.FullName
        if ($fullPath.StartsWith($reportsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $name = $f.Name.ToLower()
        $ext  = $f.Extension.ToLower()
        $isArchive = ($ext -in $simpleArchiveExts) -or (@($compoundArchiveSuffs | Where-Object { $name.EndsWith($_) }).Count -gt 0)
        $isPythonSource = $ext -in $PYTHON_SOURCE_EXTENSIONS

        if (-not $isArchive -and -not $isPythonSource) {
            $relativePath = $fullPath.Substring($scanRootFull.Length).TrimStart('\')
            $unsupported.Add([PSCustomObject]@{
                Path         = $fullPath
                RelativePath = $relativePath
                Extension    = $ext
                SizeBytes    = [int64]$f.Length
            })
        }
    }

    # Sort for deterministic text and JSON output, making re-runs and tests stable.
    return @($unsupported.ToArray() | Sort-Object RelativePath)
}

function Expand-PythonArchive {
    <#
    .SYNOPSIS
        Extract a Python package archive (.whl, .egg, .zip, .tar.gz, .tgz)
        into a staging directory for scanning.
    .PARAMETER InputFile
        Full path to the archive file.
    .PARAMETER OutputDir
        Directory to extract into.
    .PARAMETER FallbackPython
        Python executable for tarball fallback if system tar is unavailable.
    #>
    param(
        [string]$InputFile,
        [string]$OutputDir,
        [string]$FallbackPython
    )

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $name    = [IO.Path]::GetFileName($InputFile).ToLower()
    $ext     = [IO.Path]::GetExtension($InputFile).ToLower()
    $isTar   = $name.EndsWith('.tar.gz') -or $name.EndsWith('.tgz')
    $isZip   = $ext -in @('.whl', '.egg', '.zip')

    Write-Log -Level INFO -Msg "Extracting: $InputFile -> $OutputDir"

    try {
        if ($isZip) {
            # Wheels and eggs are ZIP archives. PS 5.1 Expand-Archive only accepts .zip
            # extension, so copy to a temp .zip file first.
            $tmpZip = [IO.Path]::Combine([IO.Path]::GetTempPath(), "$([IO.Path]::GetRandomFileName()).zip")
            Copy-Item -LiteralPath $InputFile -Destination $tmpZip -Force
            try {
                Expand-Archive -LiteralPath $tmpZip -DestinationPath $OutputDir -Force
            } finally {
                Remove-Item -LiteralPath $tmpZip -Force -ErrorAction SilentlyContinue
            }
            Write-Log -Level DEBUG -Msg "Expanded ZIP-type archive OK."
        }
        elseif ($isTar) {
            # Try system tar first (available on Windows 10 1803+)
            $tarCmd = Get-Command 'tar' -ErrorAction SilentlyContinue
            if ($tarCmd) {
                $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
                $tarOut = & tar -xzf $InputFile -C $OutputDir 2>&1
                $ErrorActionPreference = $prevEAP
                foreach ($line in $tarOut) { Write-Log -Level DEBUG -Msg ([string]$line) }
                Write-Log -Level DEBUG -Msg "Expanded tarball with system tar OK."
            } else {
                # Fallback: use Python's tarfile module
                Write-Log -Level WARN -Msg "System tar not found; using Python tarfile fallback."
                $pyScript = @"
import sys, tarfile, os
infile, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
with tarfile.open(infile, 'r:*') as t:
    t.extractall(outdir)
print('OK')
"@
                $tmpScript = Join-Path $env:TEMP "expand_tar_$([IO.Path]::GetRandomFileName()).py"
                Set-Content -LiteralPath $tmpScript -Value $pyScript -Encoding UTF8
                try {
                    $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
                    $pyOut = & $FallbackPython $tmpScript $InputFile $OutputDir 2>&1
                    $ErrorActionPreference = $prevEAP
                    foreach ($line in $pyOut) { Write-Log -Level DEBUG -Msg ([string]$line) }
                } finally {
                    Remove-Item -LiteralPath $tmpScript -Force -ErrorAction SilentlyContinue
                }
            }
        }
        else {
            Write-Log -Level WARN -Msg "Unrecognized archive type for: $InputFile — skipping extraction."
            return $false
        }
    } catch {
        Write-Log -Level ERROR -Msg "Extraction failed for $InputFile : $_"
        return $false
    }

    return $true
}

# ============================================================
# SCANNING FUNCTIONS
# ============================================================

function Invoke-BanditScan {
    <#
    .SYNOPSIS
        Run Bandit static analysis on a directory or file.
        Bandit detects risky Python patterns: eval/exec, pickle, subprocess shell,
        weak crypto, insecure network calls, etc.
    .OUTPUTS
        Parsed finding objects, or empty array.
    #>
    param(
        [string]$ScriptsDir,
        [string]$TargetPath
    )

    $banditExe = Join-Path $ScriptsDir 'bandit.exe'
    if (-not (Test-Path $banditExe)) {
        Write-Log -Level WARN -Msg "Bandit not available — skipping code pattern scan."
        return @()
    }

    Write-Log -Level INFO -Msg "Running Bandit on: $TargetPath"
    $tmpJson = Join-Path $env:TEMP "bandit_$([IO.Path]::GetRandomFileName()).json"

    try {
        # PS 5.1: bandit writes progress to stderr; Continue prevents false termination
        $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
        $banditOut = & $banditExe -r $TargetPath -ll -f json -o $tmpJson 2>&1
        $ErrorActionPreference = $prevEAP
        foreach ($line in $banditOut) { Write-Log -Level DEBUG -Msg "bandit: $([string]$line)" }

        if (Test-Path $tmpJson) {
            $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
            $findings = @()
            foreach ($result in $raw.results) {
                $findings += [PSCustomObject]@{
                    Tool      = 'Bandit'
                    Severity  = $result.issue_severity    # HIGH / MEDIUM / LOW
                    Confidence= $result.issue_confidence
                    File      = $result.filename
                    Line      = $result.line_number
                    Issue     = $result.issue_text
                    TestID    = $result.test_id
                }
            }
            Write-Log -Level INFO -Msg "Bandit: $($findings.Count) finding(s)."
            return $findings
        }
    } catch {
        Write-Log -Level WARN -Msg "Bandit scan error: $_"
    } finally {
        Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
    }

    return @()
}

function Invoke-DetectSecretsScan {
    <#
    .SYNOPSIS
        Run detect-secrets to find hardcoded credentials, tokens, API keys,
        and other secrets in Python source files.
    .OUTPUTS
        Parsed finding objects, or empty array.
    #>
    param(
        [string]$ScriptsDir,
        [string]$TargetPath
    )

    $dsExe = Join-Path $ScriptsDir 'detect-secrets.exe'
    if (-not (Test-Path $dsExe)) {
        Write-Log -Level WARN -Msg "detect-secrets not available — skipping secret scan."
        return @()
    }

    Write-Log -Level INFO -Msg "Running detect-secrets on: $TargetPath"
    $tmpJson = Join-Path $env:TEMP "ds_$([IO.Path]::GetRandomFileName()).json"

    try {
        # detect-secrets outputs JSON to stdout; stderr must not pollute it
        $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
        $scanArg = $TargetPath
        $pushDir = $null
        if (Test-Path -LiteralPath $TargetPath -PathType Leaf) {
            $pushDir = [System.IO.Path]::GetDirectoryName($TargetPath)
            $scanArg = [System.IO.Path]::GetFileName($TargetPath)
        } else {
            $pushDir = $TargetPath
            $scanArg = '.'
        }

        Push-Location -LiteralPath $pushDir
        try {
            & $dsExe scan --all-files --no-verify $scanArg 2>$null | Out-File -FilePath $tmpJson -Encoding UTF8
        } finally {
            Pop-Location
        }
        $ErrorActionPreference = $prevEAP

        if (Test-Path $tmpJson) {
            $raw      = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
            $findings = @()

            if ($raw.PSObject.Properties['results'] -and $raw.results) {
                $resultPaths = @($raw.results.PSObject.Properties | ForEach-Object { $_.Name })
                foreach ($filePath in $resultPaths) {
                    foreach ($secret in $raw.results.$filePath) {
                        $findings += [PSCustomObject]@{
                            Tool      = 'detect-secrets'
                            Severity  = 'HIGH'
                            Confidence= 'MEDIUM'
                            File      = $filePath
                            Line      = $secret.line_number
                            Issue     = "Potential secret detected: $($secret.type)"
                            TestID    = $secret.type
                        }
                    }
                }
            }

            Write-Log -Level INFO -Msg "detect-secrets: $($findings.Count) potential secret(s) found."
            return $findings
        }
    } catch {
        Write-Log -Level WARN -Msg "detect-secrets scan error: $_"
    } finally {
        Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
    }

    return @()
}

function Invoke-PipAuditScan {
    <#
    .SYNOPSIS
        Run pip-audit to check declared dependencies (from package METADATA)
        against the PyPI Advisory Database for known CVEs.
        As a side-effect, also writes a CycloneDX SBOM to SbomPath when provided.
    .PARAMETER SbomPath
        Optional. If provided, pip-audit is run a second time with
        --format cyclonedx-json to produce a CycloneDX SBOM at this path.
        The same temp requirements file is reused for both passes so the
        dependency set is identical. SBOM generation failure is non-fatal —
        a WARN is logged and CVE findings are returned normally.
    .OUTPUTS
        Parsed finding objects, or empty array.
    #>
    param(
        [string]$ScriptsDir,
        [string]$TargetPath,   # Extracted package directory
        [string]$SbomPath = ''
    )

    $auditExe = Join-Path $ScriptsDir 'pip-audit.exe'
    if (-not (Test-Path $auditExe)) {
        Write-Log -Level WARN -Msg "pip-audit not available — skipping CVE dependency audit."
        return @()
    }

    # Extract Requires-Dist from METADATA files
    $metaFiles = Get-ChildItem -LiteralPath $TargetPath -Recurse -File -Include 'METADATA' -ErrorAction SilentlyContinue
    $requires  = @()

    foreach ($mf in $metaFiles) {
        $lines = Get-Content -LiteralPath $mf.FullName -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line -like 'Requires-Dist:*') {
                # Strip environment markers and whitespace
                $dep = ($line -replace '^Requires-Dist:\s*', '') -replace ';.*$', ''
                $dep = $dep.Trim()
                if ($dep) { $requires += $dep }
            }
        }
    }

    $requires = @($requires | Select-Object -Unique)

    if ($requires.Count -eq 0) {
        Write-Log -Level INFO -Msg "No Requires-Dist metadata found — skipping CVE audit."
        return @()
    }

    Write-Log -Level INFO -Msg "Found $($requires.Count) declared dependencies. Running pip-audit..."

    $reqFile = Join-Path $env:TEMP "requires_$([IO.Path]::GetRandomFileName()).txt"
    $tmpJson = Join-Path $env:TEMP "pipaudit_$([IO.Path]::GetRandomFileName()).json"

    try {
        $requires | Out-File -FilePath $reqFile -Encoding ASCII
        # PS 5.1: pip-audit writes progress to stderr; Continue prevents false termination
        $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
        $auditOut = & $auditExe -r $reqFile --no-deps --disable-pip -f json -o $tmpJson 2>&1
        $ErrorActionPreference = $prevEAP
        foreach ($line in $auditOut) { Write-Log -Level DEBUG -Msg "pip-audit: $([string]$line)" }

        $findings = @()
        if (Test-Path $tmpJson) {
            $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
            foreach ($dep in $raw.dependencies) {
                foreach ($vuln in $dep.vulns) {
                    $findings += [PSCustomObject]@{
                        Tool      = 'pip-audit'
                        Severity  = 'HIGH'
                        Confidence= 'HIGH'
                        File      = "dependency: $($dep.name) $($dep.version)"
                        Line      = 0
                        Issue     = "$($vuln.id): $($vuln.description)"
                        TestID    = $vuln.id
                    }
                }
            }
        }

        Write-Log -Level INFO -Msg "pip-audit: $($findings.Count) CVE(s) found."

        # ------------------------------------------------------------------
        # SBOM pass — independent of CVE pass; failure is non-fatal.
        # Reuses the same $reqFile so the dependency set is identical.
        # ------------------------------------------------------------------
        if ($SbomPath) {
            $tmpSbom = Join-Path $env:TEMP "sbom_$([IO.Path]::GetRandomFileName()).json"
            try {
                # PS 5.1: pip-audit writes progress to stderr; Continue prevents false termination
                $prevEAP = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
                $sbomOut = & $auditExe -r $reqFile --no-deps --disable-pip -f cyclonedx-json -o $tmpSbom 2>&1
                $ErrorActionPreference = $prevEAP
                foreach ($line in $sbomOut) { Write-Log -Level DEBUG -Msg "pip-audit sbom: $([string]$line)" }

                if (Test-Path $tmpSbom) {
                    Copy-Item -LiteralPath $tmpSbom -Destination $SbomPath -Force
                    $Script:SbomFiles.Add($SbomPath)
                    Write-Log -Level INFO -Msg "SBOM written: $SbomPath"
                } else {
                    Write-Log -Level WARN -Msg "pip-audit SBOM output not produced for: $TargetPath"
                }
            } catch {
                Write-Log -Level WARN -Msg "pip-audit SBOM generation failed: $_"
            } finally {
                Remove-Item -LiteralPath $tmpSbom -Force -ErrorAction SilentlyContinue
            }
        }

        return $findings
    } catch {
        Write-Log -Level WARN -Msg "pip-audit scan error: $_"
        return @()
    } finally {
        Remove-Item -LiteralPath $reqFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-BinaryInspection {
    <#
    .SYNOPSIS
        Inspect native compiled binaries (.pyd, .so, .dll) inside a package.
        The Python helper performs static triage of PE/ELF format validity,
        imports, signatures, and section entropy.
    .OUTPUTS
        Parsed finding objects, or empty array.
    #>
    param(
        [string]$ScriptsDir,
        [string]$TargetPath,
        [string]$PythonExe = ''
    )

    if (-not $PythonExe) {
        $PythonExe = Join-Path $ScriptsDir 'python.exe'
    }

    if (-not (Test-Path -LiteralPath $PythonExe)) {
        Write-Log -Level WARN -Msg "Binary inspection Python not available — skipping native binary triage."
        return @()
    }

    $inspector = Join-Path $PSScriptRoot 'inspect_binary.py'
    if (-not (Test-Path -LiteralPath $inspector)) {
        Write-Log -Level WARN -Msg "Binary inspection helper not found at $inspector — skipping native binary triage."
        return @()
    }

    Write-Log -Level INFO -Msg "Inspecting native binaries in: $TargetPath"

    $natives = Get-ChildItem -LiteralPath $TargetPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension.ToLower() -in @('.pyd', '.so', '.dll') }

    $findings = @()
    foreach ($n in $natives) {
        $binaryPath = $n.FullName
        $tmpJson = Join-Path $env:TEMP "binary_$([IO.Path]::GetRandomFileName()).json"
        try {
            $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            $inspectOut = & $PythonExe $inspector $binaryPath $tmpJson 2>&1
            $exitCode = $LASTEXITCODE
            $ErrorActionPreference = $prevEAP
            foreach ($line in $inspectOut) { Write-Log -Level DEBUG -Msg "binary-inspect: $([string]$line)" }

            if ($exitCode -ne 0) {
                Write-Log -Level WARN -Msg "Binary inspection failed for $binaryPath with exit code $exitCode."
                continue
            }

            if (-not (Test-Path -LiteralPath $tmpJson)) {
                Write-Log -Level WARN -Msg "Binary inspection produced no output file for $binaryPath."
                continue
            }

            $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
            foreach ($finding in @($raw.findings)) {
                $findings += [PSCustomObject]@{
                    Tool       = 'BinaryInspection'
                    Severity   = $finding.severity
                    Confidence = $finding.confidence
                    File       = $binaryPath
                    Line       = 0
                    Issue      = $finding.issue
                    TestID     = $finding.testId
                }
            }
        } catch {
            Write-Log -Level WARN -Msg "Binary inspection error for ${binaryPath}: $_"
        } finally {
            Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log -Level INFO -Msg "Binary inspection: $($findings.Count) finding(s)."
    return $findings
}

# ============================================================
# REPORT GENERATION
# ============================================================

function Get-RiskLevel {
    <#
    .SYNOPSIS
        Determine an overall risk level from a collection of findings.
    #>
    param([array]$Findings)

    if ($Findings | Where-Object { $_.Severity -eq 'HIGH' }) { return 'HIGH' }
    if ($Findings | Where-Object { $_.Severity -eq 'MEDIUM' }) { return 'MEDIUM' }
    if (@($Findings).Count -gt 0) { return 'LOW' }
    return 'CLEAN'
}

function Write-SummaryReport {
    <#
    .SYNOPSIS
        Generate the flat human-readable summary report for operator review,
        including an unsupported-files warning block when needed.
        The report is structured for non-technical review, with a clear risk
        summary at the top followed by actionable findings.
    .PARAMETER UnsupportedFiles
        Unsupported file entries returned by Find-UnsupportedFiles. When
        present, they are listed near the top of the operator report.
    #>
    param(
        [string]$ReportPath,
        [array]$UnitResults,   # Array of @{Name; Kind; Findings[]}
        [string]$ScanRoot,
        [datetime]$StartTime,
        [array]$UnsupportedFiles = @()
    )

    $endTime  = Get-Date
    $elapsed  = ($endTime - $StartTime).ToString('hh\:mm\:ss')
    $allFindings = @($UnitResults | ForEach-Object { $_.Findings } | Where-Object { $_ })
    $overallRisk = Get-RiskLevel -Findings $allFindings
    $unsupportedList = @($UnsupportedFiles)

    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add("================================================================")
    $lines.Add("  PYTHON PACKAGE SECURITY SCAN — OPERATOR REPORT")
    $lines.Add("================================================================")
    $lines.Add("")
    $lines.Add("  Scan Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("  Scan Folder  : $ScanRoot")
    $lines.Add("  Elapsed Time : $elapsed")
    $lines.Add("  Units Scanned: $($UnitResults.Count)")
    $lines.Add("  Total Findings: $($allFindings.Count)")
    if ($null -ne $Script:SbomFiles -and $Script:SbomFiles.Count -gt 0) {
        foreach ($sbomEntry in $Script:SbomFiles) {
            $lines.Add("  SBOM Written : $sbomEntry")
        }
    } else {
        $lines.Add("  SBOM         : not produced (no declared dependencies)")
    }
    $lines.Add("")

    if ($unsupportedList.Count -gt 0) {
        $lines.Add("================================================================")
        $lines.Add("  !! WARNING: UNSUPPORTED FILES IN SCAN ROOT")
        $lines.Add("================================================================")
        $lines.Add("  $($unsupportedList.Count) file(s) were found in the scan target folder that the")
        $lines.Add("  scanner does not recognize. These were NOT analyzed. Review")
        $lines.Add("  manually if your submission is expected to contain only")
        $lines.Add("  Python packages or source files.")
        $lines.Add("----------------------------------------------------------------")
        $unsupportedIndex = 1
        foreach ($unsupported in $unsupportedList) {
            $lines.Add("  [$unsupportedIndex] $($unsupported.RelativePath)")
            $unsupportedIndex++
        }
        $lines.Add("================================================================")
        $lines.Add("")
    }

    $lines.Add("  OVERALL RISK LEVEL: $overallRisk")
    $lines.Add("")

    # Overall recommendation
    switch ($overallRisk) {
        'HIGH'   {
            $lines.Add("  !! RECOMMENDATION: DO NOT APPROVE without expert security review.")
            $lines.Add("     High-severity findings were detected. Escalate immediately.")
        }
        'MEDIUM' {
            $lines.Add("  !  RECOMMENDATION: Review findings below before approving.")
            $lines.Add("     Medium-severity items may require escalation depending on context.")
        }
        'LOW'    {
            $lines.Add("  *  RECOMMENDATION: Low-severity findings detected.")
            $lines.Add("     Review findings below. Escalate if uncertain.")
        }
        'CLEAN'  {
            $lines.Add("  OK RECOMMENDATION: No security findings detected.")
            $lines.Add("     Packages appear clean based on automated static analysis.")
        }
    }

    $lines.Add("")
    $lines.Add("================================================================")
    $lines.Add("  FINDINGS BY PACKAGE UNIT")
    $lines.Add("================================================================")

    $findingIndex = 1

    foreach ($unit in $UnitResults) {
        $lines.Add("")
        $lines.Add("----------------------------------------------------------------")
        $lines.Add("  UNIT : $($unit.Name)  [$($unit.Kind.ToUpper())]")
        $unitRisk = Get-RiskLevel -Findings $unit.Findings
        $lines.Add("  RISK : $unitRisk")
        $lines.Add("  FINDINGS: $(@($unit.Findings).Count)")
        $lines.Add("----------------------------------------------------------------")

        if (@($unit.Findings).Count -eq 0) {
            $lines.Add("  No findings for this unit.")
        } else {
            foreach ($f in ($unit.Findings | Sort-Object Severity)) {
                $lines.Add("")
                $lines.Add("  [$findingIndex] Severity  : $($f.Severity)")
                $lines.Add("      Tool      : $($f.Tool)")
                $lines.Add("      ID        : $($f.TestID)")
                $lines.Add("      File      : $($f.File)")
                if ($f.Line -gt 0) {
                    $lines.Add("      Line      : $($f.Line)")
                }
                $lines.Add("      Issue     : $($f.Issue)")
                $lines.Add("      Confidence: $($f.Confidence)")
                $findingIndex++
            }
        }
    }

    $lines.Add("")
    $lines.Add("================================================================")
    $lines.Add("  FINDING COUNTS BY SEVERITY")
    $lines.Add("================================================================")
    $lines.Add("")
    $lines.Add("  HIGH   : $(@($allFindings | Where-Object { $_.Severity -eq 'HIGH' }).Count)")
    $lines.Add("  MEDIUM : $(@($allFindings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count)")
    $lines.Add("  LOW    : $(@($allFindings | Where-Object { $_.Severity -eq 'LOW' }).Count)")
    $lines.Add("")
    $lines.Add("================================================================")
    $lines.Add("  TOOL COVERAGE")
    $lines.Add("================================================================")
    $lines.Add("")
    $lines.Add("  Bandit          : Code pattern analysis (eval, pickle, subprocess, weak crypto)")
    $lines.Add("  detect-secrets  : Hardcoded secrets, tokens, API keys, credentials")
    $lines.Add("  pip-audit       : Dependency CVE check against PyPI Advisory Database")
    $lines.Add("  BinaryInspect : Native binary triage (format validation, imports, entropy, signatures)")
    $lines.Add("")
    $lines.Add("  NOTE: This report is based on STATIC analysis only.")
    $lines.Add("        No package code was executed during this scan.")
    $lines.Add("        Native binaries cannot be fully assessed by static analysis.")
    $lines.Add("")
    $lines.Add("================================================================")
    $lines.Add("  END OF REPORT")
    $lines.Add("================================================================")

    $lines | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Log -Level INFO -Msg "Summary report written: $ReportPath"
}

function Write-JsonReport {
    <#
    .SYNOPSIS
        Write a machine-readable JSON report alongside the flat text summary.
        The JSON path is derived from ReportPath by swapping the extension.
        The text summary is not touched by this function.
    .PARAMETER ReportPath
        Full path to the .txt summary (e.g. summary_<timestamp>.txt).
        The JSON sibling is written to the same directory with .json extension.
    .PARAMETER UnitResults
        Same array passed to Write-SummaryReport.
    .PARAMETER ScanRoot
        Absolute path to the scanned folder.
    .PARAMETER StartTime
        Datetime the scan started — used to compute elapsedSeconds.
    .PARAMETER UnsupportedFiles
        Unsupported file entries returned by Find-UnsupportedFiles. The JSON
        report always includes them as unsupportedFiles, even when empty.
    #>
    param(
        [string]$ReportPath,
        [array]$UnitResults,
        [string]$ScanRoot,
        [datetime]$StartTime,
        [array]$UnsupportedFiles = @()
    )

    $jsonPath    = [System.IO.Path]::ChangeExtension($ReportPath, '.json')
    $endTime     = Get-Date
    $elapsedSecs = [math]::Round(($endTime - $StartTime).TotalSeconds, 1)
    $allFindings = @($UnitResults | ForEach-Object { $_.Findings } | Where-Object { $_ })
    $overallRisk = Get-RiskLevel -Findings $allFindings

    # Use Generic.List so we always get a typed array from ToArray(), regardless
    # of how many elements there are — avoids PS 5.1 scalar-unwrap under strict mode.
    $unitList = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($unit in $UnitResults) {
        $unitFindings = @($unit.Findings | Where-Object { $_ })
        $unitRisk     = Get-RiskLevel -Findings $unitFindings

        $findingList = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($f in $unitFindings) {
            $findingList.Add([PSCustomObject]@{
                Tool       = $f.Tool
                Severity   = $f.Severity
                Confidence = $f.Confidence
                File       = $f.File
                Line       = $f.Line
                Issue      = $f.Issue
                TestID     = $f.TestID
            })
        }

        $unitList.Add([PSCustomObject]@{
            name     = $unit.Name
            kind     = $unit.Kind
            risk     = $unitRisk
            findings = $findingList.ToArray()
        })
    }

    # Collect SBOM paths written during this run (may be empty for pyfile-only scans).
    # Use ArrayList rather than a typed string array: PS 5.1's ConvertTo-Json collapses
    # a single-element String[] to a bare string; ArrayList is always serialised as [].
    $sbomArr = New-Object System.Collections.ArrayList
    if ($null -ne $Script:SbomFiles) {
        foreach ($s in $Script:SbomFiles) { [void]$sbomArr.Add($s) }
    }

    # ArrayList avoids PS 5.1 scalar-unwrapping so unsupportedFiles is always []
    # or an array in the machine-readable report.
    $unsupportedArr = New-Object System.Collections.ArrayList
    foreach ($u in @($UnsupportedFiles)) {
        [void]$unsupportedArr.Add([PSCustomObject]@{
            relativePath = $u.RelativePath
            extension    = $u.Extension
            sizeBytes    = $u.SizeBytes
        })
    }

    $report = [PSCustomObject]@{
        schemaVersion  = '1.0'
        scannerVersion = '1.5.2'
        scanDate       = (Get-Date).ToUniversalTime().ToString('o')
        scanRoot       = $ScanRoot
        elapsedSeconds = $elapsedSecs
        overallRisk    = $overallRisk
        totals         = [PSCustomObject]@{
            units    = @($UnitResults).Count
            findings = $allFindings.Count
            high     = @($allFindings | Where-Object { $_.Severity -eq 'HIGH'   }).Count
            medium   = @($allFindings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
            low      = @($allFindings | Where-Object { $_.Severity -eq 'LOW'    }).Count
        }
        sbomFiles        = $sbomArr
        unsupportedFiles = $unsupportedArr
        units            = $unitList.ToArray()
    }

    # PS 5.1's Out-File -Encoding UTF8 writes a BOM; JSON consumers expect BOM-free UTF-8.
    $jsonContent = $report | ConvertTo-Json -Depth 6 -Compress:$false
    [System.IO.File]::WriteAllText($jsonPath, $jsonContent, (New-Object System.Text.UTF8Encoding($false)))
    Write-Log -Level INFO -Msg "JSON report written: $jsonPath"
}

# ============================================================
# MAIN EXECUTION
# ============================================================

if ($MyInvocation.InvocationName -ne '.') {

Show-Banner

$startTime = Get-Date

# ----------------------------------------------------------
# Step 1: Get scan folder from operator
# ----------------------------------------------------------

if (-not $Path) {
    Write-Host "  Enter the full path to the folder containing packages to scan:" -ForegroundColor White
    $Path = Read-Host "  Folder"
}

$Path = $Path.Trim('"').Trim("'")

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host "[ERROR] Path not found: $Path" -ForegroundColor Red
    exit 1
}

$Path = (Resolve-Path -LiteralPath $Path).Path

# ----------------------------------------------------------
# Step 2: Initialize venv, logs, staging, and reports paths
# ----------------------------------------------------------

$venvDir       = Join-Path $PSScriptRoot '.scan-venv'
$logsDir       = Join-Path $PSScriptRoot 'logs'
$timestamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$workspaceDir  = Join-Path $env:TEMP "python-scanner-$timestamp"
$reportsDir    = Join-Path $Path '.reports'

New-Item -ItemType Directory -Force -Path $logsDir     | Out-Null
New-Item -ItemType Directory -Force -Path $workspaceDir | Out-Null
New-Item -ItemType Directory -Force -Path $reportsDir   | Out-Null

$Script:LogPath  = Join-Path $logsDir "run_$timestamp.log"
$reportPath      = Join-Path $reportsDir "summary_$timestamp.txt"
$Script:SbomFiles = [System.Collections.Generic.List[string]]::new()

Write-Log -Level INFO -Msg "Scan session started."
Write-Log -Level INFO -Msg "Scan root  : $Path"
Write-Log -Level INFO -Msg "Report dir : $reportsDir"
Write-Log -Level INFO -Msg "Scanner venv: $venvDir"
Write-Log -Level INFO -Msg "Log file   : $Script:LogPath"
Write-Log -Level INFO -Msg "Staging dir: $workspaceDir"

# ----------------------------------------------------------
# Step 3: Locate Python
# ----------------------------------------------------------

Show-Status "Checking Python installation..."

$pythonCmd = Find-Python
if (-not $pythonCmd) {
    Write-Log -Level ERROR -Msg "Python 3 not found on PATH. Please install Python 3.x and re-run."
    Write-Host "[ERROR] Python 3 is required but was not found. Install from https://python.org and re-run." -ForegroundColor Red
    exit 1
}

# ----------------------------------------------------------
# Step 4: Create scanner venv and install tools
# ----------------------------------------------------------

Show-Status "Setting up scanner environment..."

try {
    $venv = Initialize-ScannerVenv -PythonCmd $pythonCmd -VenvDir $venvDir
} catch {
    Write-Log -Level ERROR -Msg "Failed to create scanner venv: $_"
    exit 1
}

Show-Status "Checking scanner tool dependencies..."

try {
    Install-ScannerDependencies -PipExe $venv.Pip -PythonExe $venv.Python -AutoInstall $AutoInstall.IsPresent
} catch {
    Write-Log -Level ERROR -Msg "Dependency setup failed: $_"
    Write-Host "[ERROR] Could not install required scanning tools. Check internet connectivity." -ForegroundColor Red
    exit 1
}

# ----------------------------------------------------------
# Step 5: Collect package units and identify unsupported files
# ----------------------------------------------------------

Show-Status "Scanning folder for Python packages..."

# @() forces array semantics: Get-PackageUnits returns a Generic.List which
# PowerShell enumerates into the pipeline, so a single-unit result would otherwise
# be assigned as a bare scalar and $units.Count would throw under strict mode.
$units = @(Get-PackageUnits -ScanRoot $Path)
$unsupportedFiles = @(Find-UnsupportedFiles -ScanRoot $Path)

if ($unsupportedFiles.Count -gt 0) {
    Write-Log -Level WARN -Msg "Found $($unsupportedFiles.Count) unsupported file(s) in scan root."
}

if ($units.Count -eq 0 -and $unsupportedFiles.Count -eq 0) {
    Write-Log -Level WARN -Msg "No Python package files found in: $Path"
    Write-Host ""
    Write-Host "  No recognizable Python files found. Supported types:" -ForegroundColor Yellow
    Write-Host "    Archives : .whl  .egg  .zip  .tar.gz  .tgz" -ForegroundColor Yellow
    Write-Host "    Source   : .py  .pyw" -ForegroundColor Yellow
    exit 0
}

if ($units.Count -eq 0 -and $unsupportedFiles.Count -gt 0) {
    # Unsupported-only folders still get reports so operators have a durable
    # record of exactly which submitted files the scanner skipped.
    Write-Log -Level WARN -Msg "No recognizable Python package files found, but unsupported files were present; generating report."
    Show-Status "No scannable Python units found. Generating unsupported-files report..."
} else {
    Write-Log -Level INFO -Msg "Units to scan: $($units.Count)"
    Show-Status "Found $($units.Count) unit(s) to scan. Starting analysis..."
}

# ----------------------------------------------------------
# Step 6: Process each unit — extract if needed, then scan
# ----------------------------------------------------------

$unitResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($unit in $units) {
    Write-Log -Level INFO -Msg "Processing unit: $($unit.Name) [$($unit.Kind)]"
    Show-Status "Analyzing: $($unit.Name)"

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        # Determine the directory to scan
        if ($unit.Kind -eq 'archive') {
            # Extract archive to staging workspace
            $safeName  = $unit.Name -replace '[^\w\-.]', '_'
            $stageDir  = Join-Path $workspaceDir "unit_$safeName"
            $extracted = Expand-PythonArchive `
                -InputFile     $unit.Path `
                -OutputDir     $stageDir `
                -FallbackPython $venv.Python

            if (-not $extracted) {
                Write-Log -Level WARN -Msg "Skipping scan for $($unit.Name) — extraction failed."
                continue
            }

            $scanTarget = $stageDir
        }
        else {
            # Loose .py file — scan the file directly
            $scanTarget = $unit.Path
        }

        # Run all scanners on the target
        foreach ($f in (Invoke-BanditScan       -ScriptsDir $venv.Scripts -TargetPath $scanTarget)) { $findings.Add($f) }
        foreach ($f in (Invoke-DetectSecretsScan -ScriptsDir $venv.Scripts -TargetPath $scanTarget)) { $findings.Add($f) }

        # CVE audit/SBOM require package metadata; binary inspection is useful
        # for any extracted archive.
        if ($unit.Kind -eq 'archive') {
            # Derive a SBOM filename by stripping the archive extension from $safeName then
            # building sbom_<timestamp>_<name>.cdx.json in the same .reports directory.
            $sbomSuffix   = $safeName -replace '\.tar\.gz$|\.whl$|\.egg$|\.zip$|\.tgz$', ''
            $unitSbomPath = Join-Path $reportsDir "sbom_${timestamp}_${sbomSuffix}.cdx.json"
            foreach ($f in (Invoke-PipAuditScan -ScriptsDir $venv.Scripts -TargetPath $scanTarget -SbomPath $unitSbomPath)) { $findings.Add($f) }
            foreach ($f in (Invoke-BinaryInspection -ScriptsDir $venv.Scripts -TargetPath $scanTarget -PythonExe $venv.Python)) { $findings.Add($f) }
        }

    } catch {
        Write-Log -Level ERROR -Msg "Error processing $($unit.Name): $_"
    }

    $unitResults.Add([PSCustomObject]@{
        Name     = $unit.Name
        Kind     = $unit.Kind
        Findings = $findings.ToArray()
    })

    Write-Log -Level INFO -Msg "Unit complete: $($unit.Name) — $($findings.Count) finding(s)."
}

# ----------------------------------------------------------
# Step 7: Write reports (.txt operator summary + .json sibling)
# ----------------------------------------------------------

Show-Status "Generating report..."

Write-SummaryReport `
    -ReportPath  $reportPath `
    -UnitResults $unitResults.ToArray() `
    -ScanRoot    $Path `
    -StartTime   $startTime `
    -UnsupportedFiles $unsupportedFiles

Write-JsonReport `
    -ReportPath  $reportPath `
    -UnitResults $unitResults.ToArray() `
    -ScanRoot    $Path `
    -StartTime   $startTime `
    -UnsupportedFiles $unsupportedFiles

Write-Log -Level INFO -Msg "Scan session complete. Total units: $($unitResults.Count)."

# ----------------------------------------------------------
# Step 8: Clean up extraction staging from temp
# ----------------------------------------------------------

Write-Log -Level INFO -Msg "Removing staging directory: $workspaceDir"
Remove-Item -LiteralPath $workspaceDir -Recurse -Force -ErrorAction SilentlyContinue

Show-Done -ReportPath $reportPath

} # end if ($MyInvocation.InvocationName -ne '.')
