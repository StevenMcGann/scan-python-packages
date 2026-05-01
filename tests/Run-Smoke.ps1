#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the full v1.4 scanner smoke/regression suite into a timestamped artifact folder.

.DESCRIPTION
    Creates D:\CODE\test-results\<yyyymmdd_hhmmss>\ and captures Pester output,
    fixture-generation logs, deterministic corpus hashes, production scanner smoke
    runs, and a top-level INDEX.md summary. Scan stages operate on isolated copies
    of the generated corpus so scanner-created .reports folders never land in the
    canonical fixture corpus.
#>

param(
    [switch]$PesterOnly,
    [switch]$SkipFixtures,
    [string]$OutputRoot = 'D:\CODE\test-results'
)

$RepoRoot = Split-Path $PSScriptRoot -Parent
$ScriptUnderTest = Join-Path $RepoRoot 'src\Scan-PythonPackages.ps1'
$PesterSuite = Join-Path $PSScriptRoot 'Scan-PythonPackages.Tests.ps1'
$FixtureBuilder = Join-Path $PSScriptRoot 'fixtures\build_fixtures.py'
$CorpusRoot = Join-Path $PSScriptRoot 'fixtures\corpus'
$ScannerLogRoot = Join-Path $RepoRoot 'logs'
$RunStart = Get-Date
$StageResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$ArtifactFiles = [System.Collections.Generic.List[string]]::new()

function New-RunDirectory {
    param([string]$Root)

    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    do {
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $dir = Join-Path $Root $stamp
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            return (Resolve-Path -LiteralPath $dir).Path
        }
        Start-Sleep -Seconds 1
    } while ($true)
}

function Write-Stage {
    param([string]$Name)
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Name) -ForegroundColor Cyan
}

function ConvertTo-ArtifactRelativePath {
    param([string]$Path)

    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetFullPath($script:RunDir).TrimEnd('\') + '\'
    if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($root.Length).Replace('\', '/')
    }
    return $full
}

function Register-Artifact {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        $script:ArtifactFiles.Add((ConvertTo-ArtifactRelativePath -Path $Path)) | Out-Null
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Value,
        [int]$Depth = 6
    )

    $json = $Value | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
    Register-Artifact -Path $Path
}

function Add-StageResult {
    param(
        [string]$Stage,
        [bool]$Passed,
        [string]$Result,
        [string]$Notes
    )

    $script:StageResults.Add([PSCustomObject]@{
        Stage  = $Stage
        Passed = $Passed
        Result = $Result
        Notes  = $Notes
    }) | Out-Null
}

function Get-DirectoryListingText {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return "<not present>"
    }

    $items = @(Get-ChildItem -LiteralPath $Path -Force | Sort-Object Name |
        Select-Object Mode, Length, LastWriteTime, Name |
        Format-Table -AutoSize | Out-String)
    if ([string]::IsNullOrWhiteSpace(($items -join ''))) {
        return "<empty>"
    }
    return ($items -join '')
}

function Get-RelativeHashes {
    param([string]$Root)

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($rootFull.Length).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        "$rel`t$hash"
    } | Sort-Object)
}

function Get-CorpusByteCount {
    if (-not (Test-Path -LiteralPath $CorpusRoot)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $CorpusRoot -Recurse -File | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [int64]$sum
}

function Get-FixtureCount {
    $manifestPath = Join-Path $CorpusRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { return 0 }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        return @($manifest.fixtures).Count
    } catch {
        return 0
    }
}

function Get-ToolOutput {
    param([string[]]$Command)

    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out = & $Command[0] @($Command[1..($Command.Count - 1)]) 2>&1
        $ErrorActionPreference = $prevEAP
        return (($out | ForEach-Object { [string]$_ }) -join "`n").Trim()
    } catch {
        $ErrorActionPreference = $prevEAP
        return "<unavailable: $_>"
    }
}

function Get-EnvironmentManifest {
    $versionLine = Select-String -Path $ScriptUnderTest -Pattern '^\s*Version\s*:\s*(.+?)\s*$' | Select-Object -First 1
    $scriptVersion = if ($versionLine) { $versionLine.Matches[0].Groups[1].Value.Trim() } else { '<unknown>' }
    $pesterModule = Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1
    $edition = if ($PSVersionTable.ContainsKey('PSEdition')) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }

    return [PSCustomObject]@{
        timestamp         = (Get-Date).ToUniversalTime().ToString('o')
        scriptUnderTest   = [System.IO.Path]::GetFileName($ScriptUnderTest)
        scriptVersion     = $scriptVersion
        powershellVersion = [string]$PSVersionTable.PSVersion
        powershellEdition = $edition
        os                = [System.Environment]::OSVersion.VersionString
        python            = (Get-ToolOutput -Command @('py', '--version'))
        pesterVersion     = if ($pesterModule) { [string]$pesterModule.Version } else { '<not found>' }
        host              = $env:COMPUTERNAME
        user              = $env:USERNAME
    }
}

function Invoke-PesterStage {
    $stageDir = Join-Path $RunDir '01-pester'
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    $outputLog = Join-Path $stageDir 'output.log'
    $resultXml = Join-Path $stageDir 'results.xml'
    $summaryJson = Join-Path $stageDir 'summary.json'
    Register-Artifact -Path $outputLog
    Register-Artifact -Path $resultXml

    Write-Stage '01-pester: running Pester suite'
    try {
        $config = @{
            Run = @{
                Path = $PesterSuite
                PassThru = $true
            }
            Output = @{
                Verbosity = 'Detailed'
            }
            TestResult = @{
                Enabled = $true
                OutputPath = $resultXml
                OutputFormat = 'NUnitXml'
            }
        }

        $pesterItems = @(Invoke-Pester -Configuration $config *>&1 | Tee-Object -FilePath $outputLog)
        $pesterResult = @($pesterItems | Where-Object {
            $null -ne $_ -and
            $_.PSObject.Properties['TotalCount'] -and
            $_.PSObject.Properties['FailedCount']
        } | Select-Object -Last 1)

        if (@($pesterResult).Count -eq 0) {
            throw "Invoke-Pester did not return a pass-through result object."
        }

        $result = $pesterResult[0]
        $failures = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($result.PSObject.Properties['Failed']) {
            foreach ($failure in @($result.Failed)) {
                $name = if ($failure.PSObject.Properties['ExpandedName']) { $failure.ExpandedName } elseif ($failure.PSObject.Properties['Name']) { $failure.Name } else { '<unknown>' }
                $message = ''
                if ($failure.PSObject.Properties['ErrorRecord'] -and $failure.ErrorRecord) {
                    $message = [string]$failure.ErrorRecord.Exception.Message
                } elseif ($failure.PSObject.Properties['FailureMessage']) {
                    $message = [string]$failure.FailureMessage
                }
                $failures.Add([PSCustomObject]@{ name = $name; message = $message }) | Out-Null
            }
        }

        $duration = if ($result.PSObject.Properties['Duration']) { $result.Duration } else { [timespan]::Zero }
        $summary = [PSCustomObject]@{
            totalCount = [int]$result.TotalCount
            passed     = [int]$result.PassedCount
            failed     = [int]$result.FailedCount
            skipped    = [int]$result.SkippedCount
            duration   = ([timespan]$duration).ToString('hh\:mm\:ss\.fff')
            failures   = $failures.ToArray()
        }
        Write-JsonFile -Path $summaryJson -Value $summary

        $ok = ($summary.failed -eq 0)
        Add-StageResult -Stage 'Pester' -Passed $ok -Result ("{0} / {1} / {2} (passed/total/failed)" -f $summary.passed, $summary.totalCount, $summary.failed) -Notes $summary.duration
        return $summary
    } catch {
        $_ | Out-File -FilePath $outputLog -Append -Encoding UTF8
        $summary = [PSCustomObject]@{
            totalCount = 0
            passed     = 0
            failed     = 1
            skipped    = 0
            duration   = '00:00:00.000'
            failures   = @([PSCustomObject]@{ name = 'Pester stage'; message = [string]$_ })
        }
        Write-JsonFile -Path $summaryJson -Value $summary
        Add-StageResult -Stage 'Pester' -Passed $false -Result 'FAILED' -Notes ([string]$_)
        return $summary
    }
}

function Invoke-FixturesStage {
    $stageDir = Join-Path $RunDir '02-fixtures'
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    $buildLog = Join-Path $stageDir 'build.log'
    Register-Artifact -Path $buildLog

    if ($SkipFixtures -or $PesterOnly) {
        "SKIPPED" | Out-File -FilePath $buildLog -Encoding UTF8
        Add-StageResult -Stage 'Fixtures' -Passed $true -Result 'SKIPPED' -Notes 'Skipped by flag'
        return $true
    }

    Write-Stage '02-fixtures: regenerating deterministic corpus'
    try {
        & py $FixtureBuilder *>&1 | Tee-Object -FilePath $buildLog | Out-Host
        $exitCode = $LASTEXITCODE
        $bytes = Get-CorpusByteCount
        $ok = ($exitCode -eq 0)
        Add-StageResult -Stage 'Fixtures' -Passed $ok -Result $(if ($ok) { 'OK' } else { 'FAILED' }) -Notes ("exit={0}; corpus={1} bytes" -f $exitCode, $bytes)
        return $ok
    } catch {
        $_ | Out-File -FilePath $buildLog -Append -Encoding UTF8
        Add-StageResult -Stage 'Fixtures' -Passed $false -Result 'FAILED' -Notes ([string]$_)
        return $false
    }
}

function Invoke-DeterminismStage {
    $stageDir = Join-Path $RunDir '03-determinism'
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    $hash1Path = Join-Path $stageDir 'hashes-run1.txt'
    $hash2Path = Join-Path $stageDir 'hashes-run2.txt'
    $logPath = Join-Path $stageDir 'determinism.log'
    Register-Artifact -Path $hash1Path
    Register-Artifact -Path $hash2Path
    Register-Artifact -Path $logPath

    if ($SkipFixtures -or $PesterOnly) {
        "SKIPPED" | Out-File -FilePath $logPath -Encoding UTF8
        Add-StageResult -Stage 'Determinism' -Passed $true -Result 'SKIPPED' -Notes 'Skipped by flag'
        return $true
    }

    Write-Stage '03-determinism: comparing corpus hashes across rebuilds'
    try {
        $hash1 = @(Get-RelativeHashes -Root $CorpusRoot)
        $hash1 | Out-File -FilePath $hash1Path -Encoding UTF8

        & py $FixtureBuilder *>&1 | Out-File -FilePath $logPath -Encoding UTF8
        $builderExit = $LASTEXITCODE

        $hash2 = @(Get-RelativeHashes -Root $CorpusRoot)
        $hash2 | Out-File -FilePath $hash2Path -Encoding UTF8

        $diff = @(Compare-Object -ReferenceObject $hash1 -DifferenceObject $hash2)
        if ($builderExit -ne 0) {
            "Fixture rebuild exited $builderExit." | Out-File -FilePath $logPath -Append -Encoding UTF8
        }
        if ($diff.Count -eq 0) {
            "IDENTICAL" | Out-File -FilePath $logPath -Append -Encoding UTF8
        } else {
            $diff | Format-Table -AutoSize | Out-String | Out-File -FilePath $logPath -Append -Encoding UTF8
        }

        $ok = ($builderExit -eq 0 -and $diff.Count -eq 0)
        Add-StageResult -Stage 'Determinism' -Passed $ok -Result $(if ($ok) { 'IDENTICAL' } else { 'FAILED' }) -Notes ("fixtures={0}; files={1}" -f (Get-FixtureCount), $hash2.Count)
        return $ok
    } catch {
        $_ | Out-File -FilePath $logPath -Append -Encoding UTF8
        Add-StageResult -Stage 'Determinism' -Passed $false -Result 'FAILED' -Notes ([string]$_)
        return $false
    }
}

function Invoke-ScannerSmoke {
    param(
        [string]$StageName,
        [string]$StageFolder,
        [string]$SourcePath,
        [scriptblock]$Validate
    )

    $stageDir = Join-Path $RunDir $StageFolder
    $targetDir = Join-Path $stageDir 'target'
    $consoleLog = Join-Path $stageDir 'console.log'
    $runLogCopy = Join-Path $stageDir 'run.log'
    $summaryTxtCopy = Join-Path $stageDir 'summary.txt'
    $summaryJsonCopy = Join-Path $stageDir 'summary.json'
    $sbomDir = Join-Path $stageDir 'sbom'
    $preListing = Join-Path $stageDir 'reports-listing-pre.txt'
    $postListing = Join-Path $stageDir 'reports-listing-post.txt'

    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    New-Item -ItemType Directory -Path $sbomDir -Force | Out-Null
    Register-Artifact -Path $consoleLog
    Register-Artifact -Path $runLogCopy
    Register-Artifact -Path $summaryTxtCopy
    Register-Artifact -Path $summaryJsonCopy
    Register-Artifact -Path $preListing
    Register-Artifact -Path $postListing

    Write-Stage ("{0}: scanner smoke run" -f $StageFolder)
    try {
        if (Test-Path -LiteralPath $targetDir) {
            Remove-Item -LiteralPath $targetDir -Recurse -Force
        }
        Copy-Item -LiteralPath $SourcePath -Destination $targetDir -Recurse -Force

        $reportsDir = Join-Path $targetDir '.reports'
        Get-DirectoryListingText -Path $reportsDir | Out-File -FilePath $preListing -Encoding UTF8

        $scanStart = Get-Date
        & powershell -NoProfile -ExecutionPolicy Bypass -File $ScriptUnderTest -Path $targetDir -AutoInstall *>&1 |
            Tee-Object -FilePath $consoleLog | Out-Host
        $exitCode = $LASTEXITCODE

        Get-DirectoryListingText -Path $reportsDir | Out-File -FilePath $postListing -Encoding UTF8

        $runLog = @(Get-ChildItem -LiteralPath $ScannerLogRoot -Filter 'run_*.log' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $scanStart.AddSeconds(-2) } |
            Sort-Object LastWriteTime | Select-Object -Last 1)
        if (@($runLog).Count -gt 0) {
            Copy-Item -LiteralPath $runLog[0].FullName -Destination $runLogCopy -Force
        }

        $summaryTxt = @(Get-ChildItem -LiteralPath $reportsDir -Filter 'summary_*.txt' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime | Select-Object -Last 1)
        $summaryJson = @(Get-ChildItem -LiteralPath $reportsDir -Filter 'summary_*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime | Select-Object -Last 1)
        if (@($summaryTxt).Count -gt 0) {
            Copy-Item -LiteralPath $summaryTxt[0].FullName -Destination $summaryTxtCopy -Force
        }
        if (@($summaryJson).Count -gt 0) {
            Copy-Item -LiteralPath $summaryJson[0].FullName -Destination $summaryJsonCopy -Force
        }

        $sboms = @(Get-ChildItem -LiteralPath $reportsDir -Filter 'sbom_*.cdx.json' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $scanStart.AddSeconds(-2) } |
            Sort-Object Name)
        foreach ($sbom in $sboms) {
            $dest = Join-Path $sbomDir $sbom.Name
            Copy-Item -LiteralPath $sbom.FullName -Destination $dest -Force
            Register-Artifact -Path $dest
        }

        $validation = & $Validate -StageDir $stageDir -SummaryJsonPath $summaryJsonCopy -SummaryTxtPath $summaryTxtCopy -SbomDir $sbomDir -ExitCode $exitCode
        $passed = [bool]$validation.Passed
        Add-StageResult -Stage $StageName -Passed $passed -Result $(if ($passed) { 'OK' } else { 'FAILED' }) -Notes $validation.Notes
        return $passed
    } catch {
        $_ | Out-File -FilePath $consoleLog -Append -Encoding UTF8
        Add-StageResult -Stage $StageName -Passed $false -Result 'FAILED' -Notes ([string]$_)
        return $false
    }
}

function Test-ArchivesSmoke {
    param($StageDir, $SummaryJsonPath, $SummaryTxtPath, $SbomDir, $ExitCode)

    if (-not (Test-Path -LiteralPath $SummaryJsonPath)) {
        return [PSCustomObject]@{ Passed = $false; Notes = "summary.json missing; exit=$ExitCode" }
    }
    $json = Get-Content -LiteralPath $SummaryJsonPath -Raw | ConvertFrom-Json
    $findings = [int]$json.totals.findings
    $high = [int]$json.totals.high
    $medium = [int]$json.totals.medium
    $low = [int]$json.totals.low
    $unsupported = @($json.unsupportedFiles).Count
    $sboms = @(Get-ChildItem -LiteralPath $SbomDir -Filter '*.cdx.json' -ErrorAction SilentlyContinue).Count
    $ok = ($ExitCode -eq 0 -and $unsupported -eq 0 -and $findings -gt 0 -and $sboms -ge 1)
    return [PSCustomObject]@{ Passed = $ok; Notes = ("findings: {0} (HIGH {1} / MED {2} / LOW {3}), SBOMs: {4}, unsupported: {5}" -f $findings, $high, $medium, $low, $sboms, $unsupported) }
}

function Test-NonPythonSmoke {
    param($StageDir, $SummaryJsonPath, $SummaryTxtPath, $SbomDir, $ExitCode)

    if (-not (Test-Path -LiteralPath $SummaryJsonPath)) {
        return [PSCustomObject]@{ Passed = $false; Notes = "summary.json missing; exit=$ExitCode" }
    }
    $json = Get-Content -LiteralPath $SummaryJsonPath -Raw | ConvertFrom-Json
    $unsupported = @($json.unsupportedFiles).Count
    $findings = [int]$json.totals.findings
    $sboms = @(Get-ChildItem -LiteralPath $SbomDir -Filter '*.cdx.json' -ErrorAction SilentlyContinue).Count
    $ok = ($ExitCode -eq 0 -and $unsupported -eq 3 -and $findings -eq 0 -and $sboms -eq 0 -and $json.overallRisk -eq 'CLEAN')
    return [PSCustomObject]@{ Passed = $ok; Notes = ("unsupported: {0}, findings: {1}, SBOMs: {2}, risk: {3}" -f $unsupported, $findings, $sboms, $json.overallRisk) }
}

function Test-MixedSmoke {
    param($StageDir, $SummaryJsonPath, $SummaryTxtPath, $SbomDir, $ExitCode)

    if (-not (Test-Path -LiteralPath $SummaryJsonPath)) {
        return [PSCustomObject]@{ Passed = $false; Notes = "summary.json missing; exit=$ExitCode" }
    }
    $json = Get-Content -LiteralPath $SummaryJsonPath -Raw | ConvertFrom-Json
    $unsupported = @($json.unsupportedFiles).Count
    $findings = [int]$json.totals.findings
    $units = [int]$json.totals.units
    $ok = ($ExitCode -eq 0 -and $unsupported -eq 2 -and $findings -eq 0 -and $units -eq 2 -and $json.overallRisk -eq 'CLEAN')
    return [PSCustomObject]@{ Passed = $ok; Notes = ("unsupported: {0}, findings: {1}, units: {2}, risk: {3}" -f $unsupported, $findings, $units, $json.overallRisk) }
}

function Test-RescanExclusion {
    param($StageDir, $SummaryJsonPath, $SummaryTxtPath, $SbomDir, $ExitCode)

    $logPath = Join-Path $StageDir 'exclusion-check.log'
    Register-Artifact -Path $logPath
    if (-not (Test-Path -LiteralPath $SummaryJsonPath)) {
        "FAIL: summary.json missing; exit=$ExitCode" | Out-File -FilePath $logPath -Encoding UTF8
        return [PSCustomObject]@{ Passed = $false; Notes = "summary.json missing; exit=$ExitCode" }
    }

    $json = Get-Content -LiteralPath $SummaryJsonPath -Raw | ConvertFrom-Json
    $reported = @($json.unsupportedFiles | ForEach-Object { $_.relativePath })
    $expected = @('README.md', 'data.csv', 'photo.jpg')
    $unexpected = @($reported | Where-Object { $_ -notin $expected })
    $missing = @($expected | Where-Object { $_ -notin $reported })
    $reportArtifacts = @($reported | Where-Object { $_ -like '.reports*' -or $_ -like 'summary_*' -or $_ -like 'run_*' })
    $txt = if (Test-Path -LiteralPath $SummaryTxtPath) { Get-Content -LiteralPath $SummaryTxtPath -Raw } else { '' }
    $txtHasWarning = ($txt -match 'WARNING: UNSUPPORTED FILES IN SCAN ROOT')
    $txtHasAll = $true
    foreach ($name in $expected) {
        if ($txt -notmatch [regex]::Escape($name)) { $txtHasAll = $false }
    }

    $ok = ($ExitCode -eq 0 -and $reported.Count -eq 3 -and $unexpected.Count -eq 0 -and $missing.Count -eq 0 -and $reportArtifacts.Count -eq 0 -and $txtHasWarning -and $txtHasAll)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("Expected unsupported files: $($expected -join ', ')")
    $lines.Add("Reported unsupported files: $($reported -join ', ')")
    $lines.Add("Unexpected entries: $($unexpected -join ', ')")
    $lines.Add("Missing entries: $($missing -join ', ')")
    $lines.Add("Report-artifact entries: $($reportArtifacts -join ', ')")
    $lines.Add("Text warning present: $txtHasWarning")
    $lines.Add("Text warning lists all expected files: $txtHasAll")
    $lines.Add("Result: $(if ($ok) { 'PASS' } else { 'FAIL' })")
    $lines | Out-File -FilePath $logPath -Encoding UTF8

    return [PSCustomObject]@{ Passed = $ok; Notes = $(if ($ok) { 'only original 3 unsupported files reported' } else { 'unsupported list included missing or extra entries' }) }
}

function Write-Index {
    param(
        [object]$Env,
        [object]$PesterSummary
    )

    $indexPath = Join-Path $RunDir 'INDEX.md'
    $elapsed = (Get-Date) - $RunStart
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# Smoke Test Run $([System.IO.Path]::GetFileName($RunDir))")
    $lines.Add("")
    $lines.Add("## Environment")
    $lines.Add("")
    $lines.Add("| Key | Value |")
    $lines.Add("|---|---|")
    $lines.Add("| Scanner | $($Env.scriptUnderTest) |")
    $lines.Add("| Scanner version | $($Env.scriptVersion) |")
    $lines.Add("| PowerShell | $($Env.powershellVersion) ($($Env.powershellEdition)) |")
    $lines.Add("| Python | $($Env.python) |")
    $lines.Add("| OS | $($Env.os) |")
    $lines.Add("| Host | $($Env.host) |")
    $lines.Add("")
    $lines.Add("## Summary")
    $lines.Add("")
    $lines.Add("| Stage | Result | Notes |")
    $lines.Add("|---|---|---|")
    foreach ($stage in $StageResults) {
        $lines.Add("| $($stage.Stage) | $($stage.Result) | $($stage.Notes -replace '\|','/') |")
    }

    if ($PesterSummary -and @($PesterSummary.failures).Count -gt 0) {
        $lines.Add("")
        $lines.Add("## Failed Tests")
        $lines.Add("")
        foreach ($failure in @($PesterSummary.failures)) {
            $msg = [string]$failure.message
            if ($msg.Length -gt 240) { $msg = $msg.Substring(0, 240) + '...' }
            $lines.Add("- **$($failure.name)**: $msg")
        }
    }

    $lines.Add("")
    $lines.Add("## Artifact Links")
    $lines.Add("")
    $allFiles = @(Get-ChildItem -LiteralPath $RunDir -Recurse -File | ForEach-Object {
        ConvertTo-ArtifactRelativePath -Path $_.FullName
    } | Sort-Object -Unique)
    foreach ($file in $allFiles) {
        if ($file -ne 'INDEX.md') {
            $lines.Add("- [$file]($file)")
        }
    }

    $lines.Add("")
    $lines.Add("Total runtime: $($elapsed.ToString('hh\:mm\:ss'))")
    $lines | Out-File -FilePath $indexPath -Encoding UTF8
    Register-Artifact -Path $indexPath
}

$RunDir = New-RunDirectory -Root $OutputRoot
Write-Host "Smoke artifacts: $RunDir" -ForegroundColor Green

$envManifest = Get-EnvironmentManifest
$envPath = Join-Path $RunDir 'env.json'
Write-JsonFile -Path $envPath -Value $envManifest

$pesterSummary = Invoke-PesterStage
if (-not $PesterOnly) {
    Invoke-FixturesStage | Out-Null
    Invoke-DeterminismStage | Out-Null

    Invoke-ScannerSmoke -StageName 'Scan: archives' -StageFolder '04-scan-archives' -SourcePath (Join-Path $CorpusRoot 'archives') -Validate ${function:Test-ArchivesSmoke} | Out-Null
    Invoke-ScannerSmoke -StageName 'Scan: non-python' -StageFolder '05-scan-non-python' -SourcePath (Join-Path $CorpusRoot 'non-python') -Validate ${function:Test-NonPythonSmoke} | Out-Null
    Invoke-ScannerSmoke -StageName 'Scan: mixed' -StageFolder '06-scan-mixed' -SourcePath (Join-Path $CorpusRoot 'mixed') -Validate ${function:Test-MixedSmoke} | Out-Null
    Invoke-ScannerSmoke -StageName 'Re-scan exclusion' -StageFolder '07-rescan-non-python' -SourcePath (Join-Path $RunDir '05-scan-non-python\target') -Validate ${function:Test-RescanExclusion} | Out-Null
} else {
    Add-StageResult -Stage 'Fixtures' -Passed $true -Result 'SKIPPED' -Notes 'PesterOnly'
    Add-StageResult -Stage 'Determinism' -Passed $true -Result 'SKIPPED' -Notes 'PesterOnly'
    Add-StageResult -Stage 'Scan: archives' -Passed $true -Result 'SKIPPED' -Notes 'PesterOnly'
    Add-StageResult -Stage 'Scan: non-python' -Passed $true -Result 'SKIPPED' -Notes 'PesterOnly'
    Add-StageResult -Stage 'Scan: mixed' -Passed $true -Result 'SKIPPED' -Notes 'PesterOnly'
    Add-StageResult -Stage 'Re-scan exclusion' -Passed $true -Result 'SKIPPED' -Notes 'PesterOnly'
}

Write-Stage 'INDEX: writing summary'
Write-Index -Env $envManifest -PesterSummary $pesterSummary

$allPassed = -not (@($StageResults | Where-Object { -not $_.Passed }).Count -gt 0)
Write-Host "Smoke run complete: $RunDir" -ForegroundColor Green
if ($allPassed) {
    exit 0
}
exit 1
