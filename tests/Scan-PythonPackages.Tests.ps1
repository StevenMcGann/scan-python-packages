#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 test suite for src\Scan-PythonPackages.ps1.
    Dot-sources the production script inside BeforeAll so function definitions
    are in scope during test execution, not just during discovery.
    The production main block is skipped because InvocationName -ne '.'.
#>

# Top-level BeforeAll: runs once before any Describe block.
# Everything defined here is available to all nested blocks.
BeforeAll {
    $script:ScriptUnderTest = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\Scan-PythonPackages.ps1'
    if (-not (Test-Path $script:ScriptUnderTest)) {
        throw "Production script not found at: $script:ScriptUnderTest"
    }
    # Dot-source with a dummy -Path so the param block is satisfied.
    # The main execution block is guarded by InvocationName -ne '.' and is skipped.
    . $script:ScriptUnderTest -Path $env:TEMP
}

# ============================================================
# Compare-Versions  (integration — requires Python on PATH)
# ============================================================

Describe 'Compare-Versions' {

    BeforeAll {
        # Locate a real Python 3 interpreter for integration tests.
        $script:RealPython = $null
        foreach ($candidate in @('py', 'python', 'python3')) {
            try {
                Get-Command $candidate -ErrorAction Stop | Out-Null
                $ver = & $candidate --version 2>&1
                if ($ver -match 'Python 3\.') {
                    $script:RealPython = $candidate
                    break
                }
            } catch { }
        }

        # Create a throw-away venv in TestDrive so packaging/pip._vendor.packaging
        # is available for Compare-Versions to call.
        if ($script:RealPython) {
            $script:TestVenvDir = Join-Path $TestDrive 'cv-venv'
            $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            & $script:RealPython -m venv $script:TestVenvDir 2>&1 | Out-Null
            $ErrorActionPreference = $prevEAP
            $script:VenvPython = Join-Path $script:TestVenvDir 'Scripts\python.exe'
        }
    }

    Context 'Exact match' {
        BeforeEach {
            if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
        }

        It '1.7.0 >= 1.7.0 returns $true' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.0' -Minimum '1.7.0' |
                Should -BeTrue
        }
    }

    Context 'Simple semver' {
        BeforeEach {
            if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
        }

        It '2.0.0 >= 1.7.0 returns $true' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '2.0.0' -Minimum '1.7.0' |
                Should -BeTrue
        }

        It '1.6.9 >= 1.7.0 returns $false' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.6.9' -Minimum '1.7.0' |
                Should -BeFalse
        }

        It '1.7.1 >= 1.7.0 returns $true' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.1' -Minimum '1.7.0' |
                Should -BeTrue
        }
    }

    Context 'PEP 440 pre-releases' {
        BeforeEach {
            if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
        }

        It '1.7.0rc1 < 1.7.0 returns $false (rc < release)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.0rc1' -Minimum '1.7.0' |
                Should -BeFalse
        }

        It '1.7.0a1 < 1.7.0 returns $false (alpha < release)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.0a1' -Minimum '1.7.0' |
                Should -BeFalse
        }

        It '1.7.0b2 < 1.7.0 returns $false (beta < release)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.0b2' -Minimum '1.7.0' |
                Should -BeFalse
        }

        It '1.7.0.dev0 < 1.7.0 returns $false (dev < release)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.0.dev0' -Minimum '1.7.0' |
                Should -BeFalse
        }

        It '1.8.0a1 >= 1.7.0 returns $true (alpha of later release > older release)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.8.0a1' -Minimum '1.7.0' |
                Should -BeTrue
        }
    }

    Context 'PEP 440 post-releases' {
        BeforeEach {
            if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
        }

        It '1.7.0.post1 >= 1.7.0 returns $true (post > release)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.0.post1' -Minimum '1.7.0' |
                Should -BeTrue
        }
    }

    Context 'Local version identifiers' {
        BeforeEach {
            if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
        }

        It '1.7.0+local.1 >= 1.7.0 returns $true (local >= base)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.7.0+local.1' -Minimum '1.7.0' |
                Should -BeTrue
        }
    }

    Context 'Epoch versions' {
        BeforeEach {
            if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
        }

        It '2!1.0.0 >= 1.9.9 returns $true (epoch 2 > epoch 0)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '2!1.0.0' -Minimum '1.9.9' |
                Should -BeTrue
        }
    }

    Context 'Edge cases — no Python call required' {

        It 'Empty Minimum returns $true (no minimum set)' {
            # Passes before the Python call — no real exe needed.
            Compare-Versions -PythonExe 'C:\does\not\exist\python.exe' -Installed '1.0.0' -Minimum '' |
                Should -BeTrue
        }

        It 'Empty Installed returns $false (before any Python call)' {
            Compare-Versions -PythonExe 'C:\does\not\exist\python.exe' -Installed '' -Minimum '1.0.0' |
                Should -BeFalse
        }

        It 'Missing PythonExe returns $false (fail closed, no real Python needed)' {
            Compare-Versions -PythonExe 'C:\does\not\exist\python.exe' -Installed '1.0.0' -Minimum '1.0.0' |
                Should -BeFalse
        }
    }

    Context 'Garbage version strings (require Python to attempt parse)' {
        BeforeEach {
            if (-not $script:RealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
        }

        It 'Garbage Installed string returns $false (fail closed)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed 'not-a-version!!' -Minimum '1.0.0' |
                Should -BeFalse
        }

        It 'Garbage Minimum string returns $false (fail closed)' {
            Compare-Versions -PythonExe $script:VenvPython -Installed '1.0.0' -Minimum 'not-a-version!!' |
                Should -BeFalse
        }
    }
}

# ============================================================
# Get-RiskLevel
# ============================================================

Describe 'Get-RiskLevel' {

    It 'Returns HIGH when any finding has Severity HIGH' {
        $findings = @(
            [PSCustomObject]@{ Severity = 'HIGH' }
            [PSCustomObject]@{ Severity = 'LOW' }
        )
        Get-RiskLevel -Findings $findings | Should -Be 'HIGH'
    }

    It 'Returns MEDIUM when highest severity is MEDIUM' {
        $findings = @(
            [PSCustomObject]@{ Severity = 'MEDIUM' }
            [PSCustomObject]@{ Severity = 'LOW' }
        )
        Get-RiskLevel -Findings $findings | Should -Be 'MEDIUM'
    }

    It 'Returns LOW when all findings are LOW' {
        $findings = @(
            [PSCustomObject]@{ Severity = 'LOW' }
        )
        Get-RiskLevel -Findings $findings | Should -Be 'LOW'
    }

    It 'Returns CLEAN when findings array is empty' {
        Get-RiskLevel -Findings @() | Should -Be 'CLEAN'
    }

    It 'HIGH takes precedence over MEDIUM in a mixed array' {
        $findings = @(
            [PSCustomObject]@{ Severity = 'MEDIUM' }
            [PSCustomObject]@{ Severity = 'HIGH' }
            [PSCustomObject]@{ Severity = 'LOW' }
        )
        Get-RiskLevel -Findings $findings | Should -Be 'HIGH'
    }
}

# ============================================================
# Get-PackageUnits — archive-extension splitting
# ============================================================

Describe 'Get-PackageUnits archive-extension classification' {

    # Test the two-line split that classifies $ARCHIVE_EXTENSIONS into
    # simple extensions (one dot segment) vs compound suffixes (two segments).
    # We replicate the split rather than calling Get-PackageUnits (which
    # needs a real directory and would hit Get-ChildItem).

    BeforeAll {
        $script:simpleExts    = $ARCHIVE_EXTENSIONS | Where-Object { ($_ -split '\.').Count -le 2 }
        $script:compoundSuffs = $ARCHIVE_EXTENSIONS | Where-Object { ($_ -split '\.').Count -gt 2 }
    }

    It '.whl ends up in simpleArchiveExts' {
        $script:simpleExts | Should -Contain '.whl'
    }

    It '.egg ends up in simpleArchiveExts' {
        $script:simpleExts | Should -Contain '.egg'
    }

    It '.zip ends up in simpleArchiveExts' {
        $script:simpleExts | Should -Contain '.zip'
    }

    It '.tgz ends up in simpleArchiveExts' {
        $script:simpleExts | Should -Contain '.tgz'
    }

    It '.tar.gz ends up in compoundArchiveSuffs' {
        $script:compoundSuffs | Should -Contain '.tar.gz'
    }

    It '.tar.gz does NOT appear in simpleArchiveExts' {
        $script:simpleExts | Should -Not -Contain '.tar.gz'
    }

    It 'simpleArchiveExts contains exactly 4 entries' {
        @($script:simpleExts).Count | Should -Be 4
    }

    It 'compoundArchiveSuffs contains exactly 1 entry' {
        @($script:compoundSuffs).Count | Should -Be 1
    }
}

# ============================================================
# Fixture corpus manifest (v1.5 schema, v1.5.2 scanner-output contract)
# ============================================================

Describe 'Fixture corpus manifest' {

    BeforeAll {
        $script:FixturesRoot = Join-Path $PSScriptRoot 'fixtures'
        $script:CorpusRoot   = Join-Path $script:FixturesRoot 'corpus'
        $script:ManifestPath = Join-Path $script:CorpusRoot 'manifest.json'
        $script:FixtureManifest = Get-Content -LiteralPath $script:ManifestPath -Raw | ConvertFrom-Json
    }

    It 'Uses schemaVersion 1.5 for scanner v1.5.2' {
        $script:FixtureManifest.schemaVersion | Should -Be '1.5'
        $script:FixtureManifest.scannerVersionTarget | Should -Be '1.5.2'
    }

    It 'Contains the required corpus directories' {
        foreach ($name in @('archives', 'loose', 'empty', 'non-python', 'mixed', 'malformed')) {
            Join-Path $script:CorpusRoot $name | Should -Exist
        }
    }

    It 'Declares every generated fixture path and every path exists' {
        @($script:FixtureManifest.fixtures).Count | Should -Be 31

        foreach ($fixture in $script:FixtureManifest.fixtures) {
            $fixture.path | Should -Not -BeNullOrEmpty
            Test-Path -LiteralPath (Join-Path $script:CorpusRoot $fixture.path) | Should -BeTrue
        }
    }

    It 'Covers every supported archive format and loose .py/.pyw files' {
        $paths = @($script:FixtureManifest.fixtures | ForEach-Object { $_.path })

        $paths | Where-Object { $_ -like '*.whl' }    | Should -Not -BeNullOrEmpty
        $paths | Where-Object { $_ -like '*.egg' }    | Should -Not -BeNullOrEmpty
        $paths | Where-Object { $_ -like '*.zip' }    | Should -Not -BeNullOrEmpty
        $paths | Where-Object { $_ -like '*.tar.gz' } | Should -Not -BeNullOrEmpty
        $paths | Where-Object { $_ -like '*.tgz' }    | Should -Not -BeNullOrEmpty
        $paths | Where-Object { $_ -like '*.py' }     | Should -Not -BeNullOrEmpty
        $paths | Where-Object { $_ -like '*.pyw' }    | Should -Not -BeNullOrEmpty
    }

    It 'Marks scannable fixtures as expecting JSON summaries' {
        $scannable = @($script:FixtureManifest.fixtures |
            Where-Object { $_.kind -in @('archive', 'pyfile') })

        foreach ($fixture in $scannable) {
            $fixture.expectsJson | Should -BeTrue
        }
    }

    It 'Declares SBOM expectations for dependency metadata fixtures' {
        $sbomFixtures = @($script:FixtureManifest.fixtures | Where-Object { $_.expectsSbom })
        $sbomFixtures.Count | Should -BeGreaterOrEqual 3

        foreach ($fixture in $sbomFixtures) {
            $fixture.expectedSbom | Should -Not -BeNullOrEmpty
            $fixture.expectedSbom.componentsMin | Should -BeGreaterThan 0
            if ($fixture.expectedSbom.PSObject.Properties['format']) {
                $fixture.expectedSbom.format | Should -Be 'CycloneDX'
            }
        }

        $richDeps = $sbomFixtures | Where-Object { $_.path -eq 'archives/rich_deps_pkg-1.0-py3-none-any.whl' }
        $richDeps.expectedSbom.componentsMin | Should -BeGreaterOrEqual 5
    }

    It 'Includes analyzer expectations for all scanner tools' {
        $tools = @($script:FixtureManifest.fixtures |
            ForEach-Object { $_.expectedFindings } |
            Where-Object { $_ } |
            ForEach-Object { $_.tool } |
            Sort-Object -Unique)

        $tools | Should -Contain 'Bandit'
        $tools | Should -Contain 'detect-secrets'
        $tools | Should -Contain 'pip-audit'
        $tools | Should -Contain 'BinaryInspection'
    }

    It 'Represents version-dependent weak-crypto Bandit IDs as an either-or expectation' {
        $weak = $script:FixtureManifest.fixtures |
            Where-Object { $_.path -eq 'archives/weak_crypto_pkg-1.0-py3-none-any.whl' }
        $expected = @($weak.expectedFindings)[0]

        @($expected.testIdAny) | Should -Contain 'B303'
        @($expected.testIdAny) | Should -Contain 'B324'
        $expected.min | Should -Be 1
    }

    It 'Declares unsupported-file expectations for folder fixtures' {
        $nonPython = $script:FixtureManifest.fixtures | Where-Object { $_.path -eq 'non-python' }
        $mixed = $script:FixtureManifest.fixtures | Where-Object { $_.path -eq 'mixed' }

        @($nonPython.expectedUnsupportedFiles).Count | Should -Be 3
        @($nonPython.expectedUnsupportedFiles) | Should -Contain 'README.md'
        @($nonPython.expectedUnsupportedFiles) | Should -Contain 'data.csv'
        @($nonPython.expectedUnsupportedFiles) | Should -Contain 'photo.jpg'
        @($mixed.expectedUnsupportedFiles).Count | Should -Be 2
        @($mixed.expectedUnsupportedFiles) | Should -Contain 'README.md'
        @($mixed.expectedUnsupportedFiles) | Should -Contain 'photo.jpg'
        $nonPython.expectsJson | Should -BeTrue
        $mixed.expectsJson | Should -BeTrue
    }
}

# ============================================================
# Invoke-BinaryInspection
# ============================================================

Describe 'Invoke-BinaryInspection' {

    BeforeAll {
        $script:BinaryRealPython = $null
        foreach ($candidate in @('py', 'python', 'python3')) {
            try {
                Get-Command $candidate -ErrorAction Stop | Out-Null
                $ver = & $candidate --version 2>&1
                if ($ver -match 'Python 3\.') {
                    $script:BinaryRealPython = $candidate
                    break
                }
            } catch { }
        }

        if ($script:BinaryRealPython) {
            $script:BinaryVenvDir = Join-Path $TestDrive 'binary-venv'
            $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            & $script:BinaryRealPython -m venv $script:BinaryVenvDir 2>&1 | Out-Null
            $script:BinaryVenvPython = Join-Path $script:BinaryVenvDir 'Scripts\python.exe'
            & $script:BinaryVenvPython -m pip install --quiet pefile pyelftools 2>&1 | Out-Null
            $ErrorActionPreference = $prevEAP
            $script:BinaryVenvScripts = Join-Path $script:BinaryVenvDir 'Scripts'
        }

        $script:ExpandBinaryTestWheel = {
            param(
                [string]$WheelName,
                [string]$OutputName
            )
            $archive = Join-Path $PSScriptRoot "fixtures\corpus\archives\$WheelName"
            $dest = Join-Path $TestDrive $OutputName
            $zipCopy = Join-Path $TestDrive "$OutputName.zip"
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
            Copy-Item -LiteralPath $archive -Destination $zipCopy -Force
            Expand-Archive -LiteralPath $zipCopy -DestinationPath $dest -Force
            return $dest
        }
    }

    BeforeEach {
        if (-not $script:BinaryRealPython) { Set-ItResult -Skipped -Because 'Python 3 not found on PATH' }
    }

    It 'Returns no findings for a valid PE with no suspicious imports' {
        $target = & $script:ExpandBinaryTestWheel -WheelName 'native_pyd_pkg-1.0-py3-none-any.whl' -OutputName 'native-pyd'

        $findings = @(Invoke-BinaryInspection -ScriptsDir $script:BinaryVenvScripts -TargetPath $target -PythonExe $script:BinaryVenvPython)

        $findings.Count | Should -Be 0
    }

    It 'Reports HIGH findings for suspicious PE imports' {
        $target = & $script:ExpandBinaryTestWheel -WheelName 'suspicious_imports_pkg-1.0-py3-none-any.whl' -OutputName 'suspicious-imports'

        $findings = @(Invoke-BinaryInspection -ScriptsDir $script:BinaryVenvScripts -TargetPath $target -PythonExe $script:BinaryVenvPython)

        $findings.Count | Should -BeGreaterThan 0
        @($findings | Where-Object { $_.TestID -eq 'BINARY-SUSPICIOUS-IMPORT' -and $_.Severity -eq 'HIGH' }).Count |
            Should -BeGreaterOrEqual 1
    }

    It 'Reports HIGH findings for invalid native binary format' {
        $target = & $script:ExpandBinaryTestWheel -WheelName 'fake_native_pkg-1.0-py3-none-any.whl' -OutputName 'fake-native'

        $findings = @(Invoke-BinaryInspection -ScriptsDir $script:BinaryVenvScripts -TargetPath $target -PythonExe $script:BinaryVenvPython)

        $findings.Count | Should -BeGreaterThan 0
        @($findings | Where-Object { $_.TestID -eq 'BINARY-INVALID-FORMAT' -and $_.Severity -eq 'HIGH' }).Count |
            Should -Be 1
    }

    It 'Gracefully degrades when the inspection script path is unavailable' {
        $target = & $script:ExpandBinaryTestWheel -WheelName 'native_pyd_pkg-1.0-py3-none-any.whl' -OutputName 'missing-script'
        $missingScripts = Join-Path $TestDrive 'missing-scripts'

        $findings = @(Invoke-BinaryInspection -ScriptsDir $missingScripts -TargetPath $target)

        $findings.Count | Should -Be 0
    }
}

# ============================================================
# Find-UnsupportedFiles
# ============================================================

Describe 'Find-UnsupportedFiles' {

    BeforeEach {
        $script:UnsupportedRoot = Join-Path $TestDrive 'unsupported-scan-root'
        New-Item -ItemType Directory -Path $script:UnsupportedRoot -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:UnsupportedRoot '.reports') -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $script:UnsupportedRoot 'module.py'), "pass`n")
        [System.IO.File]::WriteAllBytes((Join-Path $script:UnsupportedRoot 'pkg.tar.gz'), [byte[]](31,139,8,0))
        [System.IO.File]::WriteAllBytes((Join-Path $script:UnsupportedRoot 'package.whl'), [byte[]](80,75,3,4))
        [System.IO.File]::WriteAllText((Join-Path $script:UnsupportedRoot 'README.md'), "# readme`n")
        [System.IO.File]::WriteAllBytes((Join-Path $script:UnsupportedRoot 'photo.JPG'), [byte[]](255,216,255,217))
        [System.IO.File]::WriteAllText((Join-Path $script:UnsupportedRoot '.reports\summary_previous.txt'), "old report")
    }

    It 'Returns only unsupported files sorted by relative path' {
        $unsupported = @(Find-UnsupportedFiles -ScanRoot $script:UnsupportedRoot)

        @($unsupported.RelativePath) | Should -Be @('photo.JPG', 'README.md')
        @($unsupported.Extension) | Should -Be @('.jpg', '.md')
    }

    It 'Does not flag compound archive suffixes or scanner report artifacts' {
        $unsupported = @(Find-UnsupportedFiles -ScanRoot $script:UnsupportedRoot)

        @($unsupported.RelativePath) | Should -Not -Contain 'pkg.tar.gz'
        @($unsupported.RelativePath) | Should -Not -Contain 'summary_previous.txt'
        @($unsupported.RelativePath | Where-Object { $_ -like '.reports*' }) | Should -BeNullOrEmpty
    }
}

# ============================================================
# Find-Python
# ============================================================

Describe 'Find-Python' {

    Context 'All three candidates fail — Get-Command throws for each' {

        BeforeAll {
            # Mock Get-Command for only the three Python candidate names.
            # The function catches each exception and tries the next; when all
            # fail it returns $null.
            Mock Get-Command {
                throw "command not found: $Name"
            } -ParameterFilter { $Name -in @('py', 'python', 'python3') }
        }

        It 'Returns $null when no Python candidate is found on PATH' {
            Find-Python | Should -BeNullOrEmpty
        }
    }

    Context "'py' on PATH and reports Python 3.11.4" {

        BeforeAll {
            # Build a fake 'py.cmd' in TestDrive that outputs 'Python 3.11.4'
            # and place its directory first on PATH.  This avoids relying on
            # Pester's ability to mock native-command calls via '& $candidate'.
            $script:FakePyDir = Join-Path $TestDrive 'fake-py'
            New-Item -ItemType Directory -Path $script:FakePyDir -Force | Out-Null

            $fakeCmd = "@echo off`r`necho Python 3.11.4`r`n"
            [System.IO.File]::WriteAllText(
                (Join-Path $script:FakePyDir 'py.cmd'), $fakeCmd, [System.Text.Encoding]::ASCII)

            $script:OrigPath = $env:PATH
            $env:PATH = "$script:FakePyDir;$env:PATH"

            # Make Get-Command succeed for 'py' and fail for the other two
            # so the function stops at the first candidate.
            Mock Get-Command {
                if ($Name -eq 'py') {
                    return [PSCustomObject]@{ Name = 'py'; CommandType = 'Application' }
                }
                throw "command not found: $Name"
            } -ParameterFilter { $Name -in @('py', 'python', 'python3') }
        }

        AfterAll {
            $env:PATH = $script:OrigPath
        }

        It "Returns 'py' when py.cmd outputs 'Python 3.11.4'" {
            Find-Python | Should -Be 'py'
        }
    }
}
