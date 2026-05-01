#Requires -Version 5.1
Invoke-Pester -Path (Join-Path $PSScriptRoot 'Scan-PythonPackages.Tests.ps1') -Output Detailed -PassThru | ForEach-Object { exit $_.FailedCount }
