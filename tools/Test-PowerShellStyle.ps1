<#
.SYNOPSIS
    Fails if any PowerShell file in the repository is not formatter-clean and analyzer-clean.

.DESCRIPTION
    Runs Invoke-ScriptAnalyzer and Invoke-Formatter, both with PSScriptAnalyzerSettings.psd1
    from the repository root, over every .ps1 and .psd1 file under scripts/, tests/ps/ and
    tools/, plus the settings file itself. A file passes when the analyzer reports nothing
    and the formatter returns the file unchanged.

    PowerShell inside the documentation pages is checked separately by tools/ps_snippets.py.

.PARAMETER Fix
    Rewrite files with the formatter's output instead of failing on a difference. Line endings
    of each file are preserved (scripts/ is CRLF on purpose; see .gitattributes).

.EXAMPLE
    pwsh -NoProfile -File tools/Test-PowerShellStyle.ps1

.EXAMPLE
    pwsh -NoProfile -File tools/Test-PowerShellStyle.ps1 -Fix
#>
[CmdletBinding()]
param(
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
Import-Module PSScriptAnalyzer

$files = @(
    Get-ChildItem -Path (Join-Path $root 'scripts'), (Join-Path $root 'tests/ps'), (Join-Path $root 'tools') `
        -Include '*.ps1', '*.psd1', '*.psm1' -Recurse -File
    Get-Item -LiteralPath $settings
)

$problems = 0
foreach ($file in $files) {
    $relative = [System.IO.Path]::GetRelativePath($root, $file.FullName)
    $text = [System.IO.File]::ReadAllText($file.FullName)
    $formatted = Invoke-Formatter -ScriptDefinition $text -Settings $settings

    if ($formatted -cne $text) {
        if ($Fix) {
            [System.IO.File]::WriteAllText($file.FullName, $formatted)
            Write-Output "formatted: $relative"
        }
        else {
            $problems++
            Write-Output "${relative}: not formatted (run tools/Test-PowerShellStyle.ps1 -Fix)"
        }
    }

    # PSScriptAnalyzer occasionally throws a NullReferenceException on input it handles
    # fine a moment later; retry before letting that fail the run.
    $findings = $null
    for ($attempt = 1; $null -eq $findings; $attempt++) {
        try {
            $findings = @(Invoke-ScriptAnalyzer -Path $file.FullName -Settings $settings -ErrorAction Stop)
        }
        catch {
            if ($attempt -ge 4) {
                throw
            }
        }
    }

    foreach ($finding in $findings) {
        $problems++
        Write-Output ('{0}:{1}: {2}: {3}' -f $relative, $finding.Line, $finding.RuleName, $finding.Message)
    }
}

Write-Output ('{0} PowerShell file(s) checked, {1} problem(s)' -f $files.Count, $problems)
if ($problems -gt 0) {
    exit 1
}
