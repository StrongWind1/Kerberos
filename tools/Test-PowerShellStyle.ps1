<#
.SYNOPSIS
    Fails if any PowerShell file in the repository is not formatter-clean and analyzer-clean.

.DESCRIPTION
    Runs Invoke-ScriptAnalyzer and Invoke-Formatter, both with PSScriptAnalyzerSettings.psd1
    from the repository root, over every .ps1 and .psd1 file under scripts/, tests/ps/ and
    tools/, plus the settings file itself. A file passes when the analyzer reports nothing
    and the formatter returns the file unchanged.

    PowerShell inside the documentation pages is checked separately by tools/ps_snippets.py.

    The files are checked in a second PowerShell process. When that process ends without a
    verdict, or has not ended after two minutes, it is started again, up to four times in all.
    PSScriptAnalyzer 1.25.0 ends without a verdict in a few runs out of a hundred, in one of
    three ways: a NullReferenceException from a rule, "The term 'Get-Command' is not
    recognized" from its command lookup, or an unhandled exception that ends the whole
    process. Its command cache keeps a failed lookup for as long as the process lives, so only
    a new process can ask again. In one of 800 test runs a process also stood still for
    fifteen minutes; checking four files takes it a few seconds.

.PARAMETER Fix
    Rewrite files with the formatter's output instead of failing on a difference. Line endings
    of each file are preserved (scripts/ is CRLF on purpose; see .gitattributes).

.PARAMETER Pass
    Set by the script itself for the second process: check the files once, here, and give the
    verdict as the exit code. 0 is clean, 1 is problems found, 3 is a PSScriptAnalyzer failure.

.EXAMPLE
    pwsh -NoProfile -File tools/Test-PowerShellStyle.ps1

.EXAMPLE
    pwsh -NoProfile -File tools/Test-PowerShellStyle.ps1 -Fix
#>
[CmdletBinding()]
param(
    [switch]$Fix,

    [switch]$Pass
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Pass) {
    # The second process writes straight to this one's output.
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    foreach ($argument in @('-NoProfile', '-File', $PSCommandPath, '-Pass') + @(if ($Fix) { '-Fix' })) {
        $startInfo.ArgumentList.Add($argument)
    }

    $attempts = 4
    $limitSeconds = 120
    for ($attempt = 1; ; $attempt++) {
        $process = [System.Diagnostics.Process]::Start($startInfo)
        $ended = $process.WaitForExit($limitSeconds * 1000)
        if (-not $ended) {
            $process.Kill($true)
            $process.WaitForExit()
        }

        # 0 and 1 are verdicts. Any other code is a failure of the analyzer or of the process.
        if ($ended -and $process.ExitCode -in 0, 1) {
            exit $process.ExitCode
        }
        $outcome = if ($ended) { "exit code $($process.ExitCode)" } else { "no end after $limitSeconds seconds" }
        if ($attempt -eq $attempts) {
            Write-Output "No verdict ($outcome) in $attempts attempts."
            exit 3
        }
        Write-Output "No verdict ($outcome). Checking again in a new process: attempt $($attempt + 1) of $attempts."
    }
}

$root = Split-Path -Parent $PSScriptRoot
$settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
Import-Module PSScriptAnalyzer

# Runs one PSScriptAnalyzer command. When the command throws, the pass ends without a verdict.
function Invoke-Analyzer {
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter(Mandatory)]
        [hashtable]$Arguments,

        [Parameter(Mandatory)]
        [string]$RelativePath
    )

    try {
        & $Command @Arguments
    }
    catch {
        Write-Warning "$Command failed on ${RelativePath}: $($_.Exception.Message)"
        exit 3
    }
}

$files = @(
    Get-ChildItem -Path (Join-Path $root 'scripts'), (Join-Path $root 'tests/ps'), (Join-Path $root 'tools') `
        -Include '*.ps1', '*.psd1', '*.psm1' -Recurse -File
    Get-Item -LiteralPath $settings
)

# Problems are collected and printed at the end, so that a pass that fails half way and is
# run again reports nothing twice.
$problems = [System.Collections.Generic.List[string]]::new()
foreach ($file in $files) {
    $relative = [System.IO.Path]::GetRelativePath($root, $file.FullName)
    $text = [System.IO.File]::ReadAllText($file.FullName)
    $formatted = Invoke-Analyzer -Command 'Invoke-Formatter' -RelativePath $relative -Arguments @{
        ScriptDefinition = $text
        Settings         = $settings
    }

    if ($formatted -cne $text) {
        if ($Fix) {
            [System.IO.File]::WriteAllText($file.FullName, $formatted)
            Write-Output "formatted: $relative"
        }
        else {
            $problems.Add("${relative}: not formatted (run tools/Test-PowerShellStyle.ps1 -Fix)")
        }
    }

    $findings = @(
        Invoke-Analyzer -Command 'Invoke-ScriptAnalyzer' -RelativePath $relative -Arguments @{
            Path        = $file.FullName
            Settings    = $settings
            ErrorAction = 'Stop'
        }
    )
    foreach ($finding in $findings) {
        $problems.Add(('{0}:{1}: {2}: {3}' -f $relative, $finding.Line, $finding.RuleName, $finding.Message))
    }
}

$problems
Write-Output ('{0} PowerShell file(s) checked, {1} problem(s)' -f $files.Count, $problems.Count)
if ($problems.Count -gt 0) {
    exit 1
}
