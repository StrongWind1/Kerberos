"""Format and lint every PowerShell code block in the documentation.

The pages under ``content/`` and the shared snippets under ``includes/`` carry
PowerShell that readers paste into production Active Directory. This tool keeps
that code to the same bar as ``scripts/``: every block must be unchanged by
``Invoke-Formatter`` and produce no ``Invoke-ScriptAnalyzer`` findings, using
``PSScriptAnalyzerSettings.psd1`` at the repository root.

Usage::

    python3 tools/ps_snippets.py            # check; exit 1 on any difference or finding
    python3 tools/ps_snippets.py --fix      # rewrite blocks with the formatter's output

A block is a fenced ``powershell`` code block, at any indentation (admonitions and
list items indent their fences). A file under ``includes/`` that has no fence at all
and is pulled into a ``powershell`` fence elsewhere is treated as one whole block.
``--8<--`` snippet lines inside a block are hidden from the formatter and restored.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = ROOT / "PSScriptAnalyzerSettings.psd1"
SOURCES = ("content", "includes")

_OPEN = re.compile(
    r"^(?P<indent>[ \t]*)(?P<ticks>`{3,})\s*(?:powershell|pwsh|ps1)\b.*$", re.IGNORECASE
)
_SNIPPET = re.compile(r"^(?P<indent>[ \t]*)--8<--\s+(?P<rest>.+)$")
_SNIPPET_REF = re.compile(r'--8<--\s+"(?P<path>[^"]+)"')
_PLACEHOLDER = "# @@SNIPPET@@ "
_ATTEMPTS = 4
_PASS_SECONDS = 120

_PWSH = r"""
param([string]$Manifest, [string]$Settings, [string]$Out)
$ErrorActionPreference = 'Stop'
Import-Module PSScriptAnalyzer
$blocks = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
$results = foreach ($b in $blocks) {
    $code = [string]$b.code
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors)
    $parse = @($errors | ForEach-Object { 'line {0}: {1}' -f $_.Extent.StartLineNumber, $_.Message })
    $formatted = $code
    $findings = @()
    if ($parse.Count -eq 0 -and $code.Trim()) {
        try {
            $formatted = Invoke-Formatter -ScriptDefinition $code -Settings $Settings
            $analyse = if ($b.expanded -ne $b.code) { [string]$b.expanded } else { $formatted }
            $findings = @(Invoke-ScriptAnalyzer -ScriptDefinition $analyse -Settings $Settings |
                    ForEach-Object { 'line {0}: {1}: {2}' -f $_.Line, $_.RuleName, $_.Message })
        }
        catch {
            # A failure of the analyzer is not a finding. End without results; any exit
            # code other than 0 and 1 makes the caller run the pass again in a new process.
            Write-Warning "PSScriptAnalyzer failed on $($b.id): $($_.Exception.Message)"
            exit 3
        }
    }
    [PSCustomObject]@{ id = $b.id; formatted = $formatted; parse = $parse; findings = $findings }
}
ConvertTo-Json -InputObject @($results) -Depth 4 | Set-Content -LiteralPath $Out -Encoding utf8
"""


class Result(TypedDict):
    """What the PowerShell pass reports for one block."""

    id: str
    formatted: str
    parse: list[str]
    findings: list[str]


@dataclass
class Block:
    """One PowerShell block and where it came from."""

    path: Path
    start: int  # index of the first code line
    end: int  # index one past the last code line
    indent: str
    code: str

    @property
    def ident(self) -> str:
        return f"{self.path.relative_to(ROOT)}:{self.start + 1}"


def _hide_snippets(lines: list[str]) -> list[str]:
    """Replace ``--8<--`` lines with comments the formatter leaves alone."""
    hidden = []
    for line in lines:
        match = _SNIPPET.match(line)
        hidden.append(f"{match['indent']}{_PLACEHOLDER}{match['rest']}" if match else line)
    return hidden


def _restore_snippets(code: str) -> str:
    return re.sub(rf"(?m)^([ \t]*){re.escape(_PLACEHOLDER)}", r"\1--8<-- ", code)


def _expand(code: str) -> str:
    """Inline ``--8<--`` includes so the analyzer sees the code a reader gets.

    A settings header that only assigns variables is not "unused" when the included
    script reads them. Formatting still happens on the unexpanded block.
    """

    def inline(match: re.Match[str]) -> str:
        ref = _SNIPPET_REF.search(f"--8<-- {match['rest']}")
        target = ROOT / ref["path"] if ref else None
        if target is None or not target.is_file():
            return match[0]
        lines = target.read_text(encoding="utf-8").split("\n")
        if "```" not in "\n".join(lines):
            return "\n".join(lines).rstrip("\n")
        return "\n".join(b.code.rstrip("\n") for b in _fenced_blocks(target, lines))

    pattern = rf"(?m)^[ \t]*{re.escape(_PLACEHOLDER)}(?P<rest>.+)$"
    return re.sub(pattern, inline, code)


def _dedent(lines: list[str], indent: str) -> list[str]:
    return [line[len(indent) :] if line.startswith(indent) else line.lstrip() for line in lines]


def _fenced_blocks(path: Path, lines: list[str]) -> list[Block]:
    blocks = []
    index = 0
    while index < len(lines):
        match = _OPEN.match(lines[index])
        if not match:
            index += 1
            continue
        indent, ticks = match["indent"], match["ticks"]
        close = index + 1
        while close < len(lines) and lines[close].strip() != ticks:
            close += 1
        body = _hide_snippets(_dedent(lines[index + 1 : close], indent))
        blocks.append(Block(path, index + 1, close, indent, "\n".join(body) + "\n"))
        index = close + 1
    return blocks


def _raw_includes(files: list[Path]) -> set[Path]:
    """Includes with no fence of their own that some ``powershell`` fence pulls in."""
    raw: set[Path] = set()
    for path in files:
        for block in _fenced_blocks(path, path.read_text(encoding="utf-8").split("\n")):
            for ref in _SNIPPET_REF.finditer(_restore_snippets(block.code)):
                target = ROOT / ref["path"]
                if target.is_file() and "```" not in target.read_text(encoding="utf-8"):
                    raw.add(target)
    return raw


def collect(only: list[Path] | None = None) -> list[Block]:
    """Return every PowerShell block in the documentation sources."""
    files = sorted(p for source in SOURCES for p in (ROOT / source).rglob("*.md"))
    raw = _raw_includes(files)
    blocks = []
    for path in files:
        if only is not None and path not in only:
            continue
        lines = path.read_text(encoding="utf-8").split("\n")
        if path in raw:
            body = lines[:-1] if lines and lines[-1] == "" else lines
            blocks.append(Block(path, 0, len(body), "", "\n".join(_hide_snippets(body)) + "\n"))
        else:
            blocks.extend(_fenced_blocks(path, lines))
    return blocks


def run_pwsh(blocks: list[Block]) -> dict[str, Result]:
    """Format and analyse all blocks in one PowerShell process.

    When that process ends without results, or has not ended after ``_PASS_SECONDS``,
    it is started again, up to ``_ATTEMPTS`` times in all. PSScriptAnalyzer 1.25.0 ends
    without results in a few runs out of a hundred: a rule throws, its command lookup
    reports that ``Get-Command`` is not recognized, or an unhandled exception ends the
    process. Its command cache keeps a failed lookup for as long as the process lives,
    so only a new process can ask again. A process has also been seen to stand still
    for fifteen minutes; a pass over every block takes a few seconds.
    """
    with tempfile.TemporaryDirectory() as tmp:
        manifest, out, script = (Path(tmp) / name for name in ("in.json", "out.json", "run.ps1"))
        payload = [{"id": b.ident, "code": b.code, "expanded": _expand(b.code)} for b in blocks]
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        script.write_text(_PWSH, encoding="utf-8")
        command = [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            str(manifest),
            str(SETTINGS),
            str(out),
        ]
        outcome = ""
        for attempt in range(1, _ATTEMPTS + 1):
            try:
                completed = subprocess.run(command, check=False, timeout=_PASS_SECONDS)
            except subprocess.TimeoutExpired:
                outcome = f"no end after {_PASS_SECONDS} seconds"
            else:
                # 0 is results written, and 1 is an error in the pass itself, which a second
                # run would only repeat. Any other code is the analyzer or the process failing.
                if completed.returncode in (0, 1):
                    completed.check_returncode()
                    return _load_results(out.read_text(encoding="utf-8-sig"))
                outcome = f"exit code {completed.returncode}"
            if attempt < _ATTEMPTS:
                print(
                    f"No results ({outcome}). "
                    f"Checking again in a new process: attempt {attempt + 1} of {_ATTEMPTS}.",
                    flush=True,
                )
        msg = f"PSScriptAnalyzer gave no results in {_ATTEMPTS} attempts ({outcome})"
        raise RuntimeError(msg)


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"PowerShell output: expected a string, got {value!r}")
    return value


def _lines(value: object) -> list[str]:
    if not isinstance(value, list):
        raise TypeError(f"PowerShell output: expected a list, got {value!r}")
    return [_text(line) for line in value]


def _load_results(text: str) -> dict[str, Result]:
    """Parse the JSON the PowerShell pass wrote, checking the shape of every entry."""
    data: object = json.loads(text)
    if not isinstance(data, list):
        raise TypeError("PowerShell output: expected a list of results")
    results: dict[str, Result] = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise TypeError(f"PowerShell output: expected an object, got {entry!r}")
        result = Result(
            id=_text(entry.get("id")),
            formatted=_text(entry.get("formatted")),
            parse=_lines(entry.get("parse")),
            findings=_lines(entry.get("findings")),
        )
        results[result["id"]] = result
    return results


def apply(blocks: list[Block], results: dict[str, Result]) -> int:
    """Write the formatter's output back into the source files."""
    changed = 0
    by_file: dict[Path, list[Block]] = {}
    for block in blocks:
        by_file.setdefault(block.path, []).append(block)
    for path, file_blocks in by_file.items():
        original = path.read_text(encoding="utf-8")
        lines = original.split("\n")
        for block in sorted(file_blocks, key=lambda b: b.start, reverse=True):
            formatted = _restore_snippets(results[block.ident]["formatted"]).rstrip("\n")
            new = [
                f"{block.indent}{line.rstrip()}" if line.strip() else ""
                for line in formatted.split("\n")
            ]
            if lines[block.start : block.end] != new:
                lines[block.start : block.end] = new
                changed += 1
        if "\n".join(lines) != original:
            path.write_text("\n".join(lines), encoding="utf-8")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--fix", action="store_true", help="rewrite blocks with the formatter's output"
    )
    parser.add_argument("paths", nargs="*", type=Path, help="limit to these files (default: all)")
    args = parser.parse_args()
    only = [p.resolve() for p in args.paths] or None

    blocks = collect(only)
    results = run_pwsh(blocks)
    if args.fix:
        print(f"reformatted {apply(blocks, results)} block(s)")
        blocks = collect(only)
        results = run_pwsh(blocks)

    problems = 0
    for block in blocks:
        result = results[block.ident]
        messages = [f"does not parse: {m}" for m in result["parse"]] + list(result["findings"])
        if not result["parse"] and result["formatted"].rstrip("\n") != block.code.rstrip("\n"):
            messages.append("not formatted (run: python3 tools/ps_snippets.py --fix)")
        for message in messages:
            problems += 1
            print(f"{block.ident}: {message}")
    print(f"{len(blocks)} PowerShell block(s) checked, {problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
