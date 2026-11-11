# scripts

## Get-KdcKerberosRegistryAudit.ps1

A read-only audit of the registry values that decide which Kerberos encryption types a
domain controller's KDC issues. It never writes anything, so it is safe to run in production.

For every domain controller it reports:

- every documented path/value combination, with its type, decimal and hex value, decoded
  meaning, and whether the KDC **on that DC's OS build** actually reads it;
- values written at a path the KDC does not read, or under a misspelled name (for example
  `DefaultDomainSupportedEncTypes` under `Services\Kdc\Parameters`, which the KDC silently
  ignores);
- the DC computer account's `msDS-SupportedEncryptionTypes`, and whether it agrees with the
  configured `SupportedEncryptionTypes`;
- one **effective state** derived from the build and the settings together:
  - the etypes the KDC falls back to for accounts with no `msDS-SupportedEncryptionTypes`
    (an explicit `DefaultDomainSupportedEncTypes` when set, otherwise the build default:
    `0x27` before the April 2026 cumulative update, `0x18` on it or later);
  - which `SupportedEncryptionTypes` path is the effective KDC etype filter;
  - whether RC4 default removal (CVE-2026-20833) is active, not active, overridden by an
    explicit setting, or cannot be determined.

A DC that still hands out RC4 by default, or whose build cannot be classified, is a finding
even when its registry is empty. An empty registry is never a pass on its own.

### Requirements

- Windows PowerShell 5.1 or PowerShell 7 on the machine you run it from.
- WinRM (PowerShell remoting) to each remote DC. The local machine is read in-process.
- Local administrator rights on each DC (to read the registry).
- The RSAT ActiveDirectory module is optional; without it discovery uses
  `System.DirectoryServices`.

### Getting the script

It is a single self-contained file. Download a **specific commit**, not `main`, so that what
you run is what you reviewed:

```powershell
$commit = '<full 40-character commit SHA>'
$url    = "https://raw.githubusercontent.com/StrongWind1/Kerberos/$commit/scripts/Get-KdcKerberosRegistryAudit.ps1"
Invoke-WebRequest -Uri $url -OutFile .\Get-KdcKerberosRegistryAudit.ps1
```

Then check what you have before you run it:

```powershell
# Compare with the hash of the same file in a clone checked out at that commit.
Get-FileHash .\Get-KdcKerberosRegistryAudit.ps1 -Algorithm SHA256

# Read it. It is long, but it only reads.
Get-Content .\Get-KdcKerberosRegistryAudit.ps1 | more
```

The file is stored with CRLF line endings on purpose, so a raw download and a Git checkout
are byte-identical and hash the same.

A file downloaded with a browser carries the Mark of the Web, and the script is **not
Authenticode-signed**:

| Execution policy | What to do |
|---|---|
| `RemoteSigned` (the Windows Server default) | `Unblock-File .\Get-KdcKerberosRegistryAudit.ps1` after reviewing it |
| `AllSigned` | Sign it with your own code-signing certificate, or run it from a host with a different policy |
| One-off run | `powershell.exe -ExecutionPolicy Bypass -File .\Get-KdcKerberosRegistryAudit.ps1` |

The script prints its version in the report header, the HTML report and every `-PassThru`
row (`ScriptVersion`). The same version is in the `PSScriptInfo` block at the top of the file.

### Usage

```powershell
# Every DC in the current domain
.\Get-KdcKerberosRegistryAudit.ps1

# A named domain with an explicit credential
.\Get-KdcKerberosRegistryAudit.ps1 -Domain corp.contoso.com -Credential (Get-Credential)

# Specific hosts, or hosts from the pipeline
.\Get-KdcKerberosRegistryAudit.ps1 -ComputerName dc1.contoso.com, dc2.contoso.com
Get-ADDomainController -Filter * | .\Get-KdcKerberosRegistryAudit.ps1

# Structured output
.\Get-KdcKerberosRegistryAudit.ps1 -PassThru | Export-Csv kdc-audit.csv -NoTypeInformation
.\Get-KdcKerberosRegistryAudit.ps1 -PassThru | ConvertTo-Json -Depth 3 | Set-Content kdc-audit.json

# HTML report (sortable, filterable, self-contained)
.\Get-KdcKerberosRegistryAudit.ps1 -HtmlReport .\kdc-audit.html

# Scheduled task / CI
.\Get-KdcKerberosRegistryAudit.ps1 -NoColor -FailOn Insecure, Invalid, Unknown, Unreachable, Error
```

### Parameters

| Parameter | Purpose |
|---|---|
| `-ComputerName` | Hosts to audit. Accepts pipeline input (strings, or objects with `HostName` / `DNSHostName`). Omit to audit every DC in the domain. Duplicate names, and two names for the same machine, are audited once. |
| `-Domain` | Domain to discover DCs in. Defaults to the current domain. |
| `-Credential` | Credential for discovery and the remote read. Not used for the local machine. |
| `-PassThru` | Emit one object per row instead of the text report. `Value` is numeric. |
| `-HtmlReport <path>` | Also write the HTML report. A relative path is resolved against the current PowerShell location. Works with `-PassThru`. |
| `-GridView` | Also open the rows in `Out-GridView`, or the HTML report where that is unavailable. |
| `-NoColor` | No ANSI color. Color is switched off automatically when the script can tell its output is piped, redirected or assigned; use `-NoColor` when a calling script captures the output. |
| `-FailOn <classes>` | Set an exit code (see below). Without it the script never calls `exit`. |
| `-ThrottleLimit`, `-SessionOption`, `-UseSSL`, `-Authentication`, `-ConfigurationName` | Passed through to `Invoke-Command` for the WinRM fan-out. Use `-SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000)` so an unresponsive DC fails quickly. |

`Get-Help .\Get-KdcKerberosRegistryAudit.ps1 -Full` has the complete text.

### Status values

| Status | Meaning |
|---|---|
| `Secure` | AES-only, or a setting in its safe state. |
| `Transitional` | RC4 is still permitted alongside AES (for example `0x1C`, `0x3C`). Not broken, not finished. |
| `Insecure` | DES, RC4 without AES, RC4 still the default for unset accounts, or `KdcUseRequestedEtypesForTickets = 1`. |
| `Invalid` | Wrong path, wrong registry type, undefined bits, unrecognized value name, or a value the KDC on this build does not read. |
| `Unknown` | The build cannot be classified, or which filter path it reads is not established. Verify with a live ticket. |
| `Error` | The value could not be read (access denied, directory bind failure). This is **not** "not set". |
| `Unreachable` | The host did not answer. It gets its own row. |
| `NotDC` | The host answered but is not a domain controller. It gets one row and is not audited. |

What counts as secure is controlled by the `SECURITY POLICY` block near the top of the script.

### Exit codes

Only set when `-FailOn` is given. List the status classes that should fail the run
(`Insecure`, `Invalid`, `Transitional`, `Unknown`, `Error`, `Unreachable`, `NotDC`, or `Any`).

| Code | Meaning |
|---|---|
| `0` | None of the listed classes is present. |
| `1` | A listed security class is present (`Insecure`, `Invalid`, `Transitional`, `Unknown`). |
| `2` | A listed coverage class is present (`Error`, `Unreachable`, `NotDC`), or no domain controller could be audited. |
| `3` | Both. |

### Limits of the build map

RC4 default removal ships in cumulative updates, so the script places each DC on the rollout
timeline from its OS build revision. Read the result with these limits in mind:

- **Covered:** Windows Server 2016 (14393), 2019 (17763), 2022 (20348) and 2025 (26100).
  Any other OS build reports `UNKNOWN`.
- **Lab-verified:** only the Server 2022 enforcement boundary. `20348.4893` (March 2026
  update, KB5078766) still issued RC4 for unset accounts; `20348.5020` (April 2026 update,
  KB5082142) issued AES256.
- **From Microsoft's release history, not lab-verified:** every other threshold. They are
  the published build numbers of the January, April and July 2026 updates per OS
  ([Windows Server release information](https://learn.microsoft.com/windows/release-health/windows-server-release-info)),
  combined with the phase dates in
  [KB5073381](https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc).
- **July 2026 and later:** KB5073381 says `RC4DefaultDisablementPhase` is no longer read
  from the July 2026 update. Nobody in this project has lab-verified that. A leftover
  `RC4DefaultDisablementPhase` of 0 or 1 on such a build is reported as `Invalid` and the
  DC's default as `Unknown`, with a prompt to verify using a live ticket.
- **KDC filter path:** lab-verified on Server 2022 only (Policies takes precedence, Lsa is
  the fallback). One Server 2025 build (`26100.32522`, March 2026 update) ignored the
  Policies path and read Lsa only. Microsoft's release note for the April 2026 update
  (KB5082063, `26100.32690`) says the policy settings are read as expected; that has not
  been retested, so from that build the script reports the filter path as `UNCERTAIN`
  unless both paths hold the same value. Server 2016 and 2019 were never lab-tested; the
  Server 2022 model is assumed and labeled as assumed.
- **KDC restart:** the filter and `RC4DefaultDisablementPhase` only take effect after the
  KDC service restarts. The registry cannot show whether that has happened.
- **Phase and account state are out of scope:** the script does not look at accounts,
  keys, trusts or events. It tells you what each DC is configured to do.

When Microsoft ships a build the map does not know, extend `Rc4EnforcementBuilds` in the
policy block and say in the comment where the number came from.

### Tests

`tests/ps/` holds a Pester suite that dot-sources the script (which defines its functions
without discovering or reading anything) and drives the classifier with fixture records. It
needs no Windows, Active Directory or WinRM.

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force

# Lint (zero findings expected) with the repository settings; -Path takes one path at a time
foreach ($path in 'scripts', 'tests/ps') {
    Invoke-ScriptAnalyzer -Path $path -Recurse -Settings ./PSScriptAnalyzerSettings.psd1 -EnableExit
}

# Formatting: Invoke-Formatter must return each file unchanged
Get-ChildItem scripts, tests/ps -Filter *.ps1 -Recurse | ForEach-Object {
    $source = Get-Content -Raw -LiteralPath $_.FullName
    if ((Invoke-Formatter -ScriptDefinition $source -Settings ./PSScriptAnalyzerSettings.psd1) -cne $source) {
        throw "$($_.Name) is not formatted"
    }
}

Invoke-Pester -Path tests/ps -CI
```

Both `.ps1` files are ASCII with CRLF line endings; keep them that way (`.gitattributes`
stores `*.ps1` byte-for-byte).
