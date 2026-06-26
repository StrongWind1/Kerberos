#Requires -Version 5.1

<#
.SYNOPSIS
    Audit Kerberos KDC encryption-type registry settings across every domain controller.

.DESCRIPTION
    Discovers all domain controllers in the target Active Directory domain (the current
    domain by default, or a named -Domain, optionally with -Credential), or audits a
    caller-supplied -ComputerName list, then reads every registry value the KDC consults
    when it selects a Kerberos ticket encryption type. Each value is reported with its raw
    data, hex form,
    a decoded human-readable meaning, and a verdict stating whether that path/value
    combination is actually honored by the KDC.

    A one-time key reference lists each value's default, whether it is set automatically, and
    what it does. The audit then prints one section per domain controller and an aggregate
    summary. On a capable terminal each row is colored by its security status: green for a
    secure value, yellow for an insecure value, and red for a wrong-path location or an
    invalid value (disable with -NoColor). What counts as secure vs. insecure is controlled
    entirely by the SECURITY POLICY block near the top of this file: edit those variables to
    change the policy without touching any other code.

    Of the documented path/value combinations, only 5 change KDC behavior; the rest are
    common misconfigurations that look correct but are silently ignored. This audit surfaces
    both so an operator can spot a value set at the wrong path.

    The script only reads the registry. It never writes, so it is safe to run in production.

.PARAMETER ComputerName
    One or more specific hosts to query. When omitted, the script audits EVERY domain
    controller in the target domain (Get-ADDomainController when the RSAT ActiveDirectory
    module is present, otherwise System.DirectoryServices).

.PARAMETER Domain
    Domain whose domain controllers should be audited when -ComputerName is not given.
    Defaults to the current domain. Combine with -Credential to reach a domain the calling
    session is not authenticated to.

.PARAMETER Credential
    Optional alternate credential used for BOTH domain-controller discovery and the remote
    registry read. Defaults to the caller's current context. An explicit credential also lets
    the WinRM hop to each DC succeed from a non-interactive (network logon) session.

.PARAMETER PassThru
    Emit the raw result objects (including the Status field) to the pipeline instead of the
    formatted per-DC report. Use this to export results (Export-Csv, etc.).

.PARAMETER NoColor
    Disable ANSI color in the report. Color is on by default on a capable terminal and is
    suppressed automatically when output is piped or the host has no virtual-terminal support.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1
    Audit every DC in the current domain as the current user; per-DC sections then a summary.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -Domain corp.contoso.com -Credential (Get-Credential)
    Audit every DC in a named domain using an explicit credential.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -ComputerName dc1.contoso.com,dc2.contoso.com -Credential (Get-Credential)
    Audit two specific hosts using an explicit credential.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -PassThru | Export-Csv kdc-audit.csv -NoTypeInformation
    Capture the audit for every DC as structured objects and save them to CSV.

.NOTES
    Requires Windows PowerShell remoting (WinRM), which is enabled by default on domain
    controllers. Reading the registry needs local administrator rights on each target DC.
#>

# Advanced-script binding gives the file -Verbose, -ErrorAction and other common parameters.
[CmdletBinding()]
# Declare the shape of the objects emitted under -PassThru so callers get tab-completion.
[OutputType([System.Management.Automation.PSCustomObject])]
param(
    # Explicit host list; empty by default so the script audits every DC in the target domain.
    [Parameter()]
    [string[]]$ComputerName,

    # Domain whose DCs to audit when -ComputerName is omitted; defaults to the current domain.
    [Parameter()]
    [string]$Domain,

    # Alternate credential for discovery and the remote read; PSCredential keeps secrets safe.
    [Parameter()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    # When present, return objects instead of a pretty report so output can be piped onward.
    [Parameter()]
    [switch]$PassThru,

    # Disable ANSI color output (color is on by default when the terminal supports it).
    [Parameter()]
    [switch]$NoColor
)

# ======================== SECURITY POLICY (edit me) ========================
# Defines what the audit treats as secure vs. insecure. Change a property here
# and every value is re-classified accordingly -- no other code needs editing.
$SecurityPolicy = [PSCustomObject]@{
    # Etype bits treated as insecure (weak crypto). A functional etype value carrying any
    # of these bits is classified Insecure; an AES-only value is Secure.
    # 0x1 = DES-CBC-CRC, 0x2 = DES-CBC-MD5, 0x4 = RC4-HMAC.
    WeakEtypeBits     = (0x1 -bor 0x2 -bor 0x4)

    # Etype bits treated as strong (any AES). A value carrying one of these and no weak bit
    # is Secure. 0x08/0x10 = AES128/256 (SHA1); 0x40/0x80 = AES128/256 (SHA2, Server 2025).
    StrongEtypeBits   = (0x08 -bor 0x10 -bor 0x40 -bor 0x80)

    # RC4DefaultDisablementPhase at or above this value is Secure (RC4 enforced off); below
    # it the KDC still allows RC4 by default, so it is classified Insecure. 2 = enforce.
    MinSecureRc4Phase = 2
}
# ===========================================================================

# Decide whether to emit ANSI color: on by default, but suppressed by -NoColor or when the
# host lacks virtual-terminal support (piped output or a non-interactive remoting session),
# so captured or redirected output stays clean.
$script:Esc = [char]27
$script:UseColor = (-not $NoColor) -and $Host.UI.SupportsVirtualTerminal

# --- Helpers ---

function ConvertTo-ColorText {
    <#
    .SYNOPSIS
        Wrap text in an ANSI SGR color code when color output is enabled.
    #>
    # String in, string out; the analyzer and callers know the contract.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The text to colorize. Empty strings are allowed (blank report lines).
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        # ANSI SGR parameter(s), e.g. '31' (red), '33' (yellow), '1;36' (bold cyan).
        [Parameter(Mandatory)]
        [string]$Code
    )

    # With color disabled, return the text untouched so redirected output stays clean.
    if (-not $script:UseColor) {
        return $Text
    }

    # Wrap as ESC[<code>m <text> ESC[0m so the terminal applies then resets the color.
    return ('{0}[{1}m{2}{0}[0m' -f $script:Esc, $Code, $Text)
}

function Write-StatusColoredTable {
    <#
    .SYNOPSIS
        Render rows as a table and tint each data line by that row's security Status.
    #>
    # Coloring a whole line (not a cell) keeps Format-Table columns aligned on PowerShell 5.1.
    # Rows are matched to lines by order, so the table is rendered wide enough not to wrap.
    [CmdletBinding()]
    param(
        # The report rows to render; each carries a Status property used for the row color.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        $Rows,

        # The Format-Table -Property list (column names and/or calculated-property hashtables).
        [Parameter(Mandatory)]
        $Property
    )

    # Render once; -Width 250 keeps the wide full-path column on a single line per row.
    $text = @($Rows) | Format-Table -AutoSize -Property $Property | Out-String -Width 250
    $rowList = @($Rows)
    $index = 0
    $passedSeparator = $false

    foreach ($line in ($text -split "`r?`n")) {
        if (-not $script:UseColor) {
            # No color: emit every line unchanged.
            Write-Output $line
        } elseif (-not $passedSeparator) {
            # The header and the dashed separator print uncolored; note when we pass them.
            if ($line -match '^\s*-+(\s+-+)*\s*$') { $passedSeparator = $true }
            Write-Output $line
        } elseif ($line.Trim().Length -eq 0) {
            # Trailing blank line.
            Write-Output $line
        } else {
            # A data row: tint by the matching row's Status (red invalid, yellow insecure, green secure).
            $rowStatus = if ($index -lt $rowList.Count) { $rowList[$index].Status } else { '' }
            $index++
            $code = switch ($rowStatus) {
                'Invalid' { '31' }
                'Insecure' { '33' }
                'Secure' { '1;32' }
                default { '' }
            }
            if ($code) {
                Write-Output (ConvertTo-ColorText -Text $line -Code $code)
            } else {
                Write-Output $line
            }
        }
    }
}

function ConvertTo-KerberosEtypeName {
    <#
    .SYNOPSIS
        Decode a Kerberos supported-encryption-type bitmask into readable flag names.
    #>
    # Standard binding plus a string return contract for callers and the analyzer.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The DWORD bitmask read from the registry (for example 0x18 for AES128 + AES256).
        [Parameter(Mandatory)]
        [int]$Mask,

        # SupportedEncryptionTypes (the GPO filter) decodes high bits as "Future"; DDSET and
        # the rest treat undefined high bits as unknown. Off by default (DDSET style).
        [Parameter()]
        [switch]$SupportsFuture
    )

    # Map each defined bit to its name. A plain hashtable indexes by key; an [ordered]
    # dictionary would treat the integer bit as a positional index and decode wrongly.
    $flags = @{
        0x01 = 'DES-CBC-CRC'   # [MS-KILE] bit 0: legacy DES, broken.
        0x02 = 'DES-CBC-MD5'   # [MS-KILE] bit 1: legacy DES, broken.
        0x04 = 'RC4-HMAC'      # [MS-KILE] bit 2: RC4, deprecated by CVE-2026-20833.
        0x08 = 'AES128'        # [MS-KILE] bit 3: AES128-CTS-HMAC-SHA1-96.
        0x10 = 'AES256'        # [MS-KILE] bit 4: AES256-CTS-HMAC-SHA1-96.
        0x20 = 'AES256-SK'     # [KB5021131] bit 5: AES256 session key only.
        0x40 = 'AES128-SHA256' # [RFC 8009] bit 6: AES128-CTS-HMAC-SHA256-128 (etype 19); defined, not yet active.
        0x80 = 'AES256-SHA384' # [RFC 8009] bit 7: AES256-CTS-HMAC-SHA384-192 (etype 20); defined, not yet active.
    }

    # Collect the names of every set bit, walking keys low-to-high for stable ordering.
    $names = foreach ($bit in ($flags.Keys | Sort-Object)) {
        # Bitwise-AND isolates one flag; a non-zero result means that etype is present.
        if (($Mask -band $bit) -ne 0) {
            # Emit the friendly name for this set bit into the $names collection.
            $flags[$bit]
        }
    }

    # Decode the bits above the eight defined etype bits differently per value type:
    # SupportedEncryptionTypes carries the GPO "Future encryption types" range (bits 5-30) as
    # one checkbox, so show "Future"; DDSET has no such range, so undefined high bits are shown
    # as a raw hex token (and Resolve-SecurityStatus flags a DDSET value with them as Invalid).
    $high = $Mask -band (-bnot 0xFF)
    if ($high -ne 0) {
        if ($SupportsFuture) {
            $names = @($names) + 'Future'
        } else {
            $names = @($names) + ('0x{0:X}?' -f $high)
        }
    }

    # A mask of zero means "no etypes"; otherwise join the names with a plus sign.
    if (@($names).Count -eq 0) {
        # Zero mask is meaningful for msDS-SET (means "use the DC default"), so label it.
        return 'None (0)'
    }

    # Join the individual flag names into one compact, readable string.
    return ($names -join '+')
}

function Resolve-SettingMeaning {
    <#
    .SYNOPSIS
        Turn a raw registry value into a short, human-readable interpretation.
    #>
    # Binding plus string output contract keep this helper analyzer-clean.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # Decode strategy for this value (mask, etype number, phase, bool, or log level).
        [Parameter(Mandatory)]
        [string]$Kind,

        # The raw value read from the registry; may be any type, hence no type constraint.
        [Parameter()]
        $Value,

        # Whether the value actually exists; a missing value short-circuits to "(not set)".
        [Parameter(Mandatory)]
        [bool]$Found,

        # Passed to the etype decoder so SupportedEncryptionTypes and DDSET high bits decode
        # separately (Future vs. unknown).
        [Parameter()]
        [switch]$SupportsFuture
    )

    # A value that is absent has no meaning to decode, so report it as not set.
    if (-not $Found) {
        return '(not set)'
    }

    # Branch on the decode strategy declared for this particular registry value.
    switch ($Kind) {
        'EtypeMask' {
            # Bitmask values (DDSET, SupportedEncryptionTypes) decode to etype flag names;
            # the SupportsFuture flag keeps their high-bit handling separate.
            return (ConvertTo-KerberosEtypeName -Mask ([int]$Value) -SupportsFuture:$SupportsFuture)
        }
        'Phase' {
            # RC4DefaultDisablementPhase is an enum controlling the RC4 deprecation rollout.
            $map = @{ 0 = 'Off (no change)'; 1 = 'Audit'; 2 = 'Enforce (AES-only default)' }
            # Normalize to an integer for the lookup below.
            $number = [int]$Value
            # Return the phase description, or a generic label for an out-of-range value.
            if ($map.ContainsKey($number)) {
                return $map[$number]
            }
            return "phase $number"
        }
        'Bool' {
            # KdcUseRequestedEtypesForTickets is a security-sensitive on/off switch.
            if ([int]$Value -eq 1) {
                # A value of 1 lets clients downgrade to RC4, so call it out.
                return 'ON - downgrade'
            }
            # Any other value is the safe default.
            return 'Off'
        }
        'Log' {
            # LogLevel toggles verbose Kerberos event logging.
            if ([int]$Value -eq 1) {
                return 'Verbose'
            }
            return 'Off'
        }
        default {
            # Unknown decode kinds fall back to the raw value rendered as text.
            return [string]$Value
        }
    }
}

function Resolve-SecurityStatus {
    <#
    .SYNOPSIS
        Classify a reading's security as Secure, Insecure, Invalid, or '' (neutral).
    #>
    # String out: '' (neutral), 'Secure', 'Insecure', or 'Invalid' drive the row color.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The matrix metadata row for this value (carries Kind and Functional verdict).
        [Parameter(Mandatory)]
        $Meta,

        # The raw value read from the registry; type-free because kinds differ.
        [Parameter()]
        $Value,

        # Whether the value exists. Absent values are neutral (nothing to classify).
        [Parameter(Mandatory)]
        [bool]$Found,

        # The active SECURITY POLICY object defined at the top of the script.
        [Parameter(Mandatory)]
        $Policy
    )

    # An absent value carries no security weight here.
    if (-not $Found) {
        return ''
    }

    # A value SET at a non-functional path is invalid: it looks effective but is ignored.
    if ($Meta.Functional -eq 'No (wrong path)') {
        return 'Invalid'
    }

    # Keys that never affect KDC security (legacy/unused, diagnostic) stay neutral.
    if ($Meta.Functional -ne 'Yes') {
        return ''
    }

    # Classify the value of a functional key by its kind.
    switch ($Meta.Kind) {
        'EtypeMask' {
            # Work on the integer mask for the bit tests below.
            $mask = [int]$Value
            # SupportedEncryptionTypes (the GPO filter) may legitimately carry the "Future
            # encryption types" range (bits 5-30); only DDSET is restricted to the defined
            # etype bits, so undefined high bits make a DDSET value Invalid, not a filter value.
            $isFilter = $Meta.Name -eq 'SupportedEncryptionTypes'
            if (-not $isFilter -and ($mask -band (-bnot 0xFF)) -ne 0) {
                return 'Invalid'
            }
            # DES or RC4 present -> insecure.
            if (($mask -band $Policy.WeakEtypeBits) -ne 0) {
                return 'Insecure'
            }
            # Any AES etype (SHA1 or SHA2) present and no weak bits -> secure.
            if (($mask -band $Policy.StrongEtypeBits) -ne 0) {
                return 'Secure'
            }
            # A set mask with neither AES nor a weak bit (e.g. AES-SK alone) is not secure.
            return 'Insecure'
        }
        'Bool' {
            # KdcUseRequestedEtypesForTickets = 1 permits an RC4 downgrade.
            if ([int]$Value -eq 1) {
                return 'Insecure'
            }
            return 'Secure'
        }
        'Phase' {
            # Enforce (>= policy minimum) is secure; off/audit still allow RC4.
            if ([int]$Value -ge $Policy.MinSecureRc4Phase) {
                return 'Secure'
            }
            return 'Insecure'
        }
        default {
            # Any other functional kind has no security classification.
            return ''
        }
    }
}

# --- Registry matrix ---

# Every documented path/value combination, with the verdict on whether the KDC honors it,
# its default, whether it is set automatically, and a one-line description.
# Order controls report sorting: functional keys first, ignored/wrong-path keys last.
$registryMatrix = @(
    # 1. The single most important KDC key: fallback etypes for accounts with msDS-SET = 0.
    [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Services\KDC)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC'; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'Immediate'; Default = '0x27 (2025: 0x24)'; AutoSet = 'Manual'; Order = 1; Note = 'Fallback etype set for accounts with msDS-SupportedEncryptionTypes = 0.' }
    # 2. The hard KDC filter written by Group Policy; highest-precedence issuance control.
    [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set'; AutoSet = 'GPO'; Order = 2; Note = 'Hard KDC etype filter (GPO path). Overrides DDSET for issuance.' }
    # 3. The same filter at the legacy Lsa path; works on 2022, removed in 2025.
    [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set'; AutoSet = 'Manual'; Order = 3; Note = 'Same filter as Policies, lower precedence. Deprecated on Server 2025.' }
    # 4. The dangerous compatibility knob that lets clients force RC4; must stay 0.
    [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Services\Kdc)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'Yes'; Timing = 'Immediate'; Default = 'Not set (0)'; AutoSet = 'Manual'; Order = 4; Note = 'When 1, clients can force RC4 and bypass per-account hardening. Never set to 1.' }
    # 5. The CVE-2026-20833 RC4 deprecation phase switch (correct Policies path).
    [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'Yes'; Timing = 'KDC restart'; Default = '1 (audit); 2 Apr 2026'; AutoSet = 'Update'; Order = 5; Note = 'RC4 deprecation phase: 0 off, 1 audit, 2 enforce. Set by the CVE rollout.' }
    # 6. Verbose Kerberos logging toggle; diagnostic only.
    [PSCustomObject]@{ Setting = 'LogLevel (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'LogLevel'; Kind = 'Log'; Functional = 'Diagnostic'; Timing = 'n/a'; Default = '0 (off)'; AutoSet = 'Manual'; Order = 6; Note = 'Verbose Kerberos logging when 1. No effect on etype selection.' }
    # 7. DDSET at the Lsa path: a common mistake; the KDC never reads it here.
    [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 7; Note = 'Ignored. DDSET only works under Services\KDC.' }
    # 8. DDSET at the Policies path: the same wrong-path mistake.
    [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 8; Note = 'Ignored. DDSET only works under Services\KDC.' }
    # 9. SupportedEncryptionTypes under Services\Kdc: ignored; filter lives at Pol/Lsa.
    [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Services\Kdc)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 9; Note = 'Ignored. The KDC filter only works at the Policies and Lsa paths.' }
    # 10. KdcUseRequestedEtypesForTickets at the Lsa path: ignored; read only at Services\Kdc.
    [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 10; Note = 'Ignored. KdcUseRequestedEtypesForTickets is read only at Services\Kdc.' }
    # 11. KdcUseRequestedEtypesForTickets at the Policies path: the same wrong-path mistake.
    [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 11; Note = 'Ignored. KdcUseRequestedEtypesForTickets is read only at Services\Kdc.' }
    # 12. RC4DefaultDisablementPhase under Services\Kdc: ignored; read only at the Policies path.
    [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Services\Kdc)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 12; Note = 'Ignored. The Phase value only works at the Policies path.' }
    # 13. RC4DefaultDisablementPhase at the Lsa path: the same wrong-path mistake.
    [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 13; Note = 'Ignored. The Phase value only works at the Policies path.' }
)

# --- DC discovery ---

# Detect a real credential (not the Empty sentinel); it is reused for discovery and the read.
$haveCredential = $Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty

# An explicit -ComputerName list always wins (the "specific hosts" mode).
$targets = $ComputerName

# When no hosts were supplied, enumerate every DC in the target domain.
if (-not $targets -or @($targets).Count -eq 0) {
    try {
        # Prefer the RSAT ActiveDirectory module when present: it returns every DC (including
        # read-only DCs) and accepts -Server (the domain) and -Credential directly.
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Write-Verbose 'Discovering domain controllers via Get-ADDomainController.'
            Import-Module ActiveDirectory -ErrorAction Stop
            # Pass -Server (from -Domain) and -Credential only when the caller supplied them.
            $dcParams = @{ Filter = '*' }
            if ($Domain) { $dcParams['Server'] = $Domain }
            if ($haveCredential) { $dcParams['Credential'] = $Credential }
            $targets = Get-ADDomainController @dcParams | Select-Object -ExpandProperty HostName | Sort-Object -Unique
        } else {
            # Fallback without RSAT: the dependency-free .NET DirectoryServices API, building a
            # DirectoryContext that honors any supplied -Domain and/or -Credential.
            Write-Verbose 'ActiveDirectory module absent; discovering via DirectoryServices.'
            $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
            if ($haveCredential) {
                # Bind with the credential's user and password.
                $user = $Credential.UserName
                $pass = $Credential.GetNetworkCredential().Password
                $context = if ($Domain) {
                    [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new($contextType, $Domain, $user, $pass)
                } else {
                    [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new($contextType, $user, $pass)
                }
                $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            } elseif ($Domain) {
                # Named domain, current credentials.
                $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new($contextType, $Domain)
                $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            } else {
                # No domain, no credential: the current domain in the current context.
                $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            $targets = $targetDomain.DomainControllers | ForEach-Object { $_.Name } | Sort-Object -Unique
        }
    } catch {
        # Discovery fails off-domain, with a bad credential, or when AD is unreachable.
        throw "Could not enumerate domain controllers. Pass -ComputerName, or check -Domain/-Credential. Underlying error: $($_.Exception.Message)"
    }
}

# A discovery that returned nothing is a hard stop; there is nothing to audit.
if (-not $targets -or @($targets).Count -eq 0) {
    throw 'No domain controllers were found to query.'
}

# Report how many DCs will be queried so long runs are not mistaken for hangs.
Write-Verbose ("Querying {0} domain controller(s): {1}" -f @($targets).Count, ($targets -join ', '))

# --- Remote read ---

# Project the matrix down to just the read targets the remote scriptblock needs.
$readTargets = $registryMatrix | ForEach-Object { [PSCustomObject]@{ Path = $_.Path; Name = $_.Name } }

# This scriptblock runs on each DC and reads its own registry locally (fast and reliable).
$remoteReader = {
    # Pull the read-target list captured from the caller's session into the remote runspace.
    $items = $using:readTargets

    # Read each path/value pair and emit a flat record describing what was found.
    foreach ($item in $items) {
        # Track existence explicitly so "absent" is distinguishable from a real zero value.
        $found = $false
        # Hold the value outside the try so it is in scope for the output object.
        $value = $null

        try {
            # Read the single named value; -ErrorAction Stop routes a missing key to catch.
            $property = Get-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction Stop
            # Pull the value out by its dynamic property name.
            $value = $property.$($item.Name)
            # Reaching here means the value exists.
            $found = $true
        } catch {
            # A missing path or value is normal (the key is simply not configured here).
            $found = $false
        }

        # Emit one record per value; the local side joins this with the static metadata and
        # uses the PSComputerName that Invoke-Command stamps on each result for the DC name.
        [PSCustomObject]@{
            Path  = $item.Path
            Name  = $item.Name
            Found = $found
            Value = $value
        }
    }
}

# Build the Invoke-Command arguments so the optional credential can be added conditionally.
$invokeParams = @{
    ComputerName  = $targets
    ScriptBlock   = $remoteReader
    ErrorAction   = 'SilentlyContinue'
    ErrorVariable = 'remoteErrors'
}

# Only attach a credential when the caller actually supplied one (else use Kerberos context).
if ($haveCredential) {
    $invokeParams['Credential'] = $Credential
}

# Fan the read out to every DC in parallel; unreachable hosts land in $remoteErrors.
$rawResults = Invoke-Command @invokeParams

# Warn (do not throw) for each DC that could not be reached so the rest still report.
foreach ($remoteError in $remoteErrors) {
    Write-Warning ("Could not query {0}: {1}" -f $remoteError.TargetObject, $remoteError.Exception.Message)
}

# --- Merge, decode, and classify ---

# Index the static matrix by "path|value" for an O(1) join against the remote results.
$lookup = @{}
foreach ($entry in $registryMatrix) {
    # Compose the same key shape used during the join below.
    $lookup[("{0}|{1}" -f $entry.Path, $entry.Name)] = $entry
}

# Combine each remote reading with its metadata, decode it, and classify its security.
$report = foreach ($result in $rawResults) {
    # Look up the metadata for this reading; skip anything we did not ask for.
    $meta = $lookup[("{0}|{1}" -f $result.Path, $result.Name)]
    if ($null -eq $meta) {
        # Defensive: a result with no matching metadata is not part of the audit.
        continue
    }

    # Safely coerce the raw value to a 32-bit integer. A value stored at the wrong REG type
    # (REG_BINARY, REG_MULTI_SZ, a non-numeric REG_SZ, or an out-of-range REG_QWORD) cannot be
    # a real etype/phase/bool, so surface it as Invalid rather than let a cast misclassify it.
    $parsed = 0
    $decodable = (-not $result.Found) -or [int]::TryParse([string]$result.Value, [ref]$parsed)
    # SupportedEncryptionTypes (the GPO filter) and DDSET decode their high bits differently
    # (Future vs. unknown), so flag which value type this is for the decoder.
    $supportsFuture = $meta.Name -eq 'SupportedEncryptionTypes'
    if ($result.Found -and -not $decodable) {
        $status = 'Invalid'
        $meaning = '(unreadable: wrong registry type)'
    } else {
        # Classify the reading ('' neutral / Secure / Insecure / Invalid) and decode its meaning.
        $status = Resolve-SecurityStatus -Meta $meta -Value $result.Value -Found $result.Found -Policy $SecurityPolicy
        $meaning = Resolve-SettingMeaning -Kind $meta.Kind -Value $result.Value -Found $result.Found -SupportsFuture:$supportsFuture
    }

    # Build the operator-facing record. ComputerName comes from PSComputerName (the FQDN that
    # Invoke-Command stamps on each result); Path and Name carry the full key path and value name.
    [PSCustomObject]@{
        ComputerName = $result.PSComputerName
        Path         = $meta.Path
        Name         = $meta.Name
        Setting      = $meta.Setting
        State        = if ($result.Found) { 'Set' } else { 'Not set' }
        Value        = if ($result.Found) { $result.Value } else { $null }
        # Mask to 32 bits before formatting so a high-bit DWORD (e.g. 0xFFFFFFFF "all etypes on")
        # is not sign-extended to 16 hex digits by the negative Int32 that Get-ItemProperty returns.
        Hex          = if ($result.Found -and ($result.Value -is [int] -or $result.Value -is [long])) { '0x{0:X}' -f ([uint32]($result.Value -band 0xFFFFFFFFL)) } else { '' }
        Meaning      = $meaning
        Default      = $meta.Default
        AutoSet      = $meta.AutoSet
        Functional   = $meta.Functional
        Timing       = $meta.Timing
        Status       = $status
        Note         = $meta.Note
        Order        = $meta.Order
    }
}

# Sort by DC, then by the curated order (functional first), then by setting name.
$sorted = $report | Sort-Object -Property ComputerName, Order, Setting

# --- Output ---

# Under -PassThru, hand back structured objects (with the Status field) for export/processing.
if ($PassThru) {
    # Drop the internal Order helper column from the pipeline output to keep it clean.
    $sorted | Select-Object -Property ComputerName, Path, Name, Setting, State, Value, Hex, Meaning, Default, AutoSet, Functional, Timing, Status, Note
    return
}

# Otherwise build a readable report: key reference, then per-DC sections, then a summary.

# The set of DCs that actually responded, in stable alphabetical order.
$auditedDcs = $sorted | Select-Object -ExpandProperty ComputerName | Sort-Object -Unique

# Key reference (printed once): each value's default, whether it is set automatically,
# whether the KDC honors it, and what it does. Wrong-path keys are invalid locations (red).
Write-Output (ConvertTo-ColorText -Text '================ KEY REFERENCE ================' -Code '1;36')
$refText = $registryMatrix |
    Sort-Object Order |
    Format-Table -AutoSize -Property Path, Name,
    @{ Name = 'Works'; Expression = { $_.Functional } },
    @{ Name = 'Default'; Expression = { $_.Default } },
    @{ Name = 'Auto-set'; Expression = { $_.AutoSet } },
    @{ Name = 'Description'; Expression = { $_.Note } } |
    Out-String -Width 250
foreach ($refLine in ($refText -split "`r?`n")) {
    # A wrong-path key is an invalid location: show it in red.
    if ($refLine -match 'No \(wrong path\)') {
        Write-Output (ConvertTo-ColorText -Text $refLine -Code '31')
    } else {
        Write-Output $refLine
    }
}

# Display rule for the Value column: "Does not exist" when the value is absent, "(blank)" when
# present but empty, otherwise the decimal value (the Hex column carries the hex form).
$valueColumn = @{
    Name       = 'Value'
    Expression = {
        if ($_.State -eq 'Not set') { 'Does not exist' }
        elseif ($null -eq $_.Value -or ([string]$_.Value).Trim().Length -eq 0) { '(blank)' }
        else { [string]$_.Value }
    }
}

# Per-DC sections: full key path, value name, value (decimal), hex, and decoded meaning; each
# row tinted by its security Status (the Functional verdict lives once in the KEY REFERENCE).
foreach ($dc in $auditedDcs) {
    Write-Output ''
    Write-Output (ConvertTo-ColorText -Text ('================ {0} ================' -f $dc) -Code '1;36')
    $dcRows = $sorted | Where-Object { $_.ComputerName -eq $dc }
    Write-StatusColoredTable -Rows $dcRows -Property 'Path', 'Name', $valueColumn, 'Hex', 'Meaning'
}

# Summary section: totals (with coverage), then every insecure or invalid finding.
Write-Output (ConvertTo-ColorText -Text '================ SUMMARY ================' -Code '1;36')

# Coverage: requested vs. actually audited. Count-based, so it is unaffected by any naming
# differences between the request list and the responses.
$requested = @($targets).Count
$auditedCount = @($auditedDcs).Count
$unreached = $requested - $auditedCount

Write-Output ('DCs requested    : {0}' -f $requested)
# Tint the audited line yellow when some requested DCs could not be reached.
if ($unreached -gt 0) {
    Write-Output (ConvertTo-ColorText -Text ('DCs audited      : {0} ({1} unreachable)' -f $auditedCount, $unreached) -Code '1;33')
} else {
    Write-Output ('DCs audited      : {0}' -f $auditedCount)
}

# Findings are the rows that need attention: insecure values and invalid/wrong-path values.
$findings = $sorted | Where-Object { $_.Status -eq 'Insecure' -or $_.Status -eq 'Invalid' }
# Green when nothing needs attention, bold red when one or more values do.
$verdictCode = if (@($findings).Count -gt 0) { '1;31' } else { '1;32' }
Write-Output (ConvertTo-ColorText -Text ('Insecure/invalid : {0}' -f @($findings).Count) -Code $verdictCode)

# Findings table when there are any; otherwise a verdict that accounts for coverage so an
# incomplete or fully-failed run is never reported as a clean pass.
if (@($findings).Count -gt 0) {
    # Blank line then a table of exactly which values need attention (rows tinted by Status).
    Write-Output ''
    Write-StatusColoredTable -Rows $findings -Property 'ComputerName', 'Path', 'Name', $valueColumn, 'Hex', 'Meaning'
} elseif ($auditedCount -eq 0) {
    # No DC was successfully audited: this is a failed run, not a clean pass.
    Write-Output (ConvertTo-ColorText -Text 'INCOMPLETE: no domain controllers could be audited; this is not a pass.' -Code '1;31')
} elseif ($unreached -gt 0) {
    # Some DCs were audited cleanly but others were missed: a partial, not-clean result.
    Write-Output (ConvertTo-ColorText -Text ('No insecure/invalid values on the {0} DC(s) reached, but {1} could not be audited.' -f $auditedCount, $unreached) -Code '1;33')
} else {
    # Zero findings and full coverage: a genuine clean pass.
    Write-Output (ConvertTo-ColorText -Text 'No insecure or invalid values found on any audited DC.' -Code '1;32')
}
