#Requires -Version 5.1

<#
.SYNOPSIS
    Audit Kerberos KDC encryption-type registry settings across every domain controller.

.DESCRIPTION
    Discovers all domain controllers in the target Active Directory domain (the current
    domain by default, or a named -Domain, optionally with -Credential), or audits a
    caller-supplied -ComputerName list, then reads every registry value the KDC consults
    when it selects a Kerberos ticket encryption type. Each value is reported with its
    registry type, unsigned decimal form, hex form, raw bytes, a decoded human-readable
    meaning, and a verdict stating whether that path/value combination is actually honored
    by the KDC.

    Every value is shown in BOTH decimal and hex. Hex is always rendered with a 0x prefix
    and an even number of digits (0x18, 0x0110, 0xFFFFFFFF). A value that occupies more
    than a single byte -- either because it exceeds 255 or because it is stored at a type
    that is not REG_DWORD -- is additionally broken out byte by byte (0x10 0x01, decimals
    0-255) so a typo such as a REG_SZ holding "`n01" or a DWORD of 0x0110 is visible for
    what it is rather than silently decoding as a plausible etype mask.

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
    the WinRM hop to each DC succeed from a non-interactive (network logon) session. It does
    not apply to the local machine, which is read in-process rather than over WinRM.

.PARAMETER PassThru
    Emit the raw result objects (including the Status field) to the pipeline instead of the
    formatted per-DC report. Use this to export results (Export-Csv, etc.).

.PARAMETER NoColor
    Disable ANSI color in the report. Color is on by default on a capable terminal and is
    suppressed automatically when output is piped or the host has no virtual-terminal support.

.PARAMETER GridView
    Also open the results in an interactive table viewer. Uses Out-GridView when it is
    available; otherwise writes the same table to a self-contained HTML file and opens it.
    The text report is still written to the pipeline, so this shows both views at once.

.PARAMETER HtmlReport
    Write a self-contained, sortable, filterable HTML table of the results to this path.
    Implied by -GridView when Out-GridView is unavailable.

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
    .\Get-KdcKerberosRegistryAudit.ps1 -GridView
    Print the table report and open the same rows in an interactive table viewer.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -PassThru | Export-Csv kdc-audit.csv -NoTypeInformation
    Capture the audit for every DC as structured objects and save them to CSV.

.NOTES
    Reaching a REMOTE DC requires Windows PowerShell remoting (WinRM), which is enabled by
    default on domain controllers. The local machine is read in-process instead: WinRM to
    yourself fails Kerberos loopback with 0x80090322 on many builds, and needs the host in
    TrustedHosts to fall back to NTLM. Reading the registry needs local administrator rights
    on each target DC.
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
    [switch]$NoColor,

    # Also open the rows in an interactive table viewer alongside the text table.
    [Parameter()]
    [switch]$GridView,

    # Write a self-contained HTML table of the results to this path.
    [Parameter()]
    [string]$HtmlReport
)

# ======================== SECURITY POLICY (edit me) ========================
# Defines what the audit treats as secure vs. insecure. Change a property here
# and every value is re-classified accordingly -- no other code needs editing.
$SecurityPolicy = [PSCustomObject]@{
    # Etype bits treated as insecure (weak crypto). A functional etype value carrying any
    # of these bits is classified Insecure; an AES-only value is Secure.
    # 0x1 = DES-CBC-CRC, 0x2 = DES-CBC-MD5, 0x4 = RC4-HMAC.
    WeakEtypeBits        = (0x1 -bor 0x2 -bor 0x4)

    # Etype bits treated as strong. Only the SHA-1 AES types count: 0x08 = AES128-CTS-HMAC-
    # SHA1-96, 0x10 = AES256-CTS-HMAC-SHA1-96. The RFC 8009 AES-SHA2 bits (0x40/0x80) are
    # deliberately NOT here -- they are defined in the bitmask but are not yet active in
    # etype negotiation, and a DDSET carrying only unsupported bits yields
    # KDC_ERR_ETYPE_NOSUPP (lab-verified 2026-06-26). Add them when negotiation activates.
    StrongEtypeBits      = (0x08 -bor 0x10)

    # RC4DefaultDisablementPhase at or above this value is Secure (RC4 enforced off); below
    # it the KDC still allows RC4 by default, so it is classified Insecure. 2 = enforce.
    MinSecureRc4Phase    = 2

    # RC4 implicit enforcement (CVE-2026-20833) ships in a cumulative update, so whether an
    # absent RC4DefaultDisablementPhase behaves as Phase 2 (enforce) depends on the DC's build
    # revision (UBR), NOT any registry value. For each major OS build, give the highest revision
    # confirmed NOT enforcing and the lowest confirmed enforcing; a revision in between reports
    # INDETERMINATE. Seeded from lab observation -- extend as you confirm more builds.
    Rc4EnforcementBuilds = @{
        # Server 2022 (20348): .4893 issued RC4 for msDS-SET=0; .5020 issued AES256.
        20348 = @{ NotEnforcing = 4893; Enforcing = 5020 }
    }
}
# ===========================================================================

# Decide whether to emit ANSI color: on by default, but suppressed by -NoColor or when the
# host lacks virtual-terminal support (piped output or a non-interactive remoting session),
# so captured or redirected output stays clean.
$script:Esc = [char]27
$script:UseColor = (-not $NoColor) -and $Host.UI.SupportsVirtualTerminal

# --- Bit reference ---

# The single source of truth for bit names, shared by every decode path below. Names are
# identical to the BITS table in content/javascripts/etype-calculator.js so the script and
# the site calculator can never disagree.
#
# Provenance, per bit range (the whole table is NOT one citation):
#   bits 0-5, 16-19 : [MS-KILE] 2.2.7 "Supported Encryption Types Bit Flags" (flags A-J).
#                     Bit 5 (0x20, AES256-CTS-HMAC-SHA1-96-SK) is the session-key flag from
#                     the November 2022 OOB update, KB5021131.
#   bits 6-7        : RFC 8009 (AES-SHA2 for Kerberos 5), etypes 19 and 20. Present in the
#                     bitmask; NOT yet active in etype negotiation as of April 2026.
#   bit 31          : Microsoft GPO documentation only. Lab testing shows it is not honored
#                     in any of the three settings; the GPO "Future encryption types"
#                     checkbox actually sets bits 5-30 (0x7FFFFFE0), not bit 31.
$script:EtypeBits = @(
    [PSCustomObject]@{ Bit = 0; Mask = 0x00000001L; Name = 'DES-CBC-CRC'; Etype = 1; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 1; Mask = 0x00000002L; Name = 'DES-CBC-MD5'; Etype = 3; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 2; Mask = 0x00000004L; Name = 'RC4-HMAC'; Etype = 23; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 3; Mask = 0x00000008L; Name = 'AES128-CTS-HMAC-SHA1-96'; Etype = 17; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 4; Mask = 0x00000010L; Name = 'AES256-CTS-HMAC-SHA1-96'; Etype = 18; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 5; Mask = 0x00000020L; Name = 'AES256-CTS-HMAC-SHA1-96-SK'; Etype = $null; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 6; Mask = 0x00000040L; Name = 'AES128-CTS-HMAC-SHA256-128'; Etype = 19; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 7; Mask = 0x00000080L; Name = 'AES256-CTS-HMAC-SHA384-192'; Etype = 20; Class = 'Etype' }
    [PSCustomObject]@{ Bit = 16; Mask = 0x00010000L; Name = 'FAST-supported'; Etype = $null; Class = 'Feature' }
    [PSCustomObject]@{ Bit = 17; Mask = 0x00020000L; Name = 'Compound-identity-supported'; Etype = $null; Class = 'Feature' }
    [PSCustomObject]@{ Bit = 18; Mask = 0x00040000L; Name = 'Claims-supported'; Etype = $null; Class = 'Feature' }
    [PSCustomObject]@{ Bit = 19; Mask = 0x00080000L; Name = 'Resource-SID-compression-disabled'; Etype = $null; Class = 'Feature' }
    [PSCustomObject]@{ Bit = 31; Mask = 0x80000000L; Name = 'Future encryption types'; Etype = $null; Class = 'Future' }
)

# The GPO "Future encryption types" checkbox writes bits 5-30 as one unit. Lab-validated
# against a real "Configure encryption types allowed for Kerberos" policy (April 2026).
$script:GpoFutureMask = 0x7FFFFFE0L

# Per-setting profiles, mirroring the SETTINGS object in the site calculator. HonoredMask is
# what the KDC actually acts on for that setting; anything else is decoded but labelled so an
# operator can see a bit was set AND that it does nothing here.
#   DDSET : etype bits only. Feature flags and bit 31 are not meaningful.
#   msDS  : etype bits plus the protocol feature flags 16-19. Bit 31 is not meaningful.
#   GPO   : bits 0-4 plus the 0x7FFFFFE0 "Future" range; feature flags ride along in the range.
$script:EtypeVariants = @{
    DDSET = [PSCustomObject]@{ HonoredMask = 0x000000FFL; FutureMask = 0L }
    msDS  = [PSCustomObject]@{ HonoredMask = 0x000F00FFL; FutureMask = 0L }
    GPO   = [PSCustomObject]@{ HonoredMask = 0x7FFFFFFFL; FutureMask = $script:GpoFutureMask }
}

# Integral .NET types a registry read can hand back (REG_DWORD -> Int32, REG_QWORD -> Int64).
# Matched by full type name because Windows PowerShell 5.1 -- the shell on every domain
# controller -- has no [short]/[ushort] type accelerators, so an -is test against them throws.
$script:NumericTypeNames = @(
    'System.Int32', 'System.UInt32', 'System.Int64', 'System.UInt64',
    'System.Int16', 'System.UInt16', 'System.Byte', 'System.SByte'
)

# Kerberos etype numbers, for the legacy DefaultEncryptionType value which stores a single
# etype number rather than a bitmask (RFC 3961 section 8, RFC 3962 section 6, RFC 8009 section 5).
$script:EtypeNumbers = @{
    1  = 'des-cbc-crc'
    3  = 'des-cbc-md5'
    17 = 'aes128-cts-hmac-sha1-96'
    18 = 'aes256-cts-hmac-sha1-96'
    19 = 'aes128-cts-hmac-sha256-128'
    20 = 'aes256-cts-hmac-sha384-192'
    23 = 'rc4-hmac'
}

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

function Format-HexValue {
    <#
    .SYNOPSIS
        Render an integer as 0x-prefixed uppercase hex with an even number of digits.
    .DESCRIPTION
        Every hex figure in this report is written the same way -- 0x plus whole bytes -- so
        0x18, 0x0110 and 0xFFFFFFFF line up and a single byte is always exactly 0x??.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The number to format. Taken as [long] so a 32-bit high-bit value stays positive.
        [Parameter(Mandatory)]
        [long]$Value
    )

    # A REG_DWORD read back as a signed Int32 arrives negative (0xFFFFFFFF becomes -1). Fold it
    # into its unsigned 32-bit view first, or the format below sign-extends it to 16 hex digits.
    $number = $Value
    if ($number -lt 0) {
        $number = $number -band 0xFFFFFFFFL
    }

    # Format without a width first, then pad to a whole number of bytes (minimum one).
    $digits = '{0:X}' -f $number
    if ($digits.Length % 2 -ne 0) {
        $digits = '0' + $digits
    }
    return '0x' + $digits
}

function ConvertTo-RawByte {
    <#
    .SYNOPSIS
        Reduce a registry value of any type to the bytes it actually occupies.
    .DESCRIPTION
        Callers need the byte-level truth to spot a value that is a single byte in intent but
        is not one on disk: a DWORD of 0x0110 (bytes 0x10 0x01), a REG_SZ holding "`n01", or a
        REG_BINARY blob. Numbers are rendered little-endian (registry/x86 order) with trailing
        zero bytes trimmed, so 0x18 is one byte and 0x0110 is two. Strings are rendered as the
        UTF-16LE bytes the registry actually stores.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        # The raw value as read from the registry (or deserialized from a remote runspace).
        [Parameter()]
        [AllowNull()]
        $Value
    )

    # Nothing stored means no bytes to show.
    if ($null -eq $Value) {
        return [byte[]]@()
    }

    # REG_BINARY arrives as a byte array; remoting may hand it back as object[] of bytes.
    if ($Value -is [byte[]]) {
        return [byte[]]$Value
    }
    if ($Value -is [System.Array] -and @($Value).Count -gt 0 -and @($Value)[0] -is [byte]) {
        return [byte[]]@($Value)
    }

    # REG_MULTI_SZ: the on-disk form is each string UTF-16LE, NUL-separated, NUL-terminated.
    if ($Value -is [System.Array]) {
        $joined = (@($Value) | ForEach-Object { [string]$_ }) -join "`0"
        return [System.Text.Encoding]::Unicode.GetBytes($joined + "`0")
    }

    # REG_SZ / REG_EXPAND_SZ are stored as UTF-16LE, so show those bytes rather than ASCII;
    # that is what makes a stray newline or a wrong-type "24" obvious.
    if ($Value -is [string]) {
        return [System.Text.Encoding]::Unicode.GetBytes($Value)
    }

    # Anything numeric: little-endian bytes, trailing zeros trimmed to the significant width.
    try {
        $number = [long]$Value
    } catch {
        # A value that will not coerce to a number has no meaningful byte form here.
        return [byte[]]@()
    }
    # A REG_DWORD comes back as a signed Int32, so 0xFFFFFFFF arrives as -1. Fold it back into
    # the unsigned 32-bit view first or BitConverter would report eight 0xFF bytes, not four.
    if ($number -lt 0) {
        $number = $number -band 0xFFFFFFFFL
    }
    $bytes = [System.BitConverter]::GetBytes($number)
    $last = 0
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -ne 0) { $last = $i }
    }
    return [byte[]]$bytes[0..$last]
}

function Format-ByteList {
    <#
    .SYNOPSIS
        Render a byte array as "0x10 0x01" (hex) or "16 1" (decimal 0-255).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The bytes to render; an empty array yields an empty string.
        [Parameter()]
        [AllowNull()]
        [byte[]]$Byte,

        # Render decimals (0-255) instead of the default 0x?? hex pairs.
        [Parameter()]
        [switch]$AsDecimal
    )

    # No bytes: nothing to print (the caller decides whether that is an error).
    if ($null -eq $Byte -or $Byte.Length -eq 0) {
        return ''
    }

    # Hex is always two digits per byte so every byte reads as exactly 0x??.
    if ($AsDecimal) {
        return (($Byte | ForEach-Object { [string][int]$_ }) -join ' ')
    }
    return (($Byte | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' ')
}

function Write-AuditTable {
    <#
    .SYNOPSIS
        Render rows as a fixed-width table, one physical line per row, tinted by Status.
    .DESCRIPTION
        Format-Table wraps a wide row onto several lines, which desynchronizes any attempt to
        color line N with row N's status. This builds the table itself so a row is always one
        line: the color code therefore always lands on the right record, and a terminal that
        soft-wraps the line keeps the color across the wrap.
    #>
    [CmdletBinding()]
    param(
        # The report rows to render; each carries a Status property used for the row color.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        $Rows,

        # Column definitions: @{ Name = 'Hex'; Expression = { $_.Hex } }, in display order.
        [Parameter(Mandatory)]
        [hashtable[]]$Column,

        # Colour rows by an explicit code instead of by their Status (used for the reference).
        [Parameter()]
        [scriptblock]$ColorRule
    )

    $rowList = @($Rows)

    # Evaluate every cell up front; widths cannot be known until all text exists.
    $matrix = @()
    foreach ($row in $rowList) {
        $cells = @()
        foreach ($col in $Column) {
            # Piping binds $_ so a column Expression reads exactly like a Format-Table one.
            $cells += [string](@($row | ForEach-Object $col.Expression) -join ' ')
        }
        $matrix += , $cells
    }

    # Column width is the widest of the header and every cell in that column.
    $widths = @()
    for ($c = 0; $c -lt $Column.Count; $c++) {
        $width = ([string]$Column[$c].Name).Length
        foreach ($cells in $matrix) {
            if ($cells[$c].Length -gt $width) { $width = $cells[$c].Length }
        }
        $widths += $width
    }

    # Header and dashed separator, both uncolored so the table frame stays readable.
    $headerParts = @()
    $rulerParts = @()
    for ($c = 0; $c -lt $Column.Count; $c++) {
        $headerParts += ([string]$Column[$c].Name).PadRight($widths[$c])
        $rulerParts += ('-' * $widths[$c])
    }
    Write-Output (($headerParts -join ' ').TrimEnd())
    Write-Output (($rulerParts -join ' ').TrimEnd())

    # One line per row, padded to the computed widths, tinted by the row's security Status.
    for ($r = 0; $r -lt $matrix.Count; $r++) {
        $parts = @()
        for ($c = 0; $c -lt $Column.Count; $c++) {
            $parts += $matrix[$r][$c].PadRight($widths[$c])
        }
        $line = ($parts -join ' ').TrimEnd()

        # A caller-supplied rule wins; otherwise map Status to red/yellow/green.
        $code = if ($ColorRule) {
            [string](@($rowList[$r] | ForEach-Object $ColorRule) -join '')
        } else {
            switch ($rowList[$r].Status) {
                'Invalid' { '31' }
                'Insecure' { '33' }
                'Secure' { '1;32' }
                default { '' }
            }
        }

        if ($code) {
            Write-Output (ConvertTo-ColorText -Text $line -Code $code)
        } else {
            Write-Output $line
        }
    }
}

function ConvertTo-KerberosEtypeDecode {
    <#
    .SYNOPSIS
        Decode a Kerberos supported-encryption-type bitmask into named flags plus verdicts.
    .DESCRIPTION
        Returns an object carrying the decoded flag names, the bits that are honored by this
        particular setting, the bits that are set but ignored here, and the bits that are not
        defined at all. Every consumer (display text and security classification) reads the
        same decode so the two can never drift apart.

        Names come from $script:EtypeBits, which mirrors the site calculator verbatim. A name
        is emitted at most once: the GPO "Future encryption types" range (bits 5-30) subsumes
        the individual bits inside it, so when the full range is present the range is named
        once and the bits it covers are not repeated under a second label.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        # The bitmask as an unsigned 32-bit value (pass a [long] so bit 31 stays positive).
        [Parameter(Mandatory)]
        [long]$Mask,

        # Which setting is being decoded; the three honor different bits (see $script:EtypeVariants).
        [Parameter(Mandatory)]
        [ValidateSet('DDSET', 'GPO', 'msDS')]
        [string]$Variant
    )

    # Work on the unsigned 32-bit view; a DWORD read back as a negative Int32 must not
    # sign-extend into the upper 32 bits of the [long] and poison every mask below.
    $value = $Mask -band 0xFFFFFFFFL
    $settingProfile = $script:EtypeVariants[$Variant]

    # Names are collected with the lowest bit each one represents, then emitted in bit order.
    # The set guarantees a name can never be added twice, whatever the bit pattern.
    $found = [System.Collections.Generic.List[psobject]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    # Track which bits a name has already accounted for, so the leftovers are exact.
    $consumed = 0L

    # The GPO "Future encryption types" checkbox is bits 5-30 as one unit. When the whole
    # range is present, name it once and consume all of it: naming bit 5/6/7/16-19 as well
    # would report the same bits twice under two different labels.
    if ($settingProfile.FutureMask -ne 0 -and ($value -band $settingProfile.FutureMask) -eq $settingProfile.FutureMask) {
        $label = 'Future encryption types (bits 5-30)'
        [void]$seen.Add($label)
        $found.Add([PSCustomObject]@{ Order = 5; Label = $label })
        $consumed = $consumed -bor $settingProfile.FutureMask
    }

    # Now name every remaining set bit exactly once.
    foreach ($entry in $script:EtypeBits) {
        # Skip bits already covered by the GPO Future range.
        if (($entry.Mask -band $consumed) -ne 0) { continue }
        if (($value -band $entry.Mask) -eq 0) { continue }

        # A bit that is set but that this setting does not act on is still reported by name,
        # with the reason it does nothing -- silently dropping it hides a real misconfiguration.
        # Bit 31 gets a longer qualifier: it is NOT the GPO "Future encryption types" checkbox
        # (that is bits 5-30), and without saying so the two read as the same flag twice.
        $label = if (($entry.Mask -band $settingProfile.HonoredMask) -ne 0) {
            $entry.Name
        } elseif ($entry.Bit -eq 31) {
            '{0} (bit 31 - set but not honored; the GPO future flag is bits 5-30)' -f $entry.Name
        } else {
            '{0} (set but not honored by {1})' -f $entry.Name, $Variant
        }

        if ($seen.Add($label)) { $found.Add([PSCustomObject]@{ Order = $entry.Bit; Label = $label }) }
        $consumed = $consumed -bor $entry.Mask
    }

    # Whatever is left is a bit no setting defines ([MS-KILE] 2.2.7 reserves 8-15 and 20-30
    # and requires them to be zero), or a partial GPO Future range. Report it as raw hex.
    $undefined = ($value -band (-bnot $consumed)) -band 0xFFFFFFFFL
    if ($undefined -ne 0) {
        $label = '{0} (undefined bits)' -f (Format-HexValue -Value $undefined)
        # Sort undefined bits after every named flag; 32 is past the last real bit.
        if ($seen.Add($label)) { $found.Add([PSCustomObject]@{ Order = 32; Label = $label }) }
    }

    # Emit low bit first so the decode reads in the same order as the calculator's checkbox list.
    $names = [string[]]@($found | Sort-Object -Property Order | Select-Object -ExpandProperty Label)

    # Bits that are set, defined, and actually acted on by this setting.
    $honored = $value -band $settingProfile.HonoredMask
    # Bits that are set and defined but inert for this setting (e.g. FAST on DDSET).
    $ignored = ($value -band $consumed) -band (-bnot $settingProfile.HonoredMask) -band 0xFFFFFFFFL

    [PSCustomObject]@{
        Value         = $value
        Variant       = $Variant
        Names         = $names
        Text          = if ($names.Count -eq 0) { 'None (0x00)' } else { $names -join ' + ' }
        HonoredMask   = $honored
        IgnoredMask   = $ignored
        UndefinedMask = $undefined
    }
}

function ConvertTo-KerberosEtypeName {
    <#
    .SYNOPSIS
        Decode a bitmask to its readable flag names (the text form of ConvertTo-KerberosEtypeDecode).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The bitmask as an unsigned 32-bit value.
        [Parameter(Mandatory)]
        [long]$Mask,

        # Which of the three settings to decode as.
        [Parameter(Mandatory)]
        [ValidateSet('DDSET', 'GPO', 'msDS')]
        [string]$Variant
    )

    return (ConvertTo-KerberosEtypeDecode -Mask $Mask -Variant $Variant).Text
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
        # Decode strategy for this value (mask, phase, bool, or log level).
        [Parameter(Mandatory)]
        [string]$Kind,

        # The numeric value, already normalized to an unsigned 32-bit [long] by the caller.
        [Parameter()]
        [AllowNull()]
        $Value,

        # Whether the value actually exists; a missing value short-circuits to "(not set)".
        [Parameter(Mandatory)]
        [bool]$Found,

        # Which etype-setting variant to decode as (DDSET, GPO, or msDS); only used for EtypeMask.
        [Parameter()]
        [ValidateSet('DDSET', 'GPO', 'msDS')]
        [string]$Variant = 'DDSET'
    )

    # A value that is absent has no meaning to decode, so report it as not set.
    if (-not $Found) {
        return '(not set)'
    }

    # Normalize once: a REG_DWORD read back as a signed Int32 arrives negative, and every
    # branch below must report the unsigned 32-bit view the KDC actually sees.
    $number = 0L
    if ($null -ne $Value) {
        $number = [long]$Value
        if ($number -lt 0) { $number = $number -band 0xFFFFFFFFL }
    }

    # Branch on the decode strategy declared for this particular registry value.
    switch ($Kind) {
        'EtypeMask' {
            # Decode the unsigned 32-bit mask using the variant for this value type, so DDSET,
            # the GPO SupportedEncryptionTypes filter, and msDS-SET each decode their own way.
            return (ConvertTo-KerberosEtypeName -Mask $number -Variant $Variant)
        }
        'Etype' {
            # DefaultEncryptionType stores a single Kerberos etype NUMBER, not a bitmask -- which
            # is exactly why operators who set it expecting mask semantics see nothing happen.
            # The range guard must come first: -and short-circuits, so a value like 0xFFFFFFFF
            # never reaches the [int] cast, which would throw an overflow instead of reporting.
            if ($number -ge 0 -and $number -le [int]::MaxValue -and $script:EtypeNumbers.ContainsKey([int]$number)) {
                return ('etype {0} ({1})' -f $number, $script:EtypeNumbers[[int]$number])
            }
            return ('etype {0} ({1}) - not a known etype number' -f $number, (Format-HexValue -Value $number))
        }
        'Phase' {
            # RC4DefaultDisablementPhase is an enum controlling the RC4 deprecation rollout.
            # Absent behaves as 2 on enforcing builds, which the OS/build line reports separately.
            $map = @{
                0 = 'Off (rollback - RC4 allowed, internal DDSET 0x27)'
                1 = 'Audit (RC4 allowed, kdcsvc 201/202/206/207 logged)'
                2 = 'Enforce (RC4 blocked for msDS-SET=0, internal DDSET 0x18)'
            }
            # Range guard before the cast: an unsigned 0xFFFFFFFF would overflow [int] and throw.
            if ($number -ge 0 -and $number -le [int]::MaxValue -and $map.ContainsKey([int]$number)) {
                return $map[[int]$number]
            }
            # Only 0, 1 and 2 are defined; anything else is a typo the KDC will not act on.
            return ('{0} ({1}) - not a defined phase (0, 1 or 2)' -f $number, (Format-HexValue -Value $number))
        }
        'Bool' {
            # KdcUseRequestedEtypesForTickets is a security-sensitive on/off switch.
            if ($number -eq 1) {
                # A value of 1 lets clients downgrade to RC4, so call it out.
                return 'ON - clients may force RC4 (downgrade)'
            }
            if ($number -eq 0) {
                return 'Off'
            }
            # Non-boolean data in a boolean value is a typo worth surfacing, not "Off".
            return ('{0} ({1}) - not a defined boolean (0 or 1)' -f $number, (Format-HexValue -Value $number))
        }
        'Log' {
            # LogLevel toggles verbose Kerberos event logging.
            if ($number -eq 1) {
                return 'Verbose Kerberos logging'
            }
            if ($number -eq 0) {
                return 'Off'
            }
            return ('{0} ({1}) - not a defined log level (0 or 1)' -f $number, (Format-HexValue -Value $number))
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

        # The numeric value, already normalized to an unsigned 32-bit [long] by the caller.
        [Parameter()]
        [AllowNull()]
        $Value,

        # Whether the value exists. Absent values are neutral (nothing to classify).
        [Parameter(Mandatory)]
        [bool]$Found,

        # Which etype-setting variant this value is (DDSET, GPO, msDS).
        [Parameter(Mandatory)]
        [ValidateSet('DDSET', 'GPO', 'msDS')]
        [string]$Variant,

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

    # Keys that never affect KDC security (legacy/unused, diagnostic) stay neutral; the etype
    # settings (functional registry values and the msDS-SET AD attribute) are classified.
    if ($Meta.Functional -ne 'Yes' -and $Meta.Functional -ne 'AD attribute') {
        return ''
    }

    # Classify the value of a functional key by its kind.
    switch ($Meta.Kind) {
        'EtypeMask' {
            # Reuse the decode so classification and display can never disagree about which
            # bits are defined, which are honored here, and which are junk.
            $decode = ConvertTo-KerberosEtypeDecode -Mask ([long]$Value) -Variant $Variant
            if ($decode.UndefinedMask -ne 0) {
                return 'Invalid'
            }
            # Only bits this setting actually honors can make it secure or insecure.
            if (($decode.HonoredMask -band $Policy.WeakEtypeBits) -ne 0) {
                return 'Insecure'
            }
            if (($decode.HonoredMask -band $Policy.StrongEtypeBits) -ne 0) {
                return 'Secure'
            }
            # A set mask with neither AES-SHA1 nor a weak bit (AES-SK alone, AES-SHA2 alone,
            # feature flags alone) does not give the KDC a usable strong etype.
            return 'Insecure'
        }
        'Bool' {
            # Only 0 and 1 are defined; anything else is a typo, not a policy decision.
            $number = [long]$Value
            if ($number -eq 1) {
                return 'Insecure'
            }
            if ($number -eq 0) {
                return 'Secure'
            }
            return 'Invalid'
        }
        'Phase' {
            # Enforce (>= policy minimum) is secure; off/audit still allow RC4. Only 0-2 exist.
            $number = [long]$Value
            if ($number -lt 0 -or $number -gt 2) {
                return 'Invalid'
            }
            if ($number -ge $Policy.MinSecureRc4Phase) {
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

function Resolve-Rc4Enforcement {
    <#
    .SYNOPSIS
        Infer, from a DC's OS build revision, whether RC4 implicit enforcement is active.
    .DESCRIPTION
        The CVE-2026-20833 enforcement (an absent RC4DefaultDisablementPhase behaving as Phase 2)
        ships in a cumulative update, so it cannot be read from the registry -- only inferred from
        the build revision against the SECURITY POLICY build map. Returns a short verdict string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # OS major build, e.g. '20348'.
        [Parameter()]
        [string]$Build,

        # OS update revision (UBR), e.g. 5020. Left loose because the registry returns it raw.
        [Parameter()]
        $Ubr,

        # The per-major-build revision map from the SECURITY POLICY block.
        [Parameter(Mandatory)]
        $BuildMap
    )

    # Coerce both to integers; an unparseable build cannot be mapped.
    $major = 0
    $revision = 0
    [void][int]::TryParse([string]$Build, [ref]$major)
    [void][int]::TryParse([string]$Ubr, [ref]$revision)

    # A build with no entry in the map has not been characterized: say so rather than guess.
    if (-not $BuildMap.ContainsKey($major)) {
        return 'UNKNOWN for this build -- verify with a live msDS-SET=0 ticket'
    }

    # Compare this revision against the confirmed not-enforcing / enforcing boundaries.
    $known = $BuildMap[$major]
    if ($revision -ge $known.Enforcing) {
        return 'ACTIVE -- an unset RC4DefaultDisablementPhase behaves as enforce'
    }
    if ($revision -le $known.NotEnforcing) {
        return 'NOT active -- msDS-SET=0 accounts still get RC4 by default'
    }
    return 'INDETERMINATE -- revision between confirmed builds; verify with a live msDS-SET=0 ticket'
}

function Out-HtmlAuditReport {
    <#
    .SYNOPSIS
        Write the audit rows to a self-contained, sortable, filterable HTML table.
    .DESCRIPTION
        The table viewer companion to the text report: the same rows, colored by Status, with a
        filter box and click-to-sort headers. Self-contained so it can be mailed or archived,
        and used as the -GridView fallback on hosts where Out-GridView does not exist
        (PowerShell 7 without the GraphicalTools module, Server Core, and every non-Windows host).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The audit rows to render.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        $Rows,

        # Destination file path.
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Column order matches the -PassThru object so the two views stay comparable.
    $columns = @('ComputerName', 'OSBuild', 'Rc4Enforcement', 'Path', 'Name', 'Type', 'State',
        'Decimal', 'Hex', 'Bytes', 'BytesDecimal', 'Meaning', 'Default', 'AutoSet',
        'Functional', 'Timing', 'Status', 'Note')

    # Escape every cell: registry paths contain backslashes and notes contain angle brackets.
    $encode = {
        param($Text)
        $s = [string]$Text
        $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
        return $s
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<title>KDC Kerberos Registry Audit</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine('body{font:13px/1.45 Consolas,"Courier New",monospace;margin:1rem;background:#111;color:#ddd}')
    [void]$sb.AppendLine('h1{font-size:1.1rem;margin:0 0 .5rem}')
    [void]$sb.AppendLine('#f{width:28rem;padding:.35rem;margin-bottom:.6rem;background:#1b1b1b;color:#ddd;border:1px solid #444}')
    [void]$sb.AppendLine('table{border-collapse:collapse;width:100%}')
    [void]$sb.AppendLine('th,td{border:1px solid #333;padding:.25rem .45rem;text-align:left;vertical-align:top;white-space:pre}')
    [void]$sb.AppendLine('th{background:#222;position:sticky;top:0;cursor:pointer;user-select:none}')
    [void]$sb.AppendLine('tr.Secure td{color:#5cd65c}tr.Insecure td{color:#e6c34d}tr.Invalid td{color:#ff6b6b}')
    [void]$sb.AppendLine('tr:hover td{background:#1e1e1e}')
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<h1>KDC Kerberos Registry Audit</h1>')
    [void]$sb.AppendLine('<input id="f" placeholder="Filter rows (substring match on any column)">')
    [void]$sb.AppendLine('<table id="t"><thead><tr>')
    foreach ($column in $columns) {
        [void]$sb.AppendLine(('<th>{0}</th>' -f (& $encode $column)))
    }
    [void]$sb.AppendLine('</tr></thead><tbody>')
    foreach ($row in @($Rows)) {
        [void]$sb.AppendLine(('<tr class="{0}">' -f (& $encode $row.Status)))
        foreach ($column in $columns) {
            [void]$sb.AppendLine(('<td>{0}</td>' -f (& $encode $row.$column)))
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine('var t=document.getElementById("t");')
    [void]$sb.AppendLine('document.getElementById("f").addEventListener("input",function(){')
    [void]$sb.AppendLine('var q=this.value.toLowerCase();')
    [void]$sb.AppendLine('Array.prototype.forEach.call(t.tBodies[0].rows,function(r){')
    [void]$sb.AppendLine('r.style.display=r.textContent.toLowerCase().indexOf(q)>-1?"":"none";});});')
    [void]$sb.AppendLine('Array.prototype.forEach.call(t.tHead.rows[0].cells,function(h,i){')
    [void]$sb.AppendLine('h.addEventListener("click",function(){')
    [void]$sb.AppendLine('var rows=Array.prototype.slice.call(t.tBodies[0].rows);')
    [void]$sb.AppendLine('var asc=h.dataset.asc!=="1";h.dataset.asc=asc?"1":"0";')
    [void]$sb.AppendLine('rows.sort(function(a,b){var x=a.cells[i].textContent,y=b.cells[i].textContent;')
    [void]$sb.AppendLine('return (x<y?-1:x>y?1:0)*(asc?1:-1);});')
    [void]$sb.AppendLine('rows.forEach(function(r){t.tBodies[0].appendChild(r);});});});')
    [void]$sb.AppendLine('</script></body></html>')

    # ASCII output keeps the file byte-identical across locales and safe to diff.
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.Encoding]::ASCII)
    return $Path
}

# --- Registry matrix ---

# Every documented path/value combination, with the verdict on whether the KDC honors it,
# its default, whether it is set automatically, and a one-line description.
# Order controls report sorting: functional keys first, ignored/wrong-path keys last.
$registryMatrix = @(
    # 1. The single most important KDC key: fallback etypes for accounts with msDS-SET = 0.
    [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Services\KDC)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC'; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'Immediate'; Default = '0x27 (2025: 0x24)'; AutoSet = 'Manual'; Order = 1; Note = 'Fallback etype for accounts with msDS-SupportedEncryptionTypes = 0. When unset the KDC uses its internal default: 0x27 (2025: 0x24), or 0x18 (AES-only) on enforced KB5078763+ builds.' }
    # 2. The hard KDC filter written by Group Policy; highest-precedence issuance control.
    [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set'; AutoSet = 'GPO'; Order = 2; Note = 'Hard KDC etype filter (GPO/Policies path). Honored on Server 2022; ignored on Server 2025, where the KDC reads the Lsa path instead (lab-tested 26100.32522).' }
    # 3. The same filter at the Lsa path; honored on 2022 and (lab-tested) on Server 2025, where it is the path the KDC actually reads.
    [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set'; AutoSet = 'Manual'; Order = 3; Note = 'Same KDC etype filter as the Policies path. Honored on Server 2022; on Server 2025 the KDC reads this path and ignores Policies (lab-tested 26100.32522; reverse of the old deprecation claim).' }
    # 4. The dangerous compatibility knob that lets clients force RC4; must stay 0.
    [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Services\Kdc)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'Yes'; Timing = 'Immediate'; Default = 'Not set (0)'; AutoSet = 'Manual'; Order = 4; Note = 'When 1, a client can force RC4 for any account whose msDS-SET still lists RC4 (AES-only accounts stay AES on enforced builds). Bypasses per-account hardening; never set to 1.' }
    # 5. The CVE-2026-20833 RC4 deprecation phase switch (correct Policies path).
    [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set (CU-gated)'; AutoSet = 'Manual'; Order = 5; Note = 'RC4 phase: 0 off, 1 audit, 2 enforce. Usually unset; on KB5078763+ an absent value behaves as 2 (enforce), on older CUs as 0. The registry alone cannot confirm enforcement - check the build or a live msDS-SET=0 ticket.' }
    # 6. Verbose Kerberos logging toggle; diagnostic only.
    [PSCustomObject]@{ Setting = 'LogLevel (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'LogLevel'; Kind = 'Log'; Functional = 'Diagnostic'; Timing = 'n/a'; Default = '0 (off)'; AutoSet = 'Manual'; Order = 6; Note = 'Verbose Kerberos logging when 1. No effect on etype selection.' }
    # 7. DDSET at the Lsa path: a common mistake; the KDC never reads it here.
    [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 7; Note = 'Ignored (lab-tested 4, 24, 28: no change). DDSET only works under Services\KDC.' }
    # 8. DDSET at the Policies path: the same wrong-path mistake.
    [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 8; Note = 'Ignored (lab-tested 4, 24, 28: no change). DDSET only works under Services\KDC.' }
    # 9. SupportedEncryptionTypes under Services\Kdc: ignored; filter lives at Pol/Lsa.
    [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Services\Kdc)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 9; Note = 'Ignored (lab-tested 4, 24, 28: no change). The KDC filter only works at the Policies and Lsa paths.' }
    # 10. KdcUseRequestedEtypesForTickets at the Lsa path: ignored; read only at Services\Kdc.
    [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 10; Note = 'Ignored. KdcUseRequestedEtypesForTickets is read only at Services\Kdc.' }
    # 11. KdcUseRequestedEtypesForTickets at the Policies path: the same wrong-path mistake.
    [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 11; Note = 'Ignored. KdcUseRequestedEtypesForTickets is read only at Services\Kdc.' }
    # 12. RC4DefaultDisablementPhase under Services\Kdc: ignored; read only at the Policies path.
    [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Services\Kdc)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 12; Note = 'Ignored (silently). The Phase value only works at the Policies path.' }
    # 13. RC4DefaultDisablementPhase at the Lsa path: the same wrong-path mistake.
    [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 13; Note = 'Ignored (silently). The Phase value only works at the Policies path.' }
    # 14-16. DefaultEncryptionType at all three paths. Lab-tested with 4, 18 and 24 at each
    # path: no change to ticket etype, session key, or the 4769 msDSSET field. It is a client
    # -side legacy value that operators routinely mistake for a KDC control.
    [PSCustomObject]@{ Setting = 'DefaultEncryptionType (Lsa)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = 'DefaultEncryptionType'; Kind = 'Etype'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 14; Note = 'Ignored (lab-tested 4, 18, 24: no change to ticket etype, session key or msDSSET). Not a KDC control at any path.' }
    [PSCustomObject]@{ Setting = 'DefaultEncryptionType (Services\KDC)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC'; Name = 'DefaultEncryptionType'; Kind = 'Etype'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 15; Note = 'Ignored (lab-tested 4, 18, 24: no change). Not a KDC control at any path.' }
    [PSCustomObject]@{ Setting = 'DefaultEncryptionType (Policies)'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name = 'DefaultEncryptionType'; Kind = 'Etype'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 16; Note = 'Ignored (lab-tested 4, 18, 24: no change). Not a KDC control at any path.' }
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
# The read-target list arrives as a parameter rather than via $using: so the identical block can
# be dot-invoked in this session for the local machine, where WinRM would be the wrong tool.
$registryReader = {
    param($items)

    # Read each path/value pair and emit a flat record describing what was found.
    foreach ($item in $items) {
        # Track existence explicitly so "absent" is distinguishable from a real zero value.
        $found = $false
        # Hold the value and its registry type outside the try so both stay in scope below.
        $value = $null
        $kind = ''

        try {
            # Open the key itself rather than using Get-ItemProperty: only the RegistryKey API
            # exposes GetValueKind, and the audit has to know whether a value that parses as a
            # number is genuinely a REG_DWORD or a REG_SZ/REG_BINARY the KDC will not read.
            $key = Get-Item -LiteralPath $item.Path -ErrorAction Stop
            # GetValueNames is the reliable existence test; Get-ItemProperty -Name returns
            # nothing (without erroring) for a missing value on some builds.
            if ($key.GetValueNames() -contains $item.Name) {
                $found = $true
                # DoNotExpandEnvironmentNames keeps a REG_EXPAND_SZ byte-faithful for the
                # raw-byte view instead of silently substituting %SystemRoot% and friends.
                $value = $key.GetValue($item.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $kind = [string]$key.GetValueKind($item.Name)
            }
        } catch {
            # A missing path or an unreadable key is normal (the key is simply not configured here).
            $found = $false
        }

        # Emit one record per value; the local side joins this with the static metadata and
        # uses the PSComputerName that Invoke-Command stamps on each result for the DC name.
        [PSCustomObject]@{
            Path  = $item.Path
            Name  = $item.Name
            Found = $found
            Kind  = $kind
            Value = $value
        }
    }

    # Also read this machine's own msDS-SupportedEncryptionTypes from AD: the DC computer
    # account attribute that drives the etypes the KDC uses for its own service tickets. ADSI
    # needs no RSAT module and queries the current domain.
    $msFound = $false
    $msValue = $null
    try {
        $sam = '{0}$' -f $env:COMPUTERNAME
        $searcher = [adsisearcher]("(&(objectClass=computer)(sAMAccountName=$sam))")
        [void]$searcher.PropertiesToLoad.Add('msDS-SupportedEncryptionTypes')
        $hit = $searcher.FindOne()
        if ($hit -and $hit.Properties['msds-supportedencryptiontypes'].Count -gt 0) {
            $msValue = [int64]$hit.Properties['msds-supportedencryptiontypes'][0]
            $msFound = $true
        }
    } catch {
        $msFound = $false
    }
    [PSCustomObject]@{
        Path  = 'AD'
        Name  = 'msDS-SupportedEncryptionTypes'
        Found = $msFound
        Kind  = 'AD-Integer'
        Value = $msValue
    }

    # Read this DC's OS build so the report can state whether its cumulative-update level puts it
    # at or past the RC4 implicit-enforcement CU -- something no registry value can reveal.
    $osCaption = ''
    $osBuild = ''
    $osUbr = ''
    # SilentlyContinue + a null guard keeps the OS fields blank if the version key is unreadable.
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    if ($cv) {
        $osCaption = [string]$cv.ProductName
        $osBuild = [string]$cv.CurrentBuildNumber
        $osUbr = [string]$cv.UBR
    }
    [PSCustomObject]@{
        Path    = 'OS'
        Name    = 'OSInfo'
        Found   = $true
        Kind    = ''
        Value   = $null
        Caption = $osCaption
        Build   = $osBuild
        Ubr     = $osUbr
    }
}

# Every name that means "this machine". A DC is very often audited from a session ON that DC,
# and WinRM to yourself is both pointless and unreliable: Kerberos loopback fails with
# 0x80090322 (SEC_E_WRONG_PRINCIPAL) unless the loopback check is disabled, and falling back to
# NTLM needs the host in TrustedHosts. Reading the local registry directly avoids all of it.
$localNames = [System.Collections.Generic.List[string]]::new()
foreach ($alias in 'localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME) {
    $localNames.Add($alias)
}
try {
    $localNames.Add([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)
} catch {
    # No DNS suffix resolvable: the short name in the list above is still a valid match.
    Write-Verbose 'Could not resolve the local FQDN; matching the local host by short name only.'
}

# Split the target list: this machine is read in-process, everything else over WinRM.
$localTargets = @($targets | Where-Object { $localNames -contains $_ })
$remoteTargets = @($targets | Where-Object { $localNames -notcontains $_ })

$rawResults = @()

# Local read: no remoting, so -Credential does not apply here (the audit runs as the caller).
if ($localTargets.Count -gt 0) {
    if ($haveCredential) {
        Write-Verbose ('{0} is this machine; reading its registry locally, so -Credential is not used for it.' -f $localTargets[0])
    }
    # Stamp PSComputerName by hand so local and remote records have the identical shape.
    $localLabel = $localTargets[0]
    $rawResults += & $registryReader $readTargets | ForEach-Object {
        $_ | Add-Member -NotePropertyName PSComputerName -NotePropertyValue $localLabel -Force -PassThru
    }
}

# Remote read: fan out to every other DC in parallel; unreachable hosts land in $remoteErrors.
if ($remoteTargets.Count -gt 0) {
    # Build the Invoke-Command arguments so the optional credential can be added conditionally.
    $invokeParams = @{
        ComputerName  = $remoteTargets
        ScriptBlock   = $registryReader
        ArgumentList  = (, $readTargets)
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }

    # Only attach a credential when the caller actually supplied one (else use Kerberos context).
    if ($haveCredential) {
        $invokeParams['Credential'] = $Credential
    }

    $rawResults += Invoke-Command @invokeParams

    # Warn (do not throw) for each DC that could not be reached so the rest still report.
    foreach ($remoteError in $remoteErrors) {
        $failedHost = if ($remoteError.TargetObject) { $remoteError.TargetObject } else { '(unknown host)' }
        Write-Warning ("Could not query {0}: {1}" -f $failedHost, $remoteError.Exception.Message)
    }
}

# Pull each DC's OS/build record (emitted by the remote reader) out of the readings, and resolve
# the RC4 implicit-enforcement verdict its build revision implies. Keyed by the FQDN that
# Invoke-Command stamps on each result.
$osByDc = @{}
$enfByDc = @{}
foreach ($result in $rawResults) {
    if ($result.Name -eq 'OSInfo') {
        $osByDc[$result.PSComputerName] = $result
        $enfByDc[$result.PSComputerName] = Resolve-Rc4Enforcement -Build $result.Build -Ubr $result.Ubr -BuildMap $SecurityPolicy.Rc4EnforcementBuilds
    }
}

# --- Merge, decode, and classify ---

# Index the static matrix by "path|value" for an O(1) join against the remote results.
$lookup = @{}
foreach ($entry in $registryMatrix) {
    # Compose the same key shape used during the join below.
    $lookup[("{0}|{1}" -f $entry.Path, $entry.Name)] = $entry
}

# Synthetic metadata for the msDS-SupportedEncryptionTypes AD attribute (read per DC, not a
# registry value). Order 0 sorts it first in each DC's table; the GPO is what populates it.
$msdsMeta = [PSCustomObject]@{ Setting = 'msDS-SupportedEncryptionTypes (AD)'; Path = 'Active Directory (DC computer account)'; Name = 'msDS-SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'AD attribute'; Timing = 'n/a'; Default = '0 (falls back to DDSET)'; AutoSet = 'GPO -> SupportedEncryptionTypes'; Order = 0; Note = 'DC computer account etypes; the LSA writes this from the SupportedEncryptionTypes GPO.' }

# Combine each remote reading with its metadata, decode it, and classify its security.
$report = foreach ($result in $rawResults) {
    # Look up the metadata for this reading. The msDS-SET reading is an AD attribute, not a
    # registry path, so it uses its own synthetic metadata; anything else unmatched is skipped.
    $meta = $lookup[("{0}|{1}" -f $result.Path, $result.Name)]
    if ($null -eq $meta) {
        if ($result.Name -eq 'msDS-SupportedEncryptionTypes') {
            $meta = $msdsMeta
        } else {
            # Defensive: a result with no matching metadata is not part of the audit.
            continue
        }
    }

    # The three etype settings decode their high bits differently, so pick the variant by name.
    $variant = switch ($meta.Name) {
        'SupportedEncryptionTypes' { 'GPO' }
        'msDS-SupportedEncryptionTypes' { 'msDS' }
        default { 'DDSET' }
    }

    # Reduce the stored value to its bytes once: this drives the decimal form, the hex form and
    # the "is this really a single byte?" test that catches a REG_SZ or a mistyped 0x0110.
    $bytes = ConvertTo-RawByte -Value $result.Value
    # Match on the concrete .NET type name rather than type accelerators: [short]/[ushort] do not
    # exist in Windows PowerShell 5.1, which is what actually ships on a domain controller.
    $isNumeric = $result.Found -and $null -ne $result.Value -and $script:NumericTypeNames -contains $result.Value.GetType().FullName
    # Two numeric views. The DISPLAY value keeps every bit that is actually stored, so a
    # REG_QWORD wider than 32 bits reads the same in the Decimal/Hex columns as in its bytes;
    # only a negative Int32 (a REG_DWORD with the high bit set) is folded to its unsigned form.
    # The DECODE value is masked to 32 bits, because that is all an etype mask can carry.
    $displayNumeric = $null
    if ($isNumeric) {
        $displayNumeric = [long]$result.Value
        if ($displayNumeric -lt 0) { $displayNumeric = $displayNumeric -band 0xFFFFFFFFL }
    }
    $numeric = if ($isNumeric) { $displayNumeric -band 0xFFFFFFFFL } else { $null }

    # A value is "single byte" only when it is a real number that fits in 0-255. Anything wider,
    # and anything stored at a non-numeric type, gets its raw bytes reported.
    $multiByte = $result.Found -and (-not $isNumeric -or $bytes.Length -gt 1)

    # A value the KDC cannot read as a DWORD is Invalid regardless of what it looks like: a
    # REG_SZ of "24" parses as a number but the KDC never sees 24.
    $wrongType = $result.Found -and $result.Kind -and $result.Kind -ne 'DWord' -and $result.Kind -ne 'AD-Integer'

    if ($result.Found -and (-not $isNumeric -or $wrongType)) {
        # Wrong-type data: say what it is and show the bytes rather than guess at a meaning.
        $status = 'Invalid'
        $kindLabel = if ($result.Kind) { $result.Kind } else { 'unknown type' }
        $meaning = '(not a REG_DWORD: stored as {0}) raw bytes {1}' -f $kindLabel, (Format-ByteList -Byte $bytes)
    } else {
        # Classify the reading ('' neutral / Secure / Insecure / Invalid) and decode its meaning.
        $status = Resolve-SecurityStatus -Meta $meta -Value $numeric -Found $result.Found -Variant $variant -Policy $SecurityPolicy
        $meaning = Resolve-SettingMeaning -Kind $meta.Kind -Value $numeric -Found $result.Found -Variant $variant
        # A DWORD wider than one byte is legal but is also the shape of a fat-fingered value
        # (0x0110 instead of 0x10), so the byte breakdown rides along with the meaning.
        if ($multiByte) {
            $meaning = '{0} [multi-byte: {1}]' -f $meaning, (Format-ByteList -Byte $bytes)
        }
    }

    # Build the operator-facing record. ComputerName comes from PSComputerName (the FQDN that
    # Invoke-Command stamps on each result); Path and Name carry the full key path and value name.
    [PSCustomObject]@{
        ComputerName   = $result.PSComputerName
        Path           = $meta.Path
        Name           = $meta.Name
        Setting        = $meta.Setting
        Type           = if ($result.Found) { $result.Kind } else { '' }
        State          = if ($result.Found) { 'Set' } else { 'Not set' }
        # Decimal is the unsigned view of everything stored: a DWORD of 0xFFFFFFFF reads
        # 4294967295 (never -1), and a REG_QWORD keeps its full width instead of truncating.
        Decimal        = if (-not $result.Found) { '' } elseif ($isNumeric) { [string][uint64]$displayNumeric } else { 'n/a' }
        # Hex is always 0x-prefixed with whole bytes, so a single byte is always exactly 0x??.
        Hex            = if (-not $result.Found) { '' } elseif ($isNumeric) { Format-HexValue -Value $displayNumeric } else { 'n/a' }
        # Raw bytes, populated only when the value is not a single byte (the thing worth seeing).
        Bytes          = if ($multiByte) { Format-ByteList -Byte $bytes } else { '' }
        BytesDecimal   = if ($multiByte) { Format-ByteList -Byte $bytes -AsDecimal } else { '' }
        MultiByte      = [bool]$multiByte
        Meaning        = $meaning
        Default        = $meta.Default
        AutoSet        = $meta.AutoSet
        Functional     = $meta.Functional
        Timing         = $meta.Timing
        Status         = $status
        Note           = $meta.Note
        # Per-DC OS context so an exported row carries the build and the enforcement it implies.
        OSBuild        = if ($osByDc.ContainsKey($result.PSComputerName)) { '{0}.{1}' -f $osByDc[$result.PSComputerName].Build, $osByDc[$result.PSComputerName].Ubr } else { '' }
        Rc4Enforcement = if ($enfByDc.ContainsKey($result.PSComputerName)) { $enfByDc[$result.PSComputerName] } else { '' }
        Order          = $meta.Order
    }
}

# Sort by DC, then by the curated order (functional first), then by setting name.
$sorted = @($report | Sort-Object -Property ComputerName, Order, Setting)

# --- Output ---

# Under -PassThru, hand back structured objects (with the Status field) for export/processing.
if ($PassThru) {
    # Drop the internal Order helper column from the pipeline output to keep it clean.
    $sorted | Select-Object -Property ComputerName, OSBuild, Rc4Enforcement, Path, Name, Setting, Type, State, Decimal, Hex, Bytes, BytesDecimal, MultiByte, Meaning, Default, AutoSet, Functional, Timing, Status, Note
    return
}

# Otherwise build a readable report: key reference, then per-DC sections, then a summary.

# The set of DCs that actually responded, in stable alphabetical order.
$auditedDcs = @($sorted | Select-Object -ExpandProperty ComputerName | Sort-Object -Unique)

# Key reference (printed once): each value's default, whether it is set automatically,
# whether the KDC honors it, and what it does. Wrong-path keys are invalid locations (red).
Write-Output (ConvertTo-ColorText -Text '================ KEY REFERENCE ================' -Code '1;36')
Write-AuditTable -Rows ($registryMatrix | Sort-Object Order) -Column @(
    @{ Name = 'Path'; Expression = { $_.Path } }
    @{ Name = 'Name'; Expression = { $_.Name } }
    @{ Name = 'Works'; Expression = { $_.Functional } }
    @{ Name = 'Default'; Expression = { $_.Default } }
    @{ Name = 'Auto-set'; Expression = { $_.AutoSet } }
    @{ Name = 'Description'; Expression = { $_.Note } }
) -ColorRule { if ($_.Functional -eq 'No (wrong path)') { '31' } else { '' } }

# Display rule for the Decimal column: "Does not exist" when the value is absent, otherwise
# the unsigned decimal (the Hex column carries the same number in 0x?? form).
$decimalColumn = @{
    Name       = 'Decimal'
    Expression = {
        if ($_.State -eq 'Not set') { 'Does not exist' }
        elseif ([string]::IsNullOrEmpty([string]$_.Decimal)) { '(blank)' }
        else { [string]$_.Decimal }
    }
}

# Per-DC sections: full key path, value name, registry type, decimal, hex, raw bytes (when the
# value is not a single byte) and decoded meaning; each row tinted by its security Status.
foreach ($dc in $auditedDcs) {
    Write-Output ''
    Write-Output (ConvertTo-ColorText -Text ('================ {0} ================' -f $dc) -Code '1;36')
    # State this DC's OS build and the RC4 implicit enforcement it implies -- the registry cannot
    # show this, since the enforcement ships in a cumulative update, not a registry value.
    $os = $osByDc[$dc]
    if ($os) {
        $enf = $enfByDc[$dc]
        # Green when enforcement is active, yellow when it is not, cyan when it cannot be told.
        $enfCode = switch -Wildcard ($enf) { 'ACTIVE*' { '1;32' } 'NOT active*' { '1;33' } default { '1;36' } }
        $osLabel = if ($os.Caption) { '{0}, build {1}.{2}' -f $os.Caption, $os.Build, $os.Ubr } else { 'build {0}.{1}' -f $os.Build, $os.Ubr }
        Write-Output (ConvertTo-ColorText -Text ('OS: {0} | RC4 implicit enforcement: {1}' -f $osLabel, $enf) -Code $enfCode)
    }
    $dcRows = @($sorted | Where-Object { $_.ComputerName -eq $dc })
    Write-AuditTable -Rows $dcRows -Column @(
        @{ Name = 'Path'; Expression = { $_.Path } }
        @{ Name = 'Name'; Expression = { $_.Name } }
        @{ Name = 'Type'; Expression = { $_.Type } }
        $decimalColumn
        @{ Name = 'Hex'; Expression = { $_.Hex } }
        @{ Name = 'Bytes'; Expression = { $_.Bytes } }
        @{ Name = 'Meaning'; Expression = { $_.Meaning } }
    )
}

# Multi-byte values: any value that is not a single byte (0-255) gets its raw bytes spelled out
# in both hex (0x?? per byte) and decimal (0-255 per byte). A DWORD of 0x0110 and a REG_SZ of
# "`n01" both look like plausible settings in a decimal column and are obvious here.
$multiByteRows = @($sorted | Where-Object { $_.MultiByte })
Write-Output ''
Write-Output (ConvertTo-ColorText -Text '================ MULTI-BYTE VALUES ================' -Code '1;36')
if ($multiByteRows.Count -eq 0) {
    Write-Output 'None. Every value present is a single byte (0-255) stored as REG_DWORD.'
} else {
    Write-Output ('{0} value(s) occupy more than one byte. Raw bytes are shown little-endian, as stored.' -f $multiByteRows.Count)
    Write-Output ''
    Write-AuditTable -Rows $multiByteRows -Column @(
        @{ Name = 'ComputerName'; Expression = { $_.ComputerName } }
        @{ Name = 'Path'; Expression = { $_.Path } }
        @{ Name = 'Name'; Expression = { $_.Name } }
        @{ Name = 'Type'; Expression = { $_.Type } }
        @{ Name = 'Decimal'; Expression = { $_.Decimal } }
        @{ Name = 'Hex'; Expression = { $_.Hex } }
        @{ Name = 'Bytes (hex)'; Expression = { $_.Bytes } }
        @{ Name = 'Bytes (dec)'; Expression = { $_.BytesDecimal } }
    )
}

# msDS-SET vs SET consistency: the SupportedEncryptionTypes GPO writes the registry value, and
# the LSA copies it into the DC computer account's msDS-SupportedEncryptionTypes. Propagation
# keeps only bits 0-4, so the comparison is masked to 0x1F: a GPO of 0x7FFFFFFF landing as an
# msDS-SET of 0x1F is the documented healthy case, not drift.
Write-Output ''
Write-Output (ConvertTo-ColorText -Text '================ msDS-SET vs SET CONSISTENCY ================' -Code '1;36')
foreach ($dc in $auditedDcs) {
    # This DC's msDS-SET reading, and whichever SupportedEncryptionTypes path is configured.
    # Policies is the KDC's path on Server 2022 and the one the GPO writes; Lsa is the fallback
    # (and the path Server 2025 actually reads), so report against whichever exists.
    $msRow = $sorted | Where-Object { $_.ComputerName -eq $dc -and $_.Name -eq 'msDS-SupportedEncryptionTypes' } | Select-Object -First 1
    $setRow = $sorted | Where-Object { $_.ComputerName -eq $dc -and $_.Name -eq 'SupportedEncryptionTypes' -and $_.Path -like '*Policies*' -and $_.State -eq 'Set' } | Select-Object -First 1
    if (-not $setRow) {
        $setRow = $sorted | Where-Object { $_.ComputerName -eq $dc -and $_.Name -eq 'SupportedEncryptionTypes' -and $_.Path -like '*Lsa*' -and $_.State -eq 'Set' } | Select-Object -First 1
    }

    # Resolve each to an unsigned 32-bit value, or $null when the value is absent/unusable.
    $msVal = if ($msRow -and $msRow.State -eq 'Set' -and $msRow.Hex -ne 'n/a') { [long]$msRow.Decimal } else { $null }
    $setVal = if ($setRow -and $setRow.Hex -ne 'n/a') { [long]$setRow.Decimal } else { $null }
    $setWhere = if ($setRow) { if ($setRow.Path -like '*Policies*') { 'Policies' } else { 'Lsa' } } else { '' }

    if ($null -eq $setVal) {
        # No GPO is configuring SupportedEncryptionTypes, so nothing drives msDS-SET here.
        $msShown = if ($null -ne $msVal) { '{0} ({1})' -f (Format-HexValue -Value $msVal), $msRow.Meaning } else { 'not set' }
        Write-Output ('{0,-26} SET not configured (no GPO); msDS-SET = {1}' -f $dc, $msShown)
    } elseif ($null -ne $msVal -and ($msVal -band 0x1FL) -eq ($setVal -band 0x1FL)) {
        # The propagated etype bits agree; the LSA legitimately drops everything above bit 4.
        Write-Output (ConvertTo-ColorText -Text ('{0,-26} consistent: msDS-SET {1} and SET ({2}) {3} agree on bits 0-4' -f $dc, (Format-HexValue -Value $msVal), $setWhere, (Format-HexValue -Value $setVal)) -Code '1;32')
    } else {
        # Propagated bits disagree: the AD attribute is out of sync with the configured GPO value.
        $msShown = if ($null -ne $msVal) { Format-HexValue -Value $msVal } else { 'not set' }
        Write-Output (ConvertTo-ColorText -Text ('{0,-26} DIFFER: msDS-SET = {1}, SET ({2}) = {3} -- msDS-SET out of sync with the GPO' -f $dc, $msShown, $setWhere, (Format-HexValue -Value $setVal)) -Code '1;33')
    }
}

# Summary section: totals (with coverage), then every insecure or invalid finding.
Write-Output ''
Write-Output (ConvertTo-ColorText -Text '================ SUMMARY ================' -Code '1;36')

# Coverage: requested vs. actually audited. Count-based, so it is unaffected by any naming
# differences between the request list and the responses.
$requested = @($targets).Count
$auditedCount = @($auditedDcs).Count
$unreached = $requested - $auditedCount

Write-Output ('DCs requested     : {0}' -f $requested)
# Tint the audited line yellow when some requested DCs could not be reached.
if ($unreached -gt 0) {
    Write-Output (ConvertTo-ColorText -Text ('DCs audited       : {0} ({1} unreachable)' -f $auditedCount, $unreached) -Code '1;33')
} else {
    Write-Output ('DCs audited       : {0}' -f $auditedCount)
}

# Multi-byte values are reported whether or not they are also a security finding.
$multiByteCode = if ($multiByteRows.Count -gt 0) { '1;33' } else { '' }
if ($multiByteCode) {
    Write-Output (ConvertTo-ColorText -Text ('Multi-byte values : {0}' -f $multiByteRows.Count) -Code $multiByteCode)
} else {
    Write-Output ('Multi-byte values : {0}' -f $multiByteRows.Count)
}

# Findings are the rows that need attention: insecure values and invalid/wrong-path values.
$findings = @($sorted | Where-Object { $_.Status -eq 'Insecure' -or $_.Status -eq 'Invalid' })
# Green when nothing needs attention, bold red when one or more values do.
$verdictCode = if ($findings.Count -gt 0) { '1;31' } else { '1;32' }
Write-Output (ConvertTo-ColorText -Text ('Insecure/invalid  : {0}' -f $findings.Count) -Code $verdictCode)

# Findings table when there are any; otherwise a verdict that accounts for coverage so an
# incomplete or fully-failed run is never reported as a clean pass.
if ($findings.Count -gt 0) {
    # Blank line then a table of exactly which values need attention (rows tinted by Status).
    Write-Output ''
    Write-AuditTable -Rows $findings -Column @(
        @{ Name = 'ComputerName'; Expression = { $_.ComputerName } }
        @{ Name = 'Path'; Expression = { $_.Path } }
        @{ Name = 'Name'; Expression = { $_.Name } }
        @{ Name = 'Type'; Expression = { $_.Type } }
        $decimalColumn
        @{ Name = 'Hex'; Expression = { $_.Hex } }
        @{ Name = 'Bytes'; Expression = { $_.Bytes } }
        @{ Name = 'Meaning'; Expression = { $_.Meaning } }
    )
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

# --- Table viewer ---

# The text table above is the report; this is the same data in something sortable. Out-GridView
# when the host has it, an HTML file otherwise, so -GridView behaves the same everywhere.
$viewRows = $sorted | Select-Object -Property ComputerName, OSBuild, Rc4Enforcement, Path, Name, Setting, Type, State, Decimal, Hex, Bytes, BytesDecimal, Meaning, Default, AutoSet, Functional, Timing, Status, Note

# An explicit -HtmlReport path always gets written, with or without -GridView.
if ($HtmlReport) {
    $written = Out-HtmlAuditReport -Rows $viewRows -Path $HtmlReport
    Write-Output ''
    Write-Output (ConvertTo-ColorText -Text ('HTML table written to {0}' -f $written) -Code '1;36')
}

if ($GridView) {
    # Out-GridView can be present and still fail: it throws in a non-interactive session (a
    # scheduled task, a remoting runspace) and on Server Core, where there is no desktop to
    # draw on. Treat "threw" the same as "absent" so -GridView always produces a viewer.
    $gridShown = $false
    if (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
        try {
            # -PassThru is deliberately omitted: this is a viewer, not a picker, so it must not block.
            $viewRows | Out-GridView -Title 'KDC Kerberos Registry Audit' -ErrorAction Stop
            $gridShown = $true
        } catch {
            Write-Verbose ("Out-GridView could not display the results: {0}" -f $_.Exception.Message)
        }
    }
    if (-not $gridShown) {
        # No usable Out-GridView (PowerShell 7 without GraphicalTools, Server Core, a
        # non-interactive session, non-Windows): write the HTML viewer and open that instead.
        if (-not $HtmlReport) {
            $fallback = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'kdc-kerberos-registry-audit.html'
            $written = Out-HtmlAuditReport -Rows $viewRows -Path $fallback
            Write-Output ''
            Write-Output (ConvertTo-ColorText -Text ('Out-GridView is unavailable; HTML table written to {0}' -f $written) -Code '1;36')
            $HtmlReport = $written
        }
        try {
            Invoke-Item -LiteralPath $HtmlReport -ErrorAction Stop
        } catch {
            # A headless host has no file association; the path above is enough to open it manually.
            Write-Verbose ("Could not open {0} automatically: {1}" -f $HtmlReport, $_.Exception.Message)
        }
    }
}
