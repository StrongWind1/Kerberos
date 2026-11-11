<#PSScriptInfo

.VERSION 1.0.0

.GUID 6f0c1f0e-6f5b-4d5e-9a57-2b8c7b3f4a10

.AUTHOR StrongWind1

.COPYRIGHT Copyright 2026 StrongWind1. Licensed under the Apache License, Version 2.0.

.TAGS Kerberos ActiveDirectory KDC RC4 AES Audit

.LICENSEURI https://github.com/StrongWind1/Kerberos/blob/main/LICENSE

.PROJECTURI https://github.com/StrongWind1/Kerberos

.RELEASENOTES
    1.0.0  First versioned release. Per-DC effective state, OS-dependent filter precedence,
           read errors separated from "not set", Transitional tier, -FailOn exit codes,
           Unreachable/non-DC rows, wrong-path and unrecognized value-name detection.

#>

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
    by the KDC ON THAT DC'S OS BUILD.

    From those readings and the DC's OS build the audit derives one EFFECTIVE STATE per DC:

      * the etype set the KDC falls back to for accounts with no
        msDS-SupportedEncryptionTypes (explicit DefaultDomainSupportedEncTypes when set,
        otherwise the build default: 0x27 before the April 2026 cumulative update, 0x18 on
        it or later, adjusted by RC4DefaultDisablementPhase where that value is still read);
      * which SupportedEncryptionTypes path is the effective KDC etype filter on that OS;
      * whether RC4 default removal (CVE-2026-20833) is enforcing, not enforcing, overridden
        by an explicit setting, or cannot be determined from this script's build map.

    The header line of each DC section and the final verdict are both driven by that state.
    A DC that still hands out RC4 by default, or whose build cannot be classified, is a
    finding even when no registry value is set: an empty registry is never a clean pass on
    its own.

    Every value is shown in BOTH decimal and hex. Hex is always rendered with a 0x prefix
    and an even number of digits (0x18, 0x0110, 0xFFFFFFFF). A value stored at the wrong
    registry type, or a mask carrying bits no setting defines, is additionally broken out
    byte by byte so a typo such as a REG_SZ holding "24" or a DWORD of 0x0110 is visible
    for what it is rather than silently decoding as a plausible etype mask.

    Status values, and the row color used on a capable terminal:

      Secure        (green)    AES-only, or a setting in its safe state.
      Transitional  (cyan)     RC4 is still permitted alongside AES (for example 0x1C, 0x3C).
      Insecure      (yellow)   DES, RC4 without AES, RC4 by default, or a downgrade switch.
      Invalid       (red)      Wrong path, wrong type, undefined bits, unrecognized name, or a
                               value the KDC on this build does not read.
      Unknown       (yellow)   The build cannot be classified; verify with a live ticket.
      Error         (magenta)  The value could not be read (access denied, bind failure).
      Unreachable   (magenta)  The host did not answer.
      NotDC         (magenta)  The host answered but is not a domain controller.

    What counts as secure vs. insecure is controlled by the SECURITY POLICY block near the
    top of this file. The script only reads; it never writes, so it is safe to run in
    production.

    Limits. The build map covers Windows Server 2016, 2019, 2022 and 2025. Only the Server
    2022 enforcement boundary is lab-verified; the other thresholds are build numbers from
    Microsoft's release history combined with the dates in KB5073381. Behaviour on the July
    2026 and later updates is taken from KB5073381 and has not been lab-verified. Any other
    OS reports UNKNOWN. The filter-path precedence is lab-verified on Server 2022 only: one
    Server 2025 build (26100.32522) ignored the Policies path, Microsoft's April 2026 release
    note suggests that was fixed in 26100.32690, and nobody has retested, so on later Server
    2025 builds the audit says UNCERTAIN. A registry value that needs a KDC restart may not
    be in effect yet; the registry cannot show that.

.PARAMETER ComputerName
    One or more specific hosts to query. Accepts pipeline input (strings, or objects with a
    ComputerName, HostName or DNSHostName property). When omitted, the script audits
    EVERY domain controller in the target domain (Get-ADDomainController when the RSAT
    ActiveDirectory module is present, otherwise System.DirectoryServices). Duplicate names,
    and two names that resolve to the same machine, are audited once.

.PARAMETER Domain
    Domain whose domain controllers should be audited when -ComputerName is not given.
    Defaults to the current domain. Combine with -Credential to reach a domain the calling
    session is not authenticated to.

.PARAMETER Credential
    Optional alternate credential used for BOTH domain-controller discovery and the remote
    registry read. Defaults to the caller's current context. It does not apply to the local
    machine, which is read in-process rather than over WinRM.

.PARAMETER PassThru
    Emit the result objects to the pipeline instead of the formatted report. Each object
    carries a numeric Value, the Status and the Reason, so it exports cleanly to CSV or JSON.
    Unreachable hosts and non-DCs are represented by their own rows. -HtmlReport and
    -GridView are still honored.

.PARAMETER NoColor
    Disable ANSI color in the report. Color is on by default on a capable terminal and is
    switched off when the script can tell its output is piped, redirected or assigned. That
    detection is best-effort for output captured by a calling script; pass -NoColor there.

.PARAMETER GridView
    Also open the results in an interactive table viewer. Uses Out-GridView when it is
    available; otherwise writes the same table to a self-contained HTML file and opens it.

.PARAMETER HtmlReport
    Write a self-contained, sortable, filterable HTML report to this path. A relative path
    is resolved against the current PowerShell location. Implied by -GridView when
    Out-GridView is unavailable.

.PARAMETER FailOn
    Make the script set a process exit code, for scheduled tasks and CI. List the Status
    classes that should fail the run: Insecure, Invalid, Transitional, Unknown, Error,
    Unreachable, NotDC, or Any. Exit codes: 0 = none of the listed classes present;
    1 = a listed security class (Insecure, Invalid, Transitional, Unknown) is present;
    2 = a listed coverage class (Error, Unreachable, NotDC) is present, or no domain
    controller could be audited; 3 = both. Without -FailOn the script never calls exit.

.PARAMETER ThrottleLimit
    Maximum concurrent WinRM connections (passed to Invoke-Command). Default 32.

.PARAMETER SessionOption
    A PSSessionOption (New-PSSessionOption) for the WinRM connections, for example to set
    OpenTimeout and OperationTimeout so an unresponsive DC fails quickly.

.PARAMETER UseSSL
    Connect to WinRM over HTTPS (port 5986).

.PARAMETER Authentication
    WinRM authentication mechanism (passed to Invoke-Command). Default: Default.

.PARAMETER ConfigurationName
    WinRM session configuration (endpoint) to connect to on each DC.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1
    Audit every DC in the current domain as the current user; per-DC sections then a summary.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -Domain corp.contoso.com -Credential (Get-Credential)
    Audit every DC in a named domain using an explicit credential.

.EXAMPLE
    Get-ADDomainController -Filter * | .\Get-KdcKerberosRegistryAudit.ps1 -HtmlReport .\kdc-audit.html
    Take the DC list from the pipeline and also write the HTML report.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -PassThru | Export-Csv kdc-audit.csv -NoTypeInformation
    Capture the audit for every DC as structured objects and save them to CSV.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -PassThru | ConvertTo-Json -Depth 3 | Set-Content kdc-audit.json
    The same rows as JSON; Value is numeric.

.EXAMPLE
    .\Get-KdcKerberosRegistryAudit.ps1 -NoColor -FailOn Insecure,Invalid,Unknown,Unreachable,Error
    Scheduled-task / CI form: exit 1 on security findings, 2 on incomplete coverage, 3 on both.

.NOTES
    Reaching a REMOTE DC requires Windows PowerShell remoting (WinRM), which is enabled by
    default on domain controllers. The local machine is read in-process instead: WinRM to
    yourself fails Kerberos loopback with 0x80090322 on many builds, and needs the host in
    TrustedHosts to fall back to NTLM. Reading the registry needs local administrator rights
    on each target DC.
#>

# Advanced-script binding gives the file -Verbose, -ErrorAction and other common parameters.
[CmdletBinding()]
# Text report lines by default; structured rows under -PassThru.
[OutputType([string])]
[OutputType([System.Management.Automation.PSCustomObject])]
param(
    # Explicit host list; empty by default so the script audits every DC in the target domain.
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('HostName', 'DNSHostName')]
    [ValidateNotNullOrEmpty()]
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

    # Write a self-contained HTML report of the results to this path.
    [Parameter()]
    [string]$HtmlReport,

    # Status classes that should produce a non-zero exit code (see the help for the codes).
    [Parameter()]
    [ValidateSet('Insecure', 'Invalid', 'Transitional', 'Unknown', 'Error', 'Unreachable', 'NotDC', 'Any')]
    [string[]]$FailOn,

    # WinRM fan-out controls, passed straight through to Invoke-Command.
    [Parameter()]
    [ValidateRange(1, 1024)]
    [int]$ThrottleLimit = 32,

    [Parameter()]
    [System.Management.Automation.Remoting.PSSessionOption]$SessionOption,

    [Parameter()]
    [switch]$UseSSL,

    [Parameter()]
    [System.Management.Automation.Runspaces.AuthenticationMechanism]$Authentication = 'Default',

    [Parameter()]
    [string]$ConfigurationName
)

begin {
    # The script has begin/process/end blocks so -ComputerName can take pipeline input the
    # supported way: this begin block holds the policy, the tables and the functions, the
    # process block collects the piped names, and the end block runs the audit.

    Set-StrictMode -Version Latest

    # Names collected by the process block, one bind per pipeline object.
    $script:CollectedTarget = [System.Collections.Generic.List[string]]::new()

    # Reported in the console header, the HTML report and every -PassThru row. Keep in step with
    # .VERSION in the PSScriptInfo block at the top of the file.
    $script:AuditScriptVersion = '1.0.0'

    # ======================== SECURITY POLICY (edit me) ========================
    # Defines what the audit treats as secure vs. insecure. Change a property here
    # and every value is re-classified accordingly - no other code needs editing.
    $SecurityPolicy = [PSCustomObject]@{
        # Etype bits that are Insecure wherever they are honored. 0x1 = DES-CBC-CRC,
        # 0x2 = DES-CBC-MD5.
        InsecureEtypeBits      = (0x1 -bor 0x2)

        # Etype bits that are Transitional when a strong bit is honored alongside them, and
        # Insecure on their own. 0x4 = RC4-HMAC. 0x1C and 0x3C land here: AES is preferred but
        # RC4 is still permitted.
        TransitionalEtypeBits  = 0x4

        # Etype bits treated as strong. Only the SHA-1 AES types count: 0x08 = AES128-CTS-HMAC-
        # SHA1-96, 0x10 = AES256-CTS-HMAC-SHA1-96. The RFC 8009 AES-SHA2 bits (0x40/0x80) are
        # deliberately NOT here - they are defined in the bitmask but are not active in
        # etype negotiation, and a DDSET carrying only unsupported bits yields
        # KDC_ERR_ETYPE_NOSUPP (lab-verified 2026-06-26). Add them when negotiation activates.
        StrongEtypeBits        = (0x08 -bor 0x10)

        # RC4DefaultDisablementPhase at or above this value is Secure (RC4 default removed); below
        # it the KDC still allows RC4 by default, so it is classified Insecure. 2 = enforce.
        MinSecureRc4Phase      = 2

        # KDC etype filter path. Server 2022 (20348) honors both SupportedEncryptionTypes paths
        # with Policies taking precedence (lab 2x2, 20348.5020). On OS major builds at or above
        # LsaOnlyFilterFromBuild the lab saw the KDC read the Lsa path ONLY and ignore the
        # Policies (GPO) path - one build, 26100.32522 (March 2026 update KB5078740).
        LsaOnlyFilterFromBuild = 26100

        # Microsoft's release note for the April 2026 update of Windows Server 2025 (KB5082063,
        # 26100.32690) says Windows "reads the configured policy settings as expected" for the
        # Kerberos encryption policies. That reads as a fix for the behaviour above, but the lab
        # has NOT retested it. From the revision given here the audit therefore reports the
        # filter path as UNCERTAIN instead of asserting either model.
        LsaOnlyFilterFixedFrom = @{ 26100 = 32690 }

        # RC4 default removal (CVE-2026-20833) ships in cumulative updates, so the state of a DC
        # depends on its build revision (UBR), not on any registry value. Per OS major build:
        #
        #   AuditFrom     first revision with the January 2026 update (audit events 201-209,
        #                 RC4DefaultDisablementPhase is read; unset behaves as 1 = audit).
        #   NotEnforcing  highest revision released BEFORE the April 2026 update.
        #   Enforcing     first revision with the April 2026 update (unset accounts default to
        #                 0x18; unset RC4DefaultDisablementPhase behaves as 2).
        #   PermanentFrom first revision with the July 2026 update, where KB5073381 says support
        #                 for RC4DefaultDisablementPhase is removed.
        #   Evidence      'Lab' when the NotEnforcing/Enforcing pair was observed in the project
        #                 lab; 'Microsoft release history' when it is only the published build
        #                 number of the corresponding update (NOT lab-verified).
        #
        # Sources: build numbers from
        #   https://learn.microsoft.com/windows/release-health/windows-server-release-info
        # (retrieved 2026-11-10); phase dates from Microsoft KB5073381 (the July 2026 step is also
        # announced in Message Center MC1427604, 14 July 2026). A revision between
        # NotEnforcing and Enforcing reports INDETERMINATE. PermanentFrom is NOT lab-verified on
        # any OS. An OS major build with no entry reports UNKNOWN; do not guess thresholds.
        Rc4EnforcementBuilds   = @{
            # Windows Server 2016. Jan 2026 KB5073722, Mar KB5078938, Apr KB5082198, Jul KB5099535.
            14393 = @{ Name = 'Windows Server 2016'; AuditFrom = 8783; NotEnforcing = 8957; Enforcing = 9060; PermanentFrom = 9339; Evidence = 'Microsoft release history' }
            # Windows Server 2019. Jan 2026 KB5073723, Mar KB5078752, Apr KB5082123, Jul KB5099538.
            17763 = @{ Name = 'Windows Server 2019'; AuditFrom = 8276; NotEnforcing = 8511; Enforcing = 8644; PermanentFrom = 9020; Evidence = 'Microsoft release history' }
            # Windows Server 2022. Lab: .4893 issued RC4 for msDS-SET=0; .5020 issued AES256
            # (2026-06-26). Jan 2026 KB5073457, Mar KB5078766, Apr KB5082142, Jul KB5099540.
            20348 = @{ Name = 'Windows Server 2022'; AuditFrom = 4648; NotEnforcing = 4893; Enforcing = 5020; PermanentFrom = 5386; Evidence = 'Lab' }
            # Windows Server 2025. Jan 2026 KB5073379, Mar KB5078740, Apr KB5082063, Jul KB5099536.
            # The lab's only 2025 build (.32522) predates the April update and was not used for
            # an enforcement test.
            26100 = @{ Name = 'Windows Server 2025'; AuditFrom = 32230; NotEnforcing = 32522; Enforcing = 32690; PermanentFrom = 33158; Evidence = 'Microsoft release history' }
        }
    }
    # ===========================================================================

    # Decide whether to emit ANSI color. On by default, but off under -NoColor, when the host has
    # no virtual-terminal support, when the process's stdout is redirected, when this script is
    # not the last command in its pipeline, and when the invoking line assigns or redirects the
    # call. The last two are heuristics on the invocation info: PowerShell does not expose "my
    # output is being captured", so output captured by a CALLING script can still carry color.
    $script:Esc = [char]27
    $script:UseColor = $false
    if (-not $NoColor -and $Host.UI.SupportsVirtualTerminal) {
        $script:UseColor = $true
        try {
            if ([Console]::IsOutputRedirected) { $script:UseColor = $false }
        }
        catch {
            # Hosts without a console (remoting, some ISE builds) cannot answer; leave color on.
            Write-Verbose 'Console redirection state is not available on this host.'
        }
        if ($MyInvocation.PipelinePosition -lt $MyInvocation.PipelineLength) { $script:UseColor = $false }
        $invocationLine = [string]$MyInvocation.Line
        if ($script:UseColor -and $invocationLine) {
            $offset = [Math]::Min([Math]::Max(0, $MyInvocation.OffsetInLine - 1), $invocationLine.Length)
            # The statement fragment before the call (back to the previous separator) and after it.
            $beforeCall = @($invocationLine.Substring(0, $offset) -split '[;{(|]')[-1]
            $afterCall = @($invocationLine.Substring($offset) -split '[;|})]')[0]
            if ($beforeCall -match '=\s*[&.]?\s*$') { $script:UseColor = $false }
            if ($afterCall -match '(^|\s)[1-6*]?>{1,2}') { $script:UseColor = $false }
        }
    }

    # --- Bit reference ---

    # The single source of truth for bit names, shared by every decode path below. Names are
    # identical to the BITS table in content/javascripts/etype-calculator.js; tests/ps checks
    # that the two tables still agree.
    #
    # Provenance, per bit range (the whole table is NOT one citation):
    #   bits 0-5, 16-19 : [MS-KILE] 2.2.7 "Supported Encryption Types Bit Flags" (flags A-J).
    #                     Bit 5 (0x20, AES256-CTS-HMAC-SHA1-96-SK) is the session-key flag from
    #                     the November 2022 OOB update, KB5021131.
    #   bits 6-7        : RFC 8009 (AES-SHA2 for Kerberos 5), etypes 19 and 20. Present in the
    #                     bitmask; NOT active in etype negotiation.
    #   bit 31          : NOT in this table (and not in the calculator's). It is not defined in
    #                     [MS-KILE] 2.2.7 and lab testing shows it is not honored in any of the
    #                     three settings; the GPO "Future encryption types" checkbox actually
    #                     sets bits 5-30 (0x7FFFFFE0), not bit 31. The decode names it separately.
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
    )

    # Name of the GPO checkbox that covers bits 5-30 (FUTURE_NAME in the site calculator).
    $script:FutureCheckboxName = 'Future encryption types'

    # Bit 31: set by hand now and then because older documentation called it the "future" flag.
    $script:Bit31Mask = 0x80000000L

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
    # Matched by full type name because Windows PowerShell 5.1 - the shell on every domain
    # controller - has no [short]/[ushort] type accelerators, so an -is test against them throws.
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

    # Statuses that are findings, split into the two exit-code classes used by -FailOn.
    $script:SecurityStatuses = @('Insecure', 'Invalid', 'Transitional', 'Unknown')
    $script:CoverageStatuses = @('Error', 'Unreachable', 'NotDC')

    # ANSI SGR code per Status, shared by the table renderer and the summary.
    $script:StatusColor = @{
        Secure       = '1;32'
        Transitional = '36'
        Insecure     = '1;33'
        Invalid      = '31'
        Unknown      = '33'
        Error        = '1;35'
        Unreachable  = '1;35'
        NotDC        = '1;35'
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

            # ANSI SGR parameter(s), e.g. '31' (red), '33' (yellow), '1;36' (bold cyan). Empty
            # means "no color".
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$Code
        )

        # With color disabled, return the text untouched so redirected output stays clean.
        if (-not $script:UseColor -or -not $Code) {
            return $Text
        }

        # Wrap as ESC[<code>m <text> ESC[0m so the terminal applies then resets the color.
        return ('{0}[{1}m{2}{0}[0m' -f $script:Esc, $Code, $Text)
    }

    function Get-RecordField {
        <#
        .SYNOPSIS
            Read a property from a reader record, returning a default when it is absent.
        .DESCRIPTION
            Reader records cross a remoting boundary and older fixtures carry fewer properties.
            Under Set-StrictMode a plain $record.Missing throws, so every access goes through here.
        #>
        [CmdletBinding()]
        param(
            # The record to read from; $null yields the default.
            [Parameter()]
            [AllowNull()]
            $Record,

            # Property name.
            [Parameter(Mandatory)]
            [string]$Name,

            # Value returned when the record or the property does not exist.
            [Parameter()]
            [AllowNull()]
            $Default = $null
        )

        if ($null -eq $Record) {
            return $Default
        }
        $property = $Record.PSObject.Properties[$Name]
        if ($null -eq $property) {
            return $Default
        }
        return $property.Value
    }

    function Format-HexValue {
        <#
        .SYNOPSIS
            Render an integer as 0x-prefixed uppercase hex with an even number of digits.
        .DESCRIPTION
            Every hex figure in this report is written the same way - 0x plus whole bytes - so
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

            PowerShell unrolls a returned array: a one-byte result reaches the caller as a scalar
            and an empty one as nothing. Callers therefore wrap the call as [byte[]]@(...) so they
            always hold a byte[] (and .Count never throws under Set-StrictMode).
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
            return [byte[]][System.Text.Encoding]::Unicode.GetBytes($joined + "`0")
        }

        # REG_SZ / REG_EXPAND_SZ are stored as UTF-16LE, so show those bytes rather than ASCII;
        # that is what makes a stray newline or a wrong-type "24" obvious.
        if ($Value -is [string]) {
            return [byte[]][System.Text.Encoding]::Unicode.GetBytes($Value)
        }

        # Anything numeric: little-endian bytes, trailing zeros trimmed to the significant width.
        try {
            $number = [long]$Value
        }
        catch {
            # A value that will not coerce to a number has no meaningful byte form here.
            return [byte[]]@()
        }
        # A REG_DWORD comes back as a signed Int32, so 0xFFFFFFFF arrives as -1. Fold it back into
        # the unsigned 32-bit view first or BitConverter would report eight 0xFF bytes, not four.
        if ($number -lt 0) {
            $number = $number -band 0xFFFFFFFFL
        }
        $all = [System.BitConverter]::GetBytes($number)
        $last = 0
        for ($i = 0; $i -lt $all.Length; $i++) {
            if ($all[$i] -ne 0) { $last = $i }
        }
        return [byte[]]@($all[0..$last])
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
            [AllowEmptyCollection()]
            [byte[]]$Byte,

            # Render decimals (0-255) instead of the default 0x?? hex pairs.
            [Parameter()]
            [switch]$AsDecimal
        )

        # No bytes: nothing to print (the caller decides whether that is an error).
        if ($null -eq $Byte -or @($Byte).Count -eq 0) {
            return ''
        }

        # Hex is always two digits per byte so every byte reads as exactly 0x??.
        if ($AsDecimal) {
            return ((@($Byte) | ForEach-Object { [string][int]$_ }) -join ' ')
        }
        return ((@($Byte) | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' ')
    }

    function Get-EditDistance {
        <#
        .SYNOPSIS
            Case-insensitive Levenshtein distance between two short strings.
        .DESCRIPTION
            Used to recognize a registry value name that is a near miss of one the KDC reads
            (RC4DefaultDisablmentPhase, SuportedEncryptionTypes): the KDC ignores such a value,
            and an audit that only looks up exact names would never show it.
        #>
        [CmdletBinding()]
        [OutputType([int])]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$Left,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$Right
        )

        $a = $Left.ToLowerInvariant()
        $b = $Right.ToLowerInvariant()
        if ($a.Length -eq 0) { return $b.Length }
        if ($b.Length -eq 0) { return $a.Length }

        # Classic two-row dynamic programme; the names involved are under 40 characters.
        $previous = New-Object -TypeName 'System.Int32[]' -ArgumentList ($b.Length + 1)
        $current = New-Object -TypeName 'System.Int32[]' -ArgumentList ($b.Length + 1)
        for ($j = 0; $j -le $b.Length; $j++) { $previous[$j] = $j }
        for ($i = 1; $i -le $a.Length; $i++) {
            $current[0] = $i
            for ($j = 1; $j -le $b.Length; $j++) {
                $cost = if ($a[$i - 1] -eq $b[$j - 1]) { 0 } else { 1 }
                $best = [Math]::Min($previous[$j] + 1, $current[$j - 1] + 1)
                $current[$j] = [Math]::Min($best, $previous[$j - 1] + $cost)
            }
            $swap = $previous
            $previous = $current
            $current = $swap
        }
        return [int]$previous[$b.Length]
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
        [OutputType([string])]
        param(
            # The report rows to render; each carries a Status property used for the row color.
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [AllowNull()]
            $Rows,

            # Column definitions: @{ Name = 'Hex'; Expression = { $_.Hex } }, in display order.
            [Parameter(Mandatory)]
            [hashtable[]]$Column,

            # Colour rows by an explicit code instead of by their Status (used for the reference).
            [Parameter()]
            [scriptblock]$ColorRule
        )

        $rowList = @($Rows | Where-Object { $null -ne $_ })

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

            # A caller-supplied rule wins; otherwise map Status to its color.
            $code = ''
            if ($ColorRule) {
                $code = [string](@($rowList[$r] | ForEach-Object $ColorRule) -join '')
            }
            else {
                $rowStatus = [string](Get-RecordField -Record $rowList[$r] -Name 'Status' -Default '')
                if ($rowStatus -and $script:StatusColor.ContainsKey($rowStatus)) {
                    $code = $script:StatusColor[$rowStatus]
                }
            }

            Write-Output (ConvertTo-ColorText -Text $line -Code $code)
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
            $label = '{0} (bits 5-30)' -f $script:FutureCheckboxName
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
            # with the reason it does nothing - silently dropping it hides a real misconfiguration.
            $label = if (($entry.Mask -band $settingProfile.HonoredMask) -ne 0) {
                $entry.Name
            }
            else {
                '{0} (set but not honored by {1})' -f $entry.Name, $Variant
            }

            if ($seen.Add($label)) { $found.Add([PSCustomObject]@{ Order = $entry.Bit; Label = $label }) }
            $consumed = $consumed -bor $entry.Mask
        }

        # Bit 31 is named on its own: it is NOT the GPO "Future encryption types" checkbox (that
        # is bits 5-30), and without saying so the two read as the same flag twice. It is set but
        # inert, so it is consumed here rather than reported as an undefined bit.
        if (($value -band $script:Bit31Mask) -ne 0) {
            $label = 'Bit 31 (0x80000000 - set but not honored; the GPO "{0}" checkbox is bits 5-30)' -f $script:FutureCheckboxName
            if ($seen.Add($label)) { $found.Add([PSCustomObject]@{ Order = 31; Label = $label }) }
            $consumed = $consumed -bor $script:Bit31Mask
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
        $names = [string[]]@($found | Sort-Object -Property Order | ForEach-Object { $_.Label })

        # Bits that are set, defined, and actually acted on by this setting.
        $honored = $value -band $settingProfile.HonoredMask
        # Bits that are set and defined but inert for this setting (e.g. FAST on DDSET).
        $ignored = ($value -band $consumed) -band (-bnot $settingProfile.HonoredMask) -band 0xFFFFFFFFL

        [PSCustomObject]@{
            Value         = $value
            Variant       = $Variant
            Names         = $names
            Text          = if (@($names).Count -eq 0) { 'None (0x00)' } else { $names -join ' + ' }
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

    function Resolve-EtypeMaskTier {
        <#
        .SYNOPSIS
            Classify an etype mask as Secure, Transitional, Insecure or Invalid, with the reason.
        .DESCRIPTION
            The one place the SECURITY POLICY is applied to a mask. Only bits the setting honors
            count: DES anywhere is Insecure; RC4 next to AES is Transitional (RC4 is still
            permitted, AES is preferred); RC4 alone is Insecure; AES alone is Secure.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # The mask, unsigned 32-bit.
            [Parameter(Mandatory)]
            [long]$Mask,

            # Which setting the mask belongs to.
            [Parameter(Mandatory)]
            [ValidateSet('DDSET', 'GPO', 'msDS')]
            [string]$Variant,

            # The active SECURITY POLICY object.
            [Parameter(Mandatory)]
            $Policy
        )

        # Reuse the decode so classification and display can never disagree about which bits are
        # defined, which are honored here, and which are junk.
        $decode = ConvertTo-KerberosEtypeDecode -Mask $Mask -Variant $Variant
        if ($decode.UndefinedMask -ne 0) {
            return [PSCustomObject]@{ Status = 'Invalid'; Reason = ('Carries bits no setting defines ({0}); usually a typo.' -f (Format-HexValue -Value $decode.UndefinedMask)) }
        }

        $honored = $decode.HonoredMask
        $hasDes = ($honored -band $Policy.InsecureEtypeBits) -ne 0
        $hasRc4 = ($honored -band $Policy.TransitionalEtypeBits) -ne 0
        $hasStrong = ($honored -band $Policy.StrongEtypeBits) -ne 0

        if ($hasDes) {
            return [PSCustomObject]@{ Status = 'Insecure'; Reason = 'DES is enabled.' }
        }
        if ($hasRc4 -and $hasStrong) {
            return [PSCustomObject]@{ Status = 'Transitional'; Reason = 'RC4 is still permitted alongside AES; remove bit 0x4 once nothing depends on RC4.' }
        }
        if ($hasRc4) {
            return [PSCustomObject]@{ Status = 'Insecure'; Reason = 'RC4 without AES.' }
        }
        if ($hasStrong) {
            return [PSCustomObject]@{ Status = 'Secure'; Reason = '' }
        }
        # A set mask with neither AES-SHA1 nor a weak bit (AES-SK alone, AES-SHA2 alone, feature
        # flags alone, zero) does not give the KDC a usable strong etype.
        return [PSCustomObject]@{ Status = 'Insecure'; Reason = 'No usable AES-SHA1 etype in the mask.' }
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
                # DefaultEncryptionType stores a single Kerberos etype NUMBER, not a bitmask - which
                # is exactly why operators who set it expecting mask semantics see nothing happen.
                # The range guard must come first: -and short-circuits, so a value like 0xFFFFFFFF
                # never reaches the [int] cast, which would throw an overflow instead of reporting.
                if ($number -ge 0 -and $number -le [int]::MaxValue -and $script:EtypeNumbers.ContainsKey([int]$number)) {
                    return ('etype {0} ({1})' -f $number, $script:EtypeNumbers[[int]$number])
                }
                return ('etype {0} ({1}) - not a known etype number' -f $number, (Format-HexValue -Value $number))
            }
            'Phase' {
                # RC4DefaultDisablementPhase gated the RC4 default-removal rollout (KB5073381).
                $map = @{
                    0 = 'Off (no audit, no change - unset accounts fall back to 0x27)'
                    1 = 'Audit (RC4 still the default, Kdcsvc 201/202/206/207 logged)'
                    2 = 'Enforce (unset accounts fall back to 0x18, AES only)'
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
                return ('{0} ({1})' -f $number, (Format-HexValue -Value $number))
            }
        }
    }

    function Resolve-BuildClass {
        <#
        .SYNOPSIS
            Place a DC's OS build revision on the RC4 default-removal timeline.
        .DESCRIPTION
            Returns the rollout stage the installed cumulative update corresponds to:

              PreAudit       before the January 2026 update: RC4DefaultDisablementPhase is not read.
              Audit          January-March 2026 updates: audit events; unset Phase behaves as 1.
              Indeterminate  a revision between the last pre-April and the first April build.
              Enforcing      April-June 2026 updates: unset accounts default to 0x18; Phase is a
                             rollback switch.
              Permanent      July 2026 update or later: KB5073381 says Phase is no longer read.
              Unknown        OS build not in the map, or an unreadable revision.

            Nothing here is read from the registry settings themselves: the stage ships in a
            cumulative update, so only the build revision can reveal it.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # OS major build, e.g. '20348'.
            [Parameter()]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$Build,

            # OS update revision (UBR), e.g. 5020. Left loose because the registry returns it raw.
            [Parameter()]
            [AllowNull()]
            $Ubr,

            # The per-major-build revision map from the SECURITY POLICY block.
            [Parameter(Mandatory)]
            [hashtable]$BuildMap
        )

        $major = 0
        $revision = 0
        $majorOk = [int]::TryParse([string]$Build, [ref]$major)
        $revisionOk = [int]::TryParse([string]$Ubr, [ref]$revision)

        $result = [PSCustomObject]@{
            Class    = 'Unknown'
            Major    = $major
            Revision = $revision
            OsName   = ''
            Evidence = ''
            Detail   = ''
        }

        # A build with no entry in the map has not been characterized: say so rather than guess.
        if (-not $majorOk -or -not $BuildMap.ContainsKey($major)) {
            $result.Detail = 'OS build {0} is not in the build map' -f $(if ($Build) { $Build } else { '(unreadable)' })
            return $result
        }

        $known = $BuildMap[$major]
        $result.OsName = [string]$known.Name
        $result.Evidence = [string]$known.Evidence

        # A blank or non-numeric revision must not parse to 0 and read as a confident "old build".
        if (-not $revisionOk) {
            $result.Detail = 'update revision (UBR) is unreadable'
            return $result
        }

        if ($revision -ge $known.PermanentFrom) {
            $result.Class = 'Permanent'
            $result.Detail = 'July 2026 update or later'
        }
        elseif ($revision -ge $known.Enforcing) {
            $result.Class = 'Enforcing'
            $result.Detail = 'April 2026 update or later'
        }
        elseif ($revision -gt $known.NotEnforcing) {
            $result.Class = 'Indeterminate'
            $result.Detail = 'revision between the last pre-April and the first April 2026 build'
        }
        elseif ($revision -ge $known.AuditFrom) {
            $result.Class = 'Audit'
            $result.Detail = 'January-March 2026 update'
        }
        else {
            $result.Class = 'PreAudit'
            $result.Detail = 'older than the January 2026 update'
        }
        return $result
    }

    function Resolve-KdcEffectiveState {
        <#
        .SYNOPSIS
            Derive what a DC actually does from its build plus the settings read from it.
        .DESCRIPTION
            Combines the build class with the four settings that decide behaviour:

              DefaultDomainSupportedEncTypes (Services\Kdc)  explicit fallback for unset accounts;
                                                             takes precedence over the build default
                                                             (lab-verified on Server 2022, June 2026).
              RC4DefaultDisablementPhase (Policies)          rollout switch, read only on builds
                                                             from January to June 2026.
              SupportedEncryptionTypes (Policies / Lsa)      the KDC etype filter; which path is
                                                             read depends on the OS.

            The result drives the per-DC header line, two synthetic "effective" rows and the final
            verdict, so the three can never disagree.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # Output of Resolve-BuildClass for this DC.
            [Parameter(Mandatory)]
            $BuildInfo,

            # Readings (ConvertTo-AuditReading output) for the four deciding settings.
            [Parameter(Mandatory)]
            $Ddset,

            [Parameter(Mandatory)]
            $Phase,

            [Parameter(Mandatory)]
            $PolicyFilter,

            [Parameter(Mandatory)]
            $LsaFilter,

            # The active SECURITY POLICY object.
            [Parameter(Mandatory)]
            $Policy
        )

        $class = [string]$BuildInfo.Class
        $evidenceNote = if ($BuildInfo.Evidence -eq 'Lab') { 'lab-verified' } elseif ($BuildInfo.Evidence) { 'per Microsoft release history; not lab-verified on this OS' } else { '' }

        # ---- Fallback etypes for accounts with no msDS-SupportedEncryptionTypes ----
        $fallbackMask = $null
        $fallbackSource = ''
        $fallbackStatus = 'Unknown'
        $fallbackReason = ''
        # Whether a registry row already carries this verdict (so the effective row stays neutral
        # and the same problem is not counted twice).
        $fallbackOwnedByRow = $false
        $enforcementCode = 'Unknown'
        $enforcement = ''

        # What the build alone does, before any explicit setting.
        $buildEnforces = $class -eq 'Enforcing' -or $class -eq 'Permanent'
        # Server 2025 is documented with a 0x24 pre-enforcement default (not lab-verified); every
        # other OS uses 0x27. Both include RC4.
        $legacyDefault = if ($BuildInfo.Major -ge 26100) { 0x24L } else { 0x27L }

        $phaseUsable = $Phase.Found -and $Phase.IsNumeric -and -not $Phase.WrongType -and $Phase.Numeric -ge 0 -and $Phase.Numeric -le 2
        $ddsetUsable = $Ddset.Found -and $Ddset.IsNumeric -and -not $Ddset.WrongType

        if ($ddsetUsable) {
            # An explicit DDSET wins over the build default and over the Phase switch.
            $fallbackMask = $Ddset.Numeric -band 0xFFL
            $tier = Resolve-EtypeMaskTier -Mask $Ddset.Numeric -Variant 'DDSET' -Policy $Policy
            $fallbackStatus = $tier.Status
            $fallbackReason = $tier.Reason
            $fallbackSource = 'explicit DefaultDomainSupportedEncTypes'
            $fallbackOwnedByRow = $true
            $ddsetHex = Format-HexValue -Value $Ddset.Numeric
            if ($tier.Status -eq 'Secure') {
                $enforcementCode = 'Enforcing'
                $enforcement = 'ACTIVE - explicit DefaultDomainSupportedEncTypes {0} is AES-only' -f $ddsetHex
            }
            else {
                $enforcementCode = 'Overridden'
                $enforcement = if ($buildEnforces) {
                    'OVERRIDDEN - the build enforces AES by default, but explicit DefaultDomainSupportedEncTypes {0} takes precedence' -f $ddsetHex
                }
                else {
                    'NOT active - explicit DefaultDomainSupportedEncTypes {0} still permits RC4 or DES' -f $ddsetHex
                }
            }
        }
        elseif ($class -eq 'Unknown' -or $class -eq 'Indeterminate') {
            # No explicit DDSET and a build this script cannot place: never a pass.
            $fallbackStatus = 'Unknown'
            $fallbackSource = 'build default (cannot be determined)'
            $fallbackReason = 'Cannot tell from this build whether unset accounts still get RC4: {0}. Request a ticket for an msDS-SET=0 account, or set DefaultDomainSupportedEncTypes explicitly.' -f $BuildInfo.Detail
            $enforcementCode = 'Unknown'
            $enforcement = if ($class -eq 'Indeterminate') {
                'INDETERMINATE - {0}; verify with a live msDS-SET=0 ticket' -f $BuildInfo.Detail
            }
            else {
                'UNKNOWN - {0}; verify with a live msDS-SET=0 ticket' -f $BuildInfo.Detail
            }
        }
        elseif ($class -eq 'Permanent') {
            $fallbackMask = 0x18L
            $fallbackSource = 'build default (July 2026 update or later)'
            if ($phaseUsable -and $Phase.Numeric -lt $Policy.MinSecureRc4Phase) {
                # KB5073381 says this build no longer reads the value, but nobody has tested it.
                $fallbackStatus = 'Unknown'
                $fallbackOwnedByRow = $true
                $fallbackReason = 'RC4DefaultDisablementPhase={0} is still present. KB5073381 says updates from July 2026 no longer read it, but that has not been lab-verified.' -f $Phase.Numeric
                $enforcementCode = 'Unknown'
                $enforcement = 'EXPECTED ACTIVE - build is at the July 2026 update or later ({0}), but a leftover RC4DefaultDisablementPhase={1} is present; verify with a live msDS-SET=0 ticket and delete the value' -f $evidenceNote, $Phase.Numeric
            }
            else {
                $fallbackStatus = 'Secure'
                $enforcementCode = 'Enforcing'
                $enforcement = 'ACTIVE - July 2026 update or later; unset accounts default to 0x18 ({0})' -f $evidenceNote
            }
        }
        elseif ($class -eq 'Enforcing') {
            if ($phaseUsable -and $Phase.Numeric -lt $Policy.MinSecureRc4Phase) {
                $fallbackMask = $legacyDefault
                $fallbackStatus = 'Insecure'
                $fallbackOwnedByRow = $true
                $fallbackSource = 'RC4DefaultDisablementPhase={0} (rollback)' -f $Phase.Numeric
                $fallbackReason = 'The build enforces AES by default, but RC4DefaultDisablementPhase={0} rolls unset accounts back to RC4.' -f $Phase.Numeric
                $enforcementCode = 'Overridden'
                $enforcement = 'OVERRIDDEN - the build enforces AES by default, but RC4DefaultDisablementPhase={0} rolls it back (takes effect after a KDC restart)' -f $Phase.Numeric
            }
            else {
                $fallbackMask = 0x18L
                $fallbackStatus = 'Secure'
                $fallbackSource = 'build default (April 2026 update or later)'
                $enforcementCode = 'Enforcing'
                $enforcement = 'ACTIVE - April 2026 update or later; unset accounts default to 0x18 ({0})' -f $evidenceNote
            }
        }
        elseif ($class -eq 'Audit') {
            if ($phaseUsable -and $Phase.Numeric -ge $Policy.MinSecureRc4Phase) {
                $fallbackMask = 0x18L
                $fallbackStatus = 'Secure'
                $fallbackSource = 'RC4DefaultDisablementPhase=2 (manual enforcement)'
                $enforcementCode = 'Enforcing'
                $enforcement = 'ACTIVE - RC4DefaultDisablementPhase=2 on a January-March 2026 build (takes effect after a KDC restart; {0})' -f $evidenceNote
            }
            else {
                $fallbackMask = $legacyDefault
                $fallbackStatus = 'Insecure'
                $fallbackOwnedByRow = [bool]$phaseUsable
                $fallbackSource = 'build default (before the April 2026 update)'
                $fallbackReason = 'This build predates the April 2026 update: accounts with no msDS-SupportedEncryptionTypes still get RC4 by default.'
                $enforcementCode = 'NotEnforcing'
                $enforcement = 'NOT active - January-March 2026 update (audit only); unset accounts still get RC4 by default ({0})' -f $evidenceNote
            }
        }
        else {
            # PreAudit: the Phase value is not read at all on this build.
            $fallbackMask = $legacyDefault
            $fallbackStatus = 'Insecure'
            $fallbackSource = 'build default (before the January 2026 update)'
            $fallbackReason = 'This build predates the January 2026 update: accounts with no msDS-SupportedEncryptionTypes get RC4 by default and RC4DefaultDisablementPhase is not read.'
            $enforcementCode = 'NotEnforcing'
            $enforcement = 'NOT active - build predates the January 2026 update; unset accounts get RC4 by default ({0})' -f $evidenceNote
        }

        # ---- Effective KDC etype filter ----
        # Three models:
        #   PoliciesThenLsa  Server 2022: Policies wins, Lsa is the fallback (lab 2x2, 20348.5020).
        #                    Other pre-2025 OS versions were never lab-tested; the same model is
        #                    assumed and labelled as such.
        #   LsaOnly          Server 2025 before the April 2026 update: the one build tested
        #                    (26100.32522) read Lsa only and ignored Policies.
        #   Uncertain        Server 2025 from the April 2026 update: Microsoft's release note says
        #                    the policy settings are read as expected; not retested, so neither
        #                    model is asserted.
        $filterMode = 'PoliciesThenLsa'
        if ($BuildInfo.Major -ge $Policy.LsaOnlyFilterFromBuild) {
            $filterMode = 'Uncertain'
            if ($Policy.LsaOnlyFilterFixedFrom.ContainsKey([int]$BuildInfo.Major) -and $class -ne 'Unknown') {
                if ($BuildInfo.Revision -lt $Policy.LsaOnlyFilterFixedFrom[[int]$BuildInfo.Major]) { $filterMode = 'LsaOnly' }
            }
        }
        $filterModel = switch ($filterMode) {
            'LsaOnly' { 'Lsa path only (lab: 26100.32522 ignored the Policies path)' }
            'Uncertain' { 'UNCERTAIN - lab saw the Policies path ignored on 26100.32522; the April 2026 release note (KB5082063) says policy settings are read as expected; not retested' }
            default {
                if ($BuildInfo.Major -eq 20348) { 'Policies path, then Lsa (lab-verified on 20348.5020)' } else { 'Policies path, then Lsa (assumed; not lab-tested on this OS)' }
            }
        }

        $usable = { param($Reading) $Reading.Found -and $Reading.IsNumeric -and -not $Reading.WrongType }
        $filterPath = ''
        $filterReading = $null
        $filterAmbiguous = $false
        switch ($filterMode) {
            'LsaOnly' {
                if ($LsaFilter.Found) { $filterPath = 'Lsa'; $filterReading = $LsaFilter }
            }
            'Uncertain' {
                if ($PolicyFilter.Found -and $LsaFilter.Found) {
                    # Same value at both paths: the effective mask is the same under either model.
                    $filterPath = 'Policies or Lsa'
                    $filterReading = $LsaFilter
                    $sameValue = (& $usable $PolicyFilter) -and (& $usable $LsaFilter) -and $PolicyFilter.Numeric -eq $LsaFilter.Numeric
                    if (-not $sameValue) { $filterAmbiguous = $true }
                }
                elseif ($LsaFilter.Found) {
                    # Lsa only: effective under either model.
                    $filterPath = 'Lsa'; $filterReading = $LsaFilter
                }
                elseif ($PolicyFilter.Found) {
                    # Policies only: effective if the fix applies, inert if it does not.
                    $filterPath = 'Policies'; $filterReading = $PolicyFilter
                    $filterAmbiguous = $true
                }
            }
            default {
                if ($PolicyFilter.Found) {
                    $filterPath = 'Policies'; $filterReading = $PolicyFilter
                }
                elseif ($LsaFilter.Found) {
                    $filterPath = 'Lsa'; $filterReading = $LsaFilter
                }
            }
        }

        $filterMask = $null
        $filterStatus = ''
        $filterReason = ''
        $filterText = 'none configured (etypes are governed by account settings and the fallback above)'
        if ($null -ne $filterReading -and (& $usable $filterReading)) {
            $filterMask = $filterReading.Numeric
            $filterText = '{0} at the {1} path = {2}' -f (Format-HexValue -Value $filterMask), $filterPath, (ConvertTo-KerberosEtypeName -Mask $filterMask -Variant 'GPO')
        }
        elseif ($null -ne $filterReading) {
            $filterText = 'value at the {0} path is not a usable REG_DWORD' -f $filterPath
        }

        # A GPO filter that this build does not read is the one filter problem no registry row can
        # express on its own: the value looks right and does nothing.
        if ($filterMode -eq 'LsaOnly' -and $PolicyFilter.Found -and -not $LsaFilter.Found) {
            $filterStatus = 'Invalid'
            $filterReason = 'SupportedEncryptionTypes is set at the Policies (GPO) path only. In lab testing the KDC on Server 2025 build 26100.32522 read the filter from the Lsa path only, so this GPO does not filter KDC etypes here. Install the April 2026 update or later (its release note says the policy is read as expected; not retested) or set the same value at the Lsa path.'
            $filterText = 'NOT EFFECTIVE - set at the Policies path only, which the KDC ignored in lab testing on this build line'
        }
        elseif ($filterAmbiguous) {
            $filterMask = $null
            $filterStatus = 'Unknown'
            if ($PolicyFilter.Found -and $LsaFilter.Found) {
                $filterReason = 'SupportedEncryptionTypes differs between the Policies and Lsa paths, and which one the KDC reads on this build is not established (lab: Lsa only on 26100.32522; April 2026 release note: policy read as expected; not retested). Set both paths to the same value, or verify with a live ticket.'
                $filterText = 'UNCERTAIN - Policies and Lsa hold different values and the path this build reads is not established'
            }
            else {
                $filterReason = 'SupportedEncryptionTypes is set at the Policies (GPO) path only. The lab saw that path ignored on 26100.32522; the April 2026 release note (KB5082063) says policy settings are read as expected, but that has not been retested. Verify with a live ticket, or set the same value at the Lsa path.'
                $filterText = 'UNCERTAIN - set at the Policies path only; whether this build reads it has not been retested'
            }
        }

        [PSCustomObject]@{
            BuildClass         = $class
            BuildDetail        = [string]$BuildInfo.Detail
            BuildEvidence      = [string]$BuildInfo.Evidence
            Enforcement        = $enforcement
            EnforcementCode    = $enforcementCode
            FallbackMask       = $fallbackMask
            FallbackSource     = $fallbackSource
            FallbackStatus     = $fallbackStatus
            FallbackReason     = $fallbackReason
            FallbackOwnedByRow = $fallbackOwnedByRow
            FilterMode         = $filterMode
            FilterModel        = $filterModel
            FilterPath         = $filterPath
            FilterMask         = $filterMask
            FilterStatus       = $filterStatus
            FilterReason       = $filterReason
            FilterText         = $filterText
        }
    }

    function ConvertTo-AuditReading {
        <#
        .SYNOPSIS
            Normalize one reader record (or its absence) into the numeric views the audit needs.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # The reader's record for this value, or $null when the value does not exist.
            [Parameter()]
            [AllowNull()]
            $Record,

            # Error text for the containing key, when the key itself could not be read.
            [Parameter()]
            [AllowEmptyString()]
            [string]$KeyError = ''
        )

        $found = [bool](Get-RecordField -Record $Record -Name 'Found' -Default $false)
        $kind = [string](Get-RecordField -Record $Record -Name 'Kind' -Default '')
        $value = Get-RecordField -Record $Record -Name 'Value' -Default $null
        $errorText = [string](Get-RecordField -Record $Record -Name 'Error' -Default '')
        if (-not $errorText -and $KeyError) { $errorText = $KeyError }

        # Reduce the stored value to its bytes once: this drives the decimal form, the hex form
        # and the byte-level view that exposes a REG_SZ or a mistyped 0x0110.
        $bytes = [byte[]]@(ConvertTo-RawByte -Value $value)
        # Match on the concrete .NET type name rather than type accelerators: [short]/[ushort] do
        # not exist in Windows PowerShell 5.1, which is what actually ships on a domain controller.
        $isNumeric = $found -and $null -ne $value -and $script:NumericTypeNames -contains $value.GetType().FullName

        # Two numeric views. The DISPLAY value keeps every bit that is actually stored, so a
        # REG_QWORD wider than 32 bits reads the same in the Decimal/Hex columns as in its bytes;
        # only a negative Int32 (a REG_DWORD with the high bit set) is folded to its unsigned form.
        # The DECODE value is masked to 32 bits, because that is all an etype mask can carry.
        $displayNumeric = $null
        $numeric = $null
        if ($isNumeric) {
            $displayNumeric = [long]$value
            if ($displayNumeric -lt 0) { $displayNumeric = $displayNumeric -band 0xFFFFFFFFL }
            $numeric = $displayNumeric -band 0xFFFFFFFFL
        }

        # A value the KDC cannot read as a DWORD is Invalid regardless of what it looks like: a
        # REG_SZ of "24" parses as a number but the KDC never sees 24.
        $wrongType = $found -and $kind -and $kind -ne 'DWord' -and $kind -ne 'AD-Integer'

        [PSCustomObject]@{
            Found          = $found
            Error          = $errorText
            Kind           = $kind
            Value          = $value
            Bytes          = $bytes
            IsNumeric      = [bool]$isNumeric
            WrongType      = [bool]$wrongType
            DisplayNumeric = $displayNumeric
            Numeric        = $numeric
        }
    }

    # --- Registry matrix ---

    # Registry keys the reader enumerates in full. The first three hold the values the KDC reads;
    # Services\Kdc\Parameters is enumerated only to catch values written one level too deep, which
    # the KDC silently ignores.
    $script:KeyPolicies = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $script:KeyLsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
    $script:KeyKdc = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
    $script:KeyKdcParameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\Parameters'
    $script:AuditedKeys = @($script:KeyKdc, $script:KeyPolicies, $script:KeyLsa, $script:KeyKdcParameters)

    # Every documented path/value combination, with the verdict on whether the KDC honors it,
    # its default, whether it is set automatically, and a one-line description. Functional is the
    # OS-independent verdict; the audit refines it per DC (filter path on Server 2025, the Phase
    # value on builds that do not read it). Order controls report sorting.
    $script:RegistryMatrix = @(
        # 1. The single most important KDC key: fallback etypes for accounts with msDS-SET = 0.
        [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Services\Kdc)'; Path = $script:KeyKdc; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'Immediate'; Default = 'Not set (build default: 0x27 before the April 2026 CU, 0x18 on it or later)'; AutoSet = 'Manual'; Order = 1; Note = 'Fallback etypes for accounts with no msDS-SupportedEncryptionTypes. When unset the KDC uses its build default: 0x27 before the April 2026 cumulative update, 0x18 on it or later (CU-gated, not date-gated). An explicit value takes precedence over that default (lab-verified on Server 2022, June 2026).' }
        # 2. The KDC etype filter written by Group Policy.
        [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Policies)'; Path = $script:KeyPolicies; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set'; AutoSet = 'GPO'; Order = 2; Note = 'KDC etype filter (GPO/Policies path). On Server 2022 it takes precedence over the Lsa path. The one Server 2025 build lab-tested (26100.32522, March 2026 update) ignored this path and read Lsa only; the April 2026 release note (KB5082063, 26100.32690) says policy settings are read as expected, which has not been retested.' }
        # 3. The same filter at the Lsa path.
        [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Lsa)'; Path = $script:KeyLsa; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set'; AutoSet = 'Manual'; Order = 3; Note = 'KDC etype filter (Lsa path). On Server 2022 it is used only when the Policies path is not set. On the one Server 2025 build lab-tested (26100.32522) it is the only path the KDC read; later Server 2025 builds have not been retested.' }
        # 4. The dangerous compatibility knob that lets clients force RC4; must stay 0.
        [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Services\Kdc)'; Path = $script:KeyKdc; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'Yes'; Timing = 'Immediate'; Default = 'Not set (0)'; AutoSet = 'Manual'; Order = 4; Note = 'When 1, a client can force RC4 for any account whose msDS-SET still lists RC4 (AES-only accounts stay AES on enforced builds). Bypasses per-account hardening; never set to 1.' }
        # 5. The CVE-2026-20833 rollout switch (correct Policies path).
        [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Policies)'; Path = $script:KeyPolicies; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'Yes'; Timing = 'KDC restart'; Default = 'Not set (CU-gated)'; AutoSet = 'Manual'; Order = 5; Note = 'RC4 rollout switch: 0 off, 1 audit, 2 enforce. Read only on builds from the January 2026 update up to the July 2026 update; unset behaves as 1 on January-March builds and as 2 from the April 2026 update. Per KB5073381 it is no longer read beginning with the July 2026 security update (not lab-verified). The registry alone cannot confirm enforcement - see the build line.' }
        # 6. Verbose Kerberos logging toggle; diagnostic only.
        [PSCustomObject]@{ Setting = 'LogLevel (Lsa)'; Path = $script:KeyLsa; Name = 'LogLevel'; Kind = 'Log'; Functional = 'Diagnostic'; Timing = 'n/a'; Default = '0 (off)'; AutoSet = 'Manual'; Order = 6; Note = 'Verbose Kerberos logging when 1. No effect on etype selection.' }
        # 7. DDSET at the Lsa path: a common mistake; the KDC never reads it here.
        [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Lsa)'; Path = $script:KeyLsa; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 7; Note = 'Ignored (lab-tested 4, 24, 28: no change). DDSET only works directly under Services\Kdc.' }
        # 8. DDSET at the Policies path: the same wrong-path mistake.
        [PSCustomObject]@{ Setting = 'DefaultDomainSupportedEncTypes (Policies)'; Path = $script:KeyPolicies; Name = 'DefaultDomainSupportedEncTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 8; Note = 'Ignored (lab-tested 4, 24, 28: no change). DDSET only works directly under Services\Kdc.' }
        # 9. SupportedEncryptionTypes under Services\Kdc: ignored; filter lives at Pol/Lsa.
        [PSCustomObject]@{ Setting = 'SupportedEncryptionTypes (Services\Kdc)'; Path = $script:KeyKdc; Name = 'SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 9; Note = 'Ignored (lab-tested 4, 24, 28: no change). The KDC filter only works at the Policies and Lsa paths.' }
        # 10-13. The remaining wrong-path combinations. These follow from where each value is
        # documented to live; they were not individually lab-tested.
        [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Lsa)'; Path = $script:KeyLsa; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 10; Note = 'Not the documented location (not individually lab-tested). KdcUseRequestedEtypesForTickets is read at Services\Kdc.' }
        [PSCustomObject]@{ Setting = 'KdcUseRequestedEtypesForTickets (Policies)'; Path = $script:KeyPolicies; Name = 'KdcUseRequestedEtypesForTickets'; Kind = 'Bool'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 11; Note = 'Not the documented location (not individually lab-tested). KdcUseRequestedEtypesForTickets is read at Services\Kdc.' }
        [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Services\Kdc)'; Path = $script:KeyKdc; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 12; Note = 'Not the documented location (not individually lab-tested). KB5073381 places the value at the Policies path.' }
        [PSCustomObject]@{ Setting = 'RC4DefaultDisablementPhase (Lsa)'; Path = $script:KeyLsa; Name = 'RC4DefaultDisablementPhase'; Kind = 'Phase'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 13; Note = 'Not the documented location (not individually lab-tested). KB5073381 places the value at the Policies path.' }
        # 14-16. DefaultEncryptionType. Lab-tested with 4, 18 and 24 at each path: no change to
        # ticket etype, session key, or the 4769 fields. At the Lsa path it is a documented
        # CLIENT-side value (pre-authentication etype), so it is reported as "not a KDC control"
        # rather than as a wrong path; at the other two paths nothing reads it.
        [PSCustomObject]@{ Setting = 'DefaultEncryptionType (Lsa)'; Path = $script:KeyLsa; Name = 'DefaultEncryptionType'; Kind = 'Etype'; Functional = 'Client-side (not a KDC control)'; Timing = 'n/a'; Default = 'Not set'; AutoSet = 'Manual'; Order = 14; Note = 'Client-side pre-authentication etype NUMBER (not a bitmask). Lab-tested 4, 18, 24: no effect on the etypes the KDC issues. Reported for information; it is not a KDC control.' }
        [PSCustomObject]@{ Setting = 'DefaultEncryptionType (Services\Kdc)'; Path = $script:KeyKdc; Name = 'DefaultEncryptionType'; Kind = 'Etype'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 15; Note = 'Ignored (lab-tested 4, 18, 24: no change). Not a KDC control at any path.' }
        [PSCustomObject]@{ Setting = 'DefaultEncryptionType (Policies)'; Path = $script:KeyPolicies; Name = 'DefaultEncryptionType'; Kind = 'Etype'; Functional = 'No (wrong path)'; Timing = 'n/a'; Default = 'n/a'; AutoSet = 'n/a'; Order = 16; Note = 'Ignored (lab-tested 4, 18, 24: no change). Not a KDC control at any path.' }
    )

    # Synthetic metadata for the msDS-SupportedEncryptionTypes AD attribute (read per DC, not a
    # registry value). Order 0 sorts it first in each DC's table; the GPO is what populates it.
    $script:MsdsMeta = [PSCustomObject]@{ Setting = 'msDS-SupportedEncryptionTypes (AD)'; Path = 'Active Directory (DC computer account)'; Name = 'msDS-SupportedEncryptionTypes'; Kind = 'EtypeMask'; Functional = 'AD attribute'; Timing = 'n/a'; Default = '0 (falls back to DDSET)'; AutoSet = 'GPO -> SupportedEncryptionTypes'; Order = 0; Note = 'DC computer account etypes; the LSA writes this from the SupportedEncryptionTypes GPO.' }

    # The value names the KDC (or the Kerberos client) reads, with the key each belongs under.
    # Used to explain a value found at an unlisted location or under a misspelled name.
    $script:KnownValueHomes = @{
        'DefaultDomainSupportedEncTypes'  = 'Services\Kdc'
        'SupportedEncryptionTypes'        = 'Policies\System\Kerberos\Parameters (or Lsa\Kerberos\Parameters)'
        'KdcUseRequestedEtypesForTickets' = 'Services\Kdc'
        'RC4DefaultDisablementPhase'      = 'Policies\System\Kerberos\Parameters'
        'DefaultEncryptionType'           = 'Lsa\Kerberos\Parameters (client-side only)'
    }

    # A value name that looks etype-related. Anything matching this at an audited key that is not
    # one of the names above is reported: the KDC does not read it.
    $script:EtypeLookingName = '(?i)enc\w{0,12}type|etype|rc4|disabl\w*phase|supportedenc'

    # --- Registry reader (runs on each DC) ---

    # This scriptblock runs on each DC and reads its own registry locally (fast and reliable).
    # The key list arrives as a parameter rather than via $using: so the identical block can be
    # invoked in this session for the local machine, where WinRM would be the wrong tool.
    #
    # It enumerates EVERY value under each key rather than probing fixed names, so the local side
    # can see values written at the wrong path or under a misspelled name, and it reports a read
    # failure as an error instead of letting it pass for "not set". It deliberately avoids
    # PowerShell 5 syntax (no ::new()) so it also runs on an older remote shell.
    $script:RegistryReader = {
        param([string[]]$KeyPath)

        # One flat record shape for everything, so the results survive remoting serialization
        # (which flattens nested objects) and the local side never meets a missing property.
        $newRecord = {
            param([hashtable]$Field)
            $record = [ordered]@{
                RecordType = ''; Path = ''; Name = ''; Found = $false; Kind = ''; Value = $null; Error = ''
                Caption = ''; Build = ''; Ubr = ''; ProductType = ''; KdcService = ''; MachineFqdn = ''; Uac = $null
            }
            foreach ($fieldName in $Field.Keys) { $record[$fieldName] = $Field[$fieldName] }
            [PSCustomObject]$record
        }

        # The 64-bit registry view, whatever the bitness of this shell: a 32-bit PowerShell would
        # otherwise be redirected to WOW6432Node for the SOFTWARE keys.
        $hklm = $null
        $baseError = ''
        try {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        }
        catch {
            $baseError = $_.Exception.Message
        }

        foreach ($path in $KeyPath) {
            if ($null -eq $hklm) {
                & $newRecord @{ RecordType = 'Key'; Path = $path; Error = ('Could not open HKLM: {0}' -f $baseError) }
                continue
            }
            $key = $null
            try {
                # OpenSubKey returns $null for a key that does not exist (normal: the setting is
                # simply not configured) and THROWS when the key exists but cannot be read.
                $key = $hklm.OpenSubKey(($path -replace '^HKLM:\\', ''), $false)
                if ($null -eq $key) {
                    & $newRecord @{ RecordType = 'Key'; Path = $path; Found = $false }
                    continue
                }
                & $newRecord @{ RecordType = 'Key'; Path = $path; Found = $true }
                foreach ($valueName in $key.GetValueNames()) {
                    # The unnamed default value is never a Kerberos setting.
                    if ([string]::IsNullOrEmpty($valueName)) { continue }
                    try {
                        # DoNotExpandEnvironmentNames keeps a REG_EXPAND_SZ byte-faithful for the
                        # raw-byte view instead of silently substituting %SystemRoot% and friends.
                        $value = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        $kind = [string]$key.GetValueKind($valueName)
                        & $newRecord @{ RecordType = 'Value'; Path = $path; Name = $valueName; Found = $true; Kind = $kind; Value = $value }
                    }
                    catch {
                        & $newRecord @{ RecordType = 'Value'; Path = $path; Name = $valueName; Found = $true; Error = $_.Exception.Message }
                    }
                }
            }
            catch {
                & $newRecord @{ RecordType = 'Key'; Path = $path; Error = $_.Exception.Message }
            }
            finally {
                if ($null -ne $key) { $key.Close() }
            }
        }

        # This machine's own msDS-SupportedEncryptionTypes from AD: the DC computer account
        # attribute that drives the etypes the KDC uses for its own service tickets. ADSI needs no
        # RSAT module and queries the current domain. userAccountControl rides along so the
        # report can label a read-only DC (0x04000000 = PARTIAL_SECRETS_ACCOUNT).
        $adField = @{ RecordType = 'AD'; Path = 'AD'; Name = 'msDS-SupportedEncryptionTypes'; Kind = 'AD-Integer' }
        try {
            $sam = '{0}$' -f $env:COMPUTERNAME
            $searcher = [adsisearcher]("(&(objectCategory=computer)(sAMAccountName=$sam))")
            [void]$searcher.PropertiesToLoad.Add('msDS-SupportedEncryptionTypes')
            [void]$searcher.PropertiesToLoad.Add('userAccountControl')
            $hit = $searcher.FindOne()
            if ($null -eq $hit) {
                # A bind that works but finds nothing is a failure to read, not "attribute unset".
                $adField['Error'] = 'Computer object {0} was not found in the directory.' -f $sam
            }
            else {
                if ($hit.Properties['msds-supportedencryptiontypes'].Count -gt 0) {
                    $adField['Value'] = [int64]$hit.Properties['msds-supportedencryptiontypes'][0]
                    $adField['Found'] = $true
                }
                if ($hit.Properties['useraccountcontrol'].Count -gt 0) {
                    $adField['Uac'] = [int64]$hit.Properties['useraccountcontrol'][0]
                }
            }
        }
        catch {
            $adField['Error'] = $_.Exception.Message
        }
        & $newRecord $adField

        # OS build (to place the DC on the RC4 rollout timeline - something no Kerberos registry
        # value can reveal), the machine's role, and its own idea of its FQDN (used to recognize
        # the same machine audited under two names).
        $osField = @{ RecordType = 'OS'; Path = 'OS'; Name = 'OSInfo'; Found = $true }
        try {
            if ($null -ne $hklm) {
                $cv = $hklm.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion', $false)
                if ($null -ne $cv) {
                    $osField['Caption'] = [string]$cv.GetValue('ProductName', '')
                    $osField['Build'] = [string]$cv.GetValue('CurrentBuildNumber', '')
                    $osField['Ubr'] = [string]$cv.GetValue('UBR', '')
                    $cv.Close()
                }
                # ProductType: LanmanNT = domain controller, ServerNT = member/standalone server,
                # WinNT = workstation.
                $po = $hklm.OpenSubKey('SYSTEM\CurrentControlSet\Control\ProductOptions', $false)
                if ($null -ne $po) {
                    $osField['ProductType'] = [string]$po.GetValue('ProductType', '')
                    $po.Close()
                }
                $tcp = $hklm.OpenSubKey('SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', $false)
                if ($null -ne $tcp) {
                    $hostPart = [string]$tcp.GetValue('Hostname', '')
                    $domainPart = [string]$tcp.GetValue('Domain', '')
                    $osField['MachineFqdn'] = if ($domainPart) { '{0}.{1}' -f $hostPart, $domainPart } else { $hostPart }
                    $tcp.Close()
                }
            }
            else {
                $osField['Error'] = 'Could not open HKLM: {0}' -f $baseError
            }
        }
        catch {
            $osField['Error'] = $_.Exception.Message
        }
        try {
            $kdcService = Get-Service -Name 'kdc' -ErrorAction Stop
            $osField['KdcService'] = [string]$kdcService.Status
        }
        catch {
            $osField['KdcService'] = 'Absent'
        }
        & $newRecord $osField

        if ($null -ne $hklm) { $hklm.Close() }
    }

    # --- Discovery and read ---

    function Get-KdcAuditTarget {
        <#
        .SYNOPSIS
            Enumerate every domain controller in the target domain.
        #>
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            # Domain to enumerate; empty means the current domain.
            [Parameter()]
            [AllowEmptyString()]
            [string]$Domain,

            # Alternate credential, or the Empty sentinel for the caller's context.
            [Parameter()]
            [System.Management.Automation.PSCredential]
            [System.Management.Automation.Credential()]
            $Credential = [System.Management.Automation.PSCredential]::Empty
        )

        $haveCredential = $null -ne $Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty
        $found = @()
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
                $found = @(Get-ADDomainController @dcParams | ForEach-Object { $_.HostName })
            }
            else {
                # Fallback without RSAT: the dependency-free .NET DirectoryServices API, building a
                # DirectoryContext that honors any supplied -Domain and/or -Credential.
                Write-Verbose 'ActiveDirectory module absent; discovering via DirectoryServices.'
                $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
                if ($haveCredential) {
                    # DirectoryContext only accepts the password as a string; it is held in this
                    # scope for the duration of the bind and never written anywhere.
                    $network = $Credential.GetNetworkCredential()
                    $context = if ($Domain) {
                        [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new($contextType, $Domain, $Credential.UserName, $network.Password)
                    }
                    else {
                        [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new($contextType, $Credential.UserName, $network.Password)
                    }
                    $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
                }
                elseif ($Domain) {
                    # Named domain, current credentials.
                    $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new($contextType, $Domain)
                    $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
                }
                else {
                    # No domain, no credential: the current domain in the current context.
                    $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                }
                $found = @($targetDomain.DomainControllers | ForEach-Object { $_.Name })
            }
        }
        catch {
            # Discovery fails off-domain, with a bad credential, or when AD is unreachable.
            throw "Could not enumerate domain controllers. Pass -ComputerName, or check -Domain/-Credential. Underlying error: $($_.Exception.Message)"
        }

        return [string[]]@($found | Where-Object { $_ } | Sort-Object -Unique)
    }

    function Read-KdcAuditRecord {
        <#
        .SYNOPSIS
            Run the registry reader against every target and collect records plus failures.
        .DESCRIPTION
            The local machine is read in-process; every other target over WinRM in one
            Invoke-Command fan-out. Returns the flat reader records (each stamped with
            PSComputerName) and a table of the targets that produced nothing, with the reason.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # De-duplicated target names.
            [Parameter(Mandatory)]
            [string[]]$Target,

            # Registry keys to enumerate on each target.
            [Parameter(Mandatory)]
            [string[]]$KeyPath,

            # The reader scriptblock (injectable for tests).
            [Parameter(Mandatory)]
            [scriptblock]$Reader,

            # Extra Invoke-Command parameters (Credential, ThrottleLimit, SessionOption, ...).
            [Parameter()]
            [hashtable]$InvokeParameter = @{}
        )

        # Every name that means "this machine". A DC is very often audited from a session ON that
        # DC, and WinRM to yourself is both pointless and unreliable: Kerberos loopback fails with
        # 0x80090322 (SEC_E_WRONG_PRINCIPAL) unless the loopback check is disabled, and falling
        # back to NTLM needs the host in TrustedHosts. Reading the local registry avoids all of it.
        $localNames = [System.Collections.Generic.List[string]]::new()
        foreach ($alias in 'localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME) {
            if ($alias) { $localNames.Add($alias) }
        }
        if ($env:COMPUTERNAME) {
            try {
                $localNames.Add([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)
            }
            catch {
                # No DNS suffix resolvable: the short name in the list above is still a valid match.
                Write-Verbose 'Could not resolve the local FQDN; matching the local host by short name only.'
            }
        }

        $localTargets = @($Target | Where-Object { $localNames -contains $_ })
        $remoteTargets = @($Target | Where-Object { $localNames -notcontains $_ })

        $records = [System.Collections.Generic.List[object]]::new()
        $failures = @{}

        # Local read: every alias of this machine is the same machine, so read once and file the
        # other aliases as duplicates of the first.
        if ($localTargets.Count -gt 0) {
            $localLabel = $localTargets[0]
            if ($InvokeParameter.ContainsKey('Credential')) {
                Write-Verbose ('{0} is this machine; reading its registry locally, so -Credential is not used for it.' -f $localLabel)
            }
            try {
                foreach ($record in @(& $Reader $KeyPath)) {
                    # Stamp PSComputerName by hand so local and remote records have the same shape.
                    $record | Add-Member -NotePropertyName PSComputerName -NotePropertyValue $localLabel -Force
                    $records.Add($record)
                }
            }
            catch {
                $failures[$localLabel] = $_.Exception.Message
            }
            foreach ($extraAlias in @($localTargets | Select-Object -Skip 1)) {
                $failures[$extraAlias] = 'DUPLICATE:{0}' -f $localLabel
            }
        }

        # Remote read: fan out to every other DC in parallel; failures land in $remoteErrors.
        if ($remoteTargets.Count -gt 0) {
            $remoteErrors = @()
            $invokeParams = @{
                ComputerName  = $remoteTargets
                ScriptBlock   = $Reader
                ArgumentList  = (, $KeyPath)
                ErrorAction   = 'SilentlyContinue'
                ErrorVariable = 'remoteErrors'
            }
            foreach ($parameterName in $InvokeParameter.Keys) {
                $invokeParams[$parameterName] = $InvokeParameter[$parameterName]
            }

            foreach ($record in @(Invoke-Command @invokeParams)) {
                $records.Add($record)
            }

            # Attribute each error to its host. A connection failure carries the computer name as
            # the TargetObject; an error raised inside the remote block carries it in OriginInfo.
            foreach ($remoteError in @($remoteErrors)) {
                $failedHost = ''
                $origin = Get-RecordField -Record $remoteError -Name 'OriginInfo'
                if ($null -ne $origin) { $failedHost = [string](Get-RecordField -Record $origin -Name 'PSComputerName' -Default '') }
                if (-not $failedHost -and $remoteError.TargetObject -is [string]) { $failedHost = [string]$remoteError.TargetObject }
                if (-not $failedHost) { $failedHost = '(unknown host)' }
                Write-Warning ('Could not query {0}: {1}' -f $failedHost, $remoteError.Exception.Message)
                if (-not $failures.ContainsKey($failedHost)) { $failures[$failedHost] = $remoteError.Exception.Message }
            }
        }

        [PSCustomObject]@{
            Records  = $records.ToArray()
            Failures = $failures
        }
    }

    # --- Merge, decode, and classify ---

    function ConvertTo-KdcAuditRow {
        <#
        .SYNOPSIS
            Build one report row with the full, fixed property set.
        .DESCRIPTION
            Every row - registry value, AD attribute, derived "effective" row, unreachable host --
            has the same properties in the same order, so the rows export to CSV/JSON as one table
            and nothing downstream meets a missing property under Set-StrictMode.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # Property values to set; anything omitted keeps its neutral default.
            [Parameter(Mandatory)]
            [hashtable]$Field
        )

        $row = [ordered]@{
            ComputerName   = ''
            OSBuild        = ''
            Rc4Enforcement = ''
            Path           = ''
            Name           = ''
            Setting        = ''
            Type           = ''
            State          = ''
            # Numeric value (unsigned), or $null when there is none. Decimal/Hex are its text forms.
            Value          = $null
            Decimal        = ''
            Hex            = ''
            Bytes          = ''
            BytesDecimal   = ''
            MultiByte      = $false
            ByteAnomaly    = $false
            Meaning        = ''
            Default        = ''
            AutoSet        = ''
            Functional     = ''
            Timing         = ''
            Status         = ''
            Reason         = ''
            Note           = ''
            ScriptVersion  = $script:AuditScriptVersion
            Timestamp      = ''
            Order          = 0
        }
        foreach ($fieldName in $Field.Keys) {
            $row[$fieldName] = $Field[$fieldName]
        }
        [PSCustomObject]$row
    }

    function Resolve-RowVerdict {
        <#
        .SYNOPSIS
            Classify one reading: Status ('' neutral, Secure, Transitional, Insecure, Invalid,
            Error) plus the reason, the decoded meaning and the byte-anomaly flag.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # Static metadata for this value (Kind, Functional).
            [Parameter(Mandatory)]
            $Meta,

            # ConvertTo-AuditReading output.
            [Parameter(Mandatory)]
            $Reading,

            # Which etype-setting variant this value is (DDSET, GPO, msDS).
            [Parameter(Mandatory)]
            [ValidateSet('DDSET', 'GPO', 'msDS')]
            [string]$Variant,

            # 'Normal', or the reason this DC's build does not act on an otherwise functional value:
            # 'IgnoredFilterPath', 'ShadowedFilterPath', 'PhaseNotReadPermanent', 'PhaseNotReadPreAudit'.
            [Parameter()]
            [string]$Applicability = 'Normal',

            # The active SECURITY POLICY object.
            [Parameter(Mandatory)]
            $Policy
        )

        $status = ''
        $reason = ''
        $meaning = '(not set)'
        $byteAnomaly = $false

        if ($Reading.Error) {
            # A value that could not be read is NOT "not set": say so and let it block a clean pass.
            return [PSCustomObject]@{
                Status = 'Error'; Reason = 'The value could not be read, so nothing can be said about it.'
                Meaning = '(read error) {0}' -f $Reading.Error; ByteAnomaly = $false
            }
        }
        if (-not $Reading.Found) {
            return [PSCustomObject]@{ Status = ''; Reason = ''; Meaning = $meaning; ByteAnomaly = $false }
        }

        if (-not $Reading.IsNumeric -or $Reading.WrongType) {
            # Wrong-type data: say what it is and show the bytes rather than guess at a meaning.
            $kindLabel = if ($Reading.Kind) { $Reading.Kind } else { 'unknown type' }
            return [PSCustomObject]@{
                Status      = 'Invalid'
                Reason      = 'Not a REG_DWORD: the KDC cannot read it as a number.'
                Meaning     = '(not a REG_DWORD: stored as {0}) raw bytes {1}' -f $kindLabel, (Format-ByteList -Byte $Reading.Bytes)
                ByteAnomaly = $true
            }
        }

        $number = [long]$Reading.Numeric
        $meaning = Resolve-SettingMeaning -Kind $Meta.Kind -Value $number -Found $true -Variant $Variant
        $wide = @($Reading.Bytes).Count -gt 1

        # A multi-byte value is only an anomaly when it is also not a value any setting defines:
        # 0x7FFFFFF8 is four bytes and exactly what the GPO writes, 0x0110 is two and a typo.
        if ($Meta.Kind -eq 'EtypeMask') {
            $decode = ConvertTo-KerberosEtypeDecode -Mask $number -Variant $Variant
            $byteAnomaly = $wide -and $decode.UndefinedMask -ne 0
        }
        elseif ($Meta.Kind -ne 'Raw') {
            $byteAnomaly = $wide
        }
        if ($byteAnomaly) {
            $meaning = '{0} [bytes: {1}]' -f $meaning, (Format-ByteList -Byte $Reading.Bytes)
        }

        # A value SET at a location nothing reads is invalid: it looks effective but is ignored.
        if ($Meta.Functional -like 'No (*') {
            $reason = if ($Meta.Functional -eq 'No (wrong path)') { 'Set at a location the KDC does not read.' } else { 'Not a value name the KDC reads.' }
            return [PSCustomObject]@{ Status = 'Invalid'; Reason = $reason; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
        }

        # Keys that never affect KDC behaviour (diagnostic, client-side) stay neutral.
        if ($Meta.Functional -ne 'Yes' -and $Meta.Functional -ne 'AD attribute') {
            return [PSCustomObject]@{ Status = ''; Reason = ''; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
        }

        # A functional value that THIS DC's build does not act on.
        switch ($Applicability) {
            'IgnoredFilterPath' {
                return [PSCustomObject]@{ Status = ''; Reason = 'Not read by the KDC on this build in lab testing (see the effective filter row). It still drives the DC computer account msDS-SET and the Kerberos client on the DC.'; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
            }
            'ShadowedFilterPath' {
                return [PSCustomObject]@{ Status = ''; Reason = 'Shadowed: the Policies path is set and takes precedence on this OS.'; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
            }
            'PhaseNotReadPermanent' {
                if ($number -lt $Policy.MinSecureRc4Phase) {
                    return [PSCustomObject]@{ Status = 'Invalid'; Reason = 'Leftover rollback value. KB5073381 says updates from July 2026 no longer read it (not lab-verified): delete it and confirm with a live msDS-SET=0 ticket.'; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
                }
                return [PSCustomObject]@{ Status = ''; Reason = 'Redundant on this build: KB5073381 says updates from July 2026 no longer read it.'; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
            }
            'PhaseNotReadPreAudit' {
                if ($number -ge $Policy.MinSecureRc4Phase -and $number -le 2) {
                    return [PSCustomObject]@{ Status = 'Invalid'; Reason = 'This build predates the January 2026 update and does not read the value: it enforces nothing here.'; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
                }
                return [PSCustomObject]@{ Status = ''; Reason = 'Not read on this build (pre-January 2026 update).'; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
            }
        }

        switch ($Meta.Kind) {
            'EtypeMask' {
                # msDS-SET = 0 is the same as unset: the account uses the domain fallback.
                if ($Variant -eq 'msDS' -and $number -eq 0) {
                    $meaning = '0 (falls back to the domain default)'
                    break
                }
                $tier = Resolve-EtypeMaskTier -Mask $number -Variant $Variant -Policy $Policy
                $status = $tier.Status
                $reason = $tier.Reason
                if ($status -eq 'Transitional') {
                    $reason = switch ($Variant) {
                        'msDS' { 'RC4 is listed alongside AES on the DC computer account. Tickets to it are still AES256, but RC4 stays available as a session key and to KdcUseRequestedEtypesForTickets.' }
                        'DDSET' { 'Transitional value: accounts with no msDS-SupportedEncryptionTypes may still use RC4 alongside AES. Move to 0x18 once nothing depends on RC4.' }
                        default { 'The KDC filter still permits RC4 alongside AES.' }
                    }
                }
            }
            'Bool' {
                # Only 0 and 1 are defined; anything else is a typo, not a policy decision.
                if ($number -eq 1) {
                    $status = 'Insecure'
                    $reason = 'Clients can force RC4 tickets for any account that still lists RC4.'
                }
                elseif ($number -eq 0) {
                    $status = 'Secure'
                }
                else {
                    $status = 'Invalid'
                    $reason = 'Not a defined value (0 or 1).'
                }
            }
            'Phase' {
                # Enforce (>= policy minimum) is secure; off/audit still allow RC4. Only 0-2 exist.
                if ($number -lt 0 -or $number -gt 2) {
                    $status = 'Invalid'
                    $reason = 'Not a defined phase (0, 1 or 2).'
                }
                elseif ($number -ge $Policy.MinSecureRc4Phase) {
                    $status = 'Secure'
                }
                else {
                    $status = 'Insecure'
                    $reason = 'RC4 remains the default for accounts with no msDS-SupportedEncryptionTypes (takes effect after a KDC restart).'
                }
            }
        }

        [PSCustomObject]@{ Status = $status; Reason = $reason; Meaning = $meaning; ByteAnomaly = $byteAnomaly }
    }

    function ConvertTo-KdcAuditResult {
        <#
        .SYNOPSIS
            Turn raw reader records into the classified audit result. Pure: no I/O, no discovery.
        .DESCRIPTION
            The testable core of the script. Given the flat records the registry reader returned
            (each stamped with PSComputerName), the list of requested targets and the table of
            read failures, it produces every report row, the per-DC effective state, the coverage
            accounting and the pass/fail facts. The text report, the HTML report, -PassThru and
            the exit code are all rendered from this one object.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # Reader records from every target that answered.
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [AllowNull()]
            [object[]]$Record,

            # The requested target names, de-duplicated by name.
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [string[]]$Target,

            # Target name -> failure message. A message of 'DUPLICATE:<name>' marks an alias.
            [Parameter()]
            [hashtable]$Failure = @{},

            # The active SECURITY POLICY object.
            [Parameter(Mandatory)]
            $Policy,

            # The registry matrix (defaults to the script's own).
            [Parameter()]
            [object[]]$Matrix = $script:RegistryMatrix,

            # Report timestamp (UTC); injectable so tests are deterministic.
            [Parameter()]
            [datetime]$Timestamp = [datetime]::UtcNow
        )

        $stamp = $Timestamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

        # Group records by the host that produced them (hashtable keys are case-insensitive).
        $byHost = @{}
        $hostOrder = [System.Collections.Generic.List[string]]::new()
        foreach ($item in @($Record | Where-Object { $null -ne $_ })) {
            $hostName = [string](Get-RecordField -Record $item -Name 'PSComputerName' -Default '')
            if (-not $hostName) { continue }
            if (-not $byHost.ContainsKey($hostName)) {
                $byHost[$hostName] = [System.Collections.Generic.List[object]]::new()
                $hostOrder.Add($hostName)
            }
            $byHost[$hostName].Add($item)
        }

        # Two requested names can be the same machine (short name and FQDN, a CNAME). Each machine
        # reports its own FQDN, so keep the first host seen per machine and file the rest as
        # duplicates: counting by name would otherwise audit one DC twice and call it two.
        $duplicates = [System.Collections.Generic.List[object]]::new()
        $seenMachine = @{}
        $auditedHosts = [System.Collections.Generic.List[string]]::new()
        foreach ($hostName in $hostOrder) {
            $osRecord = $byHost[$hostName] | Where-Object { (Get-RecordField -Record $_ -Name 'Name') -eq 'OSInfo' } | Select-Object -First 1
            $machine = [string](Get-RecordField -Record $osRecord -Name 'MachineFqdn' -Default '')
            if ($machine -and $seenMachine.ContainsKey($machine)) {
                $duplicates.Add([PSCustomObject]@{ Name = $hostName; Of = $seenMachine[$machine] })
                continue
            }
            if ($machine) { $seenMachine[$machine] = $hostName }
            $auditedHosts.Add($hostName)
        }
        foreach ($failedName in @($Failure.Keys)) {
            $message = [string]$Failure[$failedName]
            if ($message -like 'DUPLICATE:*') {
                $duplicates.Add([PSCustomObject]@{ Name = [string]$failedName; Of = $message.Substring(10) })
            }
        }
        $duplicateNames = @($duplicates | ForEach-Object { $_.Name })

        # Index the static matrix by "path|value" (lower case: registry names are case-insensitive).
        $lookup = @{}
        foreach ($entry in $Matrix) {
            $lookup[('{0}|{1}' -f $entry.Path, $entry.Name).ToLowerInvariant()] = $entry
        }
        # Decode kind and variant for a known value name found at an unlisted location.
        $kindByName = @{
            'DefaultDomainSupportedEncTypes'  = @('EtypeMask', 'DDSET')
            'SupportedEncryptionTypes'        = @('EtypeMask', 'GPO')
            'KdcUseRequestedEtypesForTickets' = @('Bool', 'DDSET')
            'RC4DefaultDisablementPhase'      = @('Phase', 'DDSET')
            'DefaultEncryptionType'           = @('Etype', 'DDSET')
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        $dcStates = [System.Collections.Generic.List[object]]::new()
        $notDc = [System.Collections.Generic.List[string]]::new()

        foreach ($hostName in $auditedHosts) {
            $hostRecords = $byHost[$hostName]

            # Split this host's records by type. Records without a RecordType (older fixtures)
            # are treated as values, with the AD and OS records recognized by name.
            $osRecord = $null
            $adRecord = $null
            $keyState = @{}
            $valueByKey = @{}
            $valueList = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $hostRecords) {
                $recordName = [string](Get-RecordField -Record $item -Name 'Name' -Default '')
                $recordType = [string](Get-RecordField -Record $item -Name 'RecordType' -Default '')
                $recordPath = [string](Get-RecordField -Record $item -Name 'Path' -Default '')
                if ($recordType -eq 'OS' -or $recordName -eq 'OSInfo') { $osRecord = $item; continue }
                if ($recordType -eq 'AD' -or $recordPath -eq 'AD') { $adRecord = $item; continue }
                if ($recordType -eq 'Key') { $keyState[$recordPath.ToLowerInvariant()] = $item; continue }
                # A value record. An old-style "probed and absent" record (Found = $false with no
                # error) is the same as no record at all.
                $recordFound = [bool](Get-RecordField -Record $item -Name 'Found' -Default $false)
                $recordError = [string](Get-RecordField -Record $item -Name 'Error' -Default '')
                if (-not $recordFound -and -not $recordError) { continue }
                $valueByKey[('{0}|{1}' -f $recordPath, $recordName).ToLowerInvariant()] = $item
                $valueList.Add($item)
            }

            $build = [string](Get-RecordField -Record $osRecord -Name 'Build' -Default '')
            $ubr = [string](Get-RecordField -Record $osRecord -Name 'Ubr' -Default '')
            $caption = [string](Get-RecordField -Record $osRecord -Name 'Caption' -Default '')
            $productType = [string](Get-RecordField -Record $osRecord -Name 'ProductType' -Default '')
            $kdcService = [string](Get-RecordField -Record $osRecord -Name 'KdcService' -Default '')
            $osError = [string](Get-RecordField -Record $osRecord -Name 'Error' -Default '')
            $osBuild = if ($build -or $ubr) { '{0}.{1}' -f $build, $ubr } else { '' }
            $buildInfo = Resolve-BuildClass -Build $build -Ubr $ubr -BuildMap $Policy.Rc4EnforcementBuilds

            # Role. ProductType LanmanNT is a domain controller; anything else is not one, and
            # KDC settings on it mean nothing - report the host once and skip its values so a
            # member server can never be reported as a clean DC.
            $uac = Get-RecordField -Record $adRecord -Name 'Uac' -Default $null
            $isRodc = $null -ne $uac -and (([long]$uac -band 0x04000000L) -ne 0)
            $isDc = $productType -eq 'LanmanNT'
            if ($productType -and -not $isDc) {
                $notDc.Add($hostName)
                $rows.Add((ConvertTo-KdcAuditRow -Field @{
                            ComputerName = $hostName; OSBuild = $osBuild; Path = '(host)'; Name = 'Role'
                            Setting = 'Host role'; State = 'n/a'; Functional = 'n/a'; Timing = 'n/a'
                            Meaning = 'NOT a domain controller (ProductType={0}, kdc service {1})' -f $productType, $(if ($kdcService) { $kdcService } else { 'not reported' })
                            Status = 'NotDC'; Reason = 'KDC settings are only meaningful on a domain controller; this host was not audited.'
                            Timestamp = $stamp; Order = -3
                        }))
                continue
            }

            # The readings the effective state is derived from.
            $readingFor = {
                param([string]$Path, [string]$Name)
                $keyRecord = $keyState[$Path.ToLowerInvariant()]
                $keyError = [string](Get-RecordField -Record $keyRecord -Name 'Error' -Default '')
                ConvertTo-AuditReading -Record $valueByKey[('{0}|{1}' -f $Path, $Name).ToLowerInvariant()] -KeyError $keyError
            }
            $ddsetReading = & $readingFor $script:KeyKdc 'DefaultDomainSupportedEncTypes'
            $phaseReading = & $readingFor $script:KeyPolicies 'RC4DefaultDisablementPhase'
            $policyFilterReading = & $readingFor $script:KeyPolicies 'SupportedEncryptionTypes'
            $lsaFilterReading = & $readingFor $script:KeyLsa 'SupportedEncryptionTypes'

            $state = Resolve-KdcEffectiveState -BuildInfo $buildInfo -Ddset $ddsetReading -Phase $phaseReading -PolicyFilter $policyFilterReading -LsaFilter $lsaFilterReading -Policy $Policy

            $common = @{ ComputerName = $hostName; OSBuild = $osBuild; Rc4Enforcement = $state.Enforcement; Timestamp = $stamp }
            $newRow = {
                param([hashtable]$Field)
                $merged = @{}
                foreach ($name in $common.Keys) { $merged[$name] = $common[$name] }
                foreach ($name in $Field.Keys) { $merged[$name] = $Field[$name] }
                ConvertTo-KdcAuditRow -Field $merged
            }

            # Role row (informational for a DC; an Error when the role could not be read).
            $roleMeaning = if ($isDc) {
                'Domain controller{0}; kdc service {1}' -f $(if ($isRodc) { ' (read-only)' } else { '' }), $(if ($kdcService) { $kdcService } else { 'not reported' })
            }
            else {
                'Role could not be read{0}' -f $(if ($osError) { ': {0}' -f $osError } else { '' })
            }
            $rows.Add((& $newRow @{
                        Path = '(host)'; Name = 'Role'; Setting = 'Host role'; State = 'n/a'; Functional = 'n/a'; Timing = 'n/a'
                        Meaning = $roleMeaning
                        Status  = if ($isDc) { '' } else { 'Error' }
                        Reason  = if ($isDc) { '' } else { 'ProductOptions\ProductType was not readable, so this host is not confirmed to be a domain controller.' }
                        Order   = -3
                    }))

            # Effective fallback row. It carries a Status only when no registry row already does,
            # so one problem is one finding.
            $fallbackMeaning = if ($null -ne $state.FallbackMask) {
                '{0} = {1} [{2}]' -f (Format-HexValue -Value $state.FallbackMask), (ConvertTo-KerberosEtypeName -Mask $state.FallbackMask -Variant 'DDSET'), $state.FallbackSource
            }
            else {
                'cannot be determined [{0}]' -f $state.FallbackSource
            }
            $fallbackRowStatus = if ($state.FallbackOwnedByRow) { '' } else { $state.FallbackStatus }
            $rows.Add((& $newRow @{
                        Path = '(effective)'; Name = 'UnsetAccountEtypes'; Setting = 'Effective etypes for accounts with no msDS-SupportedEncryptionTypes'
                        State = 'Derived'; Functional = 'Derived'; Timing = 'n/a'
                        Value   = $state.FallbackMask
                        Decimal = if ($null -ne $state.FallbackMask) { [string]$state.FallbackMask } else { '' }
                        Hex     = if ($null -ne $state.FallbackMask) { Format-HexValue -Value $state.FallbackMask } else { '' }
                        Meaning = $fallbackMeaning
                        Status  = $fallbackRowStatus
                        Reason  = if ($state.FallbackOwnedByRow -and $state.FallbackReason) { '{0} (Counted on the registry row that causes it.)' -f $state.FallbackReason } else { $state.FallbackReason }
                        Note    = 'Derived from the OS build, RC4DefaultDisablementPhase and DefaultDomainSupportedEncTypes. {0}' -f $state.Enforcement
                        Order   = -2
                    }))

            # Effective filter row.
            $rows.Add((& $newRow @{
                        Path = '(effective)'; Name = 'KdcEtypeFilter'; Setting = 'Effective KDC etype filter'
                        State = 'Derived'; Functional = 'Derived'; Timing = 'KDC restart'
                        Value   = $state.FilterMask
                        Decimal = if ($null -ne $state.FilterMask) { [string]$state.FilterMask } else { '' }
                        Hex     = if ($null -ne $state.FilterMask) { Format-HexValue -Value $state.FilterMask } else { '' }
                        Meaning = $state.FilterText
                        Status  = $state.FilterStatus
                        Reason  = $state.FilterReason
                        Note    = 'Filter path model for this OS: {0}. A changed filter value only takes effect after a KDC restart; the registry cannot show whether that has happened.' -f $state.FilterModel
                        Order   = -1
                    }))

            # msDS-SupportedEncryptionTypes of the DC computer account.
            $adReading = ConvertTo-AuditReading -Record $adRecord
            $adVerdict = Resolve-RowVerdict -Meta $script:MsdsMeta -Reading $adReading -Variant 'msDS' -Policy $Policy
            $rows.Add((& $newRow @{
                        Path = $script:MsdsMeta.Path; Name = $script:MsdsMeta.Name; Setting = $script:MsdsMeta.Setting
                        Type    = if ($adReading.Found) { $adReading.Kind } else { '' }
                        State   = if ($adReading.Error) { 'Error' } elseif ($adReading.Found) { 'Set' } else { 'Not set' }
                        Value   = $adReading.DisplayNumeric
                        Decimal = if ($adReading.IsNumeric) { [string][uint64]$adReading.DisplayNumeric } else { '' }
                        Hex     = if ($adReading.IsNumeric) { Format-HexValue -Value $adReading.DisplayNumeric } else { '' }
                        Meaning = $adVerdict.Meaning; Default = $script:MsdsMeta.Default; AutoSet = $script:MsdsMeta.AutoSet
                        Functional = $script:MsdsMeta.Functional; Timing = $script:MsdsMeta.Timing
                        Status = $adVerdict.Status; Reason = $adVerdict.Reason; Note = $script:MsdsMeta.Note; Order = $script:MsdsMeta.Order
                    }))

            # One row per matrix entry.
            foreach ($meta in $Matrix) {
                $reading = & $readingFor $meta.Path $meta.Name
                # The three etype settings decode their high bits differently.
                $variant = switch ($meta.Name) {
                    'SupportedEncryptionTypes' { 'GPO' }
                    'msDS-SupportedEncryptionTypes' { 'msDS' }
                    default { 'DDSET' }
                }

                # Refine the OS-independent "Yes" for what THIS DC's build does.
                $functional = [string]$meta.Functional
                $applicability = 'Normal'
                if ($meta.Functional -eq 'Yes' -and $meta.Name -eq 'SupportedEncryptionTypes') {
                    $isPoliciesPath = $meta.Path -eq $script:KeyPolicies
                    switch ($state.FilterMode) {
                        'LsaOnly' {
                            if ($isPoliciesPath) {
                                $functional = 'Ignored on this build (lab: 26100.32522)'
                                $applicability = 'IgnoredFilterPath'
                            }
                        }
                        'Uncertain' {
                            # Neither model is asserted: classify the value normally and let the
                            # effective filter row say what cannot be established.
                            $functional = if ($isPoliciesPath) {
                                'Uncertain (lab saw it ignored on 26100.32522; April 2026 release note says fixed; not retested)'
                            }
                            elseif ($policyFilterReading.Found) {
                                'Yes, unless Policies now takes precedence (not retested)'
                            }
                            else {
                                'Yes'
                            }
                        }
                        default {
                            if (-not $isPoliciesPath -and $policyFilterReading.Found) {
                                $functional = 'Shadowed by Policies'
                                $applicability = 'ShadowedFilterPath'
                            }
                            elseif ($buildInfo.Major -ne 20348) {
                                $functional = 'Yes (assumed; not lab-tested on this OS)'
                            }
                        }
                    }
                }
                elseif ($meta.Functional -eq 'Yes' -and $meta.Name -eq 'RC4DefaultDisablementPhase') {
                    switch ($state.BuildClass) {
                        'Permanent' { $functional = 'Not read on this build (KB5073381; not lab-verified)'; $applicability = 'PhaseNotReadPermanent' }
                        'PreAudit' { $functional = 'Not read on this build (pre-January 2026 update)'; $applicability = 'PhaseNotReadPreAudit' }
                        'Unknown' { $functional = 'Depends on the build (unknown)' }
                        'Indeterminate' { $functional = 'Depends on the build (indeterminate)' }
                    }
                }

                $verdict = Resolve-RowVerdict -Meta $meta -Reading $reading -Variant $variant -Applicability $applicability -Policy $Policy
                $wide = $reading.Found -and (@($reading.Bytes).Count -gt 1 -or -not $reading.IsNumeric)
                $rows.Add((& $newRow @{
                            Path = $meta.Path; Name = $meta.Name; Setting = $meta.Setting
                            Type         = if ($reading.Found) { $reading.Kind } else { '' }
                            State        = if ($reading.Error) { 'Error' } elseif ($reading.Found) { 'Set' } else { 'Not set' }
                            Value        = $reading.DisplayNumeric
                            # Decimal is the unsigned view of everything stored: a DWORD of 0xFFFFFFFF
                            # reads 4294967295 (never -1), and a REG_QWORD keeps its full width.
                            Decimal      = if (-not $reading.Found) { '' } elseif ($reading.IsNumeric) { [string][uint64]$reading.DisplayNumeric } else { 'n/a' }
                            # Hex is always 0x-prefixed with whole bytes.
                            Hex          = if (-not $reading.Found) { '' } elseif ($reading.IsNumeric) { Format-HexValue -Value $reading.DisplayNumeric } else { 'n/a' }
                            # Raw bytes whenever the value is wider than one byte or not a number.
                            Bytes        = if ($wide) { Format-ByteList -Byte $reading.Bytes } else { '' }
                            BytesDecimal = if ($wide) { Format-ByteList -Byte $reading.Bytes -AsDecimal } else { '' }
                            MultiByte = [bool]$wide; ByteAnomaly = [bool]$verdict.ByteAnomaly
                            Meaning = $verdict.Meaning; Default = $meta.Default; AutoSet = $meta.AutoSet
                            Functional = $functional; Timing = $meta.Timing
                            Status = $verdict.Status; Reason = $verdict.Reason; Note = $meta.Note; Order = $meta.Order
                        }))
            }

            # Values that exist under an audited key but are not in the matrix: a known name at a
            # location nothing reads (DDSET under Services\Kdc\Parameters), or a near miss of a
            # known name. Exact-name probing would never see either.
            $extraOrder = 50
            foreach ($item in $valueList) {
                $valuePath = [string](Get-RecordField -Record $item -Name 'Path' -Default '')
                $valueName = [string](Get-RecordField -Record $item -Name 'Name' -Default '')
                if ($lookup.ContainsKey(('{0}|{1}' -f $valuePath, $valueName).ToLowerInvariant())) { continue }

                $knownName = @($script:KnownValueHomes.Keys | Where-Object { $_ -eq $valueName }) | Select-Object -First 1
                $nearest = ''
                $nearestDistance = 99
                if (-not $knownName) {
                    foreach ($candidate in $script:KnownValueHomes.Keys) {
                        $distance = Get-EditDistance -Left $valueName -Right $candidate
                        if ($distance -lt $nearestDistance) { $nearestDistance = $distance; $nearest = $candidate }
                    }
                    # Neither a near miss nor etype-looking: an unrelated value (ImagePath,
                    # MaxTokenSize, ...) that is none of this audit's business.
                    if ($nearestDistance -gt 3 -and $valueName -notmatch $script:EtypeLookingName) { continue }
                }

                $shortPath = $valuePath -replace '^HKLM:\\(SYSTEM\\CurrentControlSet\\|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\)', ''
                if ($knownName) {
                    $kindPair = $kindByName[[string]$knownName]
                    $extraMeta = [PSCustomObject]@{ Kind = $kindPair[0]; Functional = 'No (wrong path)' }
                    $extraVariant = $kindPair[1]
                    $extraNote = if ($valuePath -eq $script:KeyKdcParameters -and $knownName -eq 'DefaultDomainSupportedEncTypes') {
                        'DefaultDomainSupportedEncTypes under Services\Kdc\Parameters is silently ignored by the KDC. It belongs one level up, directly under Services\Kdc.'
                    }
                    else {
                        '{0} is not read at {1}. It belongs under {2}.' -f $knownName, $shortPath, $script:KnownValueHomes[[string]$knownName]
                    }
                }
                else {
                    $extraMeta = [PSCustomObject]@{ Kind = 'Raw'; Functional = 'No (unrecognized name)' }
                    $extraVariant = 'DDSET'
                    $extraNote = if ($nearestDistance -le 3) {
                        'Not a value name the KDC reads. It looks like a misspelling of {0}, which belongs under {1}.' -f $nearest, $script:KnownValueHomes[$nearest]
                    }
                    else {
                        'Not a value name the KDC reads. Closest known name: {0} (under {1}).' -f $nearest, $script:KnownValueHomes[$nearest]
                    }
                }

                $reading = ConvertTo-AuditReading -Record $item
                $verdict = Resolve-RowVerdict -Meta $extraMeta -Reading $reading -Variant $extraVariant -Policy $Policy
                $wide = $reading.Found -and (@($reading.Bytes).Count -gt 1 -or -not $reading.IsNumeric)
                $rows.Add((& $newRow @{
                            Path = $valuePath; Name = $valueName; Setting = '{0} ({1})' -f $valueName, $shortPath
                            Type         = $reading.Kind
                            State        = if ($reading.Error) { 'Error' } else { 'Set' }
                            Value        = $reading.DisplayNumeric
                            Decimal      = if ($reading.IsNumeric) { [string][uint64]$reading.DisplayNumeric } else { 'n/a' }
                            Hex          = if ($reading.IsNumeric) { Format-HexValue -Value $reading.DisplayNumeric } else { 'n/a' }
                            Bytes        = if ($wide) { Format-ByteList -Byte $reading.Bytes } else { '' }
                            BytesDecimal = if ($wide) { Format-ByteList -Byte $reading.Bytes -AsDecimal } else { '' }
                            MultiByte = [bool]$wide; ByteAnomaly = [bool]$verdict.ByteAnomaly
                            Meaning = $verdict.Meaning; Default = 'n/a'; AutoSet = 'n/a'
                            Functional = $extraMeta.Functional; Timing = 'n/a'
                            Status = $verdict.Status; Reason = $verdict.Reason; Note = $extraNote; Order = $extraOrder
                        }))
                $extraOrder++
            }

            # A host that answered but also raised an error mid-read: keep what it returned and say so.
            if ($Failure.ContainsKey($hostName) -and [string]$Failure[$hostName] -notlike 'DUPLICATE:*') {
                $rows.Add((& $newRow @{
                            Path = '(host)'; Name = 'RemoteError'; Setting = 'Remote read error'; State = 'Error'; Functional = 'n/a'; Timing = 'n/a'
                            Meaning = [string]$Failure[$hostName]; Status = 'Error'
                            Reason = 'The remote read reported an error; the rows for this DC may be incomplete.'; Order = -4
                        }))
            }

            $dcStates.Add([PSCustomObject]@{
                    ComputerName    = $hostName
                    OS              = $caption
                    OSBuild         = $osBuild
                    IsReadOnly      = [bool]$isRodc
                    BuildClass      = $state.BuildClass
                    BuildEvidence   = $state.BuildEvidence
                    Enforcement     = $state.Enforcement
                    EnforcementCode = $state.EnforcementCode
                    FallbackMask    = $state.FallbackMask
                    FallbackHex     = if ($null -ne $state.FallbackMask) { Format-HexValue -Value $state.FallbackMask } else { 'unknown' }
                    FallbackStatus  = $state.FallbackStatus
                    FallbackSource  = $state.FallbackSource
                    FilterPath      = $state.FilterPath
                    FilterMask      = $state.FilterMask
                    FilterStatus    = $state.FilterStatus
                    FilterText      = $state.FilterText
                    FilterModel     = $state.FilterModel
                })
        }

        # Requested targets that produced nothing: one Unreachable row each, by name.
        $unreachable = [System.Collections.Generic.List[object]]::new()
        foreach ($name in @($Target)) {
            if ($byHost.ContainsKey($name)) { continue }
            if ($duplicateNames -contains $name) { continue }
            $message = if ($Failure.ContainsKey($name)) { [string]$Failure[$name] } else { 'No data was returned.' }
            $unreachable.Add([PSCustomObject]@{ Name = $name; Message = $message })
            $rows.Add((ConvertTo-KdcAuditRow -Field @{
                        ComputerName = $name; Path = '(host)'; Name = 'Reachability'; Setting = 'Host reachability'
                        State = 'Unreachable'; Functional = 'n/a'; Timing = 'n/a'; Meaning = $message
                        Status = 'Unreachable'; Reason = 'The host could not be queried, so it was not audited.'
                        Timestamp = $stamp; Order = -3
                    }))
        }
        # A failure that could not be tied to a requested name still must not vanish.
        foreach ($failedName in @($Failure.Keys)) {
            $message = [string]$Failure[$failedName]
            if ($message -like 'DUPLICATE:*') { continue }
            if ($byHost.ContainsKey($failedName)) { continue }
            if (@($Target) -contains $failedName) { continue }
            $unreachable.Add([PSCustomObject]@{ Name = [string]$failedName; Message = $message })
            $rows.Add((ConvertTo-KdcAuditRow -Field @{
                        ComputerName = [string]$failedName; Path = '(host)'; Name = 'Reachability'; Setting = 'Host reachability'
                        State = 'Unreachable'; Functional = 'n/a'; Timing = 'n/a'; Meaning = $message
                        Status = 'Unreachable'; Reason = 'The host could not be queried, so it was not audited.'
                        Timestamp = $stamp; Order = -3
                    }))
        }

        # Sort by DC, then by the curated order (derived rows, functional keys, wrong-path keys).
        $sorted = @($rows | Sort-Object -Property ComputerName, Order, Setting)

        $counts = [ordered]@{}
        foreach ($statusName in @('Secure', 'Transitional', 'Insecure', 'Invalid', 'Unknown', 'Error', 'Unreachable', 'NotDC')) {
            $counts[$statusName] = @($sorted | Where-Object { $_.Status -eq $statusName }).Count
        }
        $findings = @($sorted | Where-Object { $script:SecurityStatuses -contains $_.Status -or $script:CoverageStatuses -contains $_.Status })
        $auditedDcs = @($dcStates | ForEach-Object { $_.ComputerName } | Sort-Object)

        [PSCustomObject]@{
            ScriptVersion = $script:AuditScriptVersion
            Timestamp     = $stamp
            Rows          = $sorted
            DcStates      = @($dcStates | Sort-Object -Property ComputerName)
            Requested     = @($Target)
            AuditedDcs    = $auditedDcs
            Unreachable   = $unreachable.ToArray()
            Duplicates    = $duplicates.ToArray()
            NotDcs        = $notDc.ToArray()
            Counts        = $counts
            Findings      = $findings
            # A clean pass needs at least one audited DC, nothing unreachable or unreadable, and
            # no row in any finding status - including the derived "effective" rows, so a DC that
            # still defaults to RC4 with an empty registry is not clean.
            CleanPass     = (@($auditedDcs).Count -gt 0 -and @($findings).Count -eq 0)
        }
    }

    function Get-KdcAuditExitCode {
        <#
        .SYNOPSIS
            Map an audit result and a -FailOn list to the documented exit code.
        .DESCRIPTION
            0 = none of the listed classes present; 1 = a listed security class is present
            (Insecure, Invalid, Transitional, Unknown); 2 = a listed coverage class is present
            (Error, Unreachable, NotDC) or no domain controller was audited; 3 = both.
        #>
        [CmdletBinding()]
        [OutputType([int])]
        param(
            # ConvertTo-KdcAuditResult output.
            [Parameter(Mandatory)]
            $Result,

            # Status classes that fail the run; 'Any' selects all of them.
            [Parameter()]
            [AllowEmptyCollection()]
            [string[]]$FailOn = @()
        )

        $selected = @($FailOn)
        if ($selected -contains 'Any') {
            $selected = @($script:SecurityStatuses) + @($script:CoverageStatuses)
        }

        $code = 0
        foreach ($statusName in $selected) {
            if ([int]$Result.Counts[$statusName] -le 0) { continue }
            if ($script:SecurityStatuses -contains $statusName) { $code = $code -bor 1 }
            if ($script:CoverageStatuses -contains $statusName) { $code = $code -bor 2 }
        }
        # Nothing audited is never a pass once the caller has asked for an exit code at all.
        if (@($selected).Count -gt 0 -and @($Result.AuditedDcs).Count -eq 0) { $code = $code -bor 2 }
        return [int]$code
    }

    # --- Output ---

    # The public columns, in order, for -PassThru, Out-GridView and the HTML table. Value is the
    # numeric form (unsigned) so CSV and JSON consumers do not have to parse the text columns.
    $script:PublicColumns = @('ComputerName', 'OSBuild', 'Rc4Enforcement', 'Path', 'Name', 'Setting', 'Type', 'State',
        'Value', 'Decimal', 'Hex', 'Bytes', 'BytesDecimal', 'MultiByte', 'ByteAnomaly', 'Meaning', 'Default', 'AutoSet',
        'Functional', 'Timing', 'Status', 'Reason', 'Note', 'ScriptVersion', 'Timestamp')

    function Get-KdcAuditVerdictLine {
        <#
        .SYNOPSIS
            The one-line overall verdict (text plus color code), shared by the text and HTML reports.
        #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.PSCustomObject])]
        param(
            # ConvertTo-KdcAuditResult output.
            [Parameter(Mandatory)]
            $Result
        )

        $counts = $Result.Counts
        $coverage = [int]$counts['Error'] + [int]$counts['Unreachable'] + [int]$counts['NotDC']
        $hard = [int]$counts['Insecure'] + [int]$counts['Invalid'] + [int]$counts['Unknown']
        $transitional = [int]$counts['Transitional']
        $audited = @($Result.AuditedDcs).Count

        if ($audited -eq 0) {
            return [PSCustomObject]@{ Text = 'INCOMPLETE: no domain controllers could be audited; this is not a pass.'; Code = '1;31'; Class = 'Invalid' }
        }
        if ($Result.CleanPass) {
            return [PSCustomObject]@{ Text = ('PASS: no findings on the {0} DC(s) audited. Every one defaults to AES for unset accounts.' -f $audited); Code = '1;32'; Class = 'Secure' }
        }
        $parts = @()
        if ($hard -gt 0) { $parts += '{0} insecure/invalid/unknown' -f $hard }
        if ($transitional -gt 0) { $parts += '{0} transitional (RC4 still permitted alongside AES)' -f $transitional }
        if ($coverage -gt 0) { $parts += '{0} coverage problem(s) (unreachable, unreadable or not a DC)' -f $coverage }
        $text = 'FINDINGS: {0}.' -f ($parts -join '; ')
        if ($coverage -gt 0) { $text = '{0} Coverage is INCOMPLETE, so this is not a pass even where no value was flagged.' -f $text }
        if ($hard -gt 0 -or $coverage -gt 0) {
            return [PSCustomObject]@{ Text = $text; Code = '1;31'; Class = 'Invalid' }
        }
        return [PSCustomObject]@{ Text = $text; Code = '36'; Class = 'Transitional' }
    }

    function Write-KdcAuditReport {
        <#
        .SYNOPSIS
            Render the audit result as the text report: key reference, per-DC sections, summary.
        #>
        [CmdletBinding()]
        [OutputType([string])]
        param(
            # ConvertTo-KdcAuditResult output.
            [Parameter(Mandatory)]
            $Result,

            # The registry matrix, for the key reference.
            [Parameter()]
            [object[]]$Matrix = $script:RegistryMatrix
        )

        $rows = @($Result.Rows)
        $title = { param([string]$Text) ConvertTo-ColorText -Text ('================ {0} ================' -f $Text) -Code '1;36' }

        Write-Output (ConvertTo-ColorText -Text ('KDC Kerberos Registry Audit v{0} - generated {1}' -f $Result.ScriptVersion, $Result.Timestamp) -Code '1;36')
        Write-Output ''

        # Key reference (printed once): each value's default, whether it is set automatically,
        # whether the KDC honors it, and what it does. Wrong-path keys are invalid locations (red).
        Write-Output (& $title 'KEY REFERENCE')
        Write-AuditTable -Rows ($Matrix | Sort-Object Order) -Column @(
            @{ Name = 'Path'; Expression = { $_.Path } }
            @{ Name = 'Name'; Expression = { $_.Name } }
            @{ Name = 'Works'; Expression = { $_.Functional } }
            @{ Name = 'Default'; Expression = { $_.Default } }
            @{ Name = 'Auto-set'; Expression = { $_.AutoSet } }
            @{ Name = 'Description'; Expression = { $_.Note } }
        ) -ColorRule { if ($_.Functional -like 'No (*') { '31' } else { '' } }

        # Display rule for the Decimal column: say why there is no number rather than leave a gap.
        $decimalColumn = @{
            Name       = 'Decimal'
            Expression = {
                if ($_.State -eq 'Not set') { 'Does not exist' }
                elseif ($_.State -eq 'Error') { 'READ ERROR' }
                elseif ([string]::IsNullOrEmpty([string]$_.Decimal)) { '-' }
                else { [string]$_.Decimal }
            }
        }

        # Per-DC sections. The header lines come from the effective state, so they always agree
        # with the summary verdict.
        $enforcementColor = @{ Enforcing = '1;32'; NotEnforcing = '1;33'; Overridden = '1;33'; Unknown = '33' }
        foreach ($dcState in @($Result.DcStates)) {
            $dc = $dcState.ComputerName
            Write-Output ''
            Write-Output (& $title $dc)
            $osLabel = if ($dcState.OS) { '{0}, build {1}' -f $dcState.OS, $dcState.OSBuild } else { 'build {0}' -f $dcState.OSBuild }
            if ($dcState.IsReadOnly) { $osLabel = '{0} (read-only DC)' -f $osLabel }
            Write-Output ('OS                         : {0}' -f $osLabel)
            Write-Output (ConvertTo-ColorText -Text ('RC4 default removal        : {0}' -f $dcState.Enforcement) -Code $enforcementColor[[string]$dcState.EnforcementCode])
            $fallbackCode = if ($script:StatusColor.ContainsKey([string]$dcState.FallbackStatus)) { $script:StatusColor[[string]$dcState.FallbackStatus] } else { '' }
            Write-Output (ConvertTo-ColorText -Text ('Unset-account etypes       : {0} [{1}] -> {2}' -f $dcState.FallbackHex, $dcState.FallbackSource, $dcState.FallbackStatus) -Code $fallbackCode)
            Write-Output ('KDC etype filter           : {0}' -f $dcState.FilterText)
            Write-Output ('Filter path model          : {0}' -f $dcState.FilterModel)
            Write-Output ''
            $dcRows = @($rows | Where-Object { $_.ComputerName -eq $dc -and $_.Path -notlike '(*' })
            Write-AuditTable -Rows $dcRows -Column @(
                @{ Name = 'Path'; Expression = { $_.Path } }
                @{ Name = 'Name'; Expression = { $_.Name } }
                @{ Name = 'Type'; Expression = { $_.Type } }
                $decimalColumn
                @{ Name = 'Hex'; Expression = { $_.Hex } }
                @{ Name = 'Works here'; Expression = { $_.Functional } }
                @{ Name = 'Status'; Expression = { $_.Status } }
                @{ Name = 'Meaning'; Expression = { $_.Meaning } }
            )
        }

        # Byte-level anomalies: values stored at the wrong type, and masks whose extra bytes carry
        # bits no setting defines. A documented wide value (0x7FFFFFF8 from the GPO) is NOT listed.
        $anomalyRows = @($rows | Where-Object { $_.ByteAnomaly })
        Write-Output ''
        Write-Output (& $title 'BYTE-LEVEL ANOMALIES')
        if ($anomalyRows.Count -eq 0) {
            Write-Output 'None. Every value present is a REG_DWORD whose bytes decode to defined bits.'
        }
        else {
            Write-Output ('{0} value(s) are stored at the wrong type or carry undefined bytes. Raw bytes are shown little-endian, as stored.' -f $anomalyRows.Count)
            Write-Output ''
            Write-AuditTable -Rows $anomalyRows -Column @(
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

        # msDS-SET vs SET consistency: the SupportedEncryptionTypes GPO writes the registry value,
        # and the LSA copies it into the DC computer account's msDS-SupportedEncryptionTypes.
        # Propagation keeps only bits 0-4, so the comparison is masked to 0x1F: a GPO of 0x7FFFFFFF
        # landing as an msDS-SET of 0x1F is the documented healthy case, not drift.
        Write-Output ''
        Write-Output (& $title 'msDS-SET vs SET CONSISTENCY')
        foreach ($dc in @($Result.AuditedDcs)) {
            $msRow = $rows | Where-Object { $_.ComputerName -eq $dc -and $_.Name -eq 'msDS-SupportedEncryptionTypes' } | Select-Object -First 1
            # The GPO writes the Policies path, so compare against it first and Lsa second.
            $setRow = $rows | Where-Object { $_.ComputerName -eq $dc -and $_.Name -eq 'SupportedEncryptionTypes' -and $_.Path -eq $script:KeyPolicies -and $_.State -eq 'Set' } | Select-Object -First 1
            if (-not $setRow) {
                $setRow = $rows | Where-Object { $_.ComputerName -eq $dc -and $_.Name -eq 'SupportedEncryptionTypes' -and $_.Path -eq $script:KeyLsa -and $_.State -eq 'Set' } | Select-Object -First 1
            }

            if ($msRow -and $msRow.State -eq 'Error') {
                # An unreadable attribute is not "out of sync": say it could not be compared.
                Write-Output (ConvertTo-ColorText -Text ('{0,-26} msDS-SET could not be read; consistency not checked' -f $dc) -Code $script:StatusColor['Error'])
                continue
            }
            $msVal = if ($msRow -and $msRow.State -eq 'Set' -and $null -ne $msRow.Value) { [long]$msRow.Value } else { $null }
            $setVal = if ($setRow -and $null -ne $setRow.Value) { [long]$setRow.Value } else { $null }
            $setWhere = if ($setRow) { if ($setRow.Path -eq $script:KeyPolicies) { 'Policies' } else { 'Lsa' } } else { '' }

            if ($null -eq $setVal) {
                # No GPO is configuring SupportedEncryptionTypes, so nothing drives msDS-SET here.
                $msShown = if ($null -ne $msVal) { '{0} ({1})' -f (Format-HexValue -Value $msVal), $msRow.Meaning } else { 'not set' }
                Write-Output ('{0,-26} SET not configured (no GPO); msDS-SET = {1}' -f $dc, $msShown)
            }
            elseif ($null -ne $msVal -and ($msVal -band 0x1FL) -eq ($setVal -band 0x1FL)) {
                # The propagated etype bits agree; the LSA legitimately drops everything above bit 4.
                Write-Output (ConvertTo-ColorText -Text ('{0,-26} consistent: msDS-SET {1} and SET ({2}) {3} agree on bits 0-4' -f $dc, (Format-HexValue -Value $msVal), $setWhere, (Format-HexValue -Value $setVal)) -Code '1;32')
            }
            else {
                # Propagated bits disagree: the AD attribute is out of sync with the configured value.
                $msShown = if ($null -ne $msVal) { Format-HexValue -Value $msVal } else { 'not set' }
                Write-Output (ConvertTo-ColorText -Text ('{0,-26} DIFFER: msDS-SET = {1}, SET ({2}) = {3} - msDS-SET out of sync with the configured value' -f $dc, $msShown, $setWhere, (Format-HexValue -Value $setVal)) -Code '1;33')
            }
        }

        # Cross-DC drift: the KDC settings are per-DC registry values, so two DCs can answer the
        # same request differently. List every setting whose state is not identical everywhere.
        Write-Output ''
        Write-Output (& $title 'CROSS-DC DRIFT')
        if (@($Result.AuditedDcs).Count -lt 2) {
            Write-Output 'Not applicable (fewer than two DCs audited).'
        }
        else {
            $driftRows = @()
            $comparable = @($rows | Where-Object { @($Result.AuditedDcs) -contains $_.ComputerName -and $_.Path -ne '(host)' -and $_.Order -lt 50 })
            foreach ($group in @($comparable | Group-Object -Property Setting)) {
                $signatures = @($group.Group | ForEach-Object { '{0} {1}' -f $_.State, $_.Hex } | Sort-Object -Unique)
                if ($signatures.Count -gt 1) {
                    $driftRows += [PSCustomObject]@{
                        Setting = $group.Name
                        Values  = (@($group.Group | Sort-Object ComputerName | ForEach-Object { '{0}={1}' -f $_.ComputerName, $(if ($_.Hex) { $_.Hex } elseif ($_.State -eq 'Derived') { 'none/unknown' } else { $_.State }) }) -join '; ')
                        Status  = ''
                    }
                }
            }
            if (@($driftRows).Count -eq 0) {
                Write-Output 'None. Every audited DC has the same value for every setting.'
            }
            else {
                Write-Output (ConvertTo-ColorText -Text ('{0} setting(s) differ between DCs:' -f @($driftRows).Count) -Code '1;33')
                Write-AuditTable -Rows $driftRows -Column @(
                    @{ Name = 'Setting'; Expression = { $_.Setting } }
                    @{ Name = 'Per-DC values'; Expression = { $_.Values } }
                )
            }
        }

        # Summary: coverage by name, the effective state per DC, counts, findings, verdict.
        Write-Output ''
        Write-Output (& $title 'SUMMARY')
        Write-Output ('Script version     : {0}' -f $Result.ScriptVersion)
        Write-Output ('Generated (UTC)    : {0}' -f $Result.Timestamp)
        Write-Output ('Targets requested  : {0}' -f @($Result.Requested).Count)
        Write-Output ('DCs audited        : {0}' -f @($Result.AuditedDcs).Count)
        foreach ($item in @($Result.Unreachable)) {
            Write-Output (ConvertTo-ColorText -Text ('Unreachable        : {0} - {1}' -f $item.Name, $item.Message) -Code $script:StatusColor['Unreachable'])
        }
        foreach ($name in @($Result.NotDcs)) {
            Write-Output (ConvertTo-ColorText -Text ('Not a DC           : {0}' -f $name) -Code $script:StatusColor['NotDC'])
        }
        foreach ($item in @($Result.Duplicates)) {
            Write-Output ('Duplicate target   : {0} (same machine as {1}; audited once)' -f $item.Name, $item.Of)
        }

        if (@($Result.DcStates).Count -gt 0) {
            Write-Output ''
            Write-AuditTable -Rows @($Result.DcStates) -Column @(
                @{ Name = 'ComputerName'; Expression = { $_.ComputerName } }
                @{ Name = 'Build'; Expression = { $_.OSBuild } }
                @{ Name = 'Build stage'; Expression = { $_.BuildClass } }
                @{ Name = 'RC4 default removal'; Expression = { $_.EnforcementCode } }
                @{ Name = 'Unset-account etypes'; Expression = { '{0} ({1})' -f $_.FallbackHex, $_.FallbackStatus } }
                @{ Name = 'KDC filter'; Expression = {
                        $shown = if ($_.FilterStatus -eq 'Invalid') { 'NOT EFFECTIVE (Policies path only)' }
                        elseif ($_.FilterStatus -eq 'Unknown') { 'UNCERTAIN (path not established)' }
                        elseif ($_.FilterPath) { '{0}: {1}' -f $_.FilterPath, $(if ($null -ne $_.FilterMask) { Format-HexValue -Value $_.FilterMask } else { 'unusable' }) }
                        else { 'none' }
                        $shown
                    }
                }
            ) -ColorRule {
                $fallbackStatus = [string]$_.FallbackStatus
                if ($script:StatusColor.ContainsKey($fallbackStatus)) { $script:StatusColor[$fallbackStatus] } else { '' }
            }
        }

        Write-Output ''
        $countText = @($Result.Counts.Keys | ForEach-Object { '{0}={1}' -f $_, $Result.Counts[$_] }) -join '  '
        Write-Output ('Rows by status     : {0}' -f $countText)
        Write-Output ('Byte anomalies     : {0}' -f $anomalyRows.Count)

        $findings = @($Result.Findings)
        if ($findings.Count -gt 0) {
            Write-Output ''
            Write-AuditTable -Rows $findings -Column @(
                @{ Name = 'ComputerName'; Expression = { $_.ComputerName } }
                @{ Name = 'Status'; Expression = { $_.Status } }
                @{ Name = 'Setting'; Expression = { $_.Setting } }
                @{ Name = 'Hex'; Expression = { $_.Hex } }
                @{ Name = 'Meaning'; Expression = { $_.Meaning } }
                @{ Name = 'Why'; Expression = { $_.Reason } }
            )
        }

        Write-Output ''
        $verdict = Get-KdcAuditVerdictLine -Result $Result
        Write-Output (ConvertTo-ColorText -Text $verdict.Text -Code $verdict.Code)
    }

    function Out-HtmlAuditReport {
        <#
        .SYNOPSIS
            Write the audit result to a self-contained, sortable, filterable HTML report.
        .DESCRIPTION
            The table viewer companion to the text report: version, timestamp, coverage, the
            per-DC effective state and the overall verdict, then the same rows colored by Status
            with a filter box and click-to-sort headers. Self-contained so it can be mailed or
            archived, and used as the -GridView fallback on hosts where Out-GridView does not exist
            (PowerShell 7 without the GraphicalTools module, Server Core, every non-Windows host).
        #>
        [CmdletBinding()]
        [OutputType([string])]
        param(
            # ConvertTo-KdcAuditResult output.
            [Parameter(Mandatory)]
            $Result,

            # Destination file path. A relative path is resolved against the current PowerShell
            # location (NOT the process working directory, which .NET file APIs would use).
            [Parameter(Mandatory)]
            [string]$Path
        )

        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

        # Escape every cell: registry paths contain backslashes and notes contain angle brackets.
        $encode = {
            param($Text)
            $s = [string]$Text
            $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
            return $s
        }

        $verdict = Get-KdcAuditVerdictLine -Result $Result

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('<!DOCTYPE html>')
        [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
        [void]$sb.AppendLine('<title>KDC Kerberos Registry Audit</title>')
        [void]$sb.AppendLine('<style>')
        [void]$sb.AppendLine('body{font:13px/1.45 Consolas,"Courier New",monospace;margin:1rem;background:#111;color:#ddd}')
        [void]$sb.AppendLine('h1{font-size:1.1rem;margin:0 0 .5rem}h2{font-size:1rem;margin:1rem 0 .4rem}')
        [void]$sb.AppendLine('#f{width:28rem;padding:.35rem;margin-bottom:.6rem;background:#1b1b1b;color:#ddd;border:1px solid #444}')
        [void]$sb.AppendLine('table{border-collapse:collapse;width:100%;margin-bottom:.8rem}')
        [void]$sb.AppendLine('th,td{border:1px solid #333;padding:.25rem .45rem;text-align:left;vertical-align:top;white-space:pre-wrap}')
        [void]$sb.AppendLine('#t th{background:#222;position:sticky;top:0;cursor:pointer;user-select:none}th{background:#222}')
        [void]$sb.AppendLine('.Secure,tr.Secure td{color:#5cd65c}.Transitional,tr.Transitional td{color:#5fd7d7}')
        [void]$sb.AppendLine('.Insecure,tr.Insecure td{color:#e6c34d}.Unknown,tr.Unknown td{color:#e6c34d}')
        [void]$sb.AppendLine('.Invalid,tr.Invalid td{color:#ff6b6b}')
        [void]$sb.AppendLine('.Error,tr.Error td,.Unreachable,tr.Unreachable td,.NotDC,tr.NotDC td{color:#d787ff}')
        [void]$sb.AppendLine('tr:hover td{background:#1e1e1e}dl{margin:0 0 .6rem}dt{float:left;width:12rem;color:#999}dd{margin-left:12rem}')
        [void]$sb.AppendLine('</style></head><body>')
        [void]$sb.AppendLine('<h1>KDC Kerberos Registry Audit</h1>')

        # Summary block: what ran, when, what it covered and the overall verdict.
        [void]$sb.AppendLine('<dl>')
        [void]$sb.AppendLine(('<dt>Script version</dt><dd>{0}</dd>' -f (& $encode $Result.ScriptVersion)))
        [void]$sb.AppendLine(('<dt>Generated (UTC)</dt><dd>{0}</dd>' -f (& $encode $Result.Timestamp)))
        [void]$sb.AppendLine(('<dt>Targets requested</dt><dd>{0}</dd>' -f @($Result.Requested).Count))
        [void]$sb.AppendLine(('<dt>DCs audited</dt><dd>{0}</dd>' -f (& $encode ('{0}: {1}' -f @($Result.AuditedDcs).Count, (@($Result.AuditedDcs) -join ', ')))))
        $unreachableText = @($Result.Unreachable | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Message }) -join '; '
        [void]$sb.AppendLine(('<dt>Unreachable</dt><dd class="{0}">{1}</dd>' -f $(if ($unreachableText) { 'Unreachable' } else { '' }), (& $encode $(if ($unreachableText) { $unreachableText } else { 'none' }))))
        $notDcText = @($Result.NotDcs) -join ', '
        [void]$sb.AppendLine(('<dt>Not a DC</dt><dd class="{0}">{1}</dd>' -f $(if ($notDcText) { 'NotDC' } else { '' }), (& $encode $(if ($notDcText) { $notDcText } else { 'none' }))))
        $duplicateText = @($Result.Duplicates | ForEach-Object { '{0} = {1}' -f $_.Name, $_.Of }) -join '; '
        [void]$sb.AppendLine(('<dt>Duplicate targets</dt><dd>{0}</dd>' -f (& $encode $(if ($duplicateText) { $duplicateText } else { 'none' }))))
        $countText = @($Result.Counts.Keys | ForEach-Object { '{0}={1}' -f $_, $Result.Counts[$_] }) -join '  '
        [void]$sb.AppendLine(('<dt>Rows by status</dt><dd>{0}</dd>' -f (& $encode $countText)))
        [void]$sb.AppendLine(('<dt>Verdict</dt><dd class="{0}">{1}</dd>' -f $verdict.Class, (& $encode $verdict.Text)))
        [void]$sb.AppendLine('</dl>')

        # Effective state per DC.
        [void]$sb.AppendLine('<h2>Effective state per DC</h2>')
        [void]$sb.AppendLine('<table><thead><tr><th>ComputerName</th><th>OS</th><th>Build</th><th>RC4 default removal</th><th>Unset-account etypes</th><th>KDC etype filter</th><th>Filter path model</th></tr></thead><tbody>')
        foreach ($dcState in @($Result.DcStates)) {
            [void]$sb.AppendLine(('<tr class="{0}">' -f (& $encode $dcState.FallbackStatus)))
            foreach ($cell in @(
                    $dcState.ComputerName
                    $(if ($dcState.IsReadOnly) { '{0} (read-only DC)' -f $dcState.OS } else { $dcState.OS })
                    $dcState.OSBuild
                    $dcState.Enforcement
                    ('{0} [{1}] -> {2}' -f $dcState.FallbackHex, $dcState.FallbackSource, $dcState.FallbackStatus)
                    $dcState.FilterText
                    $dcState.FilterModel
                )) {
                [void]$sb.AppendLine(('<td>{0}</td>' -f (& $encode $cell)))
            }
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</tbody></table>')

        # Every row.
        [void]$sb.AppendLine('<h2>All rows</h2>')
        [void]$sb.AppendLine('<input id="f" placeholder="Filter rows (substring match on any column)">')
        [void]$sb.AppendLine('<table id="t"><thead><tr>')
        foreach ($column in $script:PublicColumns) {
            [void]$sb.AppendLine(('<th>{0}</th>' -f (& $encode $column)))
        }
        [void]$sb.AppendLine('</tr></thead><tbody>')
        foreach ($row in @($Result.Rows)) {
            [void]$sb.AppendLine(('<tr class="{0}">' -f (& $encode $row.Status)))
            foreach ($column in $script:PublicColumns) {
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
        [System.IO.File]::WriteAllText($resolved, $sb.ToString(), [System.Text.Encoding]::ASCII)
        return $resolved
    }

}

process {
    # One bind per pipeline object (or a single pass with the -ComputerName argument).
    foreach ($name in @($ComputerName)) {
        if ($name) { $script:CollectedTarget.Add([string]$name) }
    }
}

end {
    # --- Main ---

    # Dot-sourcing the file (". .\Get-KdcKerberosRegistryAudit.ps1") defines the functions and the
    # policy without discovering or reading anything, so tests can drive ConvertTo-KdcAuditResult
    # with fixture records.
    if ($MyInvocation.InvocationName -eq '.') {
        return
    }

    # Detect a real credential (not the Empty sentinel); it is reused for discovery and the read.
    $haveCredential = $null -ne $Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty

    # The names the process block collected (pipeline input or the -ComputerName argument).
    $requestedNames = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $script:CollectedTarget) { $requestedNames.Add($name) }

    # When no hosts were supplied, enumerate every DC in the target domain.
    if ($requestedNames.Count -eq 0) {
        foreach ($name in @(Get-KdcAuditTarget -Domain ([string]$Domain) -Credential $Credential)) { $requestedNames.Add($name) }
    }

    # De-duplicate by name (trimmed, case-insensitive), keeping the first spelling and the order.
    $targets = [System.Collections.Generic.List[string]]::new()
    $seenNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $requestedNames) {
        $trimmed = ([string]$name).Trim()
        if ($trimmed -and $seenNames.Add($trimmed)) { $targets.Add($trimmed) }
    }

    # A discovery that returned nothing is a hard stop; there is nothing to audit.
    if ($targets.Count -eq 0) {
        throw 'No domain controllers were found to query.'
    }

    # Report how many DCs will be queried so long runs are not mistaken for hangs.
    Write-Verbose ('Querying {0} target(s): {1}' -f $targets.Count, ($targets -join ', '))

    # WinRM options are passed through only when the caller asked for them.
    $invokeParameter = @{ ThrottleLimit = $ThrottleLimit }
    if ($haveCredential) { $invokeParameter['Credential'] = $Credential }
    if ($null -ne $SessionOption) { $invokeParameter['SessionOption'] = $SessionOption }
    if ($UseSSL) { $invokeParameter['UseSSL'] = $true }
    if ($PSBoundParameters.ContainsKey('Authentication')) { $invokeParameter['Authentication'] = $Authentication }
    if ($ConfigurationName) { $invokeParameter['ConfigurationName'] = $ConfigurationName }

    $read = Read-KdcAuditRecord -Target $targets.ToArray() -KeyPath $script:AuditedKeys -Reader $script:RegistryReader -InvokeParameter $invokeParameter
    $result = ConvertTo-KdcAuditResult -Record $read.Records -Target $targets.ToArray() -Failure $read.Failures -Policy $SecurityPolicy

    # The same rows for every structured view.
    $viewRows = @($result.Rows | Select-Object -Property $script:PublicColumns)

    # An explicit -HtmlReport path always gets written, in every output mode. It is written BEFORE
    # anything goes to the pipeline so -PassThru cannot skip it.
    $htmlWritten = ''
    if ($HtmlReport) {
        $htmlWritten = Out-HtmlAuditReport -Result $result -Path $HtmlReport
    }

    if ($PassThru) {
        # Structured objects for export/processing; nothing else goes to the success stream.
        $viewRows
        if ($htmlWritten) { Write-Information ('HTML report written to {0}' -f $htmlWritten) -InformationAction Continue }
    }
    else {
        Write-KdcAuditReport -Result $result
        if ($htmlWritten) {
            Write-Output ''
            Write-Output (ConvertTo-ColorText -Text ('HTML report written to {0}' -f $htmlWritten) -Code '1;36')
        }
    }

    # --- Table viewer ---

    if ($GridView) {
        # Out-GridView can be present and still fail: it throws in a non-interactive session (a
        # scheduled task, a remoting runspace) and on Server Core, where there is no desktop to
        # draw on. Treat "threw" the same as "absent" so -GridView always produces a viewer.
        $gridShown = $false
        if (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            try {
                # -PassThru is deliberately omitted: this is a viewer, not a picker, so it must not block.
                $viewRows | Out-GridView -Title ('KDC Kerberos Registry Audit v{0}' -f $script:AuditScriptVersion) -ErrorAction Stop
                $gridShown = $true
            }
            catch {
                Write-Verbose ('Out-GridView could not display the results: {0}' -f $_.Exception.Message)
            }
        }
        if (-not $gridShown) {
            # No usable Out-GridView (PowerShell 7 without GraphicalTools, Server Core, a
            # non-interactive session, non-Windows): write the HTML viewer and open that instead.
            if (-not $htmlWritten) {
                $fallback = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'kdc-kerberos-registry-audit.html'
                $htmlWritten = Out-HtmlAuditReport -Result $result -Path $fallback
                Write-Information ('Out-GridView is unavailable; HTML report written to {0}' -f $htmlWritten) -InformationAction Continue
            }
            try {
                Invoke-Item -LiteralPath $htmlWritten -ErrorAction Stop
            }
            catch {
                # A headless host has no file association; the path above is enough to open it manually.
                Write-Verbose ('Could not open {0} automatically: {1}' -f $htmlWritten, $_.Exception.Message)
            }
        }
    }

    # --- Exit code ---

    # Only when the caller asked for one: an interactive run must not close the caller's shell
    # session logic or change $LASTEXITCODE unexpectedly.
    if ($FailOn) {
        exit (Get-KdcAuditExitCode -Result $result -FailOn $FailOn)
    }
}
