#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Pester tests for scripts/Get-KdcKerberosRegistryAudit.ps1.

    The script is dot-sourced, which defines its functions and policy without discovering or
    reading anything. Every scenario then feeds fixture records - the same flat shape the
    registry reader returns from a DC - to ConvertTo-KdcAuditResult, the pure core that the
    text report, the HTML report, -PassThru and the exit code are all rendered from. Nothing
    here needs Windows, Active Directory or WinRM, so the suite runs on any PowerShell.

    Run:  Invoke-Pester -Path tests/ps
#>

BeforeAll {
    $script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '../..')).Path
    $script:AuditScript = Join-Path -Path $script:RepoRoot -ChildPath 'scripts/Get-KdcKerberosRegistryAudit.ps1'
    . $script:AuditScript

    $script:POL = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $script:LSA = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
    $script:KDC = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
    $script:KDCP = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\Parameters'
    $script:FixedTime = [datetime]::new(2026, 11, 10, 12, 0, 0, [System.DateTimeKind]::Utc)

    function Get-FixtureRecord {
        # One reader record with the full property set, stamped with the host that "returned" it.
        param([string]$ComputerName, [hashtable]$Field)
        $record = [ordered]@{
            RecordType = ''; Path = ''; Name = ''; Found = $false; Kind = ''; Value = $null; Error = ''
            Caption = ''; Build = ''; Ubr = ''; ProductType = ''; KdcService = ''; MachineFqdn = ''; Uac = $null
            PSComputerName = $ComputerName
        }
        foreach ($name in $Field.Keys) { $record[$name] = $Field[$name] }
        [PSCustomObject]$record
    }

    function Get-FixtureDc {
        # Everything the reader would return for one host.
        #   -Values    @{ "<key path>|<value name>" = <int>  or  @(<value>, '<registry kind>') }
        #   -KeyErrors @{ "<key path>" = '<message>' }   (the key exists but could not be read)
        param(
            [string]$Name = 'dc1.corp.example',
            [string]$Build = '20348',
            [string]$Ubr = '5020',
            [string]$Caption = 'Windows Server 2022 Standard',
            [string]$ProductType = 'LanmanNT',
            $MsDs = 24,
            [hashtable]$Values = @{},
            [hashtable]$KeyErrors = @{},
            [string]$AdError = '',
            [string]$Fqdn = '',
            [long]$Uac = 0x82000
        )
        foreach ($path in $script:POL, $script:LSA, $script:KDC, $script:KDCP) {
            if ($KeyErrors.ContainsKey($path)) {
                Get-FixtureRecord -ComputerName $Name -Field @{ RecordType = 'Key'; Path = $path; Error = $KeyErrors[$path] }
            }
            else {
                Get-FixtureRecord -ComputerName $Name -Field @{ RecordType = 'Key'; Path = $path; Found = $true }
            }
        }
        foreach ($key in $Values.Keys) {
            $parts = $key -split '\|', 2
            $spec = @($Values[$key])
            $value = $spec[0]
            $kind = if ($spec.Count -gt 1) { [string]$spec[1] } else { 'DWord' }
            # A REG_DWORD comes back from the registry as a signed Int32.
            if ($kind -eq 'DWord' -and $value -isnot [string]) {
                $value = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([long]$value -band 0xFFFFFFFFL), 0)
            }
            Get-FixtureRecord -ComputerName $Name -Field @{ RecordType = 'Value'; Path = $parts[0]; Name = $parts[1]; Found = $true; Kind = $kind; Value = $value }
        }
        $ad = @{ RecordType = 'AD'; Path = 'AD'; Name = 'msDS-SupportedEncryptionTypes'; Kind = 'AD-Integer'; Uac = $Uac }
        if ($AdError) { $ad['Error'] = $AdError } elseif ($null -ne $MsDs) { $ad['Found'] = $true; $ad['Value'] = [int64]$MsDs }
        Get-FixtureRecord -ComputerName $Name -Field $ad
        Get-FixtureRecord -ComputerName $Name -Field @{
            RecordType = 'OS'; Path = 'OS'; Name = 'OSInfo'; Found = $true; Caption = $Caption; Build = $Build; Ubr = $Ubr
            ProductType = $ProductType; KdcService = 'Running'; MachineFqdn = $(if ($Fqdn) { $Fqdn } else { $Name })
        }
    }

    function Get-FixtureResult {
        # Classify fixture records exactly as the script's main flow does.
        param([object[]]$Record, [string[]]$Target, [hashtable]$Failure = @{})
        if (-not $Target) { $Target = @($Record | ForEach-Object { $_.PSComputerName } | Select-Object -Unique) }
        ConvertTo-KdcAuditResult -Record $Record -Target $Target -Failure $Failure -Policy $SecurityPolicy -Timestamp $script:FixedTime
    }

    function Get-FixtureRow {
        param($Result, [string]$Name, [string]$Path = '')
        $Result.Rows | Where-Object { $_.Name -eq $Name -and (-not $Path -or $_.Path -eq $Path) } | Select-Object -First 1
    }
}

Describe 'Effective state drives the verdict (review findings 1 and 4)' {
    It 'does not pass a DC that predates the April 2026 update with nothing set' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '4893')
        $result.CleanPass | Should -BeFalse
        $row = Get-FixtureRow -Result $result -Name 'UnsetAccountEtypes'
        $row.Status | Should -Be 'Insecure'
        $row.Hex | Should -Be '0x27'
        $result.DcStates[0].Enforcement | Should -BeLike 'NOT active*'
        (Get-KdcAuditVerdictLine -Result $result).Text | Should -Not -BeLike 'PASS*'
    }

    It 'passes an enforcing DC with nothing set and an AES-only DC account' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '5020')
        $result.CleanPass | Should -BeTrue
        $result.DcStates[0].Enforcement | Should -BeLike 'ACTIVE*'
        (Get-FixtureRow -Result $result -Name 'UnsetAccountEtypes').Hex | Should -Be '0x18'
    }

    It 'never passes a build it cannot classify' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Build '25398' -Ubr '1')
        $result.CleanPass | Should -BeFalse
        (Get-FixtureRow -Result $result -Name 'UnsetAccountEtypes').Status | Should -Be 'Unknown'
        $result.DcStates[0].Enforcement | Should -BeLike 'UNKNOWN*'
    }

    It 'reports UNKNOWN, not "not active", when the update revision is blank' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '')
        $result.DcStates[0].BuildClass | Should -Be 'Unknown'
        $result.DcStates[0].Enforcement | Should -BeLike 'UNKNOWN*'
    }

    It 'reports INDETERMINATE between the last pre-April and the first April build' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '4950')
        $result.DcStates[0].BuildClass | Should -Be 'Indeterminate'
        $result.CleanPass | Should -BeFalse
    }

    It 'says OVERRIDDEN when RC4DefaultDisablementPhase=0 rolls an enforcing build back' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:POL|RC4DefaultDisablementPhase" = 0 })
        $result.DcStates[0].Enforcement | Should -BeLike 'OVERRIDDEN*'
        $result.DcStates[0].FallbackStatus | Should -Be 'Insecure'
        (Get-FixtureRow -Result $result -Name 'RC4DefaultDisablementPhase' -Path $script:POL).Status | Should -Be 'Insecure'
        # Counted once, on the registry row that causes it.
        (Get-FixtureRow -Result $result -Name 'UnsetAccountEtypes').Status | Should -Be ''
        $result.CleanPass | Should -BeFalse
    }

    It 'says OVERRIDDEN when an explicit DDSET with RC4 takes precedence over the build default' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = 0x3C })
        $result.DcStates[0].Enforcement | Should -BeLike 'OVERRIDDEN*'
        $result.DcStates[0].FallbackHex | Should -Be '0x3C'
        (Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncTypes' -Path $script:KDC).Status | Should -Be 'Transitional'
    }

    It 'treats an explicit AES-only DDSET as enforcing even on an old build' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '4000' -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = 0x18 })
        $result.DcStates[0].EnforcementCode | Should -Be 'Enforcing'
        $result.CleanPass | Should -BeTrue
    }
}

Describe 'Build map (review findings 3 and 24)' {
    It 'keeps every entry ordered AuditFrom <= NotEnforcing < Enforcing < PermanentFrom' {
        foreach ($major in $SecurityPolicy.Rc4EnforcementBuilds.Keys) {
            $entry = $SecurityPolicy.Rc4EnforcementBuilds[$major]
            $entry.AuditFrom | Should -BeLessOrEqual $entry.NotEnforcing
            $entry.NotEnforcing | Should -BeLessThan $entry.Enforcing
            $entry.Enforcing | Should -BeLessThan $entry.PermanentFrom
            $entry.Evidence | Should -BeIn @('Lab', 'Microsoft release history')
        }
    }

    It 'classifies <Build>.<Ubr> as <Expected>' -ForEach @(
        @{ Build = '20348'; Ubr = '4000'; Expected = 'PreAudit' }
        @{ Build = '20348'; Ubr = '4648'; Expected = 'Audit' }
        @{ Build = '20348'; Ubr = '4893'; Expected = 'Audit' }
        @{ Build = '20348'; Ubr = '5020'; Expected = 'Enforcing' }
        @{ Build = '20348'; Ubr = '5386'; Expected = 'Permanent' }
        @{ Build = '26100'; Ubr = '32522'; Expected = 'Audit' }
        @{ Build = '26100'; Ubr = '32690'; Expected = 'Enforcing' }
        @{ Build = '26100'; Ubr = '33158'; Expected = 'Permanent' }
        @{ Build = '17763'; Ubr = '8644'; Expected = 'Enforcing' }
        @{ Build = '14393'; Ubr = '9339'; Expected = 'Permanent' }
        @{ Build = '25398'; Ubr = '2000'; Expected = 'Unknown' }
        @{ Build = '20348'; Ubr = 'abc'; Expected = 'Unknown' }
    ) {
        (Resolve-BuildClass -Build $Build -Ubr $Ubr -BuildMap $SecurityPolicy.Rc4EnforcementBuilds).Class | Should -Be $Expected
    }

    It 'only calls the Server 2022 boundary lab-verified' {
        $SecurityPolicy.Rc4EnforcementBuilds[20348].Evidence | Should -Be 'Lab'
        $SecurityPolicy.Rc4EnforcementBuilds[26100].Evidence | Should -Be 'Microsoft release history'
    }

    It 'treats an unset Phase on a January-March build as audit (RC4 still default)' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '4700')
        $result.DcStates[0].BuildClass | Should -Be 'Audit'
        $result.DcStates[0].FallbackStatus | Should -Be 'Insecure'
    }

    It 'accepts Phase=2 as manual enforcement on a January-March build' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '4700' -Values @{ "$script:POL|RC4DefaultDisablementPhase" = 2 })
        $result.DcStates[0].EnforcementCode | Should -Be 'Enforcing'
        $result.DcStates[0].FallbackHex | Should -Be '0x18'
    }

    It 'flags Phase=2 on a build that predates the January 2026 update (it enforces nothing)' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '4000' -Values @{ "$script:POL|RC4DefaultDisablementPhase" = 2 })
        $row = Get-FixtureRow -Result $result -Name 'RC4DefaultDisablementPhase' -Path $script:POL
        $row.Status | Should -Be 'Invalid'
        $row.Functional | Should -BeLike 'Not read on this build*'
        $result.DcStates[0].FallbackStatus | Should -Be 'Insecure'
    }

    It 'flags a leftover Phase=0 on a July 2026 or later build without claiming to know the outcome' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '5386' -Values @{ "$script:POL|RC4DefaultDisablementPhase" = 0 })
        $row = Get-FixtureRow -Result $result -Name 'RC4DefaultDisablementPhase' -Path $script:POL
        $row.Status | Should -Be 'Invalid'
        $row.Functional | Should -BeLike '*not lab-verified*'
        $result.DcStates[0].FallbackStatus | Should -Be 'Unknown'
        $result.DcStates[0].Enforcement | Should -BeLike 'EXPECTED ACTIVE*'
        $result.CleanPass | Should -BeFalse
    }
}

Describe 'OS-dependent filter precedence (review finding 2)' {
    It 'flags a Policies-only filter on the lab-tested Server 2025 build line as not effective' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Build '26100' -Ubr '32522' -Caption 'Windows Server 2025 Datacenter' -Values @{
                "$script:POL|SupportedEncryptionTypes" = 0x18; "$script:KDC|DefaultDomainSupportedEncTypes" = 0x18
            })
        $policies = Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:POL
        $policies.Functional | Should -BeLike 'Ignored on this build*'
        $policies.Status | Should -Be ''
        (Get-FixtureRow -Result $result -Name 'KdcEtypeFilter').Status | Should -Be 'Invalid'
        $result.DcStates[0].FilterModel | Should -BeLike 'Lsa path only*'
        $result.CleanPass | Should -BeFalse
    }

    It 'uses the Lsa path as the effective filter on the lab-tested Server 2025 build line' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Build '26100' -Ubr '32522' -Values @{
                "$script:POL|SupportedEncryptionTypes" = 0x1C; "$script:LSA|SupportedEncryptionTypes" = 0x18
            })
        $result.DcStates[0].FilterPath | Should -Be 'Lsa'
        (Get-FixtureRow -Result $result -Name 'KdcEtypeFilter').Status | Should -Be ''
        (Get-FixtureRow -Result $result -Name 'KdcEtypeFilter').Hex | Should -Be '0x18'
        (Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:LSA).Status | Should -Be 'Secure'
    }

    It 'does not assert either model on Server 2025 from the April 2026 update (not retested)' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Build '26100' -Ubr '32690' -Values @{ "$script:POL|SupportedEncryptionTypes" = 0x18 })
        $policies = Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:POL
        $policies.Functional | Should -BeLike 'Uncertain*not retested*'
        $policies.Functional | Should -Not -BeLike 'Ignored*'
        $policies.Status | Should -Be 'Secure'
        $filter = Get-FixtureRow -Result $result -Name 'KdcEtypeFilter'
        $filter.Status | Should -Be 'Unknown'
        $filter.Reason | Should -BeLike '*not been retested*'
        $result.DcStates[0].FilterModel | Should -BeLike 'UNCERTAIN*'
        $result.CleanPass | Should -BeFalse
    }

    It 'is certain on a later Server 2025 build when both paths hold the same value' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Build '26100' -Ubr '33158' -Values @{
                "$script:POL|SupportedEncryptionTypes" = 0x18; "$script:LSA|SupportedEncryptionTypes" = 0x18
            })
        $filter = Get-FixtureRow -Result $result -Name 'KdcEtypeFilter'
        $filter.Status | Should -Be ''
        $filter.Hex | Should -Be '0x18'
        $result.CleanPass | Should -BeTrue
    }

    It 'reports Unknown on a later Server 2025 build when the two paths disagree' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Build '26100' -Ubr '33158' -Values @{
                "$script:POL|SupportedEncryptionTypes" = 0x18; "$script:LSA|SupportedEncryptionTypes" = 0x1C
            })
        (Get-FixtureRow -Result $result -Name 'KdcEtypeFilter').Status | Should -Be 'Unknown'
    }

    It 'marks the Lsa path as shadowed when Policies is set on Server 2022' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{
                "$script:POL|SupportedEncryptionTypes" = 0x18; "$script:LSA|SupportedEncryptionTypes" = 0x1C
            })
        $lsa = Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:LSA
        $lsa.Functional | Should -Be 'Shadowed by Policies'
        $lsa.Status | Should -Be ''
        $result.DcStates[0].FilterPath | Should -Be 'Policies'
        $result.CleanPass | Should -BeTrue
    }

    It 'labels the filter model as assumed on an OS the lab never tested' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Build '17763' -Ubr '8644' -Values @{ "$script:POL|SupportedEncryptionTypes" = 0x18 })
        (Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:POL).Functional | Should -BeLike 'Yes (assumed*'
        $result.DcStates[0].FilterModel | Should -BeLike '*assumed*'
    }
}

Describe 'Read errors are not "not set" (review finding 5)' {
    It 'reports an unreadable key as Error on every value under it' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -KeyErrors @{ $script:POL = 'Requested registry access is not allowed.' })
        $row = Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:POL
        $row.State | Should -Be 'Error'
        $row.Status | Should -Be 'Error'
        $row.Meaning | Should -BeLike '*not allowed*'
        $result.Counts['Error'] | Should -BeGreaterThan 0
        $result.CleanPass | Should -BeFalse
    }

    It 'reports an ADSI failure as Error and does not call it drift' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -AdError 'The server is not operational.' -Values @{ "$script:POL|SupportedEncryptionTypes" = 0x18 })
        (Get-FixtureRow -Result $result -Name 'msDS-SupportedEncryptionTypes').Status | Should -Be 'Error'
        $text = (Write-KdcAuditReport -Result $result) -join "`n"
        $text | Should -Match 'msDS-SET could not be read'
        $text | Should -Not -Match 'DIFFER'
    }
}

Describe 'Classification tiers (review findings 21, 25 and 26)' {
    It 'classifies <Hex> at <Where> as <Expected>' -ForEach @(
        @{ Where = 'DDSET'; Key = 'KDC|DefaultDomainSupportedEncTypes'; Hex = '0x18'; Value = 0x18; Expected = 'Secure' }
        @{ Where = 'DDSET'; Key = 'KDC|DefaultDomainSupportedEncTypes'; Hex = '0x3C'; Value = 0x3C; Expected = 'Transitional' }
        @{ Where = 'DDSET'; Key = 'KDC|DefaultDomainSupportedEncTypes'; Hex = '0x1C'; Value = 0x1C; Expected = 'Transitional' }
        @{ Where = 'DDSET'; Key = 'KDC|DefaultDomainSupportedEncTypes'; Hex = '0x04'; Value = 0x04; Expected = 'Insecure' }
        @{ Where = 'DDSET'; Key = 'KDC|DefaultDomainSupportedEncTypes'; Hex = '0x27'; Value = 0x27; Expected = 'Insecure' }
        @{ Where = 'DDSET'; Key = 'KDC|DefaultDomainSupportedEncTypes'; Hex = '0x0110'; Value = 0x0110; Expected = 'Invalid' }
        @{ Where = 'GPO'; Key = 'POL|SupportedEncryptionTypes'; Hex = '0x7FFFFFF8'; Value = 0x7FFFFFF8; Expected = 'Secure' }
        @{ Where = 'GPO'; Key = 'POL|SupportedEncryptionTypes'; Hex = '0x7FFFFFFF'; Value = 0x7FFFFFFF; Expected = 'Insecure' }
        @{ Where = 'GPO'; Key = 'POL|SupportedEncryptionTypes'; Hex = '0x40000018'; Value = 0x40000018; Expected = 'Invalid' }
        @{ Where = 'Bool'; Key = 'KDC|KdcUseRequestedEtypesForTickets'; Hex = '0x01'; Value = 1; Expected = 'Insecure' }
        @{ Where = 'Bool'; Key = 'KDC|KdcUseRequestedEtypesForTickets'; Hex = '0x00'; Value = 0; Expected = 'Secure' }
    ) {
        $parts = $Key -split '\|'
        $path = if ($parts[0] -eq 'KDC') { $script:KDC } else { $script:POL }
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$path|$($parts[1])" = $Value })
        $row = Get-FixtureRow -Result $result -Name $parts[1] -Path $path
        $row.Hex | Should -Be $Hex
        $row.Status | Should -Be $Expected
        if ($Expected -ne 'Secure') { $row.Reason | Should -Not -BeNullOrEmpty }
    }

    It 'does not treat the documented GPO value 0x7FFFFFF8 as a byte anomaly' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:POL|SupportedEncryptionTypes" = 0x7FFFFFF8 })
        $row = Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:POL
        $row.ByteAnomaly | Should -BeFalse
        $row.MultiByte | Should -BeTrue
        $row.Bytes | Should -Be '0xF8 0xFF 0xFF 0x7F'
        $row.Meaning | Should -Not -Match 'bytes:'
    }

    It 'does treat 0x0110 as a byte anomaly' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = 0x0110 })
        (Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncTypes' -Path $script:KDC).ByteAnomaly | Should -BeTrue
    }

    It 'rejects a REG_SZ "24" as Invalid and shows its bytes' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = @('24', 'String') })
        $row = Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncTypes' -Path $script:KDC
        $row.Status | Should -Be 'Invalid'
        $row.Meaning | Should -BeLike '*not a REG_DWORD*0x32 0x00 0x34 0x00*'
        # An unusable DDSET must not be taken as the effective fallback.
        $result.DcStates[0].FallbackSource | Should -BeLike 'build default*'
    }

    It 'keeps DefaultEncryptionType at the Lsa path neutral (client-side, not a KDC control)' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:LSA|DefaultEncryptionType" = 23 })
        $row = Get-FixtureRow -Result $result -Name 'DefaultEncryptionType' -Path $script:LSA
        $row.Status | Should -Be ''
        $row.Functional | Should -BeLike 'Client-side*'
        $result.CleanPass | Should -BeTrue
    }

    It 'still flags DefaultEncryptionType under Services\Kdc as a wrong path' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultEncryptionType" = 18 })
        (Get-FixtureRow -Result $result -Name 'DefaultEncryptionType' -Path $script:KDC).Status | Should -Be 'Invalid'
    }

    It 'classifies a DC account msDS-SET of 0x1C as Transitional, not Insecure' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -MsDs 28)
        $row = Get-FixtureRow -Result $result -Name 'msDS-SupportedEncryptionTypes'
        $row.Status | Should -Be 'Transitional'
        $row.Reason | Should -BeLike '*AES256*'
    }

    It 'keeps an msDS-SET of 0 neutral' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -MsDs 0)
        (Get-FixtureRow -Result $result -Name 'msDS-SupportedEncryptionTypes').Status | Should -Be ''
    }

    It 'folds a negative Int32 DWORD to its unsigned value' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:POL|SupportedEncryptionTypes" = 0xFFFFFFFF })
        $row = Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:POL
        $row.Decimal | Should -Be '4294967295'
        $row.Hex | Should -Be '0xFFFFFFFF'
        $row.Value | Should -Be 4294967295
    }
}

Describe 'Unlisted and misspelled value names (review finding 23)' {
    It 'flags DDSET written under Services\Kdc\Parameters as silently ignored' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDCP|DefaultDomainSupportedEncTypes" = 0x18 })
        $row = Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncTypes' -Path $script:KDCP
        $row | Should -Not -BeNullOrEmpty
        $row.Status | Should -Be 'Invalid'
        $row.Functional | Should -Be 'No (wrong path)'
        $row.Note | Should -BeLike '*silently ignored*one level up*'
        # The misplaced value must not be mistaken for a working DDSET.
        $result.DcStates[0].FallbackSource | Should -BeLike 'build default*'
    }

    It 'flags a misspelled value name and names the one it resembles' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:POL|RC4DefaultDisablmentPhase" = 2 })
        $row = Get-FixtureRow -Result $result -Name 'RC4DefaultDisablmentPhase'
        $row.Status | Should -Be 'Invalid'
        $row.Functional | Should -Be 'No (unrecognized name)'
        $row.Note | Should -BeLike '*misspelling of RC4DefaultDisablementPhase*'
    }

    It 'flags an etype-looking name that is not close to any known one' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultDomainSupportedEncryptionTypes" = 24 })
        (Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncryptionTypes').Status | Should -Be 'Invalid'
    }

    It 'ignores unrelated values under the audited keys' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{
                "$script:KDC|ImagePath" = @('%SystemRoot%\System32\lsass.exe', 'ExpandString'); "$script:LSA|MaxTokenSize" = 48000
            })
        Get-FixtureRow -Result $result -Name 'ImagePath' | Should -BeNullOrEmpty
        Get-FixtureRow -Result $result -Name 'MaxTokenSize' | Should -BeNullOrEmpty
        $result.CleanPass | Should -BeTrue
    }

    It 'matches registry names case-insensitively' {
        $upper = $script:KDC.ToUpperInvariant().Replace('HKLM:', 'HKLM:')
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$upper|defaultdomainsupportedenctypes" = 0x18 })
        (Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncTypes' -Path $script:KDC).State | Should -Be 'Set'
    }
}

Describe 'Coverage: unreachable hosts, duplicates and non-DCs (review findings 14, 18 and 19)' {
    It 'emits an Unreachable row by name and is not a pass' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Name 'dc1.corp.example') -Target 'dc1.corp.example', 'dc02.corp.example' -Failure @{ 'dc02.corp.example' = 'WinRM cannot complete the operation.' }
        $row = $result.Rows | Where-Object { $_.ComputerName -eq 'dc02.corp.example' }
        @($row).Count | Should -Be 1
        $row.Status | Should -Be 'Unreachable'
        $row.Meaning | Should -BeLike '*WinRM*'
        $result.Unreachable[0].Name | Should -Be 'dc02.corp.example'
        $result.CleanPass | Should -BeFalse
        ((Write-KdcAuditReport -Result $result) -join "`n") | Should -Match 'Unreachable\s+: dc02\.corp\.example'
    }

    It 'audits one machine once when it is requested under two names' {
        $records = @(Get-FixtureDc -Name 'dc1' -Fqdn 'dc1.corp.example') + @(Get-FixtureDc -Name 'dc1.corp.example' -Fqdn 'dc1.corp.example')
        $result = Get-FixtureResult -Record $records -Target 'dc1', 'dc1.corp.example'
        @($result.AuditedDcs).Count | Should -Be 1
        $result.Duplicates[0].Name | Should -Be 'dc1.corp.example'
        @($result.Unreachable).Count | Should -Be 0
    }

    It 'files a local alias as a duplicate rather than as unreachable' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Name 'localhost') -Target 'localhost', '127.0.0.1' -Failure @{ '127.0.0.1' = 'DUPLICATE:localhost' }
        @($result.Unreachable).Count | Should -Be 0
        $result.Duplicates[0].Of | Should -Be 'localhost'
    }

    It 'reports a member server as NotDC with a single row' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Name 'filesrv01.corp.example' -ProductType 'ServerNT')
        @($result.Rows).Count | Should -Be 1
        $result.Rows[0].Status | Should -Be 'NotDC'
        @($result.AuditedDcs).Count | Should -Be 0
        $result.CleanPass | Should -BeFalse
        (Get-KdcAuditVerdictLine -Result $result).Text | Should -BeLike 'INCOMPLETE*'
    }

    It 'labels a read-only DC' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Uac 0x5001000)
        $result.DcStates[0].IsReadOnly | Should -BeTrue
        (Get-FixtureRow -Result $result -Name 'Role').Meaning | Should -BeLike '*read-only*'
    }

    It 'reports cross-DC drift' {
        $records = @(Get-FixtureDc -Name 'dc1.corp.example' -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = 0x18 }) + @(Get-FixtureDc -Name 'dc02.corp.example')
        $text = (Write-KdcAuditReport -Result (Get-FixtureResult -Record $records)) -join "`n"
        $text | Should -Match '1 setting\(s\) differ between DCs'
    }
}

Describe 'Exit codes (review finding 14)' {
    It 'returns <Expected> for <Label> with -FailOn <FailOn>' -ForEach @(
        @{ Label = 'a clean DC'; Scenario = 'clean'; FailOn = @('Any'); Expected = 0 }
        @{ Label = 'an insecure DC'; Scenario = 'insecure'; FailOn = @('Insecure', 'Invalid'); Expected = 1 }
        @{ Label = 'an insecure DC'; Scenario = 'insecure'; FailOn = @('Unreachable'); Expected = 0 }
        @{ Label = 'a transitional DC'; Scenario = 'transitional'; FailOn = @('Insecure', 'Invalid'); Expected = 0 }
        @{ Label = 'a transitional DC'; Scenario = 'transitional'; FailOn = @('Transitional'); Expected = 1 }
        @{ Label = 'an unreachable DC'; Scenario = 'unreachable'; FailOn = @('Unreachable'); Expected = 2 }
        @{ Label = 'insecure plus unreachable'; Scenario = 'both'; FailOn = @('Any'); Expected = 3 }
        @{ Label = 'no DC audited'; Scenario = 'none'; FailOn = @('Insecure'); Expected = 2 }
        @{ Label = 'an insecure DC'; Scenario = 'insecure'; FailOn = @(); Expected = 0 }
    ) {
        $result = switch ($Scenario) {
            'clean' { Get-FixtureResult -Record (Get-FixtureDc) }
            'insecure' { Get-FixtureResult -Record (Get-FixtureDc -Ubr '4893') }
            'transitional' { Get-FixtureResult -Record (Get-FixtureDc -MsDs 28) }
            'unreachable' { Get-FixtureResult -Record (Get-FixtureDc) -Target 'dc1.corp.example', 'dc09.corp.example' }
            'both' { Get-FixtureResult -Record (Get-FixtureDc -Ubr '4893') -Target 'dc1.corp.example', 'dc09.corp.example' }
            'none' { Get-FixtureResult -Record @() -Target 'dc09.corp.example' }
        }
        Get-KdcAuditExitCode -Result $result -FailOn $FailOn | Should -Be $Expected
    }
}

Describe 'Output contract (review findings 14, 15, 16 and 17)' {
    It 'gives every row the same properties, with a numeric Value' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = 0x18 }) -Target 'dc1.corp.example', 'dc09.corp.example'
        $names = @($result.Rows[0].PSObject.Properties.Name)
        foreach ($row in $result.Rows) { @($row.PSObject.Properties.Name) | Should -Be $names }
        foreach ($column in $script:PublicColumns) { $names | Should -Contain $column }
        $ddset = Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncTypes' -Path $script:KDC
        $ddset.Value | Should -Be 24
        $ddset.Value | Should -BeOfType [long]
        $ddset.ScriptVersion | Should -Be $script:AuditScriptVersion
        $ddset.Timestamp | Should -Be '2026-11-10T12:00:00Z'
        { $result.Rows | Select-Object -Property $script:PublicColumns | ConvertTo-Json -Depth 3 | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'emits no ANSI escapes when color is off' {
        $script:UseColor = $false
        $text = (Write-KdcAuditReport -Result (Get-FixtureResult -Record (Get-FixtureDc -Ubr '4893'))) -join "`n"
        $text | Should -Not -Match ([string][char]27)
        $text | Should -Match 'KDC Kerberos Registry Audit v'
    }

    It 'resolves a relative -HtmlReport path against the PowerShell location, not the process directory' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Ubr '4893') -Target 'dc1.corp.example', 'dc09.corp.example'
        Push-Location -LiteralPath $TestDrive
        try {
            $written = Out-HtmlAuditReport -Result $result -Path 'relative-report.html'
        }
        finally {
            Pop-Location
        }
        $expected = Join-Path -Path $TestDrive -ChildPath 'relative-report.html'
        $written | Should -Be $expected
        Test-Path -LiteralPath $expected | Should -BeTrue
        $html = Get-Content -LiteralPath $expected -Raw
        $html | Should -Match ([regex]::Escape($script:AuditScriptVersion))
        $html | Should -Match 'Effective state per DC'
        $html | Should -Match 'dc09\.corp\.example'
        $html | Should -Match '2026-11-10T12:00:00Z'
    }

    It 'escapes HTML in cell values' {
        $result = Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = @('<script>alert(1)</script>', 'String') })
        $path = Join-Path -Path $TestDrive -ChildPath 'escape.html'
        [void](Out-HtmlAuditReport -Result $result -Path $path)
        (Get-Content -LiteralPath $path -Raw) | Should -Not -Match '<script>alert'
    }

    It 'handles one-byte, empty and absent values under strict mode' {
        Set-StrictMode -Version Latest
        { ConvertTo-AuditReading -Record $null } | Should -Not -Throw
        (ConvertTo-AuditReading -Record $null).Bytes.Count | Should -Be 0
        $one = ConvertTo-AuditReading -Record ([PSCustomObject]@{ Found = $true; Kind = 'DWord'; Value = 24; Error = '' })
        $one.Bytes.Count | Should -Be 1
        $one.Bytes.GetType().FullName | Should -Be 'System.Byte[]'
        { Get-FixtureResult -Record (Get-FixtureDc -Values @{ "$script:KDC|DefaultDomainSupportedEncTypes" = 0 }) } | Should -Not -Throw
    }

    It 'accepts the older probe-style records (no RecordType, absent values as Found = $false)' {
        $name = 'dc1.corp.example'
        $old = @(
            [PSCustomObject]@{ Path = $script:KDC; Name = 'DefaultDomainSupportedEncTypes'; Found = $false; Kind = ''; Value = $null; PSComputerName = $name }
            [PSCustomObject]@{ Path = $script:POL; Name = 'SupportedEncryptionTypes'; Found = $true; Kind = 'DWord'; Value = 24; PSComputerName = $name }
            [PSCustomObject]@{ Path = 'AD'; Name = 'msDS-SupportedEncryptionTypes'; Found = $true; Kind = 'AD-Integer'; Value = [int64]24; PSComputerName = $name }
            [PSCustomObject]@{ Path = 'OS'; Name = 'OSInfo'; Found = $true; Kind = ''; Value = $null; Caption = 'Windows Server 2022 Standard'; Build = '20348'; Ubr = '5020'; PSComputerName = $name }
        )
        $result = Get-FixtureResult -Record $old
        (Get-FixtureRow -Result $result -Name 'DefaultDomainSupportedEncTypes' -Path $script:KDC).State | Should -Be 'Not set'
        (Get-FixtureRow -Result $result -Name 'SupportedEncryptionTypes' -Path $script:POL).Status | Should -Be 'Secure'
        # No ProductType in the old shape: the role cannot be confirmed, which is reported.
        (Get-FixtureRow -Result $result -Name 'Role').Status | Should -Be 'Error'
    }
}

Describe 'Script metadata and shared tables (review finding 22)' {
    It 'keeps the version constant in step with PSScriptInfo' {
        $source = Get-Content -LiteralPath $script:AuditScript -Raw
        $source -match '(?m)^\.VERSION\s+(\S+)' | Should -BeTrue
        $Matches[1] | Should -Be $script:AuditScriptVersion
    }

    It 'is ASCII-only with CRLF line endings' {
        $bytes = [System.IO.File]::ReadAllBytes($script:AuditScript)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        ([regex]::Matches($text, "(?<!`r)`n")).Count | Should -Be 0
    }

    It 'documents every parameter in comment-based help' {
        $help = Get-Help -Name $script:AuditScript -Full
        $documented = @($help.parameters.parameter | ForEach-Object { $_.name })
        foreach ($name in 'ComputerName', 'Domain', 'Credential', 'PassThru', 'NoColor', 'GridView', 'HtmlReport', 'FailOn', 'ThrottleLimit', 'SessionOption', 'UseSSL', 'Authentication', 'ConfigurationName') {
            $documented | Should -Contain $name
            ($help.parameters.parameter | Where-Object { $_.name -eq $name }).description | Should -Not -BeNullOrEmpty
        }
    }

    It 'uses the same bit names as the site calculator (content/javascripts/etype-calculator.js)' {
        $jsPath = Join-Path -Path $script:RepoRoot -ChildPath 'content/javascripts/etype-calculator.js'
        $js = Get-Content -LiteralPath $jsPath -Raw
        # Every "{ bit: N, ... name: "X" ..." entry of the BITS table, in whatever layout.
        $pairs = [regex]::Matches($js, '\{\s*bit:\s*(\d+)\s*,[^{}]*?\bname:\s*"([^"]+)"')
        $pairs.Count | Should -BeGreaterThan 0
        $jsNames = @{}
        foreach ($pair in $pairs) { $jsNames[[int]$pair.Groups[1].Value] = $pair.Groups[2].Value }
        foreach ($entry in $script:EtypeBits) {
            $jsNames.ContainsKey([int]$entry.Bit) | Should -BeTrue -Because "bit $($entry.Bit) should exist in the calculator's BITS table"
            $jsNames[[int]$entry.Bit] | Should -Be $entry.Name
        }
        @($jsNames.Keys).Count | Should -Be @($script:EtypeBits).Count
        # The name of the GPO checkbox that covers bits 5-30.
        if ($js -match 'FUTURE_NAME\s*=\s*"([^"]+)"') {
            $Matches[1] | Should -Be $script:FutureCheckboxName
        }
    }

    It 'names bit 31 as set-but-not-honored rather than as the GPO Future checkbox' {
        $decode = ConvertTo-KerberosEtypeDecode -Mask 0x80000018L -Variant 'DDSET'
        $decode.Text | Should -BeLike '*Bit 31*not honored*bits 5-30*'
        $decode.UndefinedMask | Should -Be 0
        (ConvertTo-KerberosEtypeDecode -Mask 0x7FFFFFF8L -Variant 'GPO').Text | Should -Be 'AES128-CTS-HMAC-SHA1-96 + AES256-CTS-HMAC-SHA1-96 + Future encryption types (bits 5-30)'
        (ConvertTo-KerberosEtypeDecode -Mask 0xFFFFFFFFL -Variant 'GPO').UndefinedMask | Should -Be 0
    }
}

Describe 'End to end on the local host' {
    # No domain controller is needed: on a non-Windows host every read fails (Error rows); on a
    # Windows member server or workstation the host is reported as NotDC. Either way the run
    # must finish, must not pass, and must exit 2 (coverage) under -FailOn Any.
    BeforeAll {
        $script:Shell = (Get-Process -Id $PID).Path
        $script:WorkDir = Join-Path -Path $TestDrive -ChildPath 'e2e'
        [void](New-Item -ItemType Directory -Path $script:WorkDir)
    }

    It 'exits 2 under -FailOn Any and writes no ANSI escapes to a redirected stream' {
        $output = & $script:Shell -NoProfile -NonInteractive -File $script:AuditScript -ComputerName localhost -FailOn Any 2>&1
        ($LASTEXITCODE -band 2) | Should -Be 2
        $text = $output -join "`n"
        $text | Should -Not -Match ([string][char]27)
        $text | Should -Match 'SUMMARY'
        $text | Should -Not -Match 'PASS:'
    }

    It 'honors -HtmlReport together with -PassThru and accepts pipeline input' {
        $command = "Set-Location -LiteralPath '$($script:WorkDir)'; `$rows = 'localhost', 'LOCALHOST' | & '$($script:AuditScript)' -PassThru -HtmlReport 'out.html' 6>`$null; `$rows.Count; (`$rows | Select-Object -ExpandProperty ComputerName -Unique) -join ','"
        $output = & $script:Shell -NoProfile -NonInteractive -Command $command 2>&1
        Test-Path -LiteralPath (Join-Path -Path $script:WorkDir -ChildPath 'out.html') | Should -BeTrue
        [int]$output[0] | Should -BeGreaterThan 0
        $output[1] | Should -Be 'localhost'
    }

    It 'does not call exit without -FailOn' {
        $null = & $script:Shell -NoProfile -NonInteractive -File $script:AuditScript -ComputerName localhost -NoColor 2>&1
        $LASTEXITCODE | Should -Be 0
    }
}
