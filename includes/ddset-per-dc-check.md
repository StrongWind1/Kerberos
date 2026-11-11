```powershell title="Read the Kerberos etype registry state on every DC (unreachable DCs are reported, not hidden)"
$DCs = (Get-ADDomainController -Filter *).HostName

$state = foreach ($dc in $DCs) {
    try {
        Invoke-Command -ComputerName $dc -ErrorAction Stop -ScriptBlock {
            function Read-RegValue {
                $regPath = $args[0]
                $valueName = $args[1]
                $key = Get-Item -LiteralPath $regPath -ErrorAction SilentlyContinue
                if (-not $key -or $key.GetValueNames() -notcontains $valueName) { return '(absent)' }
                $kind = $key.GetValueKind($valueName)
                if ($kind -ne 'DWord') { return "$($key.GetValue($valueName)) (wrong type: $kind)" }
                '0x{0:X}' -f $key.GetValue($valueName)     # explicit 0 prints as 0x0
            }
            $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
            $kdc = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
            $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            [PSCustomObject]@{
                Build          = "$($os.CurrentBuild).$($os.UBR)"
                DDSET          = Read-RegValue $kdc 'DefaultDomainSupportedEncTypes'
                'Filter (Pol)' = Read-RegValue $pol 'SupportedEncryptionTypes'
                'Filter (Lsa)' = Read-RegValue $lsa 'SupportedEncryptionTypes'
                'Phase key'    = Read-RegValue $pol 'RC4DefaultDisablementPhase'
                UseReqEtypes   = Read-RegValue $kdc 'KdcUseRequestedEtypesForTickets'
                Error          = ''
            }
        } | Select-Object @{N = 'DC'; E = { $dc } }, Build, DDSET, 'Filter (Pol)', 'Filter (Lsa)',
        'Phase key', UseReqEtypes, Error
    }
    catch {
        [PSCustomObject]@{ DC = $dc; Build = '?'; DDSET = '?'; 'Filter (Pol)' = '?'
            'Filter (Lsa)' = '?'; 'Phase key' = '?'; UseReqEtypes = '?'
            Error = $_.Exception.Message
        }
    }
}
$state | Format-Table -AutoSize -Wrap
```

How to read the result:

- **`(absent)` and `0x0` are different answers.**  An absent `DDSET` means the KDC uses its
  built-in default for the installed update level; an explicit value replaces that default.
- **Any row with an `Error` is an unknown, not a pass.**  Fix the connection and re-run
  before you rely on the table.
- **Both filter paths are shown** because the KDC does not read them the same way on every
  OS: on the Windows Server 2022 build tested with both set (6-7 April 2026) the Policies
  value won over the Lsa value; the one Windows Server 2025 build tested in the lab
  (26100.32522) honored only the Lsa value.
- **`UseReqEtypes` is `KdcUseRequestedEtypesForTickets`** under `Services\Kdc`.  It should
  read `(absent)` or `0x0` on every DC.
- **Every DC should show the same values.**  These are local registry values; nothing
  replicates them.
