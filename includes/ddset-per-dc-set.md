```powershell title="Set DefaultDomainSupportedEncTypes, one DC first (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$Value = 24          # 24 = 0x18 = AES128 + AES256.  $null = remove the value (needs $AllowLegacy).
$DCs = @('dc02.corp.local')   # one canary DC first; the rest only after it has been watched
$AllowLegacy = $false   # $true only to put back an earlier value that contained RC4 or DES
$BackupCsv = ".\ddset-before-$(Get-Date -Format yyyyMMdd-HHmmss).csv"
$DryRun = $true      # $true = read and report only.  Set $false after reviewing the plan.

# ---- Logic: one block, paste it whole or save it as a .ps1 --------------------
& {
    $ErrorActionPreference = 'Stop'
    $name = 'DefaultDomainSupportedEncTypes'
    if ($DryRun -isnot [bool]) {
        throw '$DryRun must be $true or $false: run the settings lines first.'
    }
    if ($null -ne $Value -and ($Value -isnot [int] -or $Value -lt 0)) {
        throw '$Value must be a non-negative number, or $null to remove the value.'
    }
    if ($null -eq $Value -and $AllowLegacy -ne $true) {
        throw '$Value is $null, which REMOVES the value.  That is a rollback: set $AllowLegacy = $true as well.'
    }
    if ($null -ne $Value -and -not $AllowLegacy -and (($Value -band 0x7) -or -not ($Value -band 0x18))) {
        throw '$Value has a DES or RC4 bit, or no AES bit.  Only a rollback may set $AllowLegacy = $true.'
    }
    $targets = @($DCs | Where-Object { $_ })
    if ($targets.Count -eq 0) { throw '$DCs is empty: name at least one domain controller.' }
    if (-not $DryRun -and -not $BackupCsv) {
        throw '$BackupCsv is empty: a real run needs a file for the previous values.'
    }
    $want = if ($null -eq $Value) { '(absent)' } else { '0x{0:X}' -f $Value }
    $read = {
        param($Name)
        $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -ErrorAction Stop
        if ($key.GetValueNames() -notcontains $Name) { '(absent)' }
        elseif ($key.GetValueKind($Name) -ne 'DWord') {
            "wrong type $($key.GetValueKind($Name)): $($key.GetValue($Name))"
        }
        else { '0x{0:X}' -f $key.GetValue($Name) }
    }
    $write = {
        param($Name, $Value)
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
        if ($null -eq $Value) { Remove-ItemProperty -Path $path -Name $Name -ErrorAction Stop }
        else {
            New-ItemProperty -Path $path -Name $Name -PropertyType DWord -Value $Value `
                -Force -ErrorAction Stop | Out-Null
        }
    }
    #
    # ---- Plan: read the current value from every target DC, write nothing ----
    $plan = foreach ($dc in $targets) {
        try {
            $before = Invoke-Command -ComputerName $dc -ScriptBlock $read -ArgumentList $name
            $action = if ("$before" -eq $want) { 'none: already at the target' } else { 'change' }
            [PSCustomObject]@{ DC = $dc; Before = "$before"; Target = $want; Action = $action }
        }
        catch {
            [PSCustomObject]@{ DC = $dc; Before = '?'; Target = $want
                Action = "NOT READ: $($_.Exception.Message)"
            }
        }
    }
    $plan | Format-Table -AutoSize -Wrap | Out-Host
    if (@($plan | Where-Object Action -Like 'NOT READ*').Count -gt 0) {
        throw 'A DC could not be read, so nothing was written.  Fix it or take it out of $DCs.'
    }
    $todo = @($plan | Where-Object Action -EQ 'change')
    if ($todo.Count -eq 0) {
        Write-Information 'Nothing to change.' -InformationAction Continue
        return
    }
    if ($DryRun) {
        Write-Information "Dry run: nothing was written.  $($todo.Count) DC(s) would change." -InformationAction Continue
        return
    }
    #
    # ---- Write: previous values are saved first, then one DC at a time -------
    $plan | Select-Object DC, Before, Target |
        Export-Csv -LiteralPath $BackupCsv -NoTypeInformation -Encoding UTF8 -NoClobber
    $saved = (Resolve-Path -LiteralPath $BackupCsv).Path
    Write-Information "Previous values saved to $saved" -InformationAction Continue
    $stopped = $false
    $result = foreach ($row in $todo) {
        if ($stopped) {
            [PSCustomObject]@{ DC = $row.DC; Before = $row.Before; After = $row.Before
                Result = 'not attempted'
            }
            continue
        }
        try {
            Invoke-Command -ComputerName $row.DC -ScriptBlock $write -ArgumentList $name, $Value
            $after = Invoke-Command -ComputerName $row.DC -ScriptBlock $read -ArgumentList $name
            if ("$after" -ne $want) { throw "read back $after instead of $want" }
            [PSCustomObject]@{ DC = $row.DC; Before = $row.Before; After = "$after"; Result = 'Set' }
        }
        catch {
            $stopped = $true
            [PSCustomObject]@{ DC = $row.DC; Before = $row.Before; After = '?'
                Result = "FAILED: $($_.Exception.Message)"
            }
        }
    }
    $result | Format-Table -AutoSize -Wrap | Out-Host
    if ($stopped) {
        Write-Warning 'Stopped at the first failure.  Check that DC with the per-DC registry check.'
    }
}
```

What the script does:

- **Reads before it writes.**  It prints the current value on every DC in `$DCs` next to
  the target.  If any of them cannot be read, nothing is written anywhere.
- **Dry run by default.**  Only with `$DryRun = $false` does it save the previous values to
  the CSV and then write, one DC at a time, reading each value back.  It stops at the first
  DC that fails, and the DCs after it are listed as `not attempted`.
- **Refuses a value with a DES or RC4 bit, and refuses to remove the value,** unless
  `$AllowLegacy` is set, which exists only for the rollback below.

The KDC reads the value immediately - no restart - so the change is live on a DC the moment
its row says `Set`.  Work in this order:

1. Run it as it is against **one canary DC** and read the plan.
2. Set `$DryRun = $false` and run it again for the canary.  Leave it for a working day and
   watch that DC for failed 4769 events.
3. Then set `$DCs = (Get-ADDomainController -Filter *).HostName`, do a dry run, and a real
   run.  A DC left on a different value gives different answers for the same account
   depending on which DC a client happens to reach.

**Undo.**  The CSV holds each DC's previous value in its `Before` column.  To put one back,
run the same script with `$DCs` set to that DC and `$Value` set to the number from `Before`
(`$null` if it says `(absent)`), plus `$AllowLegacy = $true` if that number contains RC4 or
DES, or if you are removing the value.  It takes effect as immediately as the change did.
A `Before` value of `wrong type ...` cannot be put back with this script, which only writes
a DWORD: the CSV keeps the old type and data for the record.
