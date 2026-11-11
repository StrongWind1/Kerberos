```powershell title="Restore msDS-SupportedEncryptionTypes from a bulk-run backup CSV (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$BackupCsv = '.\msds-set-User-20261110-140000.csv'   # the file the bulk run reported
$DryRun = $true      # $true = show what would be restored. Set $false to write.

# ---- Logic: one block, paste it whole or save it as a .ps1 --------------------
& {
    $ErrorActionPreference = 'Stop'
    $attr = 'msDS-SupportedEncryptionTypes'
    if ($DryRun -isnot [bool]) {
        throw '$DryRun must be $true or $false: run the settings lines first.'
    }
    $rows = @(Import-Csv -LiteralPath $BackupCsv -Encoding UTF8)
    if ($rows.Count -eq 0) { throw "No rows in $BackupCsv." }
    foreach ($column in 'Account', 'ObjectGuid', 'OldValue', 'NewValue') {
        if ($rows[0].PSObject.Properties.Name -notcontains $column) {
            throw "$BackupCsv has no $column column: this script cannot restore from it."
        }
    }
    $result = foreach ($row in $rows) {
        $current = '?'
        try {
            # Found by objectGUID, so a renamed or moved account is still the same row.
            $now = Get-ADObject -Identity $row.ObjectGuid -Properties $attr
            $current = if ($null -ne $now.$attr) { [string][int]$now.$attr } else { '' }
            $action =
            if ($current -eq $row.OldValue) { 'nothing to do: already at the old value' }
            elseif ($current -ne $row.NewValue) {
                'SKIPPED: changed since the bulk run, decide by hand'
            }
            elseif ($row.OldValue -eq '') {
                # the attribute was absent before the run
                Set-ADObject -Identity $row.ObjectGuid -Clear $attr -WhatIf:$DryRun
                if ($DryRun) { 'would clear the attribute' } else { 'restored: attribute cleared' }
            }
            else {
                Set-ADObject -Identity $row.ObjectGuid `
                    -Replace @{ $attr = [int]$row.OldValue } -WhatIf:$DryRun
                if ($DryRun) { 'would restore the old value' } else { 'restored' }
            }
        }
        catch {
            $action = "NOT restored: $($_.Exception.Message)"
        }
        [PSCustomObject]@{
            Account      = $row.Account
            OldValue     = if ($row.OldValue -eq '') { '(unset)' } else { $row.OldValue }
            WrittenByRun = $row.NewValue
            Current      = if ($current -eq '') { '(unset)' } else { $current }
            Action       = $action
        }
    }
    $result | Format-Table -AutoSize -Wrap | Out-Host
}
```

The restore only touches an account whose current value is still the one the bulk run
wrote.  A row marked `SKIPPED` has been changed since - by an administrator, or by the
machine itself in the case of a Windows computer account - and is left as it is; a row
marked `NOT restored` could not be read or written (a deleted account, missing rights).
Rows whose write failed during the bulk run show `nothing to do`.  To undo a restore, run
the bulk script again.
