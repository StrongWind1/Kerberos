# ---- Logic: no edits needed below this line ----------------------------------
# One block on purpose: paste the whole script, or save it as a .ps1 and run that.
# Every check below throws when it fails, and nothing after a throw runs.
& {
    $ErrorActionPreference = 'Stop'
    $attr = 'msDS-SupportedEncryptionTypes'
    #
    # ---- Checks on the settings ----------------------------------------------
    if ($DryRun -isnot [bool]) {
        throw '$DryRun must be $true or $false: run the settings header first.'
    }
    if ($Target -isnot [int] -or ($Target -band (-bnot 0x3F))) {
        throw '$Target must be a number that contains only etype bits 0-5 (0x3F).'
    }
    if (-not ($Target -band 0x18)) {
        throw '$Target has no AES bit (0x8, 0x10): this script only writes AES-capable values.'
    }
    if ($null -eq $OnlyFrom -or @($OnlyFrom).Count -eq 0) {
        throw '$OnlyFrom is empty: list the current values this run may replace.'
    }
    if (-not $DryRun -and -not $BackupCsv) {
        throw '$BackupCsv is empty: a real run needs a file for the old values.'
    }
    $ldap = switch ($AccountType) {
        'User' { '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' }
        'gMSA' { '(objectClass=msDS-GroupManagedServiceAccount)' }
        'MSA' { '(objectClass=msDS-ManagedServiceAccount)' }
        'dMSA' { '(objectClass=msDS-DelegatedManagedServiceAccount)' }
        'Computer' { '(&(objectCategory=computer)(objectClass=computer))' }
        default { throw "Unknown `$AccountType '$AccountType'" }
    }
    $domain = Get-ADDomain
    if (-not $SearchBase) { $SearchBase = $domain.DistinguishedName }
    if ($AccountType -eq 'Computer' -and $SearchBase -eq $domain.DistinguishedName) {
        throw 'Computer accounts must be scoped: set $SearchBase to an OU, not the domain root.'
    }
    if ($AccountType -eq 'Computer' -and -not $OperatingSystemLike) {
        throw '$OperatingSystemLike is empty: set it to the operatingSystem pattern to include.'
    }
    #
    # AES keys can only exist for passwords set after this date (RID 521 heuristic).
    # A newer password is NOT proof that AES keys exist: only a key audit shows that.
    $aesDate = (Get-ADGroup "$($domain.DomainSID)-521" -Properties whenCreated).whenCreated
    if ($aesDate -isnot [datetime]) {
        throw 'Could not read when the RID 521 group was created: the password-age check cannot run.'
    }
    $aesDate = $aesDate.ToUniversalTime()
    #
    $skipNames = @($Exceptions)
    if ($ExceptionGroup) {
        $skipNames += @(Get-ADGroupMember -Identity $ExceptionGroup -Recursive).SamAccountName
    }
    #
    # ---- Plan: read everything, decide per account, write nothing ------------
    $props = 'sAMAccountName', $attr, 'pwdLastSet', 'primaryGroupID', 'operatingSystem', 'servicePrincipalName'
    $found = Get-ADObject -LDAPFilter $ldap -SearchBase $SearchBase -SearchScope Subtree `
        -Properties $props
    $plan = foreach ($o in $found) {
        $old = [int]$o.$attr                       # unset reads as 0
        $pwdSet = if ($o.pwdLastSet -gt 0) { [datetime]::FromFileTimeUtc($o.pwdLastSet) }
        $isComp = $AccountType -eq 'Computer'
        $skip =
        if ($o.sAMAccountName -like 'krbtgt*') { 'krbtgt account: never changed here' }
        elseif ($skipNames -contains $o.sAMAccountName) { 'listed exception' }
        elseif ($isComp -and $o.primaryGroupID -in 516, 521) { 'domain controller or RODC' }
        elseif ($isComp -and $o.Name -in 'AZUREADSSOACC', 'AzureADKerberos') {
            'Entra ID Kerberos object'
        }
        elseif ($isComp -and @($o.servicePrincipalName) -like 'MSClusterVirtualServer/*') {
            'failover-cluster CNO/VCO'
        }
        elseif ($isComp -and $o.operatingSystem -notlike $OperatingSystemLike) {
            "operatingSystem '$($o.operatingSystem)' does not match '$OperatingSystemLike'"
        }
        elseif ($old -notin $OnlyFrom) { 'current value {0} (0x{0:X}) is not in $OnlyFrom' -f $old }
        elseif (-not $pwdSet) { 'password never set: no keys to rely on' }
        elseif ($pwdSet -lt $aesDate) { 'password predates AES keys: reset it first' }
        [PSCustomObject]@{
            Account           = $o.sAMAccountName
            OldValue          = if ($null -ne $o.$attr) { $old }   # empty = attribute was absent
            NewValue          = ($old -band (-bnot 0x3F)) -bor $Target   # keeps feature bits 16-19
            PasswordLastSet   = $pwdSet
            SkipReason        = $skip
            ObjectGuid        = [string]$o.ObjectGUID  # survives a rename or a move
            DistinguishedName = $o.DistinguishedName
        }
    }
    $todo = @($plan | Where-Object { -not $_.SkipReason })
    $skipped = @($plan | Where-Object SkipReason)
    Write-Information "Skipped: $($skipped.Count) account(s)" -InformationAction Continue
    $skipped | Sort-Object SkipReason, Account |
        Format-Table Account, OldValue, SkipReason -AutoSize | Out-Host
    Write-Information "Planned changes: $($todo.Count) account(s) under $SearchBase" -InformationAction Continue
    $todo | Sort-Object Account |
        Format-Table Account, @{N = 'OldValue'; E = { if ($null -eq $_.OldValue) { '(unset)' } else { $_.OldValue } } },
        NewValue, PasswordLastSet -AutoSize | Out-Host
    if ($todo.Count -eq 0) { return }
    #
    # ---- Write: only when $DryRun is $false ----------------------------------
    if (-not $DryRun) {
        # Old values are saved BEFORE anything is written.  An existing file is never
        # overwritten, and if the file cannot be written the run stops here.
        $todo | Select-Object Account, ObjectGuid, OldValue, NewValue, PasswordLastSet, DistinguishedName |
            Export-Csv -LiteralPath $BackupCsv -NoTypeInformation -Encoding UTF8 -NoClobber
        $saved = (Resolve-Path -LiteralPath $BackupCsv).Path
        Write-Information "Old values saved to $saved" -InformationAction Continue
    }
    $failed = 0
    foreach ($row in $todo) {
        try {
            Set-ADObject -Identity $row.ObjectGuid -Replace @{ $attr = $row.NewValue } -WhatIf:$DryRun
            if (-not $DryRun) {
                Write-Information "Updated $($row.Account): $([int]$row.OldValue) -> $($row.NewValue)" -InformationAction Continue
            }
        }
        catch {
            $failed++
            Write-Warning "NOT updated $($row.Account): $($_.Exception.Message)"
        }
    }
    if ($DryRun) {
        Write-Information 'Dry run: nothing was written and no backup file was created.' -InformationAction Continue
    }
    else {
        Write-Information "Done: $($todo.Count - $failed) updated, $failed failed.  To undo, run the restore script with $saved" -InformationAction Continue
    }
}
