The following query covers all five AD object types that can hold a `servicePrincipalName`
and groups the results by type and current `msDS-SupportedEncryptionTypes` value:

```powershell title="Summary: every SPN-bearing account, grouped by type and msDS-SET value"
Get-ADObject -LDAPFilter '(servicePrincipalName=*)' `
    -Properties sAMAccountName, objectClass, objectCategory, 'msDS-SupportedEncryptionTypes' |
    Where-Object { $_.sAMAccountName -notlike 'krbtgt*' } |
    ForEach-Object {
        $oc = $_.objectClass
        $type = if ($oc -contains 'msDS-DelegatedManagedServiceAccount') { 'dMSA' }
        elseif ($oc -contains 'msDS-GroupManagedServiceAccount') { 'gMSA' }
        elseif ($oc -contains 'msDS-ManagedServiceAccount') { 'MSA' }
        elseif ($oc -contains 'computer') { 'Computer' }
        elseif ($_.objectCategory -like '*Person*') { 'User service account' }
        else { 'Other' }
        [PSCustomObject]@{ Type = $type; SetDec = [int]$_.'msDS-SupportedEncryptionTypes' }
    } |
    Group-Object Type, SetDec |
    Sort-Object { ($_.Group[0]).Type }, { ($_.Group[0]).SetDec } |
    Select-Object Count,
    @{N = 'Type'; E = { ($_.Group[0]).Type } },
    @{N = 'msDS-SET (dec)'; E = { ($_.Group[0]).SetDec } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f ($_.Group[0]).SetDec } } |
    Format-Table -AutoSize
```

`krbtgt` and the `krbtgt_*` accounts are left out: they carry an SPN, stay unset on
purpose, and would otherwise sit in the "User service account" row at `0` for ever.
