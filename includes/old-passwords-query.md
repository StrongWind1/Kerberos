The `Read-only Domain Controllers` group (RID 521) is created when the domain is prepared
for Windows Server 2008 domain controllers - the earliest point at which a password change
can generate AES keys.  An account whose `passwordLastSet` predates that timestamp has no
AES keys.  One set after it may still have none: Microsoft's condition is a domain
functional level of 2008 or higher **and** a password change since
([Event 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)),
and the group can be older than the functional-level raise.  A password written from a
hash instead of being set normally also leaves no AES keys (seen in the lab on build
20348.5020).

```powershell title="Find enabled accounts whose passwords predate AES key generation"
$AESdate = (Get-ADGroup "$((Get-ADDomain).DomainSID)-521" -Properties whenCreated `
        -ErrorAction Stop).whenCreated
Write-Information "AES keys can exist for passwords set after: $AESdate" -InformationAction Continue

$oldPasswords = Get-ADUser -Filter 'Enabled -eq $true' `
    -Properties passwordLastSet, servicePrincipalName, 'msDS-SupportedEncryptionTypes' |
    Where-Object { -not $_.passwordLastSet -or $_.passwordLastSet -lt $AESdate } |
    Select-Object sAMAccountName,
    @{N='PasswordLastSet'; E= { if ($_.passwordLastSet) { $_.passwordLastSet }
            else { '(never set / must change)' } }
    },
    @{N = 'HasSPN'; E = { [bool]$_.servicePrincipalName } },
    @{N = 'msDS-SET'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } }

# SPN-bearing accounts first: those are the ones the KDC issues service tickets for.
$oldPasswords | Sort-Object @{E = 'HasSPN'; Descending = $true }, PasswordLastSet |
    Format-Table -AutoSize
```

This is an **approximation** - it infers key presence from password age instead of reading
the stored keys, so an empty result is not proof that every account has AES keys.  It
reads **user objects only**: computer objects (non-Windows hosts, appliances) and managed
service accounts are not checked.  Accounts that have never had a password set are shown as
`(never set / must change)` rather than silently counted as "old".  For definitive results (event-based and
replication-based methods, including offline `ntds.dit` analysis), see
[Auditing Kerberos Keys](account-key-audit.md).
