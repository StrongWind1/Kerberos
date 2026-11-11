---
description: Reference for the msDS-SupportedEncryptionTypes attribute - bit flags, what an unset value means on current domain controllers, per-account-type behavior, and queries to audit and set it.
---

# msDS-SupportedEncryptionTypes

The Active Directory attribute that drives encryption type selection for Kerberos
service tickets.

**What an unset value means today.**  On a domain controller with the April 2026 update or
later, an account whose attribute is blank or `0` is treated as `0x18` (AES128 + AES256),
unless the DC has an explicit `DefaultDomainSupportedEncTypes`.  On an older DC the same
account is treated as `0x27` and gets RC4 tickets (KB5021131; lab-verified on Server 2022
only).  A nonzero value is still worth setting: it makes the result identical on every DC
whatever its patch level, and it is where Microsoft recommends enabling RC4 for a service
that genuinely needs it (KB5073381).

---

## SPN-Bearing Account Types

--8<-- "includes/spn-account-types.md"

---

## Accounts Without SPNs: msDS-SET Does Not Matter { #no-spn-accounts }

The KDC only reads `msDS-SupportedEncryptionTypes` on the **target account** of a
TGS-REQ — the account that owns the SPN the client is requesting a service ticket for.
Regular user accounts without SPNs are never the target of a TGS-REQ, so their
`msDS-SupportedEncryptionTypes` value is never consulted during normal Kerberos
operation.

What **does** affect a non-SPN user's Kerberos experience:

| Kerberos component | What controls it | `msDS-SET` involved? |
|---|---|---|
| Pre-authentication etype | User's stored keys + client etype list | No |
| TGT ticket encryption | `krbtgt`'s keys (AES256 where krbtgt has AES keys) | No |
| TGT session key | Client etype list + KDC config | No |
| Service tickets *to* this user | Never issued (no SPN = no service ticket) | N/A |

Setting `msDS-SupportedEncryptionTypes` on a user account without an SPN has no effect
on Kerberos behavior.  If you find accounts configured this way, the attribute was likely
set by mistake (bulk script that didn't filter by SPN, or leftover config from a removed
SPN).  It is safe to clear.

Microsoft's guidance agrees: "You don't need to set a value for
msDS-SupportedEncryptionTypes for user accounts without a service principal name."  (This
site has not run a dedicated lab test for it.)

### Find Non-SPN User Accounts with msDS-SET Configured

```powershell title="Find user accounts without SPNs that have msDS-SupportedEncryptionTypes set (unnecessary)"
Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -like "*"' `
    -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
    Where-Object { -not $_.servicePrincipalName } |
    Select-Object sAMAccountName,
    @{N = 'msDS-SET (dec)'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes' } },
    Enabled |
    Sort-Object 'msDS-SET (dec)' -Descending |
    Format-Table -AutoSize
```

If the list is non-empty, you can clear the unnecessary attribute.  The script below saves
the old values first and only reports what it would do until you set `$DryRun = $false`.

```powershell title="Clear msDS-SupportedEncryptionTypes from non-SPN user accounts (dry run by default)"
$DryRun = $true
$BackupCsv = ".\msds-set-nonspn-$(Get-Date -Format yyyyMMdd-HHmmss).csv"

$targets = Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -like "*"' `
    -Properties 'msDS-SupportedEncryptionTypes', servicePrincipalName |
    Where-Object {
        -not $_.servicePrincipalName -and # krbtgt has an SPN, so it is skipped here...
        $_.sAMAccountName -notlike 'krbtgt*'       # ...and excluded by name as well
    }

# Record the current values so the change can be reversed
$targets |
    Select-Object DistinguishedName, sAMAccountName,
    @{N = 'OldValue'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } } |
    Export-Csv -Path $BackupCsv -NoTypeInformation

foreach ($u in $targets) {
    try {
        Set-ADUser -Identity $u -Clear 'msDS-SupportedEncryptionTypes' `
            -WhatIf:$DryRun -ErrorAction Stop
        if (-not $DryRun) { Write-Information "Cleared msDS-SET on: $($u.sAMAccountName)" -InformationAction Continue }
    }
    catch {
        Write-Warning "Failed on $($u.sAMAccountName): $($_.Exception.Message)"
    }
}
Write-Information "Old values saved to $BackupCsv" -InformationAction Continue
```

To put a value back, read the CSV and run
`Set-ADUser -Identity <DistinguishedName> -Replace @{'msDS-SupportedEncryptionTypes' = <OldValue>}`
for each row.

---

## What It Is

`msDS-SupportedEncryptionTypes` is a 32-bit integer attribute on user, computer, Group
Managed Service Account (gMSA), and trust account objects in Active Directory.  It declares
which Kerberos encryption types the account supports.

When the KDC processes a TGS-REQ for a service, it reads this attribute on the **target
account** to determine which etype to use for the service ticket.  If the attribute
is not set (value `0` or absent), the KDC uses the DC's `DefaultDomainSupportedEncTypes`
registry value, or a built-in default if that is absent too:

--8<-- "includes/ddset-default-by-build.md"

!!! info "This attribute controls ticket encryption, not key generation"
    Setting `msDS-SupportedEncryptionTypes` tells the KDC which etypes to *use*.  It does
    **not** control which keys are generated when the password is set.  AD generates keys
    for all supported etypes on every password set, regardless of this attribute's value
    (lab: every test account held DES, RC4, AES128 and AES256 keys whatever its attribute).

---

## Bit Flag Reference

The attribute is a 32-bit bitmask.  Bits 0-7 select encryption types and bits 16-19 are
protocol feature flags.

--8<-- "includes/etype-bits.md"

!!! info "Bits 16-19 are not encryption types"
    Bits 16-19 are protocol feature flags, not encryption types.  They are only meaningful
    on the `msDS-SupportedEncryptionTypes` AD attribute.  They have no effect in
    `DefaultDomainSupportedEncTypes` or `SupportedEncryptionTypes` (GPO).  Use the
    [Etype Calculator](etype-calculator.md) to decode composite values that include these flags.

---

## Common Composite Values

--8<-- "includes/etype-values.md"

**Which to use:**

- `0x18` for every SPN-bearing account whose service can accept AES tickets.  This is the
  target state.
- `0x1C` while an account is waiting for a password reset to gain AES keys, or while
  RC4-only clients still need a session key for it.  The ticket is already AES256 if the
  account has AES keys.
- `0x24` only for a service that **cannot decrypt AES tickets** (typically a non-Windows
  device with an RC4-only keytab).  This is Microsoft's recommendation in KB5073381; it
  keeps the ticket RC4 and so keeps the account Kerberoastable.
- Earlier versions of this site recommended `0x3C` as the transitional value for RC4-only
  clients.  Microsoft suggests `0x3C` for the DC-wide default (KB5021131), but its effect
  with a client that offers only RC4 was never lab-tested here, and [MS-KILE] describes the
  `0x20` bit as replacing RC4 session keys with AES, which such a client cannot use.  Treat
  `0x3C` for that purpose as **unverified** and test it before relying on it.

---

## Default Values

### User Accounts

User accounts have `msDS-SupportedEncryptionTypes` **not set** unless an administrator
sets it (Microsoft's KB5021131: user accounts and gMSAs "do not have the
msds-SupportedEncryptionTypes value set automatically").  The KDC therefore applies the
default for unset accounts.

Until the April 2026 update that default included RC4, which is why **every user account
with an SPN** was an RC4 Kerberoasting target: RC4 tickets crack roughly 800 times faster
than AES256 ones.  On a patched DC an unset account now gets AES256.  Setting `0x18`
explicitly still matters, because it removes the dependence on each DC's patch level and on
any `DefaultDomainSupportedEncTypes` override.  An AES256 ticket for a weak human-chosen
password is still crackable, only more slowly.

### Computer Accounts

A supported Windows machine writes its own `msDS-SupportedEncryptionTypes`, based on the
encryption types its Kerberos policy allows (KB5021131).  With no etype policy configured
the value is typically `0x1C` (28) = RC4 + AES128 + AES256; Microsoft's own RC4 guidance
shows a computer account at 28.  In the lab, a DC with every cipher allowed held `0x1F`.
The "typical `0x1C`" figure itself was **not lab-verified** here.

Computer objects that are not Windows machines (NAS filers, Linux hosts joined with a
keytab, pre-staged accounts) do not maintain the attribute.  They hold whatever the joining
tool wrote, often nothing.  Cluster name objects are a different case: Microsoft's
`New-ADServiceAccount` reference warns that "Domain-joined Windows systems and services such
as clustering manage their own msDS-SupportedEncryptionTypes attribute", so a value written
there by hand is overwritten.

### gMSA, MSA and dMSA Accounts

Managed service accounts are **not** self-maintaining: the value is whatever was written
when the account was created, and nothing updates it afterwards (KB5021131 lists gMSAs
among the accounts not set automatically).  In practice `New-ADServiceAccount` creates
gMSAs and standalone MSAs at `0x1C` (28); dMSAs (Server 2025) are reported as either unset
or `0x1C` depending on how they were provisioned.  None of these defaults was lab-verified
on this site, so query your own domain.

At `0x1C` with AES keys present, these accounts already receive **AES256** tickets, and
their random passwords make cracking impractical either way.  Set `0x18` to remove the
RC4 option entirely.

### Accounts Whose Passwords Predate AES

An account whose password was last set before the domain generated AES keys has **no AES
keys at all**, whatever its attribute says.  Reset the password once and verify the keys --
see [Password resets and AES keys](algorithms.md#password-resets-and-aes-keys).

---

## How to View the Attribute

### Single Account

```powershell
# User account
Get-ADUser -Identity svc_sql -Properties msDS-SupportedEncryptionTypes |
    Select-Object Name, msDS-SupportedEncryptionTypes

# Computer account
Get-ADComputer -Identity DC1 -Properties msDS-SupportedEncryptionTypes |
    Select-Object Name, msDS-SupportedEncryptionTypes

# gMSA
Get-ADServiceAccount -Identity gMSA_SQL -Properties msDS-SupportedEncryptionTypes |
    Select-Object Name, msDS-SupportedEncryptionTypes
```

### All SPN-Bearing Accounts — Overview (All 5 Types) { #all-spn-bearing-accounts-overview-all-5-types }

--8<-- "includes/spn-overview-query.md"

### All SPN-Bearing Accounts — Detail List

One row per account with type classification, name, current msDS-SET value, and the
first two SPNs registered on the account:

```powershell title="List all SPN-bearing accounts with type, name, msDS-SET, and SPNs"
Get-ADObject -LDAPFilter '(servicePrincipalName=*)' `
    -Properties objectClass, objectCategory, 'msDS-SupportedEncryptionTypes',
servicePrincipalName |
    ForEach-Object {
        $oc = $_.objectClass
        $type = if ($oc -contains 'msDS-DelegatedManagedServiceAccount') { 'dMSA' }
        elseif ($oc -contains 'msDS-GroupManagedServiceAccount') { 'gMSA' }
        elseif ($oc -contains 'msDS-ManagedServiceAccount') { 'MSA' }
        elseif ($oc -contains 'computer') { 'Computer' }
        elseif ($_.objectCategory -like '*Person*') { 'User service account' }
        else { 'Other' }
        $set = [int]$_.'msDS-SupportedEncryptionTypes'
        [PSCustomObject]@{
            Type             = $type
            Name             = $_.Name
            'msDS-SET (dec)' = $set
            'msDS-SET (hex)' = '0x{0:X}' -f $set
            SPNs             = ($_.servicePrincipalName | Select-Object -First 2) -join '; '
        }
    } |
    Sort-Object Type, Name |
    Format-Table -AutoSize
```

---

## How to Set the Attribute

### Single Account (PowerShell)

```powershell title="Set AES-only on a single user account and verify"
# Set to AES-only (recommended)
Set-ADUser -Identity svc_sql -Replace @{
    'msDS-SupportedEncryptionTypes' = 24
}

# Verify
Get-ADUser -Identity svc_sql -Properties msDS-SupportedEncryptionTypes |
    Select-Object Name, msDS-SupportedEncryptionTypes
```

### Single Account (GUI)

In **Active Directory Users and Computers** (ADUC), open the account properties and go to the
**Account** tab.  Under *Account options*, check:

- "This account supports Kerberos AES 128 bit encryption"
- "This account supports Kerberos AES 256 bit encryption"

These two boxes set the AES128 and AES256 bits of `msDS-SupportedEncryptionTypes`.  ADUC has
**no RC4 checkbox**, so it cannot clear an RC4 bit that is already set: check the resulting
value in the Attribute Editor tab, or use PowerShell, to confirm it is `0x18` (24).  Leave
"Use only Kerberos DES encryption types for this account" unchecked; that box is the
`UF_USE_DES_KEY_ONLY` account flag, not part of this attribute.

### Bulk Update: All SPN-Bearing User Accounts

--8<-- "includes/set-aes-user-accounts.md"

!!! warning "Confirm AES keys exist first"
    If an account has no AES keys, setting `msDS-SupportedEncryptionTypes = 0x18` makes
    ticket requests for it **fail** with `KDC_ERR_ETYPE_NOSUPP`; the KDC does not fall back
    to RC4.  Find those accounts with [Auditing Kerberos Keys](account-key-audit.md) and
    reset their passwords **before** changing the attribute
    ([one reset, then verify](algorithms.md#password-resets-and-aes-keys)).

### Bulk Update: All gMSA Accounts

--8<-- "includes/set-aes-gmsa.md"

### Bulk Update: All MSA Accounts

--8<-- "includes/set-aes-msa.md"

### Bulk Update: All dMSA Accounts

--8<-- "includes/set-aes-dmsa.md"

### Setting Computer Accounts

**Windows machines:** do not write the attribute directly.  The machine rewrites it from its
own Kerberos etype policy, so set the policy instead -- see
[Group Policy](group-policy.md#computer-accounts-auto-update).

**Non-Windows computer objects** (filers, Linux hosts, appliances) do not maintain the
attribute, so it has to be set by hand, one OU at a time, after confirming the device has
AES keys in its keytab.  Never run this against the whole domain: it would also hit domain
controllers, cluster objects and Entra-related objects.

```powershell title="Set AES-only on non-Windows computer objects in one OU (dry run by default)"
$DryRun = $true
Get-ADComputer -Filter 'OperatingSystem -notlike "Windows*"' `
    -SearchBase "OU=Appliances,DC=corp,DC=local" `
    -Properties 'msDS-SupportedEncryptionTypes', OperatingSystem |
    ForEach-Object {
        $old = [int]$_.'msDS-SupportedEncryptionTypes'
        # Keep any feature-flag bits (16-19); replace only the cipher bits
        $new = ($old -band (-bnot 0xFF)) -bor 0x18
        Write-Information ("{0}: 0x{1:X} -> 0x{2:X}" -f $_.Name, $old, $new) -InformationAction Continue
        Set-ADComputer -Identity $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = $new } `
            -WhatIf:$DryRun
    }
```

---

## Auditing: Find RC4-Dependent Accounts

### Accounts with RC4 Enabled

```powershell
# User accounts where RC4 bit (0x4) is set
Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -band 4' `
    -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
    Select-Object sAMAccountName, msDS-SupportedEncryptionTypes, servicePrincipalName
```

The query above covers user accounts only.  For a cross-type view of every SPN-bearing
account with the RC4 bit set, use the LDAP bitwise filter below — it works against all
five account types simultaneously.

### All SPN-Bearing Accounts with RC4 Enabled (All Types)

The LDAP extensible match rule `1.2.840.113556.1.4.803` performs a bitwise AND, so
this filter matches any account where bit 2 (RC4, value 4) is set and an SPN is registered:

```powershell title="Find all SPN-bearing accounts with the RC4 bit set, across all five account types"
Get-ADObject `
    -LDAPFilter '(&(servicePrincipalName=*)(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4))' `
    -Properties objectClass, objectCategory, 'msDS-SupportedEncryptionTypes',
servicePrincipalName |
    ForEach-Object {
        $oc = $_.objectClass
        $type = if ($oc -contains 'msDS-DelegatedManagedServiceAccount') { 'dMSA' }
        elseif ($oc -contains 'msDS-GroupManagedServiceAccount') { 'gMSA' }
        elseif ($oc -contains 'msDS-ManagedServiceAccount') { 'MSA' }
        elseif ($oc -contains 'computer') { 'Computer' }
        elseif ($_.objectCategory -like '*Person*') { 'User service account' }
        else { 'Other' }
        [PSCustomObject]@{
            Type             = $type
            Name             = $_.Name
            'msDS-SET (dec)' = [int]$_.'msDS-SupportedEncryptionTypes'
            'msDS-SET (hex)' = '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes'
        }
    } |
    Sort-Object Type, Name |
    Format-Table -AutoSize
```

### Accounts with No Value Set (Using Domain Default)

```powershell title="Find SPN-bearing user accounts with no explicit etype configuration"
# User accounts with an SPN whose attribute is absent or 0
Get-ADUser `
    -LDAPFilter '(&(servicePrincipalName=*)(|(!(msDS-SupportedEncryptionTypes=*))(msDS-SupportedEncryptionTypes=0)))' `
    -Properties 'msDS-SupportedEncryptionTypes', servicePrincipalName |
    Where-Object { $_.sAMAccountName -notlike 'krbtgt*' } |
    Select-Object sAMAccountName,
    @{N = 'msDS-SET'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'SPNs'; E = { ($_.servicePrincipalName | Select-Object -First 2) -join '; ' } }
```

The `krbtgt` account also has an SPN and an unset attribute.  That is its normal state;
leave it alone.

### Accounts with Old Passwords (Likely Missing AES Keys)

--8<-- "includes/old-passwords-query.md"

---

## Edge Cases

### Setting AES Without AES Keys

Setting `msDS-SupportedEncryptionTypes = 0x18` on an account that only has RC4 keys causes
the KDC to fail the ticket request.  On a DC with the April 2026 update the same happens to
an **unset** account without AES keys, because it is now treated as `0x18`.  The DC logs
**Event ID 16** (TGS) or **Event ID 14** (AS) with text like:

```
The requested etypes were 18 17. The accounts available etypes were 23.
```

Measured on the enforcing build (20348.5020) for an account holding only an RC4 key:

| Attribute | Result |
|---|---|
| `0x18` | `KDC_ERR_ETYPE_NOSUPP` — no fallback to RC4 |
| unset | `KDC_ERR_ETYPE_NOSUPP` |
| `0x1C` | RC4 ticket |
| `0x04` | RC4 ticket |

**Fix**: Reset the account password to generate AES keys.  `0x1C` keeps the service working
until then.

### Computer Accounts Update Themselves

Windows computers write their own `msDS-SupportedEncryptionTypes` from their local
Kerberos etype configuration (Group Policy or registry); Microsoft's guidance is that the
machine updates the attribute when it restarts.  A value you set by hand on a Windows
computer account should therefore be expected to be overwritten.  Use Group Policy to manage
Windows computer account etypes rather than setting the attribute directly.  (How quickly a
manual value is overwritten was not lab-tested.)

### The RC4 Compatibility Quirk

Before the November 2022 updates, the KDC did not treat the attribute as exact.  Microsoft's
KB5021131 describes environments that "might have previously been functional due to
automatically adding RC4 or by the addition of AES", and says that since those updates the
KDC "will now strictly follow what is set in the registry keys,
msds-SupportedEncryptionTypes and DefaultDomainSupportedEncTypes."  So on any DC patched
since November 2022, an AES-only attribute yields an AES ticket.

One loosening remained until 2026, and it concerns the **session key**, not the ticket.  On
the pre-April 2026 lab build, an AES-only account requested by an RC4-only client still got
its AES256 ticket, with an RC4 session key.  On the enforcing build the same request is
refused (Kdcsvc 208).  Also on pre-enforcement builds, `KdcUseRequestedEtypesForTickets = 1`
could force an RC4 **ticket** for an AES-only account; on the enforcing build it could not.

### The USE_DES_KEY_ONLY Override

The `UF_USE_DES_KEY_ONLY` flag (`0x200000` / 2097152) in `UserAccountControl` restricts the
account to **DES keys only**.  This is a legacy flag from the Windows 2000 / Server 2003
era that predates the `msDS-SupportedEncryptionTypes` attribute entirely
([MS-ADTS] §2.2.16).

How the flag ranks against `msDS-SupportedEncryptionTypes` is not settled.  [MS-KILE]
section 3.3.5.7 has the KDC look at the flag only when the account's supported encryption
types are **not** populated ("If not, the KDC SHOULD check the server or service account's
UseDESOnly flag"); with the flag set it then reports the account's supported etypes as
`0x3`.  The same section says "DES MUST NOT be used to protect the service ticket" and "If DES is
the only configured etype, the KDC MUST return KDC_ERR_ETYPE_NOTSUPP".  The lab results do
not agree with each other, and only the earlier one matches that text.  On Server 2022
build 20348.5020 a
flagged account was issued a **DES service ticket** (Event 4769 ticket etype `0x3`,
supported etypes `0x3`); the notes for that run say the flag overrode
`msDS-SupportedEncryptionTypes` but do not record the attribute's value.  An earlier run on
the pre-April build, on an unset account, recorded a failure instead.  Treat the outcome as
unpredictable and clear the flag wherever you find it.  Microsoft has removed DES from
Server 2025, so such accounts should be expected to fail against Server 2025 DCs; this site
has not tested that.

```powershell title="Find accounts with USE_DES_KEY_ONLY set"
# UF_USE_DES_KEY_ONLY = 0x200000 = 2097152
Get-ADUser -Filter 'UserAccountControl -band 2097152' `
    -Properties UserAccountControl, msDS-SupportedEncryptionTypes, servicePrincipalName |
    Select-Object sAMAccountName,
    @{N = 'UAC (hex)'; E = { '0x{0:X}' -f $_.UserAccountControl } },
    @{N = 'msDS-SET'; E = { $_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'HasSPN'; E = { [bool]$_.servicePrincipalName } },
    Enabled |
    Format-Table -AutoSize
```

**Remediation**: clear the flag on every account found:

```powershell title="Clear USE_DES_KEY_ONLY on one account"
# Replace svc_legacy with the account name
Set-ADAccountControl -Identity 'svc_legacy' -UseDESKeyOnly $false
```

After clearing the flag, reset the account password to generate fresh AES keys, then set
`msDS-SupportedEncryptionTypes = 0x18`.
