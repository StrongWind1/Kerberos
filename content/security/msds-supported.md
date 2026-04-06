---
---

# msDS-SupportedEncryptionTypes

The Active Directory attribute that drives encryption type selection for Kerberos
tickets.  Getting this attribute right on every account is the single most impactful
thing you can do to secure Kerberos in your domain.

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
| TGT ticket encryption | `krbtgt`'s keys (always AES256 on DFL >= 2008) | No |
| TGT session key | Client etype list + KDC config | No |
| Service tickets *to* this user | Never issued (no SPN = no service ticket) | N/A |

Setting `msDS-SupportedEncryptionTypes` on a user account without an SPN has no effect
on Kerberos behavior.  If you find accounts configured this way, the attribute was likely
set by mistake (bulk script that didn't filter by SPN, or leftover config from a removed
SPN).  It is safe to clear.

### Find Non-SPN User Accounts with msDS-SET Configured

```powershell title="Find user accounts without SPNs that have msDS-SupportedEncryptionTypes set (unnecessary)"
Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -like "*"' `
  -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
  Where-Object { -not $_.servicePrincipalName } |
  Select-Object sAMAccountName,
    @{N='msDS-SET (dec)'; E={[int]$_.'msDS-SupportedEncryptionTypes'}},
    @{N='msDS-SET (hex)'; E={'0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes'}},
    Enabled |
  Sort-Object 'msDS-SET (dec)' -Descending |
  Format-Table -AutoSize
```

If the list is non-empty, you can clear the unnecessary attribute:

```powershell title="Clear msDS-SupportedEncryptionTypes from non-SPN user accounts"
Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -like "*"' `
  -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
  Where-Object { -not $_.servicePrincipalName } |
  ForEach-Object {
    Set-ADUser -Identity $_ -Clear 'msDS-SupportedEncryptionTypes'
    Write-Host "Cleared msDS-SET on: $($_.sAMAccountName)"
  }
```

---

## What It Is

`msDS-SupportedEncryptionTypes` is a 32-bit integer attribute on user, computer, Group
Managed Service Account (gMSA), and trust account objects in Active Directory.  It declares
which Kerberos encryption types the account supports.

When the KDC processes a TGS-REQ for a service, it reads this attribute on the **target
account** to determine which etype to use for the service ticket.  If the attribute
is not set (value `0` or absent), the KDC falls back to `DefaultDomainSupportedEncTypes`.

!!! info "This attribute controls ticket encryption, not key generation"
    Setting `msDS-SupportedEncryptionTypes` tells the KDC which etypes to *use*.  It does
    **not** control which keys are generated when the password is set.  AD always generates
    keys for all supported etypes on password change, regardless of this attribute's value.

---

## Bit Flag Reference

The attribute is a bitmask.  Each bit enables one encryption type:

| Bit | Hex | Decimal | Encryption Type | Notes |
|---|---|---|---|---|
| 0 | `0x1` | 1 | DES-CBC-CRC | Removed in Server 2025 |
| 1 | `0x2` | 2 | DES-CBC-MD5 | Removed in Server 2025 |
| 2 | `0x4` | 4 | RC4-HMAC | Deprecated (July 2026) |
| 3 | `0x8` | 8 | AES128-CTS-HMAC-SHA1-96 | Supported since Server 2008 |
| 4 | `0x10` | 16 | AES256-CTS-HMAC-SHA1-96 | **Recommended** |
| 5 | `0x20` | 32 | AES256-CTS-HMAC-SHA1-96-SK | Session key variant (Nov 2022+).  Only honored in `DefaultDomainSupportedEncTypes`. |
| 6-30 | | | Reserved | |
| 31 | `0x80000000` | 2147483648 | Future encryption types | Allows future etypes |

Source: [MS-KILE] section 2.2.7 -- Supported Encryption Types Bit Flags.

---

## Common Composite Values

| Value (Hex) | Value (Dec) | Meaning | Recommendation |
|---|---|---|---|
| `0x0` | 0 | Not set -- falls back to `DefaultDomainSupportedEncTypes` | Risky: RC4 is used by default |
| `0x4` | 4 | RC4 only | **Bad** -- vulnerable to Kerberoasting |
| `0x18` | 24 | AES128 + AES256 | **Recommended** for all SPN-bearing accounts |
| `0x1C` | 28 | RC4 + AES128 + AES256 | Transitional -- still permits RC4 tickets |
| `0x1F` | 31 | DES + RC4 + AES128 + AES256 | Legacy -- includes DES |
| `0x38` | 56 | AES128 + AES256 + AES-SK | Recommended for `DefaultDomainSupportedEncTypes` |
| `0x3C` | 60 | RC4 + AES128 + AES256 + AES-SK | Transitional with AES session keys |

---

## Default Values

### User Accounts

By default, user accounts have `msDS-SupportedEncryptionTypes` **not set** (value 0 or
absent).  This means the KDC uses `DefaultDomainSupportedEncTypes` to decide, which
historically included RC4.

This is why **every user account with an SPN** is vulnerable to Kerberoasting out of the box.
The fix is to explicitly set the attribute to `0x18` (AES only).

### Computer Accounts

Windows machines (Vista / Server 2008 and later) automatically set their own
`msDS-SupportedEncryptionTypes` when they join the domain or process the
*Network security: Configure encryption types allowed for Kerberos* Group Policy.

The typical default for a modern Windows computer account is `0x1C` (28) = RC4 + AES128 +
AES256.

### gMSA Accounts

Group Managed Service Accounts default to `0x1C` (28) = RC4 + AES128 + AES256, and their
auto-generated 240-character passwords make RC4 cracking infeasible regardless.  Set to
`0x18` to eliminate RC4 traffic.

### MSA Accounts

Standalone Managed Service Accounts (`msDS-ManagedServiceAccount`) default to `0x1C`
(28) on Server 2008 R2+ domains, or may show `0` on older deployments.  Like gMSA,
passwords are auto-rotated and uncrackable, but RC4 tickets are still issued unless
`msDS-SupportedEncryptionTypes` is explicitly set to `0x18`.

### dMSA Accounts

Delegated Managed Service Accounts (`msDS-DelegatedManagedServiceAccount`), introduced
in Windows Server 2025, default to `0` (unset) or `0x1C` depending on domain functional
level and the provisioning tool.  Set `msDS-SupportedEncryptionTypes = 0x18` explicitly
after creating each dMSA.

### Pre-Server 2008 Accounts

Accounts created before Server 2008 (or before DFL was raised to 2008) may have **no AES
keys at all**, even if you set `msDS-SupportedEncryptionTypes` to include AES.  The password
must be reset to generate AES keys -- see
[The Double-Reset Problem](algorithms.md#the-double-reset-problem) for why very old accounts need
two resets.

---

## How to View the Attribute

### Single Account

```powershell
# User account
Get-ADUser -Identity svc_sql -Properties msDS-SupportedEncryptionTypes |
  Select-Object Name, msDS-SupportedEncryptionTypes

# Computer account
Get-ADComputer -Identity DC01 -Properties msDS-SupportedEncryptionTypes |
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
    $type = if     ($oc -contains 'msDS-DelegatedManagedServiceAccount') { 'dMSA' }
            elseif ($oc -contains 'msDS-GroupManagedServiceAccount')     { 'gMSA' }
            elseif ($oc -contains 'msDS-ManagedServiceAccount')          { 'MSA' }
            elseif ($oc -contains 'computer')                            { 'Computer' }
            elseif ($_.objectCategory -like '*Person*')                  { 'User service account' }
            else                                                          { 'Other' }
    $set = [int]$_.'msDS-SupportedEncryptionTypes'
    [PSCustomObject]@{
      Type           = $type
      Name           = $_.Name
      'msDS-SET (dec)' = $set
      'msDS-SET (hex)' = '0x{0:X}' -f $set
      SPNs           = ($_.servicePrincipalName | Select-Object -First 2) -join '; '
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
**Account** tab.  Check:

- "This account supports Kerberos AES 128 bit encryption"
- "This account supports Kerberos AES 256 bit encryption"

Uncheck any DES or RC4 options.  This sets `msDS-SupportedEncryptionTypes = 0x18` (24).

### Bulk Update: All SPN-Bearing User Accounts

--8<-- "includes/set-aes-user-accounts.md"

!!! warning "Reset passwords before or after setting AES"
    If an account does not have AES keys (password was never reset after DFL 2008), setting
    `msDS-SupportedEncryptionTypes = 0x18` will cause ticket requests to **fail** because the
    KDC will try to use AES but find no AES keys.  Always reset the password before -- or
    immediately after -- changing this attribute.  Very old accounts may need
    [two resets](algorithms.md#the-double-reset-problem).  To find which accounts lack AES keys, see
    [Auditing Kerberos Keys](account-key-audit.md).

### Bulk Update: All gMSA Accounts

--8<-- "includes/set-aes-gmsa.md"

### Bulk Update: All MSA Accounts

--8<-- "includes/set-aes-msa.md"

### Bulk Update: All dMSA Accounts

--8<-- "includes/set-aes-dmsa.md"

### Bulk Update: Computer Accounts in a Specific OU

```powershell
Get-ADComputer -Filter * `
  -SearchBase "OU=Servers,DC=corp,DC=local" `
  -Properties msDS-SupportedEncryptionTypes |
  Set-ADComputer -KerberosEncryptionType AES128, AES256
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
    $type = if     ($oc -contains 'msDS-DelegatedManagedServiceAccount') { 'dMSA' }
            elseif ($oc -contains 'msDS-GroupManagedServiceAccount')     { 'gMSA' }
            elseif ($oc -contains 'msDS-ManagedServiceAccount')          { 'MSA' }
            elseif ($oc -contains 'computer')                            { 'Computer' }
            elseif ($_.objectCategory -like '*Person*')                  { 'User service account' }
            else                                                          { 'Other' }
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
# User accounts with SPNs and no explicit etype configuration
Get-ADUser -Filter {
  servicePrincipalName -like "*" -and
  (msDS-SupportedEncryptionTypes -eq 0 -or
   msDS-SupportedEncryptionTypes -notlike "*")
} -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
  Select-Object sAMAccountName, servicePrincipalName, msDS-SupportedEncryptionTypes
```

### Accounts with Old Passwords (Likely Missing AES Keys)

--8<-- "includes/old-passwords-query.md"

---

## Edge Cases

### Setting AES Without AES Keys

Setting `msDS-SupportedEncryptionTypes = 0x18` on an account that only has RC4 keys causes
the KDC to fail the ticket request.  The DC logs **Event ID 16** (TGS) or **Event ID 14**
(AS) with text like:

```
The requested etypes were 18 17. The accounts available etypes were 23.
```

**Fix**: Reset the account password to generate AES keys.

### Computer Accounts Update Themselves

Windows computers periodically update their own `msDS-SupportedEncryptionTypes` based on
their local configuration (Group Policy or registry).  If you manually set a value, the
computer may overwrite it after the next policy refresh.  Use Group Policy to manage computer
account etypes rather than setting the attribute directly.

### The RC4 Compatibility Quirk

Per [MS-KILE] section 3.3.5.7, the KDC historically added RC4 (and DES) to the service
account's supported encryption list even if `msDS-SupportedEncryptionTypes` did not include
them.  This was for backward compatibility and meant that setting `msDS-SupportedEncryptionTypes
= 0x18` (AES only) did not always prevent RC4 tickets on older DCs (pre-Server 2019).

On **Server 2019 and later**, the KDC respects the attribute strictly and returns AES tickets
when the attribute specifies AES only.
