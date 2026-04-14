---
---

# Standardization Guide

This is the operational playbook for moving a domain to AES Kerberos encryption.
Every setting, every command, every verification step.

Two deployment paths are covered, based on whether all accounts have AES keys:

1. **[Path 1: Modern AES-Only](#path-1-modern-aes-only-environment)** -- every account
   has AES keys, RC4 is fully disabled.  The target state for all domains.
2. **[Path 2: AES Opportunistic with RC4 Fallback](#path-2-aes-opportunistic-with-rc4-fallback)** --
   all manually-managed SPN-bearing accounts and computer accounts use AES, but some regular user accounts
   (no SPNs) lack AES keys and their passwords cannot be reset yet.  RC4 remains enabled
   solely for those users' pre-authentication.

Both paths disable DES entirely.  Steps 1-3 and Step 5 are shared.  The paths diverge at
the workstation/server GPO (Step 4) and the Domain Controllers GPO (Step 6).

---

## What Affects Encryption

Five things determine which encryption type ends up in a Kerberos ticket.  Every one
must be correct for AES to work.  For the exhaustive 12-input reference (including
auto-derived values), see the
[Etype Decision Guide — All the Inputs](etype-decision-guide.md#all-the-inputs).

### 1. krbtgt account keys

The `krbtgt` account encrypts every TGT in the domain.  If `krbtgt` lacks AES keys
(password never rotated since DFL was raised to 2008), the KDC cannot issue AES-encrypted
TGTs regardless of any other setting.  Rotate the `krbtgt` password **twice** -- once to
generate AES keys, once to push the old key into the password history so both DCs in an
RODC scenario have a clean state.

### 2. Kerberos GPO (`SupportedEncryptionTypes`)

The *Network security: Configure encryption types allowed for Kerberos* GPO writes the
`SupportedEncryptionTypes` registry value and does two things depending on where it is
applied:

- **On workstations and member servers**: controls which etypes the Kerberos client
  advertises in AS-REQ and TGS-REQ.  It also auto-updates the computer account's
  `msDS-SupportedEncryptionTypes` in AD so the KDC knows what the machine supports.
- **On domain controllers**: does the same client-side work **and** acts as a hard KDC
  filter -- the KDC will not issue a ticket with an etype the GPO does not allow, even if
  the target account supports it.

You typically apply **two separate GPOs**: one for the Domain Controllers OU and one for
workstation/server OUs.  They can have different etype selections (for example, the DC GPO
may need to keep RC4 while legacy users exist -- see
[Path 2](#path-2-aes-opportunistic-with-rc4-fallback)).

### 3. `DefaultDomainSupportedEncTypes` (KDC fallback)

A per-DC registry value at `HKLM\SYSTEM\CurrentControlSet\Services\KDC`.  When a target
account has `msDS-SupportedEncryptionTypes = 0` (not set), the KDC uses this value
instead.  It is **not** replicated -- you must set it on every DC individually, and verify
every DC has the same value.

If neither `msDS-SupportedEncryptionTypes` nor `DefaultDomainSupportedEncTypes` is set,
the KDC internal default depends on the patch level:

- **Before April 2026 (KB5078763)**: `0x27` (DES + RC4 + AES-SK), which includes RC4.
- **After April 2026 (KB5078763)**: `0x18` (AES-only).  The enforcement phase is active
  by default with no key present; RC4 is blocked for unconfigured accounts.

In either case, setting an explicit `DefaultDomainSupportedEncTypes` on the DC controls
the fallback for accounts with `msDS-SET = 0` — *except* that under the April 2026
enforcement, DDSET values that include RC4 do not re-enable RC4 for unconfigured accounts.
The enforcement override takes precedence over DDSET.

### 4. `msDS-SupportedEncryptionTypes` on manually-managed SPN-bearing accounts

The Kerberos GPO handles computer accounts automatically (it writes the registry, and the
machine updates its own AD attribute).  **All other SPN-bearing account types are not
covered by GPO** and must be managed manually.  This includes user service accounts,
gMSA, MSA, and dMSA — for any of these, you must set `msDS-SupportedEncryptionTypes`
via PowerShell or ADUC.  See the [account type taxonomy](../index.md#spn-bearing-account-types)
for the full breakdown of defaults and targets.

This is the single most common miss in AES migrations: the account gets a
password reset (AES keys exist) but nobody sets the attribute, so the KDC still treats
it as `0x27` and issues RC4 tickets.  gMSA and MSA accounts are particularly easy to
overlook because their uncrackable passwords create a false sense of security — RC4
traffic is still generated even when cracking is infeasible.

### 5. Account password (keys in `ntds.dit`)

None of the above matters if the account does not physically have AES keys stored in the
database.  AES keys are generated when a password is set while the domain functional level
is 2008 or higher.  Accounts whose passwords predate that DFL have only RC4 and DES keys.
Setting `msDS-SupportedEncryptionTypes = 0x18` on such an account causes ticket requests
to **fail** -- the KDC tries AES, finds no AES key, and returns `KDC_ERR_ETYPE_NOSUPP`.

Reset the password to generate AES keys.  For accounts created before DFL 2008, reset
**twice** (once to generate AES keys in `KerberosNew`, once to promote them to
`Kerberos`).  See [Auditing Kerberos Keys](account-key-audit.md) to find which accounts
are affected.

### Summary table

| Setting | Path / Location | Scope | Affects Ticket Etype | Affects Session Key | Set By |
|---|---|---|---|---|---|
| `krbtgt` password | AD account | Domain-wide (all TGTs) | **YES** | **YES** | Password rotation |
| `SupportedEncryptionTypes` (GPO) | `HKLM\SOFTWARE\...\Kerberos\Parameters` | Per-machine | **YES** (hard filter on DC; client etype list elsewhere) | **YES** | GPO |
| `DefaultDomainSupportedEncTypes` | `HKLM\SYSTEM\...\Services\KDC` | Per-DC | **YES** (fallback for msDS-SET=0) | **YES** (AES-SK via bit `0x20`) | Manual / GPP |
| `msDS-SupportedEncryptionTypes` | AD attribute on each account | Per-account | **YES** (primary) | **YES** | PowerShell / ADUC (user accounts); auto-set by GPO (computer accounts) |
| Account password (keys in ntds.dit) | `ntds.dit` | Per-account | **YES** (must have key) | **YES** | Password reset |
| `RC4DefaultDisablementPhase` | `HKLM\SOFTWARE\...\Kerberos\Parameters` | Per-DC | **YES** (overrides internal default for TGS) | **NO** | Windows Update / manual |

!!! note "What appears in Event 4769"
    `msDS-SupportedEncryptionTypes`, `DefaultDomainSupportedEncTypes`, and
    `SupportedEncryptionTypes` (GPO) all appear in Event 4769 fields.
    `RC4DefaultDisablementPhase` changes the KDC's internal behavior but is not
    reflected in the event.  The account's stored keys appear in the `Available Keys`
    field.

**klist field mapping:**

- `KerbTicket Encryption Type` = ticket etype (the algorithm used to encrypt the ticket's `enc-part`)
- `Session Key Type` = session etype (the algorithm for the session key shared between client and service)

---

## Step 1: Audit Current State

Before changing anything, understand what your domain looks like today.

### SPN-bearing user accounts

User accounts with SPNs (objectCategory=person) are the primary Kerberoasting target —
their human-set passwords make cracked RC4 tickets actionable.  Start with a summary of
every distinct `msDS-SupportedEncryptionTypes` value to see what you are working with:

```powershell title="Summary: group SPN-bearing user accounts by msDS-SupportedEncryptionTypes value"
# Summary: group SPN-bearing user accounts by msDS-SupportedEncryptionTypes
Get-ADUser -Filter 'servicePrincipalName -like "*"' `
  -Properties 'msDS-SupportedEncryptionTypes' |
  Group-Object { [int]$_.'msDS-SupportedEncryptionTypes' } |
  Sort-Object Count -Descending |
  Select-Object Count,
    @{N='msDS-SET (dec)'; E={[int]$_.Name}},
    @{N='msDS-SET (hex)'; E={'0x{0:X}' -f [int]$_.Name}} |
  Format-Table -AutoSize
```

A healthy domain shows every account at `24` (`0x18` -- AES128 + AES256).  Anything else
needs investigation.  Common values and what they mean:

| Value | Hex | Meaning |
|---|---|---|
| `0` | `0x0` | Not set — after April 2026 (KB5078763), RC4 is **blocked** by default.  Before that patch, fell back to DDSET or internal default `0x27`. |
| `4` | `0x4` | RC4-only (explicit) |
| `7` | `0x7` | DES + RC4 |
| `24` | `0x18` | AES128 + AES256 (target) |
| `28` | `0x1C` | RC4 + AES128 + AES256 (transitional -- still allows RC4 tickets) |
| `31` | `0x1F` | DES + RC4 + AES128 + AES256 + AES-SK (GPO auto-set default on computer accounts) |

To list every SPN-bearing user account that does **not** have your target value, set
`$target` and run:

```powershell title="Detail: all SPN-bearing user accounts not at the target msDS-SET value"
# Detail: all SPN-bearing user accounts where msDS-SET != target
$target = 24  # ← set to your target value (24 = 0x18, AES-only)

Get-ADUser -Filter 'servicePrincipalName -like "*"' `
  -Properties servicePrincipalName, 'msDS-SupportedEncryptionTypes', passwordLastSet |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
  Sort-Object { [int]$_.'msDS-SupportedEncryptionTypes' }, passwordLastSet |
  Select-Object sAMAccountName,
    @{N='msDS-SET (dec)'; E={[int]$_.'msDS-SupportedEncryptionTypes'}},
    @{N='msDS-SET (hex)'; E={'0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes'}},
    passwordLastSet,
    @{N='SPNs'; E={($_.servicePrincipalName | Select-Object -First 2) -join '; '}} |
  Format-Table -AutoSize
```

### Managed service accounts (gMSA, MSA, dMSA)

gMSA, MSA, and dMSA accounts need `msDS-SupportedEncryptionTypes` set manually just like
user service accounts.  Their auto-rotating passwords eliminate the cracking risk, but
RC4 tickets are still issued unless the attribute is explicitly set to `0x18`.  A grouped
summary across all three types:

```powershell title="Summary: group managed service accounts by type and msDS-SET value"
Get-ADObject `
  -LDAPFilter '(&(servicePrincipalName=*)(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-DelegatedManagedServiceAccount)))' `
  -Properties objectClass, 'msDS-SupportedEncryptionTypes' |
  ForEach-Object {
    $oc = $_.objectClass
    $type = if     ($oc -contains 'msDS-DelegatedManagedServiceAccount') { 'dMSA' }
            elseif ($oc -contains 'msDS-GroupManagedServiceAccount')     { 'gMSA' }
            else                                                          { 'MSA' }
    [PSCustomObject]@{ Type = $type; SetDec = [int]$_.'msDS-SupportedEncryptionTypes' }
  } |
  Group-Object Type, SetDec |
  Sort-Object { ($_.Group[0]).Type }, { ($_.Group[0]).SetDec } |
  Select-Object Count,
    @{N='Type';           E={ ($_.Group[0]).Type }},
    @{N='msDS-SET (dec)'; E={ ($_.Group[0]).SetDec }},
    @{N='msDS-SET (hex)'; E={ '0x{0:X}' -f ($_.Group[0]).SetDec }} |
  Format-Table -AutoSize
```

### Cross-type overview (all 5 account types)

To see the full picture across every SPN-bearing account type in the domain:

--8<-- "includes/spn-overview-query.md"

### Computer accounts

Computer accounts get their `msDS-SupportedEncryptionTypes` auto-updated by the Kerberos
GPO, so in a well-configured domain these should all be the same value.  Differences
indicate machines that have not applied the GPO (offline, misconfigured OU, GPO
inheritance blocked).

```powershell title="Summary: group all computer accounts by msDS-SET value"
# Summary: group all computer accounts by msDS-SupportedEncryptionTypes
Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
  Group-Object { [int]$_.'msDS-SupportedEncryptionTypes' } |
  Sort-Object Count -Descending |
  Select-Object Count,
    @{N='msDS-SET (dec)'; E={[int]$_.Name}},
    @{N='msDS-SET (hex)'; E={'0x{0:X}' -f [int]$_.Name}} |
  Format-Table -AutoSize
```

To list every computer that does **not** have your target value:

```powershell title="Detail: all computer accounts not at the target msDS-SET value"
# Detail: all computer accounts where msDS-SET != target
$target = 31  # ← set to your target value (31 = 0x1F, typical GPO auto-set)

Get-ADComputer -Filter * `
  -Properties 'msDS-SupportedEncryptionTypes', passwordLastSet |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
  Sort-Object { [int]$_.'msDS-SupportedEncryptionTypes' }, passwordLastSet |
  Select-Object Name,
    @{N='msDS-SET (dec)'; E={[int]$_.'msDS-SupportedEncryptionTypes'}},
    @{N='msDS-SET (hex)'; E={'0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes'}},
    passwordLastSet |
  Format-Table -AutoSize
```

!!! tip "Why computer accounts show `31` (`0x1F`) instead of `24` (`0x18`)"
    When the Kerberos GPO checks only the AES128 and AES256 boxes, it writes
    `0x7FFFFFFF` to the registry.  The machine's Kerberos subsystem then updates its own
    AD attribute with `0x1F` (DES + RC4 + AES128 + AES256 + AES-SK) -- the high bits are
    stripped but the low bits include more than just what you checked.  This is normal.
    The DC GPO acts as the hard filter that prevents RC4/DES tickets from actually being
    issued, even though the computer account advertises them.

### Find accounts missing AES keys

See [Auditing Kerberos Keys](account-key-audit.md) for the full guide covering four
methods -- from a quick PowerShell estimate to definitive offline extraction with
ntdissector.  The results of that audit determine which path you follow:

- **Zero accounts missing AES keys** → use [Path 1](#path-1-modern-aes-only-environment)
- **Some regular users (no SPNs) missing AES keys** → use [Path 2](#path-2-aes-opportunistic-with-rc4-fallback)

Accounts without SPNs are **not** vulnerable to Kerberoasting.  Their only RC4 exposure
is pre-authentication (AS exchange).

### Check current DC registry state

`DefaultDomainSupportedEncTypes` and `SupportedEncryptionTypes` are **per-DC** values --
they are not replicated.  Check every DC individually:

```powershell title="Check DefaultDomainSupportedEncTypes and GPO etype settings on every DC"
(Get-ADDomainController -Filter *).HostName | ForEach-Object {
    $dc = $_
    $kdc = Invoke-Command -ComputerName $dc -ScriptBlock {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC' -EA 0).DefaultDomainSupportedEncTypes
    }
    $gpo = Invoke-Command -ComputerName $dc -ScriptBlock {
        (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -EA 0).SupportedEncryptionTypes
    }
    [PSCustomObject]@{
        DC                                = $dc
        'DefaultDomain (dec)'             = [int]$kdc
        'DefaultDomain (hex)'             = if ($kdc) { '0x{0:X}' -f [int]$kdc } else { '(not set)' }
        'GPO SupportedEncTypes (dec)'     = [int]$gpo
        'GPO SupportedEncTypes (hex)'     = if ($gpo) { '0x{0:X}' -f [int]$gpo } else { '(not set)' }
    }
} | Format-Table -AutoSize
```

!!! warning "Values may differ between DCs"
    Because these are local registry values, each DC can have a different value.
    A DC that missed a GPO refresh or was rebuilt from a different image may be out of
    sync.  Always verify every DC.

### Check current GPO state

Rather than checking the registry on individual machines, scan SYSVOL directly to find
**every GPO in the domain** that sets the Kerberos encryption type policy.  This is the
same approach [PingCastle](https://www.pingcastle.com/) uses ("list of domain GPO altering
the kerberos algorithms") -- it parses each GPO's `GptTmpl.inf` security template for the
`SupportedEncryptionTypes` line.

```powershell title="Find all GPOs that configure the Kerberos etype policy and their linked OUs"
# Find all GPOs that set "Network security: Configure encryption types allowed for Kerberos"
$domain = (Get-ADDomain).DNSRoot
$sysvolPath = "\\$domain\SYSVOL\$domain\Policies"

$etypeFlags = [ordered]@{
    0x1  = 'DES__CRC'
    0x2  = 'DES_MD5'
    0x4  = 'RC4'
    0x8  = 'AES128'
    0x10 = 'AES256'
    0x20 = 'AES-SK (Future)'
}

Get-GPO -All | ForEach-Object {
    $gpo = $_
    $inf = "$sysvolPath\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (Test-Path $inf) {
        Get-Content $inf | Where-Object {
            $_ -match 'Kerberos\\Parameters\\SupportedEncryptionTypes=4,'
        } | ForEach-Object {
            $value = [uint32]($_.Split(',')[1])
            $enabled = ($etypeFlags.GetEnumerator() |
                Where-Object { $value -band $_.Key } |
                ForEach-Object { $_.Value }) -join ', '

            # Get linked OUs from the GPO report
            $xml = [xml](Get-GPOReport -Guid $gpo.Id -ReportType XML)
            $links = ($xml.GPO.LinksTo | ForEach-Object { $_.SOMPath }) -join '; '

            [PSCustomObject]@{
                GPO              = $gpo.DisplayName
                'Value (dec)'    = $value
                'Value (hex)'    = '0x{0:X}' -f $value
                'Enabled Etypes' = $enabled
                'Linked To'     = if ($links) { $links } else { '(not linked)' }
            }
        }
    }
} | Format-Table -AutoSize -Wrap
```

Example output:

```text title="Example GPO etype policy scan output"
GPO                       Value (dec) Value (hex) Enabled Etypes              Linked To
---                       ----------- ----------- --------------              ---------
DC Kerberos Policy                 24 0x18        AES128, AES256              corp.local/Domain Controllers
Workstation Security               24 0x18        AES128, AES256              corp.local/Workstations; corp.local/Servers
Legacy App Servers                 28 0x1C        RC4, AES128, AES256         corp.local/Servers/Legacy
```

What to look for:

- **No results at all** -- no GPO sets the Kerberos etype policy.  Every machine uses its
  local default, and the KDC has no hard etype filter.  This is the most common
  misconfiguration.
- **RC4 or DES in `Enabled Etypes`** -- that GPO allows legacy encryption.  Check
  `Linked To` to see if it targets DCs (KDC hard filter) or workstations (client
  advertisement).
- **Multiple GPOs linked to the same OU** -- GPO precedence applies.  The GPO with the
  lowest link order wins.  Verify with `gpresult /R` on a target machine.
- **A GPO linked to `Domain Controllers` with a different value than one linked to
  workstations** -- this is expected in [Path 2](#path-2-aes-opportunistic-with-rc4-fallback)
  but should not happen in [Path 1](#path-1-modern-aes-only-environment).

---

## Step 2: Generate AES Keys (Password Resets)

AES keys are generated when a password is set while the domain functional level is 2008
or higher.  If an account's password predates that DFL raise, the account has **no AES
keys** in `ntds.dit` -- regardless of what `msDS-SupportedEncryptionTypes` says.  Setting
the attribute on a keyless account does not create keys; it just causes ticket requests
to fail with `KDC_ERR_ETYPE_NOSUPP`.

### Identify accounts that need a reset

The Read-Only Domain Controllers group (RID 521) was created when the domain reached
DFL 2008.  Its `WhenCreated` timestamp is the earliest point at which password changes
generate AES keys.  Any SPN-bearing user account whose `passwordLastSet` is earlier than
that date definitely lacks AES keys:

```powershell title="Find SPN-bearing user accounts with passwords predating AES key generation"
$AESdate = (Get-ADGroup -Filter * -Properties SID, WhenCreated |
  Where-Object { $_.SID -like '*-521' }).WhenCreated

Write-Host "AES keys available since: $AESdate"

Get-ADUser -Filter 'Enabled -eq $true -and servicePrincipalName -like "*"' `
  -Properties passwordLastSet |
  Where-Object { $_.passwordLastSet -lt $AESdate } |
  Sort-Object passwordLastSet |
  Select-Object sAMAccountName, passwordLastSet
```

**Computer accounts** auto-rotate their password every 30 days.  After DFL reaches 2008,
the next rotation generates AES keys automatically -- no manual action needed for online,
healthy machines.

**Managed service accounts** (gMSA, MSA, dMSA) have passwords managed by AD.  They are
unlikely to predate DFL 2008; their next automatic rotation will generate AES keys if
somehow missing.

### The double-reset problem

Accounts whose passwords were set before DFL 2008 may need the password reset **twice**,
not once.  The first reset writes new AES keys into the `KerberosNew` credential set in
`ntds.dit`, but the `Kerberos` (active) set may still hold only the old RC4 key.  The
KDC reads the active set first.  Only the second reset promotes the new keys from
`KerberosNew` into `Kerberos`, making them usable.

The rule is simple: **if the account predates DFL 2008, reset twice**.  See
[Algorithms & Keys — The Double-Reset Problem](algorithms.md#the-double-reset-problem)
for the full explanation and how to verify key state with DSInternals.

### Reset user service account passwords

!!! danger "Coordinate with service owners before every reset"
    Resetting a user service account password breaks every service running under that
    account until the new password is deployed.  For each account:

    1. Identify all services, scheduled tasks, and application pools using the account.
    2. Schedule a maintenance window.
    3. Reset the password (twice if the account predates DFL 2008).
    4. Update the password in every service configuration.
    5. Restart the services.
    6. Verify authentication worked -- check Event 4769 for AES tickets, not just
       that the service started.

### Verify AES keys exist after reset

The fastest check is Event 4769 on a DC.  Trigger a service ticket request for the
account (connect to the service), then look at the `Available Keys` field:

```text title="Event 4769 — Available Keys after a successful AES key reset"
Available Keys: AES-SHA1, RC4
```

If the field shows only `RC4`, AES keys were not generated.  Either the DFL was still
below 2008 when the reset ran, or the account needs a second reset.

For definitive verification without waiting for an auth event, use DSInternals to read
the stored keys directly from AD replication data
(see [Auditing Kerberos Keys](account-key-audit.md#method-2-dsinternals-definitive-online)):

```powershell title="Inspect stored Kerberos keys for a single account via DSInternals"
Get-ADReplAccount -SamAccountName svc_example -Server dc01.corp.local
# Look for AES256_CTS_HMAC_SHA1_96 in SupplementalCredentials → KerberosNew → Credentials
```

---

## Step 3: Set msDS-SupportedEncryptionTypes on Manually-Managed SPN-Bearing Accounts { #step-3-set-msds-supportedencryptiontypes-on-manually-managed-spn-bearing-accounts }

The Kerberos GPO handles computer accounts automatically (Step 4).  All other
SPN-bearing account types must be updated manually: user service accounts, gMSA, MSA,
and dMSA.  See the [account type taxonomy](../index.md#spn-bearing-account-types)
for the full list of defaults and targets for each type.

The KDC uses `msDS-SupportedEncryptionTypes` when issuing service tickets.  Without an
explicit value, it falls back to the domain default (`0x27`, which includes RC4).

Setting this attribute to `0x18` switches service tickets from RC4 to AES immediately —
no DC restart, no GPO refresh, no delay.

### What value to use

| Value | Hex | Meaning | When to use |
|---|---|---|---|
| 24 | `0x18` | AES128 + AES256 | **Recommended** -- AES-only, no RC4 fallback |
| 28 | `0x1C` | RC4 + AES128 + AES256 | Transitional -- keeps RC4 as fallback for legacy clients |

Do **not** use `0x10` (AES256 only) unless you are certain no client needs AES128.
Do **not** use `0x04` (RC4 only) -- this blocks AES entirely.

### Single account

```powershell title="Set AES-only on a single SPN-bearing account"
Set-ADUser svc_example -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

Verify:

```powershell title="Verify msDS-SET value on a single account"
(Get-ADUser svc_example -Properties 'msDS-SupportedEncryptionTypes').'msDS-SupportedEncryptionTypes'
# Expected: 24
```

### Bulk: all SPN-bearing user accounts not at target

Use the same summary query from [Step 1](#spn-bearing-user-accounts) to see what you are
working with, then set `$target` and update every account that does not already match:

```powershell title="Bulk set msDS-SET to AES-only on all SPN-bearing user accounts, with change log"
$target = 24  # ← set to your target value (24 = 0x18, AES-only)

Get-ADUser -Filter 'servicePrincipalName -like "*"' `
  -Properties 'msDS-SupportedEncryptionTypes' |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
  ForEach-Object {
    $old = [int]$_.'msDS-SupportedEncryptionTypes'
    Set-ADUser $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = $target }
    [PSCustomObject]@{
        Account = $_.sAMAccountName
        'Old (dec)' = $old
        'Old (hex)' = '0x{0:X}' -f $old
        'New (dec)' = $target
        'New (hex)' = '0x{0:X}' -f $target
    }
  } | Format-Table -AutoSize
```

This updates every SPN-bearing user account in the domain -- including accounts with
`msDS-SET = 0` (not set, using default), explicit RC4 (`0x4`), DES values (`0x1`, `0x2`,
`0x3`), or any other non-target value.  The output shows exactly what changed on each
account.

!!! warning "Verify AES keys exist first"
    Setting `msDS-SupportedEncryptionTypes = 0x18` on an account that lacks AES keys
    (password never reset since DFL 2008) will cause ticket requests to **fail**.
    Complete [Step 2](#step-2-generate-aes-keys-password-resets) before running this.
    If you are unsure, run the [key audit](account-key-audit.md) first.

### Bulk: all gMSA accounts not at target

```powershell title="Bulk set msDS-SET to AES-only on all gMSA accounts"
$target = 24

Get-ADServiceAccount -Filter * -Properties objectClass, 'msDS-SupportedEncryptionTypes' |
  Where-Object { $_.objectClass -contains 'msDS-GroupManagedServiceAccount' } |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
  ForEach-Object {
    $old = [int]$_.'msDS-SupportedEncryptionTypes'
    Set-ADServiceAccount $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = $target }
    [PSCustomObject]@{
        Account = $_.sAMAccountName
        'Old (hex)' = '0x{0:X}' -f $old
        'New (hex)' = '0x{0:X}' -f $target
    }
  } | Format-Table -AutoSize
```

### Bulk: all MSA accounts not at target

```powershell title="Bulk set msDS-SET to AES-only on all MSA accounts"
$target = 24

Get-ADServiceAccount -Filter * -Properties objectClass, 'msDS-SupportedEncryptionTypes' |
  Where-Object { $_.objectClass -contains 'msDS-ManagedServiceAccount' } |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
  ForEach-Object {
    $old = [int]$_.'msDS-SupportedEncryptionTypes'
    Set-ADServiceAccount $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = $target }
    [PSCustomObject]@{
        Account = $_.sAMAccountName
        'Old (hex)' = '0x{0:X}' -f $old
        'New (hex)' = '0x{0:X}' -f $target
    }
  } | Format-Table -AutoSize
```

### Bulk: all dMSA accounts not at target

```powershell title="Bulk set msDS-SET to AES-only on all dMSA accounts"
$target = 24

Get-ADObject -LDAPFilter '(&(objectClass=msDS-DelegatedManagedServiceAccount)(servicePrincipalName=*))' `
  -Properties 'msDS-SupportedEncryptionTypes' |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
  ForEach-Object {
    $old = [int]$_.'msDS-SupportedEncryptionTypes'
    Set-ADObject $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = $target }
    [PSCustomObject]@{
        Account = $_.Name
        'Old (hex)' = '0x{0:X}' -f $old
        'New (hex)' = '0x{0:X}' -f $target
    }
  } | Format-Table -AutoSize
```

### Verify with Event 4769

Request a service ticket and check the 4769 event on the DC.

**Before** (msDS-SET = 0, effective default `0x27`):

```text title="Event 4769 — before setting msDS-SET (RC4 ticket)"
Service Name:                     svc_example
MSDS-SupportedEncryptionTypes:    0x27 (DES, RC4, AES-Sk)
Available Keys:                   AES-SHA1, RC4
Ticket Encryption Type:           0x17
Session Encryption Type:          0x12
```

**After** (msDS-SET = `0x18`):

```text title="Event 4769 — after setting msDS-SET = 0x18 (AES ticket)"
Service Name:                     svc_example
MSDS-SupportedEncryptionTypes:    0x18 (AES128-SHA96, AES256-SHA96)
Available Keys:                   AES-SHA1, RC4
Ticket Encryption Type:           0x12
Session Encryption Type:          0x12
```

The ticket etype changes from `0x17` (RC4) to `0x12` (AES256).  The session key also
becomes AES256 -- no more split etype.

### Verify with klist

On the client machine after obtaining a fresh service ticket:

```text title="klist — service ticket after setting msDS-SET = 0x18"
klist tickets

#2>     Client: user@CORP.LOCAL
        Server: HTTP/svc-example.corp.local@CORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
```

Before the change, `KerbTicket Encryption Type` would show `RSADSI RC4-HMAC(NT)`.

---

## Step 4: Configure Computer Accounts via GPO

Computer accounts get their `msDS-SupportedEncryptionTypes` from Group Policy.  When a
GPO writes the `SupportedEncryptionTypes` registry value on a machine, the machine's
Kerberos subsystem auto-updates its own AD computer account attribute.

### Apply the etype GPO to workstation/server OUs

1. Open **Group Policy Management** → create or edit a GPO linked to your workstation/server OUs.
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options**.
3. Find **Network security: Configure encryption types allowed for Kerberos**.
4. Set the checkboxes based on your path:

=== "Path 1: AES-Only"

    ```
    [ ] DES_CBC_CRC
    [ ] DES_CBC_MD5
    [ ] RC4_HMAC_MD5
    [x] AES128_HMAC_SHA1
    [x] AES256_HMAC_SHA1
    [x] Future encryption types
    ```

=== "Path 2: RC4 Fallback"

    ```
    [ ] DES_CBC_CRC
    [ ] DES_CBC_MD5
    [x] RC4_HMAC_MD5
    [x] AES128_HMAC_SHA1
    [x] AES256_HMAC_SHA1
    [x] Future encryption types
    ```

    RC4 must be enabled in the workstation GPO so the Kerberos client includes RC4 in
    its AS-REQ etype list.  Without it, users who only have RC4 keys cannot
    pre-authenticate from these machines -- the KDC has no common etype to use for the
    AS-REP and returns `KDC_ERR_ETYPE_NOSUPP`.

    This does **not** weaken service ticket security.  Service ticket encryption is
    controlled by the target account's `msDS-SupportedEncryptionTypes` (set to `0x18`
    in Step 3), not the client's etype list.

### What happens automatically

The GPO writes a registry value (e.g., `0x7fffffff` with "Future" checked, or `0x18`
without).  The machine's Kerberos subsystem then updates its own computer account's
`msDS-SupportedEncryptionTypes` in AD.  During this update, only the 5 standard etype
bits (0-4) are written to the AD attribute -- high bits like "Future encryption types"
are stripped.

| GPO registry value | AD attribute after auto-update |
|---|---|
| `0x7fffffff` (all + future) | `0x1F` (31 = DES + RC4 + AES128 + AES256) |
| `0x18` (AES128 + AES256) | `0x18` (24 = AES128 + AES256) |
| `0x1C` (RC4 + AES128 + AES256) | `0x1C` (28 = RC4 + AES128 + AES256) |

!!! tip "Which value to use"
    **Path 1** (AES-only): check only AES128 and AES256 → registry gets `0x18`, AD
    attribute becomes `0x18`.

    **Path 2** (RC4 fallback): also check RC4 → registry gets `0x1C`, AD attribute
    becomes `0x1C`.  Service tickets to these computers still use AES256 because the KDC
    picks the strongest etype with a matching key, and computer accounts always have AES
    keys (machine passwords auto-rotate).  The RC4 bit is present but never used.

### Skip the wait: set msDS-SupportedEncryptionTypes directly

The GPO auto-update path (GPO → registry → machine updates its own AD attribute) depends
on two things happening in sequence: the machine must process the GPO, and then the
Kerberos subsystem must write the new value to AD.  In practice this means waiting for
the next Group Policy refresh cycle (up to 90 minutes + random offset for workstations,
5 minutes for DCs), and the machine must be online and reachable.

You can skip this entirely by writing `msDS-SupportedEncryptionTypes` directly on the
computer account in AD.  The change takes effect on the KDC immediately -- the next
TGS-REQ for that computer's SPNs will use the new etype.

**Single computer:**

```powershell title="Set AES-only directly on a single computer account"
Set-ADComputer LAB-PC-03 -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

**Bulk: all computer accounts that are not already AES-only:**

```powershell title="Bulk set AES-only on all computer accounts not already at target"
Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
  Where-Object {
    $_.'msDS-SupportedEncryptionTypes' -ne 24 -and
    $_.'msDS-SupportedEncryptionTypes' -ne 28   # skip transitional RC4+AES accounts
  } |
  ForEach-Object {
    Set-ADComputer $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
    Write-Host "Set msDS-SET=24 on $($_.Name)"
  }
```

!!! note "GPO will overwrite your manual value"
    When the machine eventually processes the etype GPO, its Kerberos subsystem will
    overwrite the AD attribute with whatever the GPO registry value maps to.  If the GPO
    is also set to AES-only, the values match and nothing changes.  If the GPO differs
    (e.g., includes RC4), the GPO value will win on the next refresh.

    This is fine -- the manual set gives you **immediate** protection while the GPO
    propagates.  Once GPO has been applied everywhere, the manual and GPO values converge.

    If a machine is offline or decommissioned and will never process the GPO, the manual
    AD value is the **only** value that matters.  The KDC reads the AD attribute, not the
    machine's local registry.

### Using msDS-SupportedEncryptionTypes to find GPO problems

Because the GPO auto-update writes a predictable value to the computer account's
`msDS-SupportedEncryptionTypes`, you can query AD to find machines where the GPO has
**not** been applied.  Any computer account with `msDS-SET = 0` (never set) or an
unexpected value is a machine that either never received the GPO, has not been online
since the GPO was linked, or is blocked from applying it.

**Find computers where GPO has not updated msDS-SET:**

```powershell title="Find computer accounts where msDS-SET is 0 (GPO has not applied)"
# Assumes your etype GPO sets AES-only (expected msDS-SET = 24 or 28)
Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes', LastLogonDate,
    OperatingSystem, DistinguishedName |
  Where-Object { $_.'msDS-SupportedEncryptionTypes' -eq 0 } |
  Select-Object Name,
    @{N='msDS-SET'; E={$_.'msDS-SupportedEncryptionTypes'}},
    LastLogonDate,
    OperatingSystem,
    @{N='OU'; E={($_.DistinguishedName -split ',', 2)[1]}} |
  Sort-Object LastLogonDate |
  Format-Table -AutoSize
```

Common causes for `msDS-SET = 0` on a computer account:

| Cause | How to identify | Fix |
|---|---|---|
| Machine is offline / decommissioned | `LastLogonDate` is weeks/months old | Clean up stale accounts, or set msDS-SET manually |
| Machine is in an OU not covered by the GPO | Check the `OU` column against your GPO scope | Move the machine or extend GPO scope |
| GPO is blocked or overridden by a higher GPO | Run `gpresult /r` on the machine | Fix GPO precedence / remove block |
| Machine is a non-Windows device (NAS, printer) | `OperatingSystem` is blank or non-Windows | Set msDS-SET manually (these devices cannot process GPO) |
| Computer account was just created | `LastLogonDate` is recent but GPO hasn't refreshed yet | Wait for next refresh or run `gpupdate /force` |

**Find computers with unexpected msDS-SET values:**

```powershell title="Find computer accounts with RC4 but no AES in msDS-SET"
# Find any computer account where msDS-SET includes RC4 but not AES
Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
  Where-Object {
    $v = $_.'msDS-SupportedEncryptionTypes'
    $v -ne 0 -and ($v -band 4) -and -not ($v -band 0x10)
  } |
  Select-Object Name,
    @{N='msDS-SET'; E={$_.'msDS-SupportedEncryptionTypes'}},
    @{N='msDS-SET-Hex'; E={'0x{0:X}' -f $_.'msDS-SupportedEncryptionTypes'}} |
  Format-Table -AutoSize
```

These are machines that have a GPO applied, but the GPO includes RC4.  Either the
machine is picking up a different GPO than intended, or the GPO itself needs to be
updated to remove RC4.

!!! tip "Ongoing monitoring"
    Run the `msDS-SET = 0` query regularly (weekly, or as a scheduled task).  It catches
    newly joined machines that haven't processed the GPO yet, machines that were moved
    between OUs, and stale accounts that should be disabled.  This is cheaper and more
    reliable than trying to parse `gpresult` output from every machine.

### Verify: check a computer account after GPO applies

```powershell title="Force GPO refresh and verify msDS-SET on a computer account"
# Force GPO refresh on a target machine
Invoke-Command -ComputerName LAB-PC-03 -ScriptBlock { gpupdate /force }

# Wait a moment, then check the AD attribute
Get-ADComputer LAB-PC-03 -Properties 'msDS-SupportedEncryptionTypes' |
  Select-Object Name, @{N='msDS-SET'; E={$_.'msDS-SupportedEncryptionTypes'}}
# Expected: msDS-SET = 24
```

---

## Step 5: Set DefaultDomainSupportedEncTypes on Every DC

### Why this matters

Accounts with `msDS-SupportedEncryptionTypes = 0` (not set) use
`DefaultDomainSupportedEncTypes` as the fallback etype list.  Without this registry
value, the KDC uses the post-November 2022 built-in default: `0x27` (DES + RC4 +
AES-SK).  That means unconfigured accounts still get RC4 tickets.

Setting `DefaultDomainSupportedEncTypes = 0x18` on every DC ensures that even accounts
you missed in Step 3 will get AES tickets.

### Set on all DCs

```powershell title="Set DefaultDomainSupportedEncTypes to AES-only on every DC"
$DCs = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $DCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC'
        Set-ItemProperty -Path $path -Name 'DefaultDomainSupportedEncTypes' -Value 24
    }
    Write-Host "Set DefaultDomainSupportedEncTypes=24 on $dc"
}
```

!!! warning "Per-DC, not replicated"
    This is a **local registry value** on each DC.  It is not replicated through AD.
    You must set it on every DC individually.  If you add a new DC later, you must set
    it on the new DC as well.

### Verify on all DCs

```powershell title="Verify DefaultDomainSupportedEncTypes on every DC"
$DCs = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $DCs) {
    $val = Invoke-Command -ComputerName $dc -ScriptBlock {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC'
        (Get-ItemProperty $path -EA 0).DefaultDomainSupportedEncTypes
    }
    [PSCustomObject]@{
        DC    = $dc
        Value = if ($val) { "$val (0x$($val.ToString('X')))" } else { '(not set)' }
    }
} | Format-Table -AutoSize
```

Every DC should show `24 (0x18)`.

---

## Step 6: Apply Etype GPO to Domain Controllers

The etype GPO applied to domain controllers has a different effect than the same GPO on
workstations.  On a DC, the GPO value acts as a **KDC hard filter** -- the KDC will
refuse to issue tickets with any etype not in this value.  It also controls what etypes
the KDC will use for AS-REP encryption (the reply a user decrypts with their own key
during login).  On workstations, the same GPO only controls the client's etype
advertisement.  Different OU, different impact.

### How the GPO filter interacts with DefaultDomainSupportedEncTypes

The GPO `SupportedEncryptionTypes` filter and `DefaultDomainSupportedEncTypes` are two
independent mechanisms.  The filter **overrides** DDSET for ticket issuance — it does not
intersect with it.

If the DC GPO blocks RC4 but `DefaultDomainSupportedEncTypes` still says `0x27`
(includes RC4), the KDC will:

1. Look up the target account → `msDS-SET = 0` → fall back to `DefaultDomainSupportedEncTypes = 0x27`
2. The Event 4769 `msDSSET` field shows `0x27` (from DDSET)
3. The GPO filter overrides and issues an AES ticket (the strongest etype the filter allows)

The result is an **AES ticket**, not an authentication failure — the GPO filter takes
precedence.  However, you should still align both settings for clarity: set
`DefaultDomainSupportedEncTypes = 0x18` so the `msDSSET` event field and the actual ticket
etype agree, and to ensure correct behavior if the GPO filter is ever removed.

!!! warning "KDC restart required"
    The GPO filter (`SupportedEncryptionTypes`) is only read at KDC service start.  After
    applying or changing the GPO on a DC, run `Restart-Service kdc`.  Without the restart,
    the old filter (or no filter) remains active.

The specific GPO checkboxes for the Domain Controllers OU depend on which path you are
following.  See the path-specific sections below.

---

## Path 1: Modern AES-Only Environment

For domains where **every account has AES keys** and no legacy constraints remain.

### Prerequisites

Before entering this path, confirm:

- All SPN-bearing user accounts have AES keys and `msDS-SupportedEncryptionTypes = 0x18`
  (Steps 2-3 complete)
- All computer accounts have `msDS-SupportedEncryptionTypes` set via GPO or manually
  (Step 4 complete)
- `DefaultDomainSupportedEncTypes = 0x18` on every DC (Step 5 complete)
- **No** regular user accounts lack AES keys (the
  [key audit](account-key-audit.md)
  returns zero results)

### Step 6: Apply AES-Only GPO to Domain Controllers

1. Open **Group Policy Management** → create or edit a GPO linked to the **Domain Controllers** OU.
2. Set the checkboxes:

    ```
    [ ] DES_CBC_CRC
    [ ] DES_CBC_MD5
    [ ] RC4_HMAC_MD5
    [x] AES128_HMAC_SHA1
    [x] AES256_HMAC_SHA1
    [x] Future encryption types
    ```

3. Run `gpupdate /force` on each DC (or wait for the next refresh cycle).

### Verify: request a ticket and check Event 4769

After full standardization (Steps 1-6 complete), Event 4769 for a service ticket request
should look like:

```text title="Event 4769 — fully standardized AES-only environment"
Service Name:                     svc_example
MSDS-SupportedEncryptionTypes:    0x18 (AES128-SHA96, AES256-SHA96)
Available Keys:                   AES-SHA1, RC4
Advertized Etypes:                AES256-CTS-HMAC-SHA1-96
Ticket Encryption Type:           0x12
Session Encryption Type:          0x12
```

Every field confirms AES: the account is configured for AES (`0x18`), the ticket is
AES256 (`0x12`), and the session key is AES256 (`0x12`).

### RC4DefaultDisablementPhase: you are already ahead of it

With this configuration, the April and July 2026 enforcement phases
([CVE-2026-20833](rc4-deprecation.md)) have no effect on your environment:

- `RC4DefaultDisablementPhase` controls the KDC's assumed etype for accounts with
  `msDS-SET = 0` when `DefaultDomainSupportedEncTypes` is not set.  You have explicitly
  set `DefaultDomainSupportedEncTypes = 0x18`, so the enforcement phase's internal
  override is never consulted.
- July 2026 removes the `RC4DefaultDisablementPhase` key.  No impact -- you are not
  using it.
- No Kdcsvc events 201-209 should appear because no account is using the implicit RC4
  default.

### Path 1: Verification Checklist

- [ ] All SPN-bearing user service accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All gMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All MSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All dMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All SPN-bearing user accounts have had passwords reset after DFL 2008 (AES keys exist)
- [ ] All regular user accounts have AES keys (passwords reset after DFL 2008)
- [ ] `DefaultDomainSupportedEncTypes = 0x18` on **every** DC (verify each one individually)
- [ ] AES-only GPO applied to the Domain Controllers OU (DES and RC4 disabled)
- [ ] AES-only GPO applied to workstation/server OUs
- [ ] No Event ID 16 (etype mismatch) on any DC
- [ ] No Kdcsvc Event 201-209 on any DC
- [ ] Event 4769 shows `Ticket Encryption Type = 0x12` (AES256) for all service tickets
- [ ] Event 4768 shows AES pre-authentication for all TGT requests
- [ ] `klist` on clients shows `AES-256-CTS-HMAC-SHA1-96` for all tickets
- [ ] Computer accounts with `msDS-SET = 0` have been investigated (stale accounts, GPO gaps, non-Windows devices)

---

## Path 2: AES Opportunistic with RC4 Fallback

For domains where all manually-managed SPN-bearing accounts and computer accounts are AES-only, but some
**regular user accounts** (no SPNs) lack AES keys and their passwords cannot be reset
yet.

### When to use this path

You have completed Steps 1-5 and confirmed:

- All SPN-bearing user accounts have AES keys and `msDS-SupportedEncryptionTypes = 0x18`
- All computer accounts have `msDS-SupportedEncryptionTypes` set via GPO
- `DefaultDomainSupportedEncTypes = 0x18` on every DC

But some regular user accounts remain with passwords that predate DFL 2008.  These
accounts have **no AES keys** and their passwords cannot be reset because of:

- Password is unknown (set decades ago, nobody remembers the value, and resetting it
  would lock the user out of systems that cache the old credential)
- Business process dependency (password is embedded in scripts, batch jobs, or legacy
  applications outside the domain admins' control)
- Organizational constraints (labor agreements, compliance rules, or management decisions
  preventing forced password resets without user consent)
- Third-party management (account managed by an external vendor who sets the schedule)

### Understanding your RC4 exposure

These accounts have **no SPNs**.  This fundamentally changes the risk profile compared
to RC4 on a user service account.

**What uses RC4 for these users:**

| Component | Etype | Why |
|---|---|---|
| Pre-authentication (AS-REQ timestamp) | RC4 | Encrypted with the user's key; only RC4 key exists |
| AS-REP enc-part (TGT session key delivery) | RC4 | KDC must encrypt the reply with a key the user can decrypt |

**What uses AES despite these users having only RC4 keys:**

| Component | Etype | Why |
|---|---|---|
| TGT ticket encryption | AES256 | Encrypted with krbtgt's key, not the user's key |
| TGT session key | AES256 | Negotiated between client etype list and KDC; independent of user's stored keys |
| Service ticket encryption | AES256 | Determined by target account's `msDS-SET = 0x18` |
| Service ticket session key | AES256 | Intersection of client, service, and KDC etype lists |

**What this means:**

- **Not Kerberoastable.**  These users have no SPNs.  Nobody can request a service ticket
  encrypted with their key.  The Kerberoasting attack vector does not apply.
- **Pre-auth capture risk.**  An attacker with network position (ARP spoofing, compromised
  switch, sniffing the wire) can capture the RC4-encrypted pre-auth timestamp from an
  AS-REQ and attempt offline cracking.  This is sometimes called "AS-REQ roasting."
  Mitigations: strong passwords, network segmentation, Credential Guard.
- **Not AS-REP roastable** (unless `DONT_REQ_PREAUTH` is set on the account, which is a
  separate misconfiguration and should never be enabled).
- **Service tickets are fully protected.**  When these users request service tickets, the
  tickets are encrypted with the target account's AES key.  The user's RC4 key is not
  involved in the TGS exchange at all.

### What you do NOT need to do for these users

These are common misconceptions for this scenario:

| Action | Why it is unnecessary |
|---|---|
| Set `msDS-SupportedEncryptionTypes` on these users | They have no SPNs.  `msDS-SET` controls service ticket etype for tickets issued **to** the account's SPN.  No SPN means `msDS-SET` has no effect. |
| Change `DefaultDomainSupportedEncTypes` to include RC4 | `DefaultDomainSupportedEncTypes` is consulted during TGS processing (service ticket issuance) for accounts with `msDS-SET = 0`.  These users are never the **target** of a TGS-REQ because they have no SPNs.  Keep it at `0x18`. |
| Worry about Kerberoasting these users | No SPN = no Kerberoasting.  The only roasting risk is AS-REQ roasting (pre-auth capture), which requires network position and a weak password. |

### Step 6: Apply RC4 + AES GPO to Domain Controllers

The DC GPO must include RC4 so the KDC can use RC4 for the AS-REP enc-part when users
with only RC4 keys log in.  If the DC GPO blocks RC4, these users get
`KDC_ERR_ETYPE_NOSUPP` at login -- the KDC has no common etype to encrypt the AS-REP.

1. Open **Group Policy Management** → create or edit a GPO linked to the **Domain Controllers** OU.
2. Set the checkboxes:

    ```
    [ ] DES_CBC_CRC
    [ ] DES_CBC_MD5
    [x] RC4_HMAC_MD5
    [x] AES128_HMAC_SHA1
    [x] AES256_HMAC_SHA1
    [x] Future encryption types
    ```

3. Run `gpupdate /force` on each DC (or wait for the next refresh cycle).

!!! info "RC4 in the DC GPO does not weaken service tickets"
    The DC GPO allowing RC4 means the KDC **can** use RC4 -- not that it **will**.
    Service ticket etype is controlled by the target account's
    `msDS-SupportedEncryptionTypes`.  Since all manually-managed SPN-bearing accounts have `msDS-SET = 0x18`
    (Step 3), service tickets are AES256.  The DC GPO allowing RC4 only matters for
    the AS exchange (login) of users whose only keys are RC4.

    Similarly, `DefaultDomainSupportedEncTypes = 0x18` (Step 5) ensures that even
    SPN-bearing accounts you may have missed default to AES.  The DC GPO does not override
    this -- it is a filter that removes etypes, not one that adds them.

### Why DefaultDomainSupportedEncTypes stays at 0x18

A common question: "If I need RC4 for some users, should I also set
`DefaultDomainSupportedEncTypes` to include RC4?"

No.  `DefaultDomainSupportedEncTypes` is consulted during **TGS processing** when a
SPN-bearing account has `msDS-SET = 0`.  It controls what etype the KDC uses for service
tickets to unconfigured accounts.

Your legacy users have no SPNs.  Nobody requests service tickets for them.
`DefaultDomainSupportedEncTypes` is irrelevant for their authentication.  Keeping it at
`0x18` ensures that any SPN-bearing account you missed in Step 3 gets AES tickets instead of
falling back to RC4.

### RC4DefaultDisablementPhase and July 2026

`RC4DefaultDisablementPhase` controls the KDC's assumed etype for accounts with
`msDS-SET = 0` during **TGS processing** (service ticket issuance).  It does **not**
affect the AS exchange (pre-authentication / login).

Since your legacy users have no SPNs:

- **Audit phase** (January 2026): Kdcsvc events 201-209 may appear for SPN-bearing accounts
  you missed, but not for these regular users.
- **Enforcement phase** (April 2026): the KDC assumes `0x18` for unconfigured accounts
  during TGS processing.  You already set `DefaultDomainSupportedEncTypes = 0x18`
  explicitly, so the enforcement override is never consulted.  No impact on your legacy
  users.
- **July 2026**: the `RC4DefaultDisablementPhase` key is removed.  Permanent enforcement.
  Still no impact on your legacy users -- their login path (AS exchange) is controlled by
  the DC GPO, which you explicitly set to include RC4.

The DC GPO is under your control.  Microsoft's enforcement removes the **implicit** RC4
default for TGS processing.  It does not modify your **explicit** DC GPO.  Your legacy
users continue to log in as long as the DC GPO includes RC4.

### Identifying and tracking legacy users

Maintain a list of users without AES keys so you know when you can transition to Path 1:

```powershell title="List regular users without AES keys for tracking legacy RC4 exposure"
$AESdate = (Get-ADGroup -Filter * -Properties SID, WhenCreated |
  Where-Object { $_.SID -like '*-521' }).WhenCreated

$legacy = Get-ADUser -Filter 'Enabled -eq $true' -Properties passwordLastSet, servicePrincipalName |
  Where-Object {
    $_.passwordLastSet -lt $AESdate -and
    -not $_.servicePrincipalName
  } |
  Select-Object sAMAccountName, passwordLastSet

Write-Host "Regular users without AES keys: $($legacy.Count)"
$legacy | Sort-Object passwordLastSet | Format-Table -AutoSize
```

Run this query regularly (monthly, or as a scheduled task).  The count should decrease
over time as users change their passwords through normal operations (expiry, self-service
reset, helpdesk reset).  Each password change on DFL >= 2008 generates AES keys
automatically.

### Monitoring RC4 pre-authentication

Track which users are still doing RC4 pre-auth by monitoring Event 4768 (TGT requests)
on DCs:

```powershell title="Monitor Event 4768 for accounts still using RC4 pre-authentication"
# Find AS-REQ events using RC4 pre-auth
# Event 4768 where Ticket Encryption Type includes 0x17 or Pre-Authentication Type indicates RC4
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4768
} -MaxEvents 1000 |
  Where-Object { $_.Message -match 'RSADSI RC4-HMAC' } |
  ForEach-Object {
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        Account = ($_.Properties[0].Value)
    }
  } |
  Group-Object Account |
  Select-Object Count, Name |
  Sort-Object Count -Descending
```

A user who appears in this list with a recent `passwordLastSet` date has already
generated AES keys -- investigate why they are still doing RC4 pre-auth (client machine
GPO issue, stale ticket cache, etc.).

### Planning the exit to Path 1

This path is transitional.  The goal is to reach zero legacy users and switch to Path 1.

**How users naturally exit the legacy list:**

- **Password expiry**: when a user's password expires and they set a new one, AES keys
  are generated.  This is the primary mechanism.  If your password policy enforces
  expiry (e.g., 90 or 180 days), most users will self-heal within one cycle.
- **Self-service password reset**: users who reset their own passwords through a portal
  or Ctrl+Alt+Del generate AES keys.
- **Helpdesk reset**: any admin-initiated password reset generates AES keys.
- **Account deprovisioning**: users who leave the organization have their accounts
  disabled.  Disabled accounts don't need AES keys.

**For users whose passwords never expire:**

These are the long-tail problem.  Options:

1. **Enable password expiry** on these accounts.  The next forced change generates AES
   keys.
2. **Coordinate a bulk reset** with users during a planned maintenance window.
3. **Accept the delay** and wait for users to reset voluntarily.  Track them in the
   monitoring query above.

**When to switch to Path 1:**

When the legacy user query returns zero results and the RC4 pre-auth monitoring shows
no RC4 events, update both GPOs:

1. **Workstation/server GPO**: remove RC4 from the checkboxes (AES128 + AES256 + Future
   only).
2. **Domain Controllers GPO**: remove RC4 from the checkboxes (AES128 + AES256 + Future
   only).
3. Verify: confirm no `KDC_ERR_ETYPE_NOSUPP` errors or Event 4768 failures after the
   change.

### Path 2: Verification Checklist

- [ ] All SPN-bearing user service accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All gMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All MSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All dMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All SPN-bearing user accounts have had passwords reset after DFL 2008 (AES keys exist)
- [ ] `DefaultDomainSupportedEncTypes = 0x18` on **every** DC (verify each one individually)
- [ ] RC4 + AES GPO applied to the Domain Controllers OU (DES disabled, RC4 and AES enabled)
- [ ] RC4 + AES GPO applied to workstation/server OUs (so legacy users can pre-auth from any machine)
- [ ] No Event ID 16 (etype mismatch) on any DC
- [ ] Event 4769 shows `Ticket Encryption Type = 0x12` (AES256) for all **service tickets** (manually-managed SPN-bearing accounts are AES-only regardless of DC GPO)
- [ ] `klist` on clients shows `AES-256-CTS-HMAC-SHA1-96` for service tickets
- [ ] Legacy user count is tracked and decreasing over time
- [ ] RC4 pre-auth monitoring is active on all DCs (Event 4768)
- [ ] Computer accounts with `msDS-SET = 0` have been investigated (stale accounts, GPO gaps, non-Windows devices)
- [ ] Exit criteria defined: switch to Path 1 when legacy user count reaches zero

---

## Reference: What RC4DefaultDisablementPhase Actually Does

The `RC4DefaultDisablementPhase` registry key was introduced with the January 2026
update (CVE-2026-20833).  It controls how the KDC handles accounts with
`msDS-SupportedEncryptionTypes = 0` when no explicit `DefaultDomainSupportedEncTypes`
is set.  This section is a shared reference for both paths.

### The three values

| Value | Phase | Behavior |
|---|---|---|
| **absent** (no key, post KB5078763) | Enforcement | RC4 blocked for unconfigured accounts.  KDC internally assumes `0x18`.  This is the default after the April 2026 update — no configuration required. |
| **0** | Pre-2026 rollback | RC4 is the implicit default.  The KDC internally assumes `0x27` for unconfigured accounts.  Valid until July 2026. |
| **1** | Audit | Same as 0, but the KDC logs Kdcsvc events 201/202 whenever it would use RC4 from the implicit default.  Valid until July 2026. |
| **2** | Enforcement | Same as absent.  Explicitly sets what the April 2026 patch makes the default. |

### It does NOT modify DefaultDomainSupportedEncTypes

This is the critical distinction.  `RC4DefaultDisablementPhase` overrides the KDC's
**internal** default -- the value the KDC uses when both `msDS-SupportedEncryptionTypes`
and `DefaultDomainSupportedEncTypes` are absent.

If you have **explicitly set** `DefaultDomainSupportedEncTypes = 0x18` (AES-only, Step 5),
the enforcement phase and your explicit value agree — AES is the result either way.

If `DefaultDomainSupportedEncTypes` is set to a value that includes RC4 (e.g. `0x1C`),
the enforcement phase **overrides** it for accounts with `msDS-SET = 0`.  RC4 is still
blocked for those accounts; the explicit DDSET only applies to accounts that have an
explicit `msDS-SupportedEncryptionTypes` value.  Lab-verified on KB5078763 (2026-04-14).

### Scope: TGS processing only

`RC4DefaultDisablementPhase` affects how the KDC selects etypes during **TGS processing**
(service ticket issuance).  It does **not** affect the AS exchange (pre-authentication /
TGT issuance).  Users with only RC4 keys can still log in as long as the DC GPO allows
RC4.

### Interaction matrix

What the KDC uses as the effective etype list for accounts with `msDS-SupportedEncryptionTypes = 0`
during TGS processing:

| `RC4DefaultDisablementPhase` | `DefaultDomainSupportedEncTypes` | Effective default for msDS-SET=0 accounts | Notes |
|---|---|---|---|
| absent (post KB5078763) | not set | `0x18` (AES-only) | April 2026 default — enforcement is on with no configuration |
| absent (post KB5078763) | `0x1C` (includes RC4) | `0x18` (AES-only) | **Enforcement overrides DDSET.** RC4 blocked. Event 205 at KDC start. Lab-verified 2026-04-14. |
| 0 (rollback) | not set | `0x27` (RC4 + AES-SK) | Pre-2026 behavior restored; valid until July 2026 |
| 0 (rollback) | `0x18` (explicit) | `0x18` (AES-only) | Explicit value used |
| 1 (audit) | not set | `0x27` (RC4 + AES-SK) | RC4 allowed; events 201/202 logged. Valid until July 2026. |
| 1 (audit) | `0x18` (explicit) | `0x18` (AES-only) | Events not triggered -- already AES |
| 2 (enforce) | not set | `0x18` (AES-only) | Same as absent; redundant after April 2026 patch |
| 2 (enforce) | `0x1C` (includes RC4) | `0x18` (AES-only) | **Enforcement overrides DDSET.** RC4 blocked. Lab-verified 2026-04-14. |
| Removed (July 2026) | not set | `0x18` (AES-only) | Permanent enforcement, no rollback |
| Removed (July 2026) | `0x1C` (includes RC4) | `0x18` (AES-only) | **Enforcement still overrides DDSET.** RC4 blocked for unconfigured accounts. |

### July 2026 timeline

The July 2026 update removes the `RC4DefaultDisablementPhase` registry key entirely.
Enforcement becomes permanent.  There is no rollback mechanism for the TGS default.

For both paths in this guide, you have explicitly set `DefaultDomainSupportedEncTypes =
0x18` (Step 5).  The enforcement phase and its removal have no effect on your
configuration -- your explicit value was already controlling TGS behavior.
