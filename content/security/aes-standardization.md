---
description: >-
  Operational playbook for finishing an AES-only Kerberos configuration in Active Directory:
  audit, key generation, msDS-SupportedEncryptionTypes, the KDC etype filter, and removing
  the remaining RC4 exceptions, with safe bulk scripts and verification at every step.
---

# AES Standardization Guide

This is the operational playbook for getting a domain to AES-only Kerberos and keeping it
there: every setting, every command, every verification step.

Domain controllers with the April 2026 cumulative update or later already treat an account
with no `msDS-SupportedEncryptionTypes` as AES-only.  So this is no longer a race against a
deadline.  It is clean-up work with four goals:

1. Make the AES configuration **explicit** on every SPN-bearing account, so behavior does
   not depend on which update a particular DC has installed.
2. Find the accounts and services that **cannot** use AES yet — accounts without AES keys,
   services with RC4-only keytabs, clients that only offer RC4 — and fix them.
3. Close the **KDC etype filter** on the domain controllers so DES and RC4 cannot be issued
   even by mistake.
4. Shrink the list of **RC4 exceptions** to zero.

!!! danger "Something is failing right now?"
    Start with the [enforcement triage runbook](enforcement-triage.md), not this page.
    This playbook assumes a working domain that you are tightening in a controlled way.

For background on how the KDC chooses an etype and what Microsoft changed in 2026, see
[RC4 Deprecation](rc4-deprecation.md).

Two deployment paths are covered, based on whether all accounts have AES keys:

1. **[Path 1: Modern AES-Only](#path-1-modern-aes-only-environment)** — every account
   has AES keys, RC4 is fully disabled.  The target state for all domains.
2. **[Path 2: AES Opportunistic with RC4 Fallback](#path-2-aes-opportunistic-with-rc4-fallback)** —
   all manually-managed SPN-bearing accounts and computer accounts use AES, but some regular user accounts
   (no SPNs) lack AES keys and their passwords cannot be reset yet.  RC4 remains enabled
   solely for those users' pre-authentication.

Both paths disable DES entirely.  Steps 1, 2, 3 and 5 are the same for both.  The paths
differ in two places: the checkboxes of the workstation/server GPO (Step 4) and of the
domain controller filter (Step 6, with Step 6a for Path 1 and Step 6b for Path 2).

!!! warning "Every bulk command on this page is a dry run until you say otherwise"
    The scripts that change something — accounts, a DC's registry, a test account — start
    with `$DryRun = $true`: they print what they would do and write nothing.  The bulk
    scripts change only accounts whose current value you have listed, skip `krbtgt`, and on
    a real run save the old values to a CSV before writing.  Read the plan they print
    before you set `$DryRun = $false`.  The single-account commands carry `-WhatIf`; remove
    it to write.

    Each script is a few settings lines followed by **one block**.  Paste the whole script,
    or save it as a `.ps1` file and run that.  A check that fails stops the block, and
    nothing after it runs.

---

## What Affects Encryption

These settings decide which encryption type ends up in a Kerberos ticket, and all of them
must be right for AES to work.  For the exhaustive reference (including auto-derived
values), see the
[Etype Decision Guide — All the Inputs](etype-decision-guide.md#all-the-inputs).

### 1. krbtgt account keys

The `krbtgt` account's key encrypts every TGT in the domain.  If `krbtgt` has no AES keys
(its password has not been changed since the domain gained AES support), the KDC cannot
issue AES-encrypted TGTs regardless of any other setting.  Per KB5021131, a DC logs System
event 42 ("The Kerberos Key Distribution Center lacks strong keys for account:
accountname", with `krbtgt` as the account name) in that state.

One password change creates the AES keys.  Do **not** rotate `krbtgt` twice in a row: the
second rotation retires the previous key, and every TGT issued under it stops working.
Follow the [KRBTGT rotation procedure](mitigations.md#priority-9-krbtgt-password-rotation),
which checks replication after each rotation and waits at least one maximum ticket
lifetime (10 hours by default) before the second.

**Leave `msDS-SupportedEncryptionTypes` on the `krbtgt` account unset.**  The bulk scripts
on this page exclude `krbtgt` and every `krbtgt_*` account for that reason.

### 2. Kerberos GPO (`SupportedEncryptionTypes`)

The *Network security: Configure encryption types allowed for Kerberos* GPO writes the
`SupportedEncryptionTypes` registry value and does two things depending on where it is
applied:

- **On workstations and member servers**: controls which etypes the Kerberos client
  advertises in AS-REQ and TGS-REQ.  The machine also writes the low five bits of the value
  to its own computer account's `msDS-SupportedEncryptionTypes` in AD.
- **On domain controllers**: does the same client-side work **and** acts as a KDC etype
  filter — but only after the KDC service has been restarted, and not identically on every
  OS version (see [Step 6](#step-6-apply-etype-gpo-to-domain-controllers)).

You typically apply **two separate GPOs**: one for the Domain Controllers OU and one for
workstation/server OUs.  They can have different etype selections (for example, the DC GPO
may need to keep RC4 while legacy users exist -- see
[Path 2](#path-2-aes-opportunistic-with-rc4-fallback)).

### 3. `DefaultDomainSupportedEncTypes` (KDC fallback)

A per-DC registry value at `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`.  When a target
account has `msDS-SupportedEncryptionTypes` unset or `0`, the KDC uses this value
instead.  It is **not** replicated -- you must set it on every DC individually, and verify
every DC has the same value.  It takes effect immediately, without a KDC restart.

When the value is absent, the KDC falls back to a built-in default that depends on the
installed update:

--8<-- "includes/ddset-default-by-build.md"

An explicit value always wins over the built-in default, in both directions: an explicit
`0x18` pins AES-only on an unpatched DC, and an explicit value that includes RC4 re-enables
RC4 for every unconfigured account on a patched one.

### 4. `msDS-SupportedEncryptionTypes` on manually-managed SPN-bearing accounts

Windows computer accounts maintain their own value.  **No other SPN-bearing account type
does**: user service accounts, gMSA, MSA, and dMSA keep whatever an administrator wrote, or
nothing.  See the [account type taxonomy](../index.md#spn-bearing-account-types) for the
full breakdown.

Leaving the attribute unset is no longer an RC4 exposure on a patched DC, but it is still
the most common loose end in an AES migration: an unset account's behavior depends on each
DC's update level and on `DefaultDomainSupportedEncTypes`, so the same request can be
answered differently by two DCs.  Writing `24` removes that dependency.

### 5. Account password (keys in `ntds.dit`)

None of the above matters if the account does not have AES keys stored in the database.
AES keys are generated when a password is set in a domain that supports AES; Microsoft's
condition is a domain functional level of 2008 or greater and at least one password change
since
([event 4768 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)).
Accounts whose passwords predate that have only RC4 and DES keys.

An account without AES keys **fails** when the KDC wants AES for it — whether that is
because you set `msDS-SupportedEncryptionTypes = 0x18`, or because the attribute is unset
and the DC applies the AES-only default.  The KDC returns `KDC_ERR_ETYPE_NOSUPP`; it does
not quietly fall back to RC4 (lab: Server 2022 build 20348.5020).

One password reset generates the keys.  See [Auditing Kerberos Keys](account-key-audit.md)
to find which accounts are affected.

### 6. What the service can decrypt

The KDC chooses the ticket etype from what is stored in AD.  It cannot know whether the
service on the other end is able to decrypt the result.  A Windows service running under
the account always can.  A service that authenticates with a **keytab** (Linux and Unix
daemons, Java application servers, many storage and network appliances) can only decrypt
tickets for the etypes and key version its keytab contains.  See the
[pre-check in Step 3](#before-you-change-the-value-can-the-service-decrypt-aes).

### Summary table

| Setting | Path / Location | Scope | Takes effect | Set By |
|---|---|---|---|---|
| `krbtgt` password | AD account | Domain-wide (all TGTs) | After replication | Controlled rotation |
| `SupportedEncryptionTypes` (GPO) | `HKLM\SOFTWARE\...\Policies\System\Kerberos\Parameters` | Per-machine (KDC filter on DCs; client etype list elsewhere) | Clients: new logon session.  KDC filter: **KDC restart** | GPO |
| `DefaultDomainSupportedEncTypes` | `HKLM\SYSTEM\...\Services\Kdc` | Per-DC (fallback for unset accounts) | Immediately | Manual / GPO preference |
| `msDS-SupportedEncryptionTypes` | AD attribute on each account | Per-account (primary input for service tickets) | After replication; cached tickets live on until they expire | PowerShell / ADUC; Windows computers write their own |
| Account password (keys in `ntds.dit`) | `ntds.dit` | Per-account (a key must exist for the etype) | After replication | Password reset |
| Keytab / service configuration | On the service host | Per-service | When the service reloads it | Service owner |

`RC4DefaultDisablementPhase` is not in this table: it was a temporary gate for the 2026
rollout and is covered under
[Historical: RC4DefaultDisablementPhase](#reference-what-rc4defaultdisablementphase-actually-does).

**klist field mapping:**

- `KerbTicket Encryption Type` = ticket etype (the algorithm used to encrypt the ticket's `enc-part`)
- `Session Key Type` = session etype (the algorithm for the session key shared between client and service)

---

## GPO Model for AES Deployments

Most domains use three GPOs to cover AES-only and mixed-etype environments:

| GPO | Target OU | Etype checkboxes | Purpose |
|---|---|---|---|
| DC GPO | Domain Controllers OU | AES128 + AES256 + Future (add RC4 only if needed for legacy AS exchange) | KDC etype filter; controls pre-auth |
| AES-only machines | Workstations/Servers (modern) | AES128 + AES256 + Future | Restricts client etype advertisement; the machine writes `0x18` to its own account |
| AES+RC4 machines | Workstations/Servers (legacy) | RC4 + AES128 + AES256 + Future | Lets these clients still offer RC4 while preferring AES |

For any SPN-bearing account that is not a computer account — user service accounts, gMSA,
MSA, dMSA — set `msDS-SupportedEncryptionTypes` directly in AD.  The Kerberos GPO does not
manage these account types.

### How service ticket etypes are selected

The service ticket encryption type is determined by the **target account**, not the
client.  The KDC takes the target's effective etype set (`msDS-SupportedEncryptionTypes`,
or the DC's fallback when that is unset), keeps the etypes the account actually has keys
for, and picks the strongest one the KDC filter allows.

This has three practical implications:

1. **Adding RC4 to an account does not produce RC4 tickets.**  An account with
   `msDS-SET = 28` (RC4 + AES) and AES keys still gets AES256 tickets — the strongest
   etype wins.  The ticket is RC4 only when the account's value has no AES bits (`4`,
   `36`) or the account has no AES keys.
2. **The client's etype list decides the session key, and whether the request succeeds at
   all.**  The session key must be an etype both the client offered and the account's
   effective set contains.  If there is no overlap the KDC returns
   `KDC_ERR_ETYPE_NOSUPP`.  That is what the RC4 bit in `28` is for: it lets an RC4-only
   client agree a session key for an AES ticket.
3. **The KDC filter must allow whatever you expect to be issued.**  An account whose
   explicit value shares no etype with the DC filter cannot get a ticket at all.

--8<-- "includes/kdc-filter-matrix.md"

---

## Step 1: Audit Current State

Before changing anything, understand what your domain looks like today.

### SPN-bearing user accounts

User accounts with SPNs (objectCategory=person) are the primary Kerberoasting target —
their human-set passwords make a cracked ticket actionable.  Start with a summary of
every distinct `msDS-SupportedEncryptionTypes` value to see what you are working with:

```powershell title="Summary: group SPN-bearing user accounts by msDS-SupportedEncryptionTypes value"
Get-ADUser -Filter 'servicePrincipalName -like "*"' `
    -Properties 'msDS-SupportedEncryptionTypes' |
    Where-Object { $_.sAMAccountName -notlike 'krbtgt*' } |
    Group-Object { [int]$_.'msDS-SupportedEncryptionTypes' } |
    Sort-Object Count -Descending |
    Select-Object Count,
    @{N = 'msDS-SET (dec)'; E = { [int]$_.Name } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f [int]$_.Name } } |
    Format-Table -AutoSize
```

`krbtgt` is filtered out on purpose: it has an SPN (`kadmin/changepw`), it will always show
as unset, and it must stay that way.

A finished domain shows every account at `24` (`0x18` -- AES128 + AES256), plus the
exceptions you have recorded.  Anything else needs investigation.  What each value does:

--8<-- "includes/etype-values.md"

To list every SPN-bearing user account that does **not** have your target value, set
`$target` and run:

```powershell title="Detail: all SPN-bearing user accounts not at the target msDS-SET value"
$target = 24  # 24 = 0x18, AES-only

Get-ADUser -Filter 'servicePrincipalName -like "*"' `
    -Properties servicePrincipalName, 'msDS-SupportedEncryptionTypes', passwordLastSet |
    Where-Object { $_.sAMAccountName -notlike 'krbtgt*' -and
        [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
    Sort-Object { [int]$_.'msDS-SupportedEncryptionTypes' }, passwordLastSet |
    Select-Object sAMAccountName,
    @{N = 'msDS-SET (dec)'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes' } },
    passwordLastSet,
    @{N = 'SPNs'; E = { ($_.servicePrincipalName | Select-Object -First 2) -join '; ' } } |
    Format-Table -AutoSize
```

### Managed service accounts and the cross-type overview

gMSA, MSA, and dMSA accounts need `msDS-SupportedEncryptionTypes` set manually just like
user service accounts.  Their auto-rotating passwords remove the cracking risk, but an
unset value still leaves the ticket etype to each DC's fallback.

--8<-- "includes/spn-overview-query.md"

### Computer accounts

A Windows machine writes its own `msDS-SupportedEncryptionTypes`.  With no Kerberos etype
policy it typically registers `28` (`0x1C` -- RC4 + AES128 + AES256); with a policy it
registers the low five bits of the policy value.  In a well-configured domain the Windows
computers in one OU therefore all show the same value.  (The `28` figure is Windows'
commonly documented behavior and was not separately verified in this site's lab — run the
summary below to see what your own machines register.)

```powershell title="Summary: group all computer accounts by msDS-SET value"
Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
    Group-Object { [int]$_.'msDS-SupportedEncryptionTypes' } |
    Sort-Object Count -Descending |
    Select-Object Count,
    @{N = 'msDS-SET (dec)'; E = { [int]$_.Name } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f [int]$_.Name } } |
    Format-Table -AutoSize
```

How to read the groups:

| Value | What it usually means |
|---|---|
| `24` (`0x18`) | Windows host that has applied an AES-only etype GPO.  The target. |
| `28` (`0x1C`) | Windows host with no etype GPO applied (the commonly documented self-registered default; see the note above), or one that applies an RC4 + AES GPO.  Tickets for it are still AES256. |
| `31` (`0x1F`) | Windows host whose policy allows every cipher box, DES included.  Find the GPO and fix it. |
| `0` / unset | The object never registered a value: a **non-Windows** device, a pre-staged account, or a machine that has never booted on the domain.  This is not a "GPO has not applied yet" signal. |
| `4`, `7` and other values without AES | Set by hand or by a third-party join tool.  Investigate each one. |

To list every computer that does **not** have the value your GPO should produce:

```powershell title="Detail: computer accounts not at the expected msDS-SET value"
$expected = 24  # what your workstation/server etype GPO produces (24 for AES-only)

Get-ADComputer -Filter * `
    -Properties 'msDS-SupportedEncryptionTypes', passwordLastSet, OperatingSystem, LastLogonDate |
    Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $expected } |
    Sort-Object { [int]$_.'msDS-SupportedEncryptionTypes' }, Name |
    Select-Object Name,
    @{N = 'msDS-SET (dec)'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes' } },
    OperatingSystem, LastLogonDate, passwordLastSet |
    Format-Table -AutoSize
```

### Find accounts missing AES keys

See [Auditing Kerberos Keys](account-key-audit.md) for the full guide — from a quick
PowerShell estimate, through the event-log fields, to definitive offline extraction with
ntdswolf.  The results of that audit determine which path you follow:

- **Zero accounts missing AES keys** → use [Path 1](#path-1-modern-aes-only-environment)
- **Some regular users (no SPNs) missing AES keys** → use [Path 2](#path-2-aes-opportunistic-with-rc4-fallback)
- **Any SPN-bearing account missing AES keys** → fix it in [Step 2](#step-2-generate-aes-keys-password-resets)
  before anything else.  On a patched DC that account is already failing, or is only
  working because something explicitly allows RC4 for it.

### Find what is still asking for RC4

Configuration queries tell you what *should* happen.  The domain controllers' logs tell you
what clients and services are actually doing.

**The KDC's own RC4 events.**  Since the January 2026 update, DCs log System events for
requests the RC4 change affects — but not on every DC.  Per KB5073381, the events for
unconfigured accounts (201-204) require that the DC has no `DefaultDomainSupportedEncTypes`
value ("Warning Event 201 is NOT logged if DefaultDomainSupportedEncTypes is manually
defined"), so a DC with an explicit value stays silent about them:

--8<-- "includes/kdcsvc-events.md"

--8<-- "includes/kdcsvc-event-query.md"

**Microsoft's usage scripts.**  Microsoft publishes two scripts in its
[Kerberos-Crypto repository](https://github.com/microsoft/Kerberos-Crypto/tree/main/scripts)
that read the etype fields added to Security events 4768 and 4769 in January 2025:

| Script | What it answers |
|---|---|
| `Get-KerbEncryptionUsage.ps1` | Which requests were issued with which ticket and session-key etype.  `-Encryption RC4` narrows the output to RC4. |
| `List-AccountKeys.ps1` | Which key types each account that authenticated actually has. |

Microsoft's walkthrough is
[Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos).
Both scripts need Kerberos auditing enabled on the DCs:

--8<-- "includes/verify-kerberos-auditing.md"

Both subcategories must show **Success and Failure**.

### Check current DC registry state

`DefaultDomainSupportedEncTypes` and `SupportedEncryptionTypes` are **per-DC** values --
they are not replicated.  Check every DC individually:

--8<-- "includes/ddset-per-dc-check.md"

The `Build` column tells you each DC's update level; how to confirm that a DC is actually
enforcing, with a live request, is in
[Step 1 of the triage runbook](enforcement-triage.md#step-1-is-each-dc-enforcing).

A `Phase key` column that is not `(absent)` is a leftover `RC4DefaultDisablementPhase`
value from the 2026 rollout.  Remove it once you have confirmed nothing depends on it; see
[Historical: RC4DefaultDisablementPhase](#reference-what-rc4defaultdisablementphase-actually-does).
The `UseReqEtypes` column is `KdcUseRequestedEtypesForTickets` under `Services\Kdc`; it
should read `(absent)` or `0x0` on every DC.

### Check current GPO state

Rather than checking the registry on individual machines, scan SYSVOL directly to find
**every GPO in the domain** that delivers a Kerberos etype value.  Two delivery mechanisms
matter:

- the security option *Configure encryption types allowed for Kerberos*, stored in each
  GPO's `GptTmpl.inf` (the approach [PingCastle](https://www.pingcastle.com/) uses), and
- **Group Policy Preferences registry items**, stored in `Registry.xml` — the usual way to
  deliver `DefaultDomainSupportedEncTypes`, or a filter value at the `Lsa` path.

```powershell title="Find every GPO that delivers a Kerberos etype value, and where it is linked"
$domain = (Get-ADDomain).DNSRoot
$sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
$valueNames = 'SupportedEncryptionTypes', 'DefaultDomainSupportedEncTypes',
'RC4DefaultDisablementPhase', 'KdcUseRequestedEtypesForTickets'

function ConvertTo-EtypeText ([uint32]$Value) {
    $names = [ordered]@{ 0x1 = 'DES-CRC'; 0x2 = 'DES-MD5'; 0x4 = 'RC4'
        0x8 = 'AES128'; 0x10 = 'AES256'
    }
    $out = @($names.GetEnumerator() | Where-Object { $Value -band $_.Key } |
            ForEach-Object { $_.Value })
    if (($Value -band 0x7FFFFFE0) -eq 0x7FFFFFE0) { $out += 'Future' }   # GPO checkbox
    elseif ($Value -band 0x20) { $out += 'AES-SK' }
    if ($out) { $out -join ', ' } else { '(none)' }
}

Get-GPO -All | ForEach-Object {
    $gpo = $_
    $root = "$sysvolPath\{$($gpo.Id)}\Machine"
    $found = @()

    # 1. Security option -> writes the Policies path
    $inf = "$root\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (Test-Path -LiteralPath $inf) {
        foreach ($line in Get-Content -LiteralPath $inf) {
            if ($line -match 'Kerberos\\Parameters\\SupportedEncryptionTypes=4,(\d+)') {
                $found += [PSCustomObject]@{ Name = 'SupportedEncryptionTypes'
                    Value = [uint32]$Matches[1]; Source = 'Security option (Policies path)'
                }
            }
        }
    }

    # 2. Group Policy Preferences registry items -> any path
    $gpp = "$root\Preferences\Registry\Registry.xml"
    if (Test-Path -LiteralPath $gpp) {
        foreach ($hit in Select-Xml -LiteralPath $gpp -XPath '//Registry/Properties') {
            $p = $hit.Node
            if ($p.GetAttribute('name') -in $valueNames -and
                $p.GetAttribute('type') -eq 'REG_DWORD') {
                $found += [PSCustomObject]@{ Name = $p.GetAttribute('name')
                    Value                         = [Convert]::ToUInt32($p.GetAttribute('value'), 16)
                    Source                        = "Registry preference ($($p.GetAttribute('key')))"
                }
            }
        }
    }

    if ($found) {
        $xml = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
        $links = ($xml.GPO.LinksTo | ForEach-Object { $_.SOMPath }) -join '; '
        foreach ($f in $found) {
            [PSCustomObject]@{
                GPO         = $gpo.DisplayName
                Setting     = $f.Name
                'Value'     = '0x{0:X}' -f $f.Value
                Etypes      = if ($f.Name -like '*Enc*Types') { ConvertTo-EtypeText $f.Value } else { '' }
                Source      = $f.Source
                'Linked To' = if ($links) { $links } else { '(not linked)' }
            }
        }
    }
} | Format-Table -AutoSize -Wrap
```

Example output:

```text title="Example GPO etype policy scan output"
GPO                  Setting                        Value      Etypes                       Source                                        Linked To
---                  -------                        -----      ------                       ------                                        ---------
DC Kerberos Policy   SupportedEncryptionTypes       0x7FFFFFF8 AES128, AES256, Future       Security option (Policies path)               corp.local/Domain Controllers
DC Kerberos Policy   DefaultDomainSupportedEncTypes 0x18       AES128, AES256               Registry preference (SYSTEM\...\Services\Kdc) corp.local/Domain Controllers
Workstation Security SupportedEncryptionTypes       0x7FFFFFF8 AES128, AES256, Future       Security option (Policies path)               corp.local/Workstations; corp.local/Servers
Legacy App Servers   SupportedEncryptionTypes       0x7FFFFFFC RC4, AES128, AES256, Future  Security option (Policies path)               corp.local/Servers/Legacy
```

What to look for:

- **No results at all** -- no GPO delivers a Kerberos etype value.  Every machine uses its
  local default, and the KDC has no etype filter.
- **RC4 or DES in `Etypes`** -- that GPO allows legacy encryption.  Check `Linked To` to
  see whether it targets DCs (KDC filter) or workstations (client advertisement).
- **Multiple GPOs linked to the same OU** -- GPO precedence applies.  The GPO with the
  lowest link order wins.  Verify with `gpresult /R` on a target machine.
- **A GPO linked to `Domain Controllers` with a different value than one linked to
  workstations** -- this is expected in [Path 2](#path-2-aes-opportunistic-with-rc4-fallback)
  but should not happen in [Path 1](#path-1-modern-aes-only-environment).
- **A leftover `RC4DefaultDisablementPhase` or `KdcUseRequestedEtypesForTickets` item** --
  neither belongs in a finished configuration.

The scan lists what a GPO **contains**, not what is applied: it also lists GPOs whose link or
computer settings are disabled, GPOs narrowed by security or WMI filtering, and Preferences
items that are disabled or whose action is Delete (which removes the value instead of setting
it).  Treat each row as a place to look, and take the value in force from the per-DC
registry check.

This scan reads the two standard locations.  It does not see values pushed by scripts,
configuration-management tools, or hand edits — the per-DC registry check above does.

---

## Step 2: Generate AES Keys (Password Resets)

AES keys are generated when a password is set in a domain at functional level 2008 or
higher.  If an account's password predates that, the account has **no AES keys** in
`ntds.dit` --
regardless of what `msDS-SupportedEncryptionTypes` says.  Setting the attribute on a
keyless account does not create keys; it just makes ticket requests for it fail with
`KDC_ERR_ETYPE_NOSUPP`.

### Identify accounts that need a reset

--8<-- "includes/old-passwords-query.md"

Work through the rows with `HasSPN = True` first.

**Computer accounts** rotate their own password every 30 days by default, so any Windows
machine that has been online since the domain gained AES support has AES keys.

**Managed service accounts** (gMSA, MSA, dMSA) have passwords managed by AD and are
generated with AES keys.

### How many resets: one { #password-resets-and-aes-keys }

<a id="the-double-reset-problem"></a>**One password reset is enough.**  Every password set on an AES-capable DC writes the full
set of keys for the new password — RC4, AES128 and AES256 — in one operation.  Microsoft's
guidance for an account that only has RC4 keys is the same: reset the password once.

The "reset twice" advice that circulates belongs to a different problem.  AD keeps the
previous password's keys alongside the current ones, and for two kinds of account that
history matters:

- **`krbtgt`** — tickets issued under the previous key stay valid until a second rotation
  replaces it.
- **Trust accounts** — the same, for inter-realm tickets.

For an ordinary service account, reset once, verify the keys (below), and reset again only
if the verification shows AES keys are still missing.

### Reset user service account passwords

!!! danger "Coordinate with service owners before every reset"
    Resetting a user service account password breaks every service running under that
    account until the new password is deployed.  For each account:

    1. Identify all services, scheduled tasks, and application pools using the account.
    2. Identify every **keytab** exported for the account.  A reset increments the key
       version number (`msDS-KeyVersionNumber`), so every keytab must be regenerated even
       if the service could already handle AES.
    3. Schedule a maintenance window.
    4. Reset the password.
    5. Update the password in every service configuration, and redeploy keytabs.
    6. Restart the services.
    7. Verify authentication worked -- check that tickets are being issued and accepted,
       not just that the service started.

A new password exists only on the DC that processed the reset until replication carries it
to the others.  Clients that already hold a service ticket keep using it until it expires
(10 hours by default) or the cache is purged with `klist purge`, so some failures surface
hours after the change.

### Verify AES keys exist after reset

The quickest check is the `ServiceAvailableKeys` field of Security event 4769 on a DC.
Trigger a service ticket request for the account (connect to the service), then look at
the newest event for that service name:

```text title="Event 4769 — service keys after a successful reset"
ServiceAvailableKeys: AES-SHA1, RC4
```

If the field shows only `RC4`, AES keys were not generated — the reset was processed by a
DC that cannot generate them, or it did not happen.

For verification without waiting for an authentication event, use DSInternals to read
the stored keys directly from AD replication data
(see [Auditing Kerberos Keys](account-key-audit.md#method-2-dsinternals-definitive-online)):

```powershell title="Inspect stored Kerberos keys for a single account via DSInternals"
(Get-ADReplAccount -SamAccountName svc_example -Server dc1.corp.local).
SupplementalCredentials.KerberosNew.Credentials.KeyType
# Expected to include AES256_CTS_HMAC_SHA1_96 and AES128_CTS_HMAC_SHA1_96
```

---

## Step 3: Set msDS-SupportedEncryptionTypes on Manually-Managed SPN-Bearing Accounts { #step-3-set-msds-supportedencryptiontypes-on-manually-managed-spn-bearing-accounts }

Windows computer accounts are handled through Group Policy (Step 4).  All other
SPN-bearing account types must be updated by hand: user service accounts, gMSA, MSA,
and dMSA.  See the [account type taxonomy](../index.md#spn-bearing-account-types)
for the full list of defaults and targets for each type.

The KDC reads `msDS-SupportedEncryptionTypes` when it issues a service ticket for the
account.  Without an explicit value it uses the DC's fallback, which differs by update
level (see [What Affects Encryption](#3-defaultdomainsupportedenctypes-kdc-fallback)).
An explicit `24` gives the same answer on every DC.

### What value to use

| Situation | Value | Why |
|---|---|---|
| Account has AES keys and the service can decrypt AES | `24` (`0x18`) | The target.  AES256 ticket, AES256 session key. |
| Service is fine with AES, but some **clients** can only offer RC4 | `28` (`0x1C`) | Ticket stays AES256; the RC4 bit lets those clients agree a session key.  Record it as an exception. |
| The **service** cannot decrypt AES tickets at all | `36` (`0x24`) or `4` | A value with the RC4 bit and neither AES cipher bit makes the KDC issue an RC4 ticket for an account that has AES keys (`4`, `36` and the old default `39` all do); `28` does not.  `36` is Microsoft's suggestion in KB5073381 (RC4 ticket; AES256 session key for a client that lists AES256 first — that split was seen in the lab on the pre-April build only).  The DC filter must also allow RC4. |
| Account has no AES keys yet | Leave it and go back to [Step 2](#step-2-generate-aes-keys-password-resets) | No value fixes missing keys.  Until the reset, `28` keeps the account working on its RC4 key (lab: build 20348.5020, RC4 ticket); `24` or unset fails. |

Do **not** use `16` (`0x10`, AES256 only) unless you are certain no client needs AES128.

The full procedure for creating, scoping and retiring an RC4 exception is
[Keeping RC4 for Specific Accounts](rc4-deprecation.md#rc4-exceptions); this playbook only
tracks them (see
[RC4 Exceptions](#optional-enabling-rc4-for-specific-accounts-after-july-2026)).

### Before you change the value: can the service decrypt AES?

Having AES keys in AD is necessary but not sufficient.  Before an account moves to `24`,
confirm with the service owner that the service side can use them:

| Service type | What to confirm |
|---|---|
| Windows service, IIS application pool, scheduled task running as the account | Nothing extra.  Windows derives the keys from the password it was given. |
| gMSA / MSA / dMSA on Windows hosts | Nothing extra. |
| Anything that uses a **keytab** (Linux/Unix daemons, Java application servers, databases on Linux, storage and network appliances) | The keytab contains AES256 (and AES128) entries for the **current** key version.  A keytab exported with only an RC4 entry cannot decrypt an AES ticket even though AD holds AES keys; the service rejects the ticket. |
| Appliance or application with its own Kerberos settings | Its permitted-etype configuration includes AES, and the vendor documents AES support for the installed version. |

How to check or regenerate a keytab is specific to each product; use the vendor's
procedure.  If a service cannot be confirmed, leave its account out of the bulk run by
adding it to `$Exceptions`.

### Single account

```powershell title="Set AES-only on a single SPN-bearing account, keeping its feature bits (-WhatIf)"
$u = Get-ADUser svc_example -Properties 'msDS-SupportedEncryptionTypes'
$v = [int]$u.'msDS-SupportedEncryptionTypes'
Write-Information "Value before the change: $v (0 = unset)" -InformationAction Continue
Set-ADUser $u -Replace @{ 'msDS-SupportedEncryptionTypes' = ($v -band (-bnot 0x3F)) -bor 24 } -WhatIf
```

The command prints what it would do.  Note the value it reports, then remove `-WhatIf` to
write.  To undo, write the old value back with the same `-Replace`, or run
`Set-ADUser svc_example -Clear 'msDS-SupportedEncryptionTypes'` if it was unset.

Verify:

```powershell title="Verify msDS-SET value on a single account"
(Get-ADUser svc_example -Properties 'msDS-SupportedEncryptionTypes').'msDS-SupportedEncryptionTypes'
# Expected: 24
```

### Bulk update { #bulk-update-script }

Use the summary query from [Step 1](#spn-bearing-user-accounts) to see what you are
working with, then run the bulk script — first as it is, to read the plan.

--8<-- "includes/set-aes-user-accounts.md"

The same script handles the three managed service account types.  Run it once per type:

| `$AccountType` | Selects | Notes |
|---|---|---|
| `'User'` | User objects that have at least one SPN | `krbtgt` and `krbtgt_*` are always skipped |
| `'gMSA'` | Every `msDS-GroupManagedServiceAccount` object | With or without an SPN |
| `'MSA'` | Every `msDS-ManagedServiceAccount` object | With or without an SPN |
| `'dMSA'` | Every `msDS-DelegatedManagedServiceAccount` object (Windows Server 2025) | With or without an SPN |

A sensible order of work:

1. Run with `$DryRun = $true` and read both tables: what is skipped and why, and what
   would change, with the old and the new value of each account.
2. Resolve the skips that should not be skips (password resets from Step 2, keytab checks).
3. **Confirm that every account in the planned-changes table has AES keys**, with a method
   that reads keys: the [event fields](account-key-audit.md#detecting-accounts-that-need-password-reset-via-event-logs)
   for accounts in use, [DSInternals](account-key-audit.md#method-2-dsinternals-definitive-online)
   or an offline audit for the rest.  The script's password-date check is a heuristic, not
   a key check — see
   [why it is only approximate](account-key-audit.md#why-this-is-only-approximate).  An
   account without AES keys that is set to `24` stops working.
4. Set `$SearchBase` to one OU, set `$DryRun = $false`, and run the pilot.
5. Watch for a day (see the verification below), then widen `$SearchBase`.
6. Only then decide whether to widen `$OnlyFrom` to pick up accounts that carry an old
   explicit value such as `28`.

### Undo a bulk run

Every real run (`$DryRun = $false`) that has something to change first saves a CSV of
those accounts, with the `objectGUID`, the old value and the new value of each.  A dry run
writes no file.  To put the old values back:

--8<-- "includes/restore-msds-set.md"

### When the change takes effect

The KDC reads the attribute on every request, so a DC applies the new value as soon as the
change has replicated to it — there is nothing to restart.  Two delays remain:

- **Replication.**  Other DCs keep answering from the old value until they receive the
  change.
- **Cached tickets.**  A client that already holds a service ticket keeps using it until it
  expires (10 hours by default) or the user runs `klist purge`.  A service that cannot
  decrypt AES may therefore keep working for hours and then fail.

### Verify

On a patched DC an unset account that has AES keys already receives AES256 tickets, so the
ticket etype in event 4769 looks the same before and after this step.  Verify the things
that actually changed or could have broken.

**1. The attribute is at the target everywhere.**  Re-run the *not at target* query from
[Step 1](#spn-bearing-user-accounts).  The only rows left should be your recorded
exceptions and the accounts the bulk script skipped.

**2. No account lacks the keys its value now requires.**  In Security event 4769 on the
DCs, compare the service's effective value with the keys it has:

| Account state | `ServiceSupportedEncryptionTypes` | `ServiceAvailableKeys` | Result |
|---|---|---|---|
| Unset, patched DC, has AES keys | `0x18 (AES128-SHA96, AES256-SHA96)` | `AES-SHA1, RC4` | AES256 ticket — identical to the next row |
| `24`, has AES keys | `0x18 (AES128-SHA96, AES256-SHA96)` | `AES-SHA1, RC4` | AES256 ticket |
| `24` or unset on a patched DC, **no AES keys** | — | `RC4` | Request fails: `Status` `0xE`, `TicketEncryptionType` `0xFFFFFFFF` |

The [event-based query on the key audit page](account-key-audit.md#detecting-accounts-that-need-password-reset-via-event-logs)
lists exactly those accounts.

**3. The KDC refused nothing new.**  Re-run the [KDC event query](#find-what-is-still-asking-for-rc4)
from Step 1 and look for new 204, 208 or 209 events naming the accounts you changed.

**4. The services still accept their tickets.**  None of the checks above can see a service
that is handed an AES ticket it cannot decrypt: the KDC issued the ticket and has nothing
to log.  KB5073381 describes the keytab case this way: "This will most likely manifest in
the form of authentication failures from the target service rather than from the KDC."
Ask each service owner to confirm a fresh logon to the service after the change — fresh
meaning after `klist purge` on the client, or after the old tickets have expired.

### Verify with klist

On a client machine, purge the cache and request a fresh service ticket:

```text title="klist — service ticket for an AES-only account"
klist purge
klist get HTTP/svc-example.corp.local

#2>     Client: user@CORP.LOCAL
        Server: HTTP/svc-example.corp.local@CORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
```

`RSADSI RC4-HMAC(NT)` on either line means RC4 is still in play for that request: on the
`KerbTicket` line the account is being issued RC4 tickets, on the `Session Key` line the
client only offered RC4.

---

## Step 4: Configure Computer Accounts via GPO

A Windows machine derives its computer account's `msDS-SupportedEncryptionTypes` from its
own Kerberos configuration.  When a GPO writes the `SupportedEncryptionTypes` registry
value, the machine writes the matching value to its account in AD.

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

    Link it to one pilot OU first.  With RC4 unticked these machines stop offering RC4, so
    a user who only has RC4 keys cannot pre-authenticate from them (the reason the Path 2
    tab keeps RC4), and they cannot get a ticket for an account that is still an RC4-only
    (`4`) exception.  To undo, re-tick RC4 in the GPO; like the change itself, the undo
    reaches a machine with its next new logon session.

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

A changed client policy applies to **new logon sessions**.  Sessions that are already
running keep the etype list they started with.

### What happens automatically

The GPO writes one bit per ticked cipher box, plus bits 5-30 (`0x7FFFFFE0`) when "Future
encryption types" is ticked.  The machine then writes only the five cipher bits (0-4) to
its computer account in AD.

| Boxes ticked | Registry value | Computer account `msDS-SET` |
|---|---|---|
| AES128 + AES256 + Future | `0x7FFFFFF8` | `0x18` (24) |
| AES128 + AES256 | `0x18` | `0x18` (24) |
| RC4 + AES128 + AES256 + Future | `0x7FFFFFFC` | `0x1C` (28) |
| Every box | `0x7FFFFFFF` | `0x1F` (31 = DES + RC4 + AES128 + AES256) |

`0x1F` contains no AES session-key bit; that flag is `0x20` and never reaches the
computer account through this policy.  The last row was observed in the lab; the others
follow from the same rule (cipher bits 0-4 are copied, bits 5-30 are dropped) and are
worth confirming on one machine before you rely on them.

!!! tip "Which value to use"
    **Path 1** (AES-only): tick AES128, AES256 and Future → the AD attribute becomes
    `0x18`.

    **Path 2** (RC4 fallback): also tick RC4 → the AD attribute becomes `0x1C`.  Service
    tickets to these computers are still AES256, because the KDC picks the strongest etype
    with a matching key and computer accounts have AES keys.  The RC4 bit only allows an
    RC4 session key, for a client that offers no AES or lists RC4 ahead of it.

### Skip the wait: set msDS-SupportedEncryptionTypes directly

The GPO path depends on each machine processing policy and then updating its own account,
so the machine must be online and reachable.  You can write
`msDS-SupportedEncryptionTypes` on the computer account directly instead; DCs use the new
value as soon as the change replicates.

**Single computer:**

```powershell title="Set AES-only directly on a single computer account, keeping its feature bits (-WhatIf)"
$c = Get-ADComputer WS01 -Properties 'msDS-SupportedEncryptionTypes'
$v = [int]$c.'msDS-SupportedEncryptionTypes'
Write-Information "Value before the change: $v (0 = unset)" -InformationAction Continue
Set-ADComputer $c -Replace @{ 'msDS-SupportedEncryptionTypes' = ($v -band (-bnot 0x3F)) -bor 24 } -WhatIf
```

Remove `-WhatIf` to write.  To undo, write the reported old value back the same way.

**Bulk, one OU at a time:**

--8<-- "includes/set-aes-computer-accounts.md"

The undo procedure is the same as in [Step 3](#undo-a-bulk-run).

!!! note "The machine will overwrite a manual value"
    A Windows machine rewrites the attribute from its own configuration.  If its etype GPO
    is also AES-only, the values match and nothing changes.  If the GPO differs (for
    example, it includes RC4), the machine's value wins the next time it updates its
    account.  Treat the manual write as a way to get ahead of policy propagation, not as a
    substitute for the GPO.

    A manual write also blinds the check in the next section: once you have written `24`,
    AD shows `24` whether or not the machine ever applied the policy.

    If a machine is offline or decommissioned and will never process the GPO, the value in
    AD is the **only** value that matters.  The KDC reads the AD attribute, not the
    machine's local registry.

### Using msDS-SupportedEncryptionTypes to find GPO problems

Because each Windows machine reports what its policy produces, AD tells you where the
etype GPO has **not** landed: those machines still show the value they registered without
it (commonly `28`) instead of the `24` your AES-only GPO produces.

```powershell title="Windows computers that have not picked up the AES-only etype GPO"
$expected = 24

Get-ADComputer -Filter 'OperatingSystem -like "Windows*"' `
    -Properties 'msDS-SupportedEncryptionTypes', LastLogonDate, OperatingSystem |
    Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -notin 0, $expected } |
    Select-Object Name,
    @{N = 'msDS-SET'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    LastLogonDate, OperatingSystem,
    @{N = 'OU'; E = { ($_.DistinguishedName -split ',', 2)[1] } } |
    Sort-Object OU, Name |
    Format-Table -AutoSize
```

| Cause | How to identify | Fix |
|---|---|---|
| Machine is offline / decommissioned | `LastLogonDate` is weeks or months old | Clean up stale accounts, or set the value directly |
| Machine is in an OU not covered by the GPO | Check the `OU` column against your GPO scope | Move the machine or extend GPO scope |
| GPO is blocked or overridden by a higher GPO | Run `gpresult /r` on the machine | Fix GPO precedence / remove block |
| GPO applied but the account was not updated yet | `LastLogonDate` is recent | Run `gpupdate /force`, then restart the machine if the value does not change |

Accounts with **no value at all** are a different population — objects that never
registered one:

```powershell title="Computer objects with no msDS-SET (non-Windows, pre-staged, or never booted)"
Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes', LastLogonDate,
OperatingSystem, servicePrincipalName |
    Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -eq 0 } |
    Select-Object Name, OperatingSystem, LastLogonDate,
    @{N = 'SPNs'; E = { @($_.servicePrincipalName).Count } },
    @{N = 'OU'; E = { ($_.DistinguishedName -split ',', 2)[1] } } |
    Sort-Object OperatingSystem, Name |
    Format-Table -AutoSize
```

The `[int]` cast matters: an unset attribute is `$null`, and `$null -eq 0` is false in
PowerShell, so an uncast comparison silently returns nothing.

Each of these needs a decision by hand.  A NAS, a Linux host or an appliance that is joined
to the domain decrypts tickets with whatever its own software and keytab support.  On a
patched DC that has no explicit RC4 `DefaultDomainSupportedEncTypes` it is being issued
AES256 tickets today; if it is working, it handles AES and
can be set to `24` explicitly, and if it is not, see the
[triage runbook](enforcement-triage.md).

**Find computers whose value has RC4 or DES but no AES:**

```powershell title="Find computer accounts whose msDS-SET has legacy ciphers but no AES"
Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes', OperatingSystem |
    Where-Object {
        $v = [int]$_.'msDS-SupportedEncryptionTypes'
        ($v -band 0x7) -and -not ($v -band 0x18)      # DES/RC4 set, neither AES bit set
    } |
    Select-Object Name, OperatingSystem,
    @{N = 'msDS-SET'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'msDS-SET-Hex'; E = { '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes' } } |
    Format-Table -AutoSize
```

!!! tip "Ongoing monitoring"
    Run these queries on a schedule.  They catch newly joined machines that have not
    processed the GPO, machines that were moved between OUs, and stale accounts that
    should be disabled.  This is cheaper and more reliable than parsing `gpresult` output
    from every machine.

### Verify: check a computer account after GPO applies

```powershell title="Force GPO refresh and verify msDS-SET on a computer account"
$Computer = 'WS01'
Invoke-Command -ComputerName $Computer -ScriptBlock { gpupdate /force }

Get-ADComputer $Computer -Properties 'msDS-SupportedEncryptionTypes' |
    Select-Object Name, @{N = 'msDS-SET'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } }
# Expected: msDS-SET = 24 (may need a restart of the machine before it updates its account)
```

---

## Step 5: Set DefaultDomainSupportedEncTypes on Every DC

### Why this still matters

On a DC with the April 2026 update or later, an absent `DefaultDomainSupportedEncTypes`
already means AES-only for unconfigured accounts.  There are still two things to do here:

1. **Find and remove any explicit value that includes RC4.**  An explicit value overrides
   the built-in default, so a DC carrying `0x27`, `0x3C` or `0x1C` from an earlier
   migration phase is still issuing RC4-capable answers for every unconfigured account.
   Such a DC logs System event 205 each time the KDC starts.
2. **Pin `0x18` explicitly.**  Then the fallback no longer depends on which update a DC
   has: a DC restored from an old image, or one that has fallen behind on patching,
   behaves like the rest.

### Before you change it

On a DC that runs the April 2026 update or later and shows `DDSET = (absent)` in the
[per-DC registry check](#check-current-dc-registry-state), pinning `0x18` changes nothing.
Two kinds of DC **do** change behavior, at the moment the value is written:

- a DC with an explicit value that contains RC4 (`0x27`, `0x3C`, `0x1C`, `0x24`): every
  unconfigured account it answers for loses its RC4 fallback;
- a DC older than the April 2026 update with no value: its built-in default was `0x27`.

If you have either, clear this gate first:

1. **Step 3 left no account behind.**  The accounts the bulk script skipped as `password
   predates AES keys` or `password never set`, and every service you held back because its
   keytab could not be confirmed, are still unset.  Those are exactly the accounts that
   live on the fallback you are about to remove.  Reset the password, fix the service, or
   give the account an explicit, recorded exception before you go on.
2. **Nothing is still being issued RC4 through that DC.**  The KDC events cannot tell you:
   201-204 are not logged on a DC that has an explicit value (see
   [Step 1](#find-what-is-still-asking-for-rc4)).  Run Microsoft's
   `Get-KerbEncryptionUsage.ps1 -Encryption RC4` on that DC and account for every RC4
   service ticket it lists whose target has no `msDS-SupportedEncryptionTypes` of its own.
3. **One DC first.**  The script below starts with a single canary DC, records every
   previous value, and is undone by running it again.

### Set on all DCs

--8<-- "includes/ddset-per-dc-set.md"

!!! warning "Per-DC, not replicated"
    This is a **local registry value** on each DC.  It is not replicated through AD.
    You must set it on every DC individually.  If you add a new DC later, you must set
    it on the new DC as well — or deliver it with a Group Policy Preferences registry item
    linked to the Domain Controllers OU so new DCs receive it automatically.

### Verify on all DCs

Re-run the [per-DC registry check](#check-current-dc-registry-state) from Step 1.  Every
DC should show `DDSET = 0x18` and an empty `Error` column.

---

## Step 6: Close the KDC Filter on Domain Controllers { #step-6-apply-etype-gpo-to-domain-controllers }

The etype GPO has a different effect on domain controllers than on workstations.  On a DC
the `SupportedEncryptionTypes` value is also a **KDC etype filter**: the KDC will not
issue a ticket, or accept pre-authentication, with an etype the value does not allow.  On
workstations the same GPO only controls the client's etype advertisement.  Different OU,
different impact.

The checkboxes differ by path — see [Step 6a](#step-6-apply-aes-only-gpo-to-domain-controllers)
and [Step 6b](#step-6-apply-rc4-aes-gpo-to-domain-controllers).  The rollout procedure is
the same for both and is described here once.

### How the filter interacts with the other settings

The filter and the account's effective etype set are two independent mechanisms, and they
do not simply intersect (see the matrix under
[How service ticket etypes are selected](#how-service-ticket-etypes-are-selected)):

- For an **unconfigured** account, an AES-only filter lifts an RC4 fallback to AES.  A DC
  whose `DefaultDomainSupportedEncTypes` still includes RC4 will issue AES256 once the
  filter is active.  Align the two anyway (Step 5), so the configuration still holds if
  the filter is ever removed.
- For an account with an **explicit** value, the filter never substitutes anything.  An
  account set to `4` (RC4-only) behind an AES-only filter gets `KDC_ERR_ETYPE_NOSUPP`.
  Every RC4 exception you still need must be resolved, or the filter must keep RC4
  ([Path 2](#path-2-aes-opportunistic-with-rc4-fallback)), before you close it.
- The filter also applies to the **AS exchange**.  A user who only has RC4 keys cannot
  log on through a DC whose filter is AES-only.

### Before an AES-only filter: `krbtgt` must have AES keys { #check-krbtgt-keys }

Every TGT is encrypted with a `krbtgt` key (see
[krbtgt account keys](#1-krbtgt-account-keys)).  If `krbtgt` has no AES keys the KDC cannot
issue AES TGTs, and an AES-only filter forbids the RC4 ones.  Check before the first KDC
restart, not afterwards.  In a TGT request the service is `krbtgt`, so the
`ServiceAvailableKeys` field of Security event 4768 is `krbtgt`'s key list as that DC sees
it:

```powershell title="Check that krbtgt has AES keys, as every DC reports it"
$DCs = (Get-ADDomainController -Filter *).HostName
$xpath = "*[System[(EventID=4768)]] and *[EventData[Data[@Name='Status']='0x0']]"

$krbtgtKeys = foreach ($dc in $DCs) {
    try {
        $ev = Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath `
            -MaxEvents 1 -ErrorAction Stop
        $d = @{}
        ([xml]$ev.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        $keys = $d.ServiceAvailableKeys
        $verdict = if ($d.ServiceName -ne 'krbtgt' -or -not $keys -or $keys -in @('N/A', '-')) {
            'NOT CHECKED: this event carries no krbtgt key list'
        }
        elseif ($keys -match 'AES') { 'AES keys present' }
        else { 'NO AES KEYS' }
        [PSCustomObject]@{ DC = $dc; EventTime = $ev.TimeCreated; KrbtgtKeys = $keys; Verdict = $verdict }
    }
    catch {
        [PSCustomObject]@{ DC = $dc; EventTime = $null; KrbtgtKeys = '?'
            Verdict = "NOT CHECKED - $($_.Exception.Message)"
        }
    }
}
$krbtgtKeys | Format-Table -AutoSize -Wrap
Get-ADUser -Identity krbtgt -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
```

- **Every DC must say `AES keys present`.**  That is the gate for an AES-only filter.
- **`NO AES KEYS` on any DC**: do not close the filter.  Rotate `krbtgt` once, following the
  [KRBTGT rotation procedure](mitigations.md#priority-9-krbtgt-password-rotation), let it
  replicate, and run the check again.
- **`NOT CHECKED` is an unknown, not a pass.**  The key list exists only in the event
  format introduced with the January 2025 updates, and only when Kerberos auditing is on
  (see [Step 1](#find-what-is-still-asking-for-rc4)).  For a DC that cannot answer this
  way, read the keys directly with the
  [single-account DSInternals command](account-key-audit.md#method-2-dsinternals-definitive-online).

[Path 2](#path-2-aes-opportunistic-with-rc4-fallback) keeps RC4 in the filter, so this is
not a gate there; its AES256 TGTs still depend on `krbtgt` having AES keys.

### Rolling out a filter change { #rolling-out-a-filter-change }

!!! warning "The filter is read only when the KDC service starts"
    `gpupdate` delivers the registry value, but the running KDC keeps using the filter it
    loaded at start-up — or no filter at all.  Until the service is restarted, nothing
    changes and every verification passes vacuously.  Then the filter switches on DC by DC,
    whenever each one happens to reboot.  Control that moment yourself.

1. **Edit the GPO** linked to the Domain Controllers OU and let it replicate.
2. **Deliver the value without activating it.**  Run `gpupdate /force` on every DC, then
   confirm with the [per-DC registry check](#check-current-dc-registry-state) that every
   DC shows the new `Filter (Pol)` value.
3. **Activate it on one canary DC.**  Pick a DC that is not the only one in its site.

    ```powershell title="Activate the delivered filter on the canary DC"
    $CanaryDC = 'dc02.corp.local'
    Invoke-Command -ComputerName $CanaryDC -ScriptBlock { Restart-Service kdc }
    ```

4. **Prove the filter is active on the canary** with the positive test below (Path 1), and
   confirm that ordinary logons and service access through that DC still work.
5. **Watch the canary** for failed 4768/4769 events and KDC System events 16 and 27 for at
   least one working day.
6. **Restart the KDC service on the remaining DCs one at a time**, checking each before
   moving on.  Do not leave the domain half-activated for long: any unplanned DC reboot
   activates the filter on that DC too.

**Aiming a test at one DC.**  A client uses whichever DC it has located, so a test that is
meant for the canary can be answered by another DC.  Microsoft's `klist` reference gives
the command "to target the client computer to the specific domain controller".  Run it on
the test client; the reference says the command needs Domain Admin rights or equivalent for
all of its parameters:

```text title="Bind a test client's Kerberos requests to the DC under test, and release it afterwards"
klist purge_bind
klist add_bind CORP.LOCAL dc02.corp.local
klist query_bind

  ... run the test ...

klist purge_bind
```

Microsoft describes the binding as a *preferred* domain controller, so treat it as a
request, not as proof: after each test, confirm on the DC itself that it logged the
request.  Leave no binding behind — `klist purge_bind` removes it.

**Positive test (AES-only filter).**  A registry value proves delivery, not activation.
To prove the KDC is filtering, ask it for something the filter must refuse — from a client
that would otherwise be given it.

The client is the part that is easy to get wrong.  A client that offers only AES is
refused a ticket for an RC4-only account by **any** DC, filtered or not, so a test run from
such a client always "passes".  A DC that has just received the AES-only policy is such a
client for every new logon session, which is why this test is not run in a session on the
DC.  It has four parts: a control that proves the client is given the RC4 ticket while no
filter is active, the same request after the KDC restart, a check of what the DC under
test logged, and the clean-up.

**Part 1: create the test account**, before the first KDC restart (rollout step 3).

```powershell title="Positive test, part 1: create a throwaway RC4-only test account (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$TestName = 'kdc-filter-test'
$TestSpn = 'HTTP/kdc-filter-test.corp.local'
$DryRun = $true      # $true = show what would be created.  Set $false to create it.

# ---- Logic: one block, paste it whole or save it as a .ps1 --------------------
& {
    $ErrorActionPreference = 'Stop'
    if ($DryRun -isnot [bool]) {
        throw '$DryRun must be $true or $false: run the settings lines first.'
    }
    # 40 random characters that nobody ever sees, plus four fixed ones so that a
    # complexity rule is always met.  The password is never needed again.
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    $bytes = New-Object byte[] 40
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $pw = New-Object System.Security.SecureString
    foreach ($b in $bytes) { $pw.AppendChar($alphabet[$b % $alphabet.Length]) }
    foreach ($c in 'Aa1-'.ToCharArray()) { $pw.AppendChar($c) }
    #
    # msDS-SupportedEncryptionTypes = 4: RC4 only, no etype in common with the filter
    New-ADUser -Name $TestName -SamAccountName $TestName -AccountPassword $pw -Enabled $true `
        -ServicePrincipalNames $TestSpn `
        -Description 'TEMPORARY KDC filter test account - delete after the rollout' `
        -OtherAttributes @{ 'msDS-SupportedEncryptionTypes' = 4 } -WhatIf:$DryRun
    if ($DryRun) {
        Write-Information "Dry run: $TestName was not created." -InformationAction Continue
    }
    else {
        Write-Information "Created $TestName.  Remove it with the clean-up script when the rollout is done." -InformationAction Continue
    }
}
```

**Part 2: the control.**  Wait for the account to replicate.  Then, on the test client,
while no DC has an active filter yet:

```text title="Positive test, part 2 (control): with no filter active, the client must be GIVEN an RC4 ticket"
klist purge
klist get HTTP/kdc-filter-test.corp.local
```

The request must succeed, and the new ticket must show `RSADSI RC4-HMAC(NT)` as its
`KerbTicket Encryption Type`.  If it is refused, this client does not offer RC4 and cannot
run the test at all: use a machine that still applies an RC4 + AES etype policy.  Without a
passing control the rest proves nothing.  Stay in the same logon session for every DC you
test.

**Part 3: the same request after the KDC restart**, bound to the DC you just restarted:

```text title="Positive test, part 3: the same request, aimed at the DC whose KDC was restarted"
klist purge_bind
klist add_bind CORP.LOCAL dc02.corp.local
klist purge
klist get HTTP/kdc-filter-test.corp.local
```

With the filter active the request is refused; Microsoft's example of this failure reads
`klist failed with 0xc00002fd/-1073741059: The encryption type requested is not supported
by the KDC.`  With the filter inactive a ticket comes back, RC4 again.

**Part 4: read the verdict from the DC**, not from the client:

```powershell title="Positive test, part 4: verdict from the Security log of the DC under test"
# ---- Operator settings -------------------------------------------------------
$TestDC = 'dc02.corp.local'
$TestName = 'kdc-filter-test'
$TestSpn = 'HTTP/kdc-filter-test.corp.local'
$Since = (Get-Date).AddMinutes(-10)   # must be later than the KDC restart on $TestDC

# ---- Logic: one block; it only reads -----------------------------------------
& {
    $ErrorActionPreference = 'Stop'
    try {
        $all = @(Get-WinEvent -ComputerName $TestDC -FilterHashtable @{
                LogName = 'Security'; Id = 4769; StartTime = $Since
            })
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            throw "NOT CHECKED: the Security log of $TestDC could not be read ($($_.Exception.Message))"
        }
        $all = @()
    }
    $hits = @(foreach ($ev in $all) {
            $d = @{}
            ([xml]$ev.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            # a refused request can carry the SPN instead of the account name
            if ($d.ServiceName -eq $TestName -or $d.ServiceName -like "$TestSpn*") {
                [PSCustomObject]@{
                    Time          = $ev.TimeCreated
                    Client        = $d.TargetUserName
                    Status        = $d.Status
                    TicketEtype   = $d.TicketEncryptionType
                    ClientOffered = $d.ClientAdvertizedEncryptionTypes
                }
            }
        })
    $hits | Format-Table -AutoSize -Wrap | Out-Host
    $issued = @($hits | Where-Object Status -EQ '0x0')
    $refused = @($hits | Where-Object Status -EQ '0xE')
    $noRc4 = @($refused | Where-Object {
            $_.ClientOffered -and $_.ClientOffered -ne '-' -and $_.ClientOffered -notmatch 'RC4'
        })
    if ($issued.Count -gt 0) {
        $last = ($issued | Sort-Object Time)[-1].Time
        Write-Warning "FAIL: $TestDC issued a ticket for the test account at $last.  If that is later than its KDC restart, its filter is NOT active."
    }
    elseif ($refused.Count -eq 0) {
        Write-Warning "INCONCLUSIVE: $TestDC logged no refused request for the test account since $Since.  The request went to another DC, or failure auditing is off."
    }
    elseif ($noRc4.Count -eq $refused.Count) {
        Write-Warning 'INCONCLUSIVE: the client offered no RC4, so any DC would have refused it.  Use a client that passes the control.'
    }
    else {
        Write-Information "PASS: $TestDC refused the request (0xE, KDC_ERR_ETYPE_NOSUPP).  This counts only if the control passed in the same logon session." -InformationAction Continue
    }
}
```

| Verdict | Meaning | Next |
|---|---|---|
| `PASS` | This DC logged the refusal.  Together with a passing control, its filter is active. | Go on to the next DC. |
| `FAIL` | This DC issued a ticket for the RC4-only account after its KDC restart. | The filter is not active on it.  Check `Filter (Pol)` in the per-DC registry check; on Server 2025 see below. |
| `INCONCLUSIVE` | The DC under test did not log the request, or the client never offered RC4. | Not a pass.  Fix the binding, the auditing or the client, and repeat part 3. |

`ClientOffered` is shown for information.  It cannot replace the control: on a refused
request the DC may write `-` there, as it does in Microsoft's published example of a failed
4769.

**Clean-up.**  Remove the account when the last DC has passed — and also when you stop for
any other reason: a `FAIL` you cannot resolve today, a rollback, an abandoned change, or a
pause of more than the working day (create it again when you resume).  Nothing removes it
for you.

```powershell title="Positive test, clean-up: remove the test account (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$TestName = 'kdc-filter-test'
$DryRun = $true      # $true = show what would be removed.  Set $false to remove it.

# ---- Logic: one block, paste it whole or save it as a .ps1 --------------------
& {
    $ErrorActionPreference = 'Stop'
    if ($DryRun -isnot [bool]) {
        throw '$DryRun must be $true or $false: run the settings lines first.'
    }
    $u = Get-ADUser -Identity $TestName -Properties Description
    if ($u.Description -notlike 'TEMPORARY KDC filter test account*') {
        throw "$TestName does not carry the test account's description: not removing it."
    }
    Remove-ADUser -Identity $u -Confirm:$false -WhatIf:$DryRun
    if ($DryRun) {
        Write-Information "Dry run: $($u.DistinguishedName) was not removed." -InformationAction Continue
    }
    else {
        Write-Information "Removed $($u.DistinguishedName).  On the test client: klist purge_bind" -InformationAction Continue
    }
}
```

The refusal itself is lab-verified: on Server 2022 build 20348.5020 an explicit RC4-only
account was issued an RC4 ticket with no filter and got `KDC_ERR_ETYPE_NOSUPP` behind an
AES-only filter, from the same client.  The lab drove it with a Linux client, so the
`klist` steps above have not been run there; check them on your first DC.

**Rollback.**  Removing or loosening the filter follows the same rule as applying it, with
two traps:

1. Change the GPO back by **re-ticking RC4**.  Do not unlink the GPO or set the policy to
   "Not Defined" and expect the value to go away.  Microsoft documents that a security
   setting which is no longer defined, and has no earlier value to return to, "doesn't
   revert to anything and remains defined as is" — the behavior known as tattooing.  The
   registry value stays, and it is the registry value the KDC loads.
2. Run `gpupdate /force` on the affected DCs and confirm with the
   [per-DC registry check](#check-current-dc-registry-state) that `Filter (Pol)` changed.
3. Look at `Filter (Lsa)` in the same table.  If you delivered a value to the `Lsa` path
   for a Windows Server 2025 DC (see below), the GPO checkboxes do not touch it: change or
   remove that Preferences item as well.
4. **Restart the KDC service** on each of them.  A removed value keeps filtering until the
   restart, exactly as a new value stays inactive until one.

When one DC is causing an outage and Group Policy is too slow, write the value on that DC
directly and restart its KDC:

```powershell title="Rollback on one DC: write the filter value directly and restart its KDC (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$DC = 'dc02.corp.local'
$FilterValue = 0x7FFFFFFC   # RC4 + AES128 + AES256 + Future.  $null = remove the value.
$DryRun = $true      # $true = show the current values and the plan.  Set $false to act.

# ---- Logic: one block, paste it whole or save it as a .ps1 --------------------
& {
    $ErrorActionPreference = 'Stop'
    if ($DryRun -isnot [bool]) {
        throw '$DryRun must be $true or $false: run the settings lines first.'
    }
    if (-not (Get-Variable -Name FilterValue -ErrorAction SilentlyContinue)) {
        throw '$FilterValue is not defined: run the settings lines first.'
    }
    if ($null -ne $FilterValue -and $FilterValue -isnot [int]) {
        throw '$FilterValue must be a number, or $null to remove the value.'
    }
    $result = Invoke-Command -ComputerName $DC -ArgumentList $FilterValue, $DryRun -ScriptBlock {
        param($FilterValue, $DryRun)
        $ErrorActionPreference = 'Stop'
        $name = 'SupportedEncryptionTypes'
        $paths = [ordered]@{
            Policies = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            Lsa      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
        }
        foreach ($where in $paths.Keys) {
            $path = $paths[$where]
            $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
            $present = $key -and ($key.GetValueNames() -contains $name)
            $before = if ($present) { '0x{0:X}' -f $key.GetValue($name) } else { '(absent)' }
            # An existing value is replaced or removed.  A missing one is created only
            # at the Policies path, which is where the GPO writes it.
            $plan = if ($null -eq $FilterValue -and $present) { 'remove' }
            elseif ($null -ne $FilterValue -and ($present -or $where -eq 'Policies')) {
                'set to 0x{0:X}' -f $FilterValue
            }
            else { 'leave' }
            if (-not $DryRun -and $plan -eq 'remove') {
                Remove-ItemProperty -Path $path -Name $name
            }
            if (-not $DryRun -and $plan -like 'set*') {
                if (-not $key) { New-Item -Path $path -Force | Out-Null }
                New-ItemProperty -Path $path -Name $name -PropertyType DWord `
                    -Value $FilterValue -Force | Out-Null
            }
            [PSCustomObject]@{ Path = $where; Before = $before; Plan = $plan
                Done = (-not $DryRun -and $plan -ne 'leave')
            }
        }
        if (-not $DryRun) { Restart-Service -Name kdc }
    }
    $result | Format-Table Path, Before, Plan, Done -AutoSize | Out-Host
    if ($DryRun) {
        Write-Information "Dry run: nothing was changed on $DC and its KDC was not restarted." -InformationAction Continue
    }
    else {
        Write-Information "Done: see the table for what was changed on $DC; its KDC was restarted." -InformationAction Continue
    }
}
```

The `Before` column is the undo: run the script again with that value.  A direct edit does
not change the GPO, so make the GPO agree (step 1) and re-run the per-DC registry check
after the next policy refresh to see which value is in place.

### Windows Server 2025 domain controllers

The KDC has not read the filter from the same place on every OS build.  In this site's
lab, a Windows Server 2022 DC honored the value at both the Policies path (where the GPO
writes it) and the `Lsa` path, with Policies taking precedence.  The one Windows Server
2025 build tested — 26100.32522, the **March 2026** update, so before the April 2026
cumulative update — honored **only** the `Lsa` path: the value the standard GPO wrote was
present in the registry and ignored by the KDC.

Microsoft's April 2026 cumulative update for Server 2025 (KB5082063, build 26100.32690)
states that "Windows reads the configured policy settings as expected" for Kerberos
encryption policies, so the problem is reported fixed from that build on.  That has **not
been retested here**.

--8<-- "includes/lab-builds.md"

Do not assume either behavior.  On every Server 2025 DC, whatever its update level:

1. Run the positive test above after the KDC restart.
2. If the verdict is `FAIL` — the test account still receives an RC4 ticket — the filter is
   not being read from the Policies path on that build.  First bring the DC up to the April 2026 cumulative update
   (KB5082063) or later, restart the KDC service and repeat the test.  If it still fails,
   deliver the same value to
   `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\SupportedEncryptionTypes`
   (REG_DWORD) with a Group Policy Preferences registry item, restart the KDC service, and
   repeat the test.

In a mixed 2022/2025 fleet, an untested 2025 DC is the place where RC4 tickets keep being
issued after you believe the filter is closed.

---

## Path 1: Modern AES-Only Environment

For domains where **every account has AES keys** and no legacy constraints remain.

### Prerequisites

Before entering this path, confirm:

- All SPN-bearing user accounts have AES keys and `msDS-SupportedEncryptionTypes = 0x18`
  (Steps 2-3 complete), apart from recorded exceptions
- No recorded exception still depends on RC4.  An account at `4` or `36` stops working
  behind an AES-only filter, and the RC4-only clients that a `28` exception exists for can
  no longer authenticate through it (the filter also applies to the AS exchange)
- `krbtgt` has AES keys on every DC — run the
  [`krbtgt` key check](#check-krbtgt-keys) before the first KDC restart
- All computer accounts have been reviewed (Step 4 complete)
- `DefaultDomainSupportedEncTypes = 0x18` on every DC (Step 5 complete).  An absent value
  gives the same result only where every DC has the April 2026 update or later; this guide
  pins `0x18` so the answer does not depend on patch level
- **No** regular user accounts lack AES keys (the
  [key audit](account-key-audit.md)
  returns zero results)
- Trusts have been checked: see
  [Trust Encryption Types](mitigations.md#priority-11-trust-encryption-types)

### Step 6a: AES-Only Filter on Domain Controllers { #step-6-apply-aes-only-gpo-to-domain-controllers }

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

3. Confirm that [`krbtgt` has AES keys](#check-krbtgt-keys) on every DC.
4. Follow [Rolling out a filter change](#rolling-out-a-filter-change): deliver with
   `gpupdate`, restart the KDC service on a canary DC, run the positive test, then roll
   through the remaining DCs one at a time.

### Verify: request a ticket and check Event 4769

After full standardization (Steps 1-6 complete), a 4769 event for a service ticket request
should look like:

```text title="Event 4769 — fully standardized AES-only environment"
ServiceName:                      svc_example
ServiceSupportedEncryptionTypes:  0x18 (AES128-SHA96, AES256-SHA96)
ServiceAvailableKeys:             AES-SHA1, RC4
ClientAdvertizedEncryptionTypes:  AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96
TicketEncryptionType:             0x12
SessionKeyEncryptionType:         0x12
```

Every field confirms AES: the account is configured for AES (`0x18`), the ticket is
AES256 (`0x12`), and the session key is AES256 (`0x12`).  `RC4` under
`ServiceAvailableKeys` is expected — every password still produces an RC4 key; it is
simply never selected.

### Path 1: Verification Checklist

- [ ] All SPN-bearing user service accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All gMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All MSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All dMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] `krbtgt` has AES keys and its `msDS-SupportedEncryptionTypes` is unset
- [ ] All SPN-bearing user accounts have AES keys (verified, not inferred from dates)
- [ ] All regular user accounts have AES keys
- [ ] Every keytab-based service has been confirmed to decrypt AES tickets
- [ ] `DefaultDomainSupportedEncTypes = 0x18` on **every** DC — or absent on every DC, all on
      the April 2026 update or later (per-DC check shows no errors)
- [ ] AES-only filter delivered to every DC **and** the KDC service restarted on every DC
- [ ] Positive test passed on every DC, including every Windows Server 2025 DC
- [ ] The `kdc-filter-test` account has been removed and `klist purge_bind` run on the test client
- [ ] AES-only GPO applied to workstation/server OUs
- [ ] No KDC System events 203, 204, 208 or 209 on any DC for 30 days, with every DC
      actually checked
- [ ] No unexplained KDC System events 16 or 27 on any DC
- [ ] Event 4769 shows `TicketEncryptionType = 0x12` (AES256) for service tickets
- [ ] `klist` on clients shows `AES-256-CTS-HMAC-SHA1-96` for tickets and session keys
- [ ] Computer objects with no `msDS-SET` have each been investigated
- [ ] No leftover `RC4DefaultDisablementPhase` or `KdcUseRequestedEtypesForTickets` value on any DC

---

## Path 2: AES Opportunistic with RC4 Fallback

For domains where all manually-managed SPN-bearing accounts and computer accounts are AES-only, but some
**regular user accounts** (no SPNs) lack AES keys and their passwords cannot be reset
yet.

### When to use this path

You have completed Steps 1-5 and confirmed:

- All SPN-bearing user accounts have AES keys and `msDS-SupportedEncryptionTypes = 0x18`
- All computer accounts have been reviewed (Step 4)
- `DefaultDomainSupportedEncTypes = 0x18` on every DC (or absent on every DC, with all of
  them on the April 2026 update or later)

But some regular user accounts remain with passwords that predate AES support.  These
accounts have **no AES keys** and their passwords cannot be reset because of:

- Password is unknown (set decades ago, nobody remembers the value, and resetting it
  would lock the user out of systems that cache the old credential)
- Business process dependency (password is embedded in scripts, batch jobs, or legacy
  applications outside the domain admins' control)
- Organizational constraints (labor agreements, compliance rules, or management decisions
  preventing forced password resets without user consent)
- Third-party management (account managed by an external vendor who sets the schedule)

!!! warning "Windows Server 2025 domain controllers may not serve these users at all"
    This path depends on the AS exchange still working for an account that has only RC4
    keys.  Microsoft's guidance says of Server 2025: "Starting with Windows Server 2025,
    domain controllers don't issue RC4 Ticket Granting Tickets. While you can authenticate
    **to** legacy devices with RC4, the legacy device isn't able to authenticate using
    Kerberos. You need to use earlier versions of Windows Server for your domain
    controllers."
    ([Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos))

    This site's lab does not settle it.  Its one Server 2025 check (build 26100.32522, the
    March 2026 update) still got an RC4 answer to a TGT request that asked for RC4.  That
    is not the same as a logon by an account that has only RC4 keys, which was not run on
    any build.

    If the domain has, or is about to get, a Server 2025 DC: before you rely on this path,
    bind a test client to that DC and log on with one legacy user (the method is in
    [Step 6b](#step-6-apply-rc4-aes-gpo-to-domain-controllers)).  If the logon fails, those
    users need a password reset, or DCs running an earlier Windows Server version, as
    Microsoft says.

### Understanding your RC4 exposure

These accounts have **no SPNs**.  This fundamentally changes the risk profile compared
to RC4 on a user service account.

**What uses RC4 for these users:**

| Component | Etype | Why |
|---|---|---|
| Pre-authentication (AS-REQ timestamp) | RC4 | Encrypted with the user's key; only an RC4 key exists |
| AS-REP enc-part (TGT session key delivery) | RC4 | KDC must encrypt the reply with a key the user can decrypt |

**What uses AES despite these users having only RC4 keys:**

| Component | Etype | Why |
|---|---|---|
| TGT ticket encryption | AES256 | Encrypted with krbtgt's key, not the user's key |
| TGT session key | AES256 | Chosen from the client's etype list; independent of the user's stored keys |
| Service ticket encryption | AES256 | Determined by the target account's `msDS-SET = 0x18` |
| Service ticket session key | AES256 | An etype the client offered that the target's set contains |

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

### Step 6b: RC4 + AES Filter on Domain Controllers { #step-6-apply-rc4-aes-gpo-to-domain-controllers }

The DC filter must include RC4 so the KDC can use RC4 for the AS exchange when users
with only RC4 keys log in.  If the DC filter blocks RC4, these users get
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

3. Follow [Rolling out a filter change](#rolling-out-a-filter-change): deliver with
   `gpupdate`, restart the KDC service on a canary DC, then roll through the remaining DCs
   one at a time.  The positive test in that section is written for an AES-only filter and
   does not apply here; instead confirm that a known legacy user can still log on through
   the canary DC, and that the [per-DC registry check](#check-current-dc-registry-state)
   shows the value on every DC.

    To make that logon go through the canary: bind a test workstation to it with
    `klist add_bind` (see *Aiming a test at one DC* under
    [Rolling out a filter change](#rolling-out-a-filter-change)), have the legacy user
    log on there, then run the
    [RC4 pre-authentication query](#monitoring-rc4-pre-authentication) with its `$DCs` line
    replaced by `$DCs = @('dc02.corp.local')`.  A row for that user proves the canary
    served the logon with RC4 pre-authentication.  No row means another DC answered, or the
    logon failed: check the user's 4768 and 4771 events on the canary before you go on.
    Do this on a Windows Server 2025 DC in particular; see the warning under
    [When to use this path](#when-to-use-this-path).

!!! info "RC4 in the DC filter does not weaken service tickets"
    The filter allowing RC4 means the KDC **can** use RC4 -- not that it **will**.
    Service ticket etype is controlled by the target account's
    `msDS-SupportedEncryptionTypes`.  Since all manually-managed SPN-bearing accounts have `msDS-SET = 0x18`
    (Step 3), service tickets are AES256.  The filter allowing RC4 only matters for
    the AS exchange (login) of users whose only keys are RC4.

    Similarly, `DefaultDomainSupportedEncTypes = 0x18` (Step 5) ensures that even
    SPN-bearing accounts you may have missed default to AES.  A filter that allows RC4
    does not turn an AES fallback into RC4.

### Why DefaultDomainSupportedEncTypes stays at 0x18

A common question: "If I need RC4 for some users, should I also set
`DefaultDomainSupportedEncTypes` to include RC4?"

No.  `DefaultDomainSupportedEncTypes` is consulted during **TGS processing** when a
SPN-bearing account has `msDS-SET = 0`.  It controls what etype the KDC uses for service
tickets to unconfigured accounts.

Your legacy users have no SPNs.  Nobody requests service tickets for them.
`DefaultDomainSupportedEncTypes` is irrelevant for their authentication.  Keeping it at
`0x18` ensures that any SPN-bearing account you missed in Step 3 gets AES tickets.

### What Microsoft's 2026 change does and does not touch { #rc4defaultdisablementphase-and-july-2026 }

The 2026 RC4 change altered one thing: the etype set the KDC assumes for a **service
ticket target** that has no `msDS-SupportedEncryptionTypes`.  In the lab it left the AS
exchange alone: on an enforcing Server 2022 DC (build 20348.5020) a TGT request that asked
for RC4 was still answered with RC4, at every setting of the rollout gate.  The lab did
**not** run the case this path rests on — a logon by an account that has only RC4 keys —
so for that case the result is an inference, not an observation.

So for these legacy users:

- Their login path (AS exchange) is governed by the DC filter, which you have explicitly
  set to include RC4.  Microsoft's change does not modify an explicit filter.
- Their service tickets were never affected: the targets are AES-only accounts.
- On Windows Server 2025 DCs Microsoft says RC4 TGTs are not issued at all; see the warning
  under [When to use this path](#when-to-use-this-path).

None of this has been tested on a DC with the July 2026 update or later.  Confirm it on
your own canary DC — a legacy user logging on through it — before you rely on this path,
and again whenever you install a new cumulative update while it is in use.

### Identifying and tracking legacy users

Maintain a list of users without AES keys so you know when you can transition to Path 1.
Run the [old-password query](#identify-accounts-that-need-a-reset) from Step 2, then:

```powershell title="Count and list regular users (no SPN) whose passwords predate AES keys"
$legacy = $oldPasswords | Where-Object { -not $_.HasSPN }

Write-Information "Regular users without AES keys: $(@($legacy).Count)" -InformationAction Continue
$legacy | Sort-Object PasswordLastSet | Format-Table sAMAccountName, PasswordLastSet -AutoSize
```

Run this regularly (monthly, or as a scheduled task).  The count should decrease
over time as users change their passwords through normal operations (expiry, self-service
reset, helpdesk reset).  Each password change generates AES keys automatically.

### Monitoring RC4 pre-authentication

The date-based list is an estimate.  The DCs record the real thing: since the January 2025
update, Security event 4768 carries the etype used for pre-authentication
(`PreAuthEncryptionType`), the keys the account has (`AccountAvailableKeys`) and the etypes
the client offered (`ClientAdvertizedEncryptionTypes`).

```powershell title="Find TGT requests that pre-authenticated with RC4, on every DC"
$Since = (Get-Date).AddDays(-30)
$DCs = (Get-ADDomainController -Filter *).HostName
$stamp = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$xpath = "*[System[(EventID=4768) and TimeCreated[@SystemTime>='$stamp']]] and " +
"*[EventData[Data[@Name='PreAuthEncryptionType']='0x17']]"

$rc4PreAuth = foreach ($dc in $DCs) {
    try {
        Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath -ErrorAction Stop |
            ForEach-Object {
                $d = @{}
                ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                [PSCustomObject]@{
                    DC            = $dc
                    Time          = $_.TimeCreated
                    Account       = $d.TargetUserName
                    AccountKeys   = $d.AccountAvailableKeys
                    ClientOffered = $d.ClientAdvertizedEncryptionTypes
                    ClientAddress = $d.IpAddress
                }
            }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Write-Information "${dc}: no RC4 pre-authentication since $Since" -InformationAction Continue
        }
        else {
            Write-Warning "${dc}: NOT CHECKED - $($_.Exception.Message)"
        }
    }
}

$rc4PreAuth | Group-Object Account, AccountKeys |
    Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
```

How to read it:

- **`AccountKeys` without AES** — the account genuinely has no AES keys.  It leaves the
  list when its password is changed.
- **`AccountKeys` with AES, RC4 pre-auth anyway** — the account is fine; the **client** is
  the problem.  `ClientOffered` shows what it advertised.  Look at the machine at
  `ClientAddress` (an etype policy that lists only RC4, a non-Windows client, an old
  application).
- **A DC printed `NOT CHECKED`** — you have no data from that DC.  Its events are not
  covered by an empty result.
- **Nothing from any DC, including in normal operation** — check that the DCs are logging
  the January 2025 event format at all: open one recent 4768 and confirm it contains a
  `PreAuthEncryptionType` field.  The Security log must also reach back as far as `$Since`.

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

All four must hold:

- the legacy user list is empty,
- the RC4 pre-authentication query has returned **no events from any DC for at least 30
  days**,
- no DC printed `NOT CHECKED` in that query, and
- that silence means something: on every DC the Security log reaches back the full 30
  days, and a recent 4768 carries the `PreAuthEncryptionType` field (see *How to read it*
  above).  A log that only holds three days cannot show 30 quiet ones.

Then update both GPOs:

1. **Workstation/server GPO**: remove RC4 from the checkboxes (AES128 + AES256 + Future
   only).
2. **Domain Controllers GPO**: remove RC4, and roll the change out as a filter change —
   [canary DC first, KDC restart, positive test](#rolling-out-a-filter-change).  Removing
   RC4 from the DC filter is the step that locks out anyone you missed.
3. Verify: confirm no `KDC_ERR_ETYPE_NOSUPP` errors or Event 4768 failures after each DC
   is activated.

### Path 2: Verification Checklist

- [ ] All SPN-bearing user service accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All gMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All MSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All dMSA accounts have `msDS-SupportedEncryptionTypes = 0x18`
- [ ] All SPN-bearing user accounts have AES keys (verified, not inferred from dates)
- [ ] Every keytab-based service has been confirmed to decrypt AES tickets
- [ ] `DefaultDomainSupportedEncTypes = 0x18` on **every** DC — or absent on every DC, all on
      the April 2026 update or later (per-DC check shows no errors)
- [ ] RC4 + AES filter delivered to every DC **and** the KDC service restarted on every DC (DES disabled)
- [ ] RC4 + AES GPO applied to workstation/server OUs (so legacy users can pre-auth from any machine)
- [ ] No KDC System events 203, 204, 208 or 209 on any DC, with every DC actually checked
- [ ] Event 4769 shows `TicketEncryptionType = 0x12` (AES256) for **service tickets**
- [ ] `klist` on clients shows `AES-256-CTS-HMAC-SHA1-96` for service tickets
- [ ] Legacy user count is tracked and decreasing over time
- [ ] RC4 pre-authentication query runs on a schedule against **all** DCs
- [ ] Computer objects with no `msDS-SET` have each been investigated
- [ ] A legacy-user logon is re-tested on a canary DC after each new cumulative update
- [ ] Exit criteria defined: switch to Path 1 after 30 days with no RC4 pre-authentication

---

## Historical: RC4DefaultDisablementPhase { #reference-what-rc4defaultdisablementphase-actually-does }

Earlier versions of this guide treated `RC4DefaultDisablementPhase` as a live control.  It
was a temporary rollout gate.

--8<-- "includes/phase-values.md"

What that means for this playbook:

- Do not set it.  Nothing in Steps 1-6 uses it.
- Per Microsoft (KB5073381 FAQ and Message Center MC1427604, 14 July 2026), the value is
  **no longer read** beginning with the July 2026 security update.  That has not been
  lab-verified here.
- If the [per-DC registry check](#check-current-dc-registry-state) shows a leftover value,
  delete it and restart the KDC service on that DC during a normal maintenance window.  On
  a DC with the July 2026 update or later (Server 2022 build 20348.5386 / KB5099540, Server
  2025 build 26100.33158 / KB5099536, or higher) it is inert clutter that misleads the next
  audit; on a DC still on an April-June 2026 update, a leftover `0` or `1` means that DC is
  issuing RC4 for unconfigured accounts.
- Treat that deletion as a change, not as tidying.  On an April-June 2026 build, deleting
  a `0` or `1` switches the DC to the AES-only default at the restart, so clear the
  [Step 5 gate](#before-you-change-it) for that DC first.  And the KDC restart also
  activates any `SupportedEncryptionTypes` filter value that has been delivered to the DC
  but not yet loaded (see [Rolling out a filter change](#rolling-out-a-filter-change)).
- The timeline and the full behavior matrix are on the
  [RC4 Deprecation](rc4-deprecation.md) page.

### How DDSET interacts with enforcement { #how-ddset-interacts-with-enforcement }

Microsoft's change replaced the KDC's **built-in** default — the value it uses when both
`msDS-SupportedEncryptionTypes` and `DefaultDomainSupportedEncTypes` are absent.  An
explicit `DefaultDomainSupportedEncTypes` is still honored, including one that contains
RC4; the DC logs System event 205 as a standing warning.  The lab confirmed this on an
enforcing Server 2022 DC (April 2026 update).  Microsoft's KB5073381 FAQ says the setting
stays: "we will honor any configuration explicitly set by an administrator".  That KB was
last revised on 14 April 2026, and the July 2026 Message Center post (MC1427604) does not
mention `DefaultDomainSupportedEncTypes`, so its behavior on a July 2026 or later update
rests on the KB alone and is not lab-verified here.  The table under
[What Affects Encryption](#3-defaultdomainsupportedenctypes-kdc-fallback) lists the
default for each update level.

Operational guidance:

- An explicit DDSET that contains RC4 re-enables RC4 for **every** unconfigured account in
  the domain, on that DC.  It is a blunt instrument.
- Prefer an explicit `msDS-SupportedEncryptionTypes` on the individual account for a
  targeted exception.
- This guide pins DDSET at `0x18` (Step 5), which is the same as the patched default and
  therefore safe on every update level.

---

## RC4 Exceptions { #optional-enabling-rc4-for-specific-accounts-after-july-2026 }

Some services will outlive this project.  The KDC's built-in default no longer gives them
RC4, so each one needs an explicit, recorded exception on **its own account**.  The
step-by-step procedure, including the client side and the GPO model for mixed
environments, is [Keeping RC4 for Specific Accounts](rc4-deprecation.md#rc4-exceptions).
The short version:

| What cannot do AES | Exception | Also required |
|---|---|---|
| A **client** that only offers RC4, talking to a service that is fine with AES | `28` on the service account | Nothing on the DC filter for the ticket; the filter must allow RC4 for the session key |
| The **service** itself cannot decrypt AES tickets | `36` (`0x24`, Microsoft's recommendation in KB5073381) on the service account | RC4 in the DC filter (Path 2 filter).  The RC4 ticket with an AES256 session key was seen in the lab on the pre-April build only |
| The account has **no AES keys** | None — reset the password.  Until then `28` on the account keeps it working on its RC4 key (lab: build 20348.5020) | RC4 in the DC filter while the bridge is in place |

Two things an exception does **not** do:

- `28` or `60` does not make the KDC issue RC4 tickets to an account that has AES keys.
  If the service cannot decrypt AES, those values change nothing for it.
- It does not help a client that has been restricted to AES-only by the workstation GPO.
  An AES-only client asking for a ticket to an RC4-only (`4`) account gets
  `KDC_ERR_ETYPE_NOSUPP`.

The bulk scripts on this page leave exceptions alone as long as their current value is not
listed in `$OnlyFrom`.  Add the account names to `$Exceptions` (or put them in a group and
name it in `$ExceptionGroup`) before you ever widen `$OnlyFrom`.

### Track every exception

Every account that still has an RC4 bit should be documented:

| Field | Value |
|---|---|
| Account name | `svc_legacy` |
| Value set | `36` (`0x24`) |
| SPNs | `HTTP/legacy-app.corp.local` |
| System | Legacy ERP application, version 4.2 |
| Why RC4 | Vendor does not support AES (ticket filed: VENDOR-12345) |
| Owner | Name of the service owner who accepted the risk |
| Review date | No more than 90 days after the exception was created |

Review on schedule and remove the exception when the system is upgraded; the order of
operations is in
[Removing Exceptions Afterwards](enforcement-triage.md#removing-exceptions-afterwards).
This query lists what the directory actually contains, to reconcile against the record:

```powershell title="List every SPN-bearing account that still has the RC4 bit set"
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4))' `
    -Properties sAMAccountName, 'msDS-SupportedEncryptionTypes', whenChanged |
    Select-Object sAMAccountName,
    @{N = 'Class'; E = { $_.ObjectClass } },
    @{N = 'msDS-SET'; E = { '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes' } },
    whenChanged |
    Sort-Object Class, sAMAccountName |
    Format-Table -AutoSize
```
