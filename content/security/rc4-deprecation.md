---
description: What the 2026 Kerberos RC4 enforcement (CVE-2026-20833) shipped, how the KDC selects encryption types now, the Kdcsvc 201-209 event reference, and how to keep RC4 for a specific account.
---

# RC4 Deprecation (CVE-2026-20833)

What shipped, how the KDC decides now, what each Kdcsvc event means, and how to keep RC4
for a specific account.  If something is failing right now, start with
[RC4 Enforcement: Am I Affected?](enforcement-triage.md).  For the step-by-step clean-up
to AES-only, see the [AES Standardization Guide](aes-standardization.md).

!!! info "As of 2026-11-10"
    Microsoft's guidance was last checked on 2026-11-10: at that date the change log of
    [KB5073381](https://support.microsoft.com/help/5073381) ended on April 14, 2026, and
    the July 2026 phase was announced in Message Center post MC1427604 (July 14, 2026).
    Lab results on this page were last re-run on 2026-06-26.  **Nothing here is
    lab-verified on a July 2026 or later cumulative update.**

---

## Why RC4 Was Removed as the Default

RC4 was a known liability in Kerberos for over a decade:

- **Kerberoasting**: any authenticated domain user can request a service ticket for any SPN and crack it offline.  RC4 tickets crack at roughly 800x the speed of AES, so a weak password falls in hours.  See [Kerberoasting](../attacks/roasting/kerberoasting.md).
- **Key = NT hash**: the RC4 Kerberos key is the account's NT hash.  Compromising one gives the attacker both.
- **No salt**: RC4 keys are unsalted MD4 hashes, so precomputed tables work.  AES keys are salted per account and stretched with 4,096 PBKDF2 iterations.
- **Standards**: RFC 7465 prohibited RC4 in TLS in 2015.  RFC 8429 deprecated it for Kerberos in 2018.

Despite all this, RC4 remained the implicit default for any SPN-bearing account without an explicit `msDS-SupportedEncryptionTypes` until the April 2026 update.

RC4 itself has not been removed from Windows.  What changed is that the KDC no longer *assumes* it.

---

## What Shipped

--8<-- "includes/rc4-timeline.md"

!!! warning "Enforcement is gated on the installed update, not the calendar date"
    A DC enforces once it has its OS's April 2026 cumulative update or anything newer.  A DC on an earlier update does **not** enforce, whatever the date: its built-in default for unconfigured accounts stays `0x27` (RC4).  Cross-checked live: a DC on build 20348.4893 still issued RC4 for an `msDS-SET = 0` account while a DC on build 20348.5020 issued AES256, with an identically empty Kerberos registry on both.  A domain whose DCs sit at different patch levels therefore has **mixed enforcement**.  Confirm each DC from its build number or a live ticket request, not from the date and not from the (normally absent) `RC4DefaultDisablementPhase` value.  Cumulative-update KB numbers differ per OS version, so compare builds.

--8<-- "includes/lab-builds.md"

### What Microsoft says about July 2026

- Message Center MC1427604 (admin center, sign-in required; a shorter public version is on the [Windows message center](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center), 14 July 2026): the July 2026 update removes "Audit mode and the `RC4DefaultDisablementPhase` rollback setting", leaving enforcement as "the only supported behavior".  It adds: "If RC4 must be retained for specific services, explicit configuration is still possible, but it leaves those scenarios vulnerable to CVE-2026-20833 and should be used only as a temporary measure."
- KB5073381: `RC4DefaultDisablementPhase` "is temporary and will no longer be read after the enforcement date", and updates released in or after July 2026 "remove support" for it.  The KB describes the value as no longer read; it does not say an existing value is deleted from the registry.
- KB5073381 FAQ: Microsoft will not remove the ability to configure `DefaultDomainSupportedEncTypes` and "will honor any configuration explicitly set by an administrator", logging Kdcsvc 205 for insecure values.
- MC1427604 also names who it expects to be hit: "Applications, services, or devices that rely on legacy encryption configurations or explicitly defined RC4 usage are most likely to be affected."  It does not say how an explicit RC4 setting is affected.  Re-test each RC4 exception after a DC receives a July or later update.

This site's lab has not been re-run on a July or later build, so treat these points as Microsoft's statements.

---

## How the KDC Selects a Service Ticket Encryption Type

### The decision algorithm

When a client requests a service ticket (TGS-REQ), the KDC works from the **target service account**, not from the client:

1. **Read `msDS-SupportedEncryptionTypes`** on the target account.  If it is non-zero, that is the account's effective set.
2. **If it is unset or zero**, use `DefaultDomainSupportedEncTypes` on this DC.  If that is not set either, use the build's own default: `0x27` before the April 2026 update, `0x18` (AES-only) with it or anything newer.
3. **Apply the DC's etype filter** (`SupportedEncryptionTypes`).  For an account with an explicit set, no overlap with the filter means `KDC_ERR_ETYPE_NOSUPP`.  For an unconfigured account, the filter can strip RC4 from a default that includes it and the KDC issues AES instead.
4. **Pick the strongest etype** left in the set for which the account actually has a key.  If the account has no key for any of them, the request fails; the KDC does not fall back to RC4 outside the set.
5. **Agree a session key** from the etypes the client offered and the effective set.  If they share none, the request fails with `KDC_ERR_ETYPE_NOSUPP`.

--8<-- "includes/ddset-default-by-build.md"

--8<-- "includes/kdc-filter-matrix.md"

### The client does not choose the ticket etype

The etype list the client sends does not select the ticket etype.  A modern Windows client receives an RC4 service ticket for a service account configured as RC4-only, and an AES256 ticket for one configured as RC4 + AES, regardless of the order of its own list.  (The exception is `KdcUseRequestedEtypesForTickets = 1`, which should not be set; see [Registry Settings](registry.md#kdcuserequestedetypesfortickets).)

The client list does matter for step 5.  In the lab:

- an RC4-only service account (`msDS-SET = 4`) with a client that offered only AES256: **failed**;
- an AES-only service account (`msDS-SET = 24`) with a client that offered only RC4: allowed before enforcement (AES256 ticket, RC4 session key), **blocked** on the enforcing build with Kdcsvc 208;
- an RC4 + AES account (`msDS-SET = 28`) with a client that offered only RC4: AES256 ticket, RC4 session key.

So an RC4 exception on a service account works for ordinary Windows clients, which still offer RC4 unless a Kerberos etype GPO restricts them to AES.  A client restricted to AES-only cannot use a service whose account is RC4-only.

### The AES session key flag (bit 0x20)

Bit 5 of the bitmask (`0x20`, value 32) is `AES256-CTS-HMAC-SHA1-96-SK`.  It does not add a ticket etype.  It tells the KDC to use an AES256 session key even when the ticket itself is encrypted with RC4.

It was introduced in November 2022 (KB5021131).  An account with `msDS-SET = 36` (`0x24`, RC4 + AES-SK) receives an RC4-encrypted ticket and an AES256 session key.  The lab saw exactly that, with the bit set on the account itself, on a pre-April 2026 Server 2022 build (6-7 April 2026, revision not recorded).  It was not reproduced on the enforcing build 20348.5020, where the test client negotiated an RC4 session key; `0x24` is nonetheless the value KB5073381 recommends for a service that cannot accept AES tickets.  The flag is also part of the old built-in default `0x27` (`0x7` | `0x20`: DES + RC4 + AES-SK), which is why unconfigured accounts used to show an RC4 ticket with an AES session key.

### TGT encryption type

The TGT is encrypted with the `krbtgt` account's key.  When `krbtgt` has AES keys, which is the case on any domain that reached functional level 2008 and has rotated the `krbtgt` password since, TGTs are AES256.

The 2026 enforcement applies to service tickets only.  In the lab, AS requests behaved the same at every `RC4DefaultDisablementPhase` value and on every build tested.

Server 2025 has a separate restriction that is not part of this enforcement.  Microsoft states: "Starting with Windows Server 2025, domain controllers don't issue RC4 Ticket Granting Tickets. While you can authenticate to legacy devices with RC4, the legacy device isn't able to authenticate using Kerberos" ([Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).  The one Server 2025 build in this site's lab (26100.32522, the March 2026 update) still answered an AS request that asked for RC4 with RC4.  The two have not been reconciled; plan on Microsoft's statement.

**Leave `msDS-SupportedEncryptionTypes` on the `krbtgt` account unset.**  TGT encryption follows the stored keys; the lab DC issued AES256 TGTs with the attribute at 0.

---

## The Controls

Three settings are live.  The [AES Standardization Guide](aes-standardization.md#what-affects-encryption) covers what to set them to; this section says what each one does.

### `msDS-SupportedEncryptionTypes` (AD attribute, per account)

The account's own declaration of the etypes it supports.  The KDC reads it when issuing service tickets *for* the account.  When it is non-zero, the DC default is not used for that account.

--8<-- "includes/etype-values.md"

- User service accounts, gMSA, MSA and dMSA: set it with PowerShell or ADUC.
- Windows computer accounts: the machine maintains its own value, and the Kerberos etype GPO applied to the machine changes what it writes.
- `krbtgt`: leave unset.

Setting the attribute does not create keys.  An account declared AES-only that has no AES keys fails.

### `DefaultDomainSupportedEncTypes` (registry, per DC)

Path: `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`, value name `DefaultDomainSupportedEncTypes`, REG_DWORD.

!!! warning "Not under `\Parameters`"
    The value lives directly under `Services\Kdc`, the path KB5021131 documents.  The lab confirmed that copies under the `Lsa` and `Policies` Kerberos keys are silently ignored.  `Services\Kdc\Parameters` is not the documented location either; a value created there does nothing you can rely on (the lab saw that subkey ignored for `RC4DefaultDisablementPhase`, and did not test it separately for this value).

The KDC-side effective set for accounts whose `msDS-SupportedEncryptionTypes` is unset or zero.  It takes effect immediately, with no KDC restart.  It is not replicated, so every DC has its own.

An explicit value replaces the build's default, including the enforced `0x18`; see [below](#ddset-overrides-the-enforcement-default).

### `SupportedEncryptionTypes` (the Kerberos etype policy; per machine)

Group Policy: *Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Configure encryption types allowed for Kerberos.*

The policy writes `SupportedEncryptionTypes` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`.

On a **domain controller** the value is the KDC's etype filter.  It applies to service tickets, and it is read only when the KDC service starts.  In the lab an AES-only filter also blocked RC4 pre-authentication; that was seen on one pre-April 2026 Server 2022 build (6-7 April 2026, revision not recorded) and has not been re-run on 20348.5020 or later.  Two build differences from the lab:

- Server 2022 (20348.5020) honored the value at both the `Policies` path and the `Lsa` path (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`), with `Policies` taking precedence.
- Server 2025 (26100.32522, the only 2025 build tested) honored the `Lsa` path and **ignored** the `Policies` path, so the standard GPO did not filter anything on that DC.  That build is the March 2026 update.  Microsoft's April 2026 update for Server 2025 (KB5082063) says Kerberos encryption policy settings are read "as expected", which may change this result; it has not been retested here.

On a **workstation or member server** it controls which etypes the Kerberos client offers, and it changes the value the machine writes to its own computer account.

### `RC4DefaultDisablementPhase` (historical)

The temporary audit/rollback gate for the 2026 rollout.  See [Historical: RC4DefaultDisablementPhase](#phase-behavior-what-the-registry-setting-actually-does).

---

## An Explicit DDSET Overrides the Enforced Default { #ddset-overrides-the-enforcement-default }

The April 2026 update changed only the *built-in* default, the one used when `DefaultDomainSupportedEncTypes` is absent.  If the value is explicitly set, the KDC uses it for unconfigured accounts.

Lab results on the enforcing Server 2022 build (20348.5020, April-June 2026), for an account with `msDS-SupportedEncryptionTypes = 0`:

| `DefaultDomainSupportedEncTypes` | Service ticket | Notes |
|---|---|---|
| not set | AES256 | Built-in `0x18`.  Event 4769 `ServiceSupportedEncryptionTypes` shows `0x18`. |
| `0x18` (AES128 + AES256) | AES256 | Same result as not set. |
| `0x10` (AES256) | AES256 | |
| `0x1C` (RC4 + AES) | AES256 | Strongest in the set.  Whether a client that offers only RC4 can agree a session key under this value is **not established**: the one recorded run of that case (14 April 2026) was blocked, and the June sweep did not record the client's etypes or the session key. |
| `0x04` (RC4) | RC4 | The explicit value wins over the enforced default. |
| `0x27` (the old default) | RC4 | Reproduces pre-enforcement behavior. |
| `0x08` (AES128 only) | `KDC_ERR_ETYPE_NOSUPP` for a client that offered only AES256 | No session key type in common. |

Changes applied without a KDC restart.  Kdcsvc 205 is logged at each KDC start while the value includes a non-AES cipher.  It is a warning that never becomes an error.

**After the July 2026 update:** KB5073381 says an administrator-set value is still honored.  That has not been lab-verified here.

!!! warning "A DDSET that includes RC4 re-enables RC4 for every unconfigured account"
    It applies to every account with `msDS-SupportedEncryptionTypes = 0` served by that DC.  Use it as a short-lived emergency measure (see the [triage runbook](enforcement-triage.md#fix-2-temporary-domain-wide-default)); set exceptions per account instead.

!!! note "Superseded lab note"
    A first test on 2026-04-14 concluded that an explicit DDSET could not override enforcement.  Retests on 2026-04-25 and 2026-06-26 showed that it does, matching KB5073381.  The table above reflects the retests.

---

## Kdcsvc Event Reference

--8<-- "includes/kdcsvc-events.md"

Things worth knowing when you read these:

- **Audit events belong to audit mode.**  201, 202, 206 and 207 are only written while a DC is in audit mode, which per Microsoft the July 2026 update removed.  On an enforcing DC you see 203, 204, 208 and 209, plus 205 at KDC start.  The lab's enforcing build (20348.5020) logged 203, 205 and 208; 204 and 209 were not triggered there.
- **201-204 need both "unset" conditions.**  They are logged only when the service has no `msDS-SupportedEncryptionTypes` **and** the DC has no `DefaultDomainSupportedEncTypes`.  If the DC has an explicit default, the KDC uses it; an insecure one produces 205 at start, and an AES-only one moves RC4-dependent requests to 206-209.
- **Event 16 accompanies every blocked TGS request.**  The pre-existing System event 16 ("did not have a suitable key... The requested etypes were... The accounts available etypes were...") is logged next to 203 and 208 too.  It does not by itself mean the account lacks keys: in the lab it appeared for an RC4-only client against an account that had RC4 and AES keys.  Read the two etype lists in its text.
- **The Security log shows the block as well.**  The matching Event 4769 has `Status` `0xe`, `TicketEncryptionType` `0xffffffff`, and (in the lab) the full SPN string in `Service Name`.
- **The events report effective values.**  In a 203 event the service's supported-etypes field shows `0x18`, the enforced default, not the `0` stored in AD.
- **No event does not mean no problem.**  Per Microsoft, these events are generated only when the KDC cannot issue AES tickets or session keys.  A service that receives an AES ticket it cannot decrypt (an RC4-only keytab) fails without any Kdcsvc event.

---

## What Must Be True for an Account to Work

On an enforcing DC, each of these has to hold.  They are also the pre-conditions for removing RC4 anywhere else.

### `krbtgt`

`krbtgt` must have AES keys.  That is true on any domain that has been at functional level 2008 or higher and has rotated the `krbtgt` password since.

```powershell title="Check krbtgt"
# 1. When was the password last set?  It must postdate the move to DFL 2008.
Get-ADUser krbtgt -Properties PasswordLastSet, 'msDS-KeyVersionNumber' |
    Select-Object PasswordLastSet, 'msDS-KeyVersionNumber'

# 2. Has any DC logged System event 42 (the KDC lacks strong keys for krbtgt)?
Get-ADDomainController -Filter * | ForEach-Object {
    $dc = $_.HostName
    try {
        Get-WinEvent -ComputerName $dc -ErrorAction Stop -MaxEvents 5 -FilterHashtable @{
            LogName = 'System'; Id = 42
            ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'
        } | Select-Object @{N = 'DC'; E = { $dc } }, TimeCreated, Message
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            Write-Warning "$dc : $($_.Exception.Message)"
        }
    }
}
```

For a definitive answer, read the stored key types with DSInternals (this performs replication and will trigger DCSync detections):

```powershell title="krbtgt key types via DSInternals"
(Get-ADReplAccount -SamAccountName krbtgt -Server dc1.corp.local).
SupplementalCredentials.KerberosNew.Credentials.KeyType
```

If `krbtgt` lacks AES keys, rotate its password using the procedure in [Mitigations: KRBTGT Password Rotation](mitigations.md#priority-9-krbtgt-password-rotation).  Do not reset it twice back to back: the second reset must wait for replication and for outstanding tickets to expire.

### SPN-bearing user service accounts

Every user account with a service principal name needs:

1. AES keys in the directory (a password set while the domain was at DFL 2008 or higher);
2. an effective etype set that includes AES: either `msDS-SupportedEncryptionTypes = 24`, or unset on an enforcing DC.

An account with AES keys and an unset attribute simply gets AES256 tickets now.  An account explicitly at `4` keeps getting RC4 tickets.  An account without AES keys fails unless its explicit set includes RC4.

### Computer accounts

Windows machines maintain their own `msDS-SupportedEncryptionTypes` and rotate their own passwords, so they normally have AES keys and an AES-capable value.  Investigate computer objects whose value is unset or `0`: they are usually non-Windows devices, pre-staged objects, or machines that have not started in a long time.

### Non-Windows services with keytabs

A service that authenticates with a keytab must have AES keys **in the keytab**, not just in AD.  An RC4-only keytab cannot decrypt the AES256 ticket the KDC now issues.

```bat title="Export an AES256 keytab (run on a Windows host with RSAT)"
ktpass /out service.keytab ^
  /princ HTTP/web.corp.local@CORP.LOCAL ^
  /mapuser CORP\svc_web /mapop set ^
  /pass * ^
  /ptype KRB5_NT_PRINCIPAL ^
  /crypto AES256-SHA1
```

!!! warning "`ktpass` changes the account"
    By default `ktpass /pass` **sets the account's password** to the value you supply (`-setpass` suppresses that) and rewrites its user principal name to the `/princ` value (`-setupn` suppresses that).  A password set raises the key version number, so every keytab previously exported for the account stops working.  Plan it as a password change.

### Regular user accounts (only for an AES-only DC filter)

The 2026 enforcement does not touch logon.  Users without AES keys become a problem in two cases.  The first is removing RC4 from the **DC etype filter**: in the lab an AES-only filter also blocked RC4 pre-authentication (one pre-April 2026 Server 2022 build).  The second is a Server 2025 DC, which per Microsoft does not issue RC4 TGTs (see [TGT encryption type](#tgt-encryption-type)).  If some users still lack AES keys, keep RC4 in the DC filter ([Path 2](aes-standardization.md#path-2-aes-opportunistic-with-rc4-fallback) in the Standardization Guide) until their passwords have been reset.

---

## Keeping RC4 for Specific Accounts { #rc4-exceptions }

RC4 can still be issued where it is explicitly configured.  Microsoft's position (MC1427604) is that this "leaves those scenarios vulnerable to CVE-2026-20833 and should be used only as a temporary measure".

### Pick the value from the reason

Adding RC4 to an account's bitmask does **not** by itself produce RC4 tickets.  The KDC picks the strongest etype the account has a key for, so an account at `28` or `60` that has AES keys still receives AES256 tickets.  Choose the value from what actually cannot do AES:

| Why RC4 is needed | Set on the service account | What the KDC issues | Also required |
|---|---|---|---|
| The **service cannot decrypt AES tickets** (RC4-only keytab or Kerberos stack) | `36` (`0x24`: RC4 + AES session key), Microsoft's recommended value; or `4` (RC4 only) if the service cannot use an AES session key either | RC4 ticket.  With `36`, an AES256 session key; with `4`, an RC4 session key. | The DC etype filter must allow RC4.  With `4`, clients must still offer RC4. |
| The **account has no AES keys** yet | Reset the password; that is the fix.  `28` only as a bridge until the reset. | With `28` and no AES key: RC4 ticket, from the only key the account has. | The DC etype filter must allow RC4.  Return to `24` after the reset. |
| A **client can only do RC4** | `28` | AES256 ticket with an RC4 session key. | The DC etype filter must allow RC4.  The service itself must handle AES tickets. |

What is and is not lab-verified:

- `36` on an account gave an RC4 ticket with an AES256 session key (Windows `klist` and a client that offered only AES256) on a pre-April 2026 Server 2022 build (6-7 April 2026, revision not recorded).  On the enforcing build 20348.5020 the split was not reproduced: the test client negotiated an RC4 session key.  The recommendation of `36` is Microsoft's (KB5073381).
- `4` gave an RC4 ticket to a client that offered RC4 and refused a client that offered only AES256, on both builds.
- `28` with an RC4-only client gave an AES256 ticket and an RC4 session key on the enforcing build (20348.5020).
- `28` on an account stripped of AES keys gave an RC4 ticket on the enforcing build (20348.5020).
- `60` (`0x3C`) was tested only with AES-capable clients, on the pre-April build, where it gave AES256.  Whether its AES-session-key bit prevents an RC4-only client from agreeing a session key has **not** been tested, and neither has `60` on an account without AES keys; use `28` for both cases.

### Set it

```powershell title="User service account, gMSA or MSA"
# User service account
Set-ADUser -Identity svc_legacy -Replace @{ 'msDS-SupportedEncryptionTypes' = 36 }

# gMSA, MSA or dMSA
Set-ADServiceAccount -Identity gmsa_legacy -Replace @{ 'msDS-SupportedEncryptionTypes' = 36 }
```

For a **non-Windows computer object**, set the attribute on the object with `Set-ADComputer`.  For a **Windows machine**, apply a Kerberos etype GPO that includes RC4 to that machine's OU; the machine writes its own attribute, and a value set by hand may be overwritten.

The change applies once it has replicated to the DC that answers.  Clients keep using cached tickets until they expire or are purged (`klist purge`).

### Check the DC etype filter

If the DCs have a `SupportedEncryptionTypes` filter that excludes RC4, the account-level setting is not enough: an account explicitly set to RC4-only gets `KDC_ERR_ETYPE_NOSUPP`.  Add RC4 to the filter on every DC and restart the KDC on each, one at a time.  If the DCs have no filter, there is nothing to change.

### Policy model for mixed environments

| GPO | Linked to | Etypes | Purpose |
|---|---|---|---|
| DC policy | Domain Controllers | AES128 + AES256 (+ RC4 while any exception exists) | The KDC filter.  For what it covers, including the pre-authentication result and the Server 2025 note, see [The Controls](#supportedencryptiontypes-the-kerberos-etype-policy-per-machine). |
| AES-only machines | Modern workstations and servers | AES128 + AES256 | What those clients offer, and what they write to their computer accounts |
| AES + RC4 machines | Legacy machines | RC4 + AES128 + AES256 | Lets those machines offer RC4 |

A machine in the AES-only group cannot use a service whose account is RC4-only (`4`).  Use `36` on the service account where the service can handle an AES session key.

For SPN-bearing accounts that are not computers, a GPO does nothing; set the attribute directly.

!!! warning "Every exception is Kerberoastable at RC4 speed"
    Any authenticated domain user can request a ticket for the account and attack it offline, roughly 800x faster than with AES.  Give every account that keeps RC4 a 30+ character random password.  Record the account, the system that needs RC4, the reason, an owner, and a review date, and remove the exception when the reason is gone (see [Removing exceptions](enforcement-triage.md#removing-exceptions-afterwards)).

---

## Historical: RC4DefaultDisablementPhase { #phase-behavior-what-the-registry-setting-actually-does }

--8<-- "includes/phase-values.md"

If you find this value on a DC today, check that DC's build before deleting it.

- **July 2026 update or later** (Server 2022 build 20348.5386 or higher, Server 2025 build 26100.33158 or higher): per Microsoft the value is no longer read.  Delete it; a leftover `0` or `1` suggests a rollback that no longer exists.
- **April-June 2026 update only** (Server 2022 builds 20348.5020 to 20348.5256): the value is still the rollback switch.  With `0` or `1` that DC is issuing RC4 for unconfigured accounts, and deleting the value turns enforcement on at the next KDC restart (the value is read at KDC start).  Treat the deletion as switching that DC to enforcement: check what depends on RC4 first, using the [triage runbook](enforcement-triage.md).

??? note "Lab matrix from the April-July 2026 rollback window"
    Measured on Server 2022 build 20348.5020 with `DefaultDomainSupportedEncTypes` absent.
    Cells show the service ticket etype.

    | Phase | unset / 0 | `msDS-SET` = 4 (RC4) | `msDS-SET` = 24 (AES) | `msDS-SET` = 28 (RC4 + AES) |
    |---|---|---|---|---|
    | **absent / 2** | AES256 | RC4 | AES256 | AES256 |
    | **0 / 1** | RC4 | RC4 | AES256 | AES256 |

    - Phase absent and Phase 2 were identical.  Phase 0 and Phase 1 produced the same
      tickets; they differed only in whether audit events were written.
    - Phase 0/1 affected **only** accounts with no `msDS-SupportedEncryptionTypes`.  It
      returned their built-in default to `0x27`, which contains no AES ticket etype, so
      those accounts received RC4 tickets even from clients that preferred AES.
    - The ticket etype of explicitly configured accounts did not depend on the phase.  What
      did change for them was the RC4-only-client case: allowed with event 206 in audit,
      refused with event 208 under enforcement.
    - An explicit `DefaultDomainSupportedEncTypes` was unaffected by the phase value.
    - The value had to be created under the `Policies\System\Kerberos\Parameters` key and
      needed a KDC restart.  A value under `Services\Kdc\Parameters` was ignored.

---

## Frequently Asked Questions

**Is RC4 gone from Windows?**

No.  RC4 can still be enabled explicitly, per account or (per Microsoft) through an explicit `DefaultDomainSupportedEncTypes`.  What changed is the implicit default: the KDC no longer assumes RC4 for accounts that declare nothing.

**Can I roll back?**

Not domain-wide.  Per Microsoft, the July 2026 update removed audit mode and the `RC4DefaultDisablementPhase` rollback setting.  What remains is explicit configuration: an RC4 [exception on the affected account](#rc4-exceptions), or as a short-lived emergency measure an explicit `DefaultDomainSupportedEncTypes` that includes RC4 on every DC.

**Why did something break months after April?**

Because enforcement follows the update, not the date, and because some settings only apply at a restart.  Typical triggers: a DC finally received the April-or-later update; a DC that had been rolled back with `RC4DefaultDisablementPhase` received the July update, which per Microsoft stops reading that value; a DC rebooted and its KDC picked up an etype filter set weeks earlier; or a long-lived service ticket expired and the replacement came from an enforcing DC.  See [Why did this break months after April?](enforcement-triage.md#why-did-this-break-months-after-april).

**Is `DefaultDomainSupportedEncTypes` with RC4 supported long-term?**

Microsoft's KB says it will keep honoring an administrator-set value and will log Kdcsvc 205 for insecure ones.  It also calls a domain-wide RC4 default a last resort that "leaves all accounts in the domain vulnerable to CVE-2026-20833".  The lab confirmed the override on the April-June 2026 enforcing build; it has not been re-tested after July.  Treat it as an emergency measure, not a steady state.

**Does `DefaultDomainSupportedEncTypes` need to include RC4 for my legacy services?**

No.  It only applies to accounts with no `msDS-SupportedEncryptionTypes`.  If the legacy service's account carries its own explicit value, the DC default is irrelevant to it.

**Do I still need an etype filter on the DCs?**

Not to stop RC4 being issued by default; the enforced default already does that for unconfigured accounts, and explicit AES-only accounts never needed it.  The filter is what makes RC4 *impossible*: it also blocks explicitly RC4-configured accounts (lab: 20348.5020) and, on the one pre-April 2026 build where that was checked, RC4 pre-authentication.  That is the last step of an AES-only migration, and it requires every user and service to have AES keys first.

**What about Server 2025 domain controllers?**

Two things differ in this site's lab on build 26100.32522: the KDC read its etype filter only from the `Lsa` registry path, so the standard Kerberos etype GPO (which writes the `Policies` path) did not filter anything; and only the AS exchange was cross-checked for RC4 enforcement on that build.  That build predates the April 2026 update for Server 2025, whose release note says Kerberos encryption policy settings are read "as expected", so the filter-path result may no longer hold.  Verify a 2025 DC's behavior directly before relying on either.

A third difference comes from Microsoft, not the lab: Server 2025 domain controllers "don't issue RC4 Ticket Granting Tickets", so a device or account that can only use RC4 cannot log on through one, and Microsoft's own advice for that case is "to use earlier versions of Windows Server for your domain controllers" ([Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).  The lab's AS cross-check on build 26100.32522 did not show that restriction; see [TGT encryption type](#tgt-encryption-type).

**I have no Kdcsvc events.  Am I clean?**

Not necessarily.  Check that the query actually reached every DC, and remember that the events only cover cases where the KDC cannot issue AES.  A service with an RC4-only keytab fails on the service side with nothing logged by the KDC.
