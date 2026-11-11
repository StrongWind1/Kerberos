---
description: Where Kerberos encryption in Active Directory stands after the 2026 RC4 enforcement, how to check your own domain, and a map of the Security section.
---

# Kerberos Security Overview

Where Kerberos encryption in Active Directory stands today, how to check your own domain,
and where each topic lives in this section.

- **Something is broken right now?**  Go to
  [RC4 Enforcement: Am I Affected?](enforcement-triage.md).
- **New to Kerberos encryption?**  Read the [Quick Start Guide](quick-start.md) first.
- **Cleaning up to AES-only?**  Jump to the [Standardization Guide](aes-standardization.md).

!!! info "As of 2026-11-10"
    Microsoft's guidance was last checked on 2026-11-10.  Lab results on this site were
    last re-run on 2026-06-26 (Server 2022 builds 20348.4893 and 20348.5020, Server 2025
    build 26100.32522).  Nothing here is lab-verified on a July 2026 or later cumulative
    update; statements about that update are attributed to Microsoft.

---

## Current State

- **RC4 is no longer the implicit default.**  A domain controller with the April 2026
  cumulative update or later treats an account whose `msDS-SupportedEncryptionTypes` is
  unset or `0` as AES-only (`0x18`), unless that DC has an explicit
  `DefaultDomainSupportedEncTypes`.  Before that update the built-in default was `0x27`
  and those accounts received RC4 service tickets.
- **The change is per DC and gated on the installed update**, not on the calendar.  A DC on
  an older update still issues RC4 for unconfigured accounts, so a domain can be in a
  mixed state.
- **The rollback switch is gone.**  Per Microsoft (Message Center MC1427604 and
  [KB5073381](https://support.microsoft.com/help/5073381)), the July 2026 update removed
  audit mode and the `RC4DefaultDisablementPhase` rollback setting.
- **Explicit configuration is still honored.**  An account that declares RC4 in
  `msDS-SupportedEncryptionTypes` still gets RC4 (lab: Server 2022 build 20348.5020, the
  April 2026 update; for the July update, Microsoft's
  [Windows message center](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center)
  says that phase blocks RC4 requests "when no explicit configuration is present"), and KB5073381 states that an administrator-set
  `DefaultDomainSupportedEncTypes` is honored.
- **Logon was not part of this change.**  The enforcement applies to service tickets (the
  TGS exchange).  In the lab, TGT issuance behaved the same before and after (Server 2022
  builds 20348.4893 and 20348.5020).  Server 2025 DCs have a separate restriction on RC4
  at logon; see [What happened to each kind of account](#what-happened-to-each-kind-of-account).

--8<-- "includes/rc4-timeline.md"

--8<-- "includes/ddset-default-by-build.md"

### Why RC4 had to go

- **RC4 is fast to crack.**  The RC4 key is the NT hash (`MD4(UTF-16LE(password))`, no
  salt).  It cracks at roughly 800 times the speed of AES.  See
  [Algorithms & Keys](algorithms.md#cracking-speed-comparison).
- **Any domain user can Kerberoast.**  Any authenticated user can request a service ticket
  for any SPN and attack it offline.  See
  [Kerberoasting](../attacks/roasting/kerberoasting.md).
- **RC4 key = pass-the-hash.**  The RC4 Kerberos key is the NT hash, so a compromised RC4
  key is also an NTLM credential.

### What happened to each kind of account

The KDC picks the strongest etype in the account's effective set for which the account has
a key.  "Effective set" means the account's own `msDS-SupportedEncryptionTypes` if it is
non-zero, otherwise the DC's default.

**Service tickets** on a DC with no explicit `DefaultDomainSupportedEncTypes`:

| Keys in AD | `msDS-SET` | Before the April 2026 update | April 2026 update or later |
|---|---|---|---|
| AES + RC4 | unset / 0 | RC4 ticket | AES256 ticket |
| RC4 only | unset / 0 | RC4 ticket | **Fails** (`KDC_ERR_ETYPE_NOSUPP`): the enforced default needs an AES key |
| AES + RC4 | 24 (AES) | AES256 ticket | AES256 ticket |
| AES + RC4 | 28 (RC4 + AES) | AES256 ticket | AES256 ticket |
| AES + RC4 | 4 (RC4 only) | RC4 ticket | RC4 ticket |
| RC4 only | 24 (AES) | **Fails**: no AES key | **Fails**: no AES key |
| RC4 only | 28 (RC4 + AES) | RC4 ticket | RC4 ticket (the only key it has) |

The "RC4 only" rows were measured in the lab on the enforcing build only (Server 2022
20348.5020).  Their "before" cells are the expected results, not separate lab runs.

One more thing changed for accounts that are AES-only, whether explicitly or through the
enforced default: a client that offers **only RC4** used to receive an AES256 ticket with
an RC4 session key.  On an enforcing DC that request is refused (Kdcsvc 203 or 208),
because no session key type is common to both sides.

**Logon and TGTs** are governed by the user's stored keys and the DC's etype filter, not by
this enforcement:

| User's keys in AD | DC filter allows RC4? | Pre-authentication | TGT |
|---|---|---|---|
| AES + RC4 | Yes or no | AES256 | AES256 |
| RC4 only | Yes, or no filter set | RC4 | AES256 (encrypted with the `krbtgt` key) |
| RC4 only | No (AES-only filter) | **Fails**: no usable key | n/a |

The risk for a user with only RC4 keys is therefore the DC filter, not the 2026 change.
Two limits on this table:

- **The two "RC4 only" rows are the expected result, not a lab result.**  A logon by an
  account that holds only an RC4 key has not been run in this site's lab.
- **Server 2025 DCs are different, per Microsoft**: "Starting with Windows Server 2025,
  domain controllers don't issue RC4 Ticket Granting Tickets. While you can authenticate
  to legacy devices with RC4, the legacy device isn't able to authenticate using Kerberos"
  ([Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
  Plan for an account or device that can only use RC4 to fail at logon against a Server
  2025 DC, whatever the filter allows.  The one Server 2025 logon check in this site's lab
  (build 26100.32522, the March 2026 update) recorded a request that asked for RC4 still
  being answered with RC4; that result has not been reconciled with Microsoft's statement.

---

## Am I Affected?

Run these from a management host with RSAT, against every DC.  Check 5 is the exception:
it has to run on the DCs themselves.  The [triage runbook](enforcement-triage.md) has the
fix for each finding.

### 1. Which DCs are enforcing, and what overrides do they carry?

--8<-- "includes/ddset-per-dc-check.md"

A DC enforces once it has its OS's April 2026 cumulative update or later; how to confirm
that with a live request is in
[RC4 Enforcement: Am I Affected?](enforcement-triage.md#step-1-is-each-dc-enforcing).
`DDSET` should be absent or `0x18` on every DC: a value that includes RC4 re-enables RC4
for every unconfigured account that DC serves.  Absent only means AES-only on a DC that
has the April 2026 update or later, so pin `0x18` on every DC while patch levels are
mixed.  `UseReqEtypes` should be `(absent)` or `0x0`.  For the full registry report, including
wrong-path detection, run
[`Get-KdcKerberosRegistryAudit.ps1`](https://github.com/StrongWind1/Kerberos/blob/main/scripts/Get-KdcKerberosRegistryAudit.ps1);
the reference for each value is [Registry Audit](registry-audit.md).

### 2. Is the KDC blocking anything?

Kdcsvc events 203, 204, 208 and 209 are logged when the KDC refuses a request under
enforcement.  Event 205 is logged at KDC start when `DefaultDomainSupportedEncTypes`
explicitly includes a non-AES cipher.

--8<-- "includes/kdcsvc-event-query.md"

For what each event means, see the
[Kdcsvc event reference](rc4-deprecation.md#kdcsvc-event-reference).

### 3. Which SPN-bearing accounts have no explicit configuration, or still declare RC4?

This overview covers all five object types that can hold an SPN (user service accounts,
computer accounts, gMSA, MSA, dMSA):

--8<-- "includes/spn-overview-query.md"

Accounts at `0` use the DC's default: AES-only on an enforcing DC, or whatever an explicit
`DefaultDomainSupportedEncTypes` says.  Accounts whose value includes the RC4 bit (`4`)
still receive RC4 tickets or RC4 session keys by design.

User service accounts are the Kerberoasting target, so list them separately:

```powershell title="SPN-bearing user accounts that are unset or declare RC4"
Get-ADUser -Filter 'servicePrincipalName -like "*"' `
    -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
    Where-Object {
        $_.SamAccountName -ne 'krbtgt' -and (
            [int]$_.'msDS-SupportedEncryptionTypes' -eq 0 -or
            [int]$_.'msDS-SupportedEncryptionTypes' -band 4)
    } |
    Select-Object sAMAccountName,
    @{N = 'msDS-SET (dec)'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'SPNs'; E = { ($_.servicePrincipalName | Select-Object -First 2) -join '; ' } }
```

See [msDS-SupportedEncryptionTypes](msds-supported.md) for the per-type breakdown.

### 4. Which accounts may have no AES keys?

--8<-- "includes/old-passwords-query.md"

Accounts in this list may hold only an RC4 key.  On an enforcing DC such an account fails
if its `msDS-SupportedEncryptionTypes` is unset or AES-only.  Reset the password before
setting `0x18`.  For definitive key checks, see
[Auditing Kerberos Keys](account-key-audit.md).

### 5. Is Kerberos auditing on?

Without it, DCs do not write the 4768/4769 events the other checks rely on.  `auditpol`
reports the policy of the computer it runs on, so run this **on each DC** (or through
`Invoke-Command -ComputerName dc1.corp.local`); on the management host it would show the
management host's own policy.

--8<-- "includes/verify-kerberos-auditing.md"

Both must show **Success and Failure** on every DC.  If not, configure them through
[Group Policy](group-policy.md#kerberos-auditing-policies).

---

## What Controls Encryption

Three settings are live.  A fourth existed only for the 2026 rollout.

| Setting | Where | What it does | Healthy value |
|---|---|---|---|
| `msDS-SupportedEncryptionTypes` | AD attribute on each account | The account's declared etypes.  When non-zero, this is the effective set for its service tickets. | `0x18` (24) on SPN-bearing accounts that have AES keys |
| `DefaultDomainSupportedEncTypes` | `HKLM\SYSTEM\CurrentControlSet\Services\Kdc` on each DC | The effective set for accounts whose attribute is unset or `0`.  Immediate; per DC; not replicated. | Absent (only when every DC has the April 2026 update or later), or `0x18` (24) |
| `SupportedEncryptionTypes` (the Kerberos etype GPO) | Registry on each machine | On a DC: a filter over the tickets the KDC issues, read at KDC start.  In the lab an AES-only filter also blocked RC4 pre-authentication (one pre-April 2026 Server 2022 build; not re-run since).  On a client: what it offers. | Includes AES128 + AES256; RC4 only while something still needs it |
| `RC4DefaultDisablementPhase` (historical) | Registry on each DC | Was the audit/rollback gate from January to July 2026.  Per Microsoft, no longer read after the July 2026 update. | Absent.  A leftover `0` or `1` is an audit finding; on a DC that has only an April-June 2026 update it is still live, so read [the removal steps](enforcement-triage.md#removing-exceptions-afterwards) before deleting it. |

How they combine:

- An explicit `msDS-SupportedEncryptionTypes` is never replaced by the DC's default.  The
  default only fills in for unset accounts.
- The DC filter applies to every request.  If an account's explicit set shares no etype
  with the filter, the request fails with `KDC_ERR_ETYPE_NOSUPP`; the filter does not
  substitute another etype.  For unset accounts the filter can remove RC4 from a default
  that includes it.
- The client's etype list does not choose the ticket etype.  It does have to share an
  etype with the effective set so that a session key can be agreed.

The full rules, with lab matrices, are in the [Etype Decision Guide](etype-decision-guide.md)
and [Registry Settings](registry.md).  To keep RC4 for one account, see
[RC4 exceptions](rc4-deprecation.md#rc4-exceptions).

---

## Who Is Exposed

Five AD object types can hold a `servicePrincipalName`:

| Type | Kerberoastable in practice? | Password | Action |
|---|---|---|---|
| **User service account** | **Yes**: human-chosen password | Human-set | Set `0x18`; use a 25+ character random password; or migrate to gMSA |
| Computer account | No: random machine password | Auto-rotated (30 days by default) | Windows maintains the attribute; check non-Windows and long-offline objects |
| gMSA | No: random managed password | Auto-rotated | Set `0x18` to remove RC4 from its declared set |
| MSA | No: random managed password | Auto-rotated | Set `0x18` |
| dMSA (Server 2025+) | No: random managed password | Auto-rotated | Set `0x18` |

User service accounts are the priority: they are the only SPN-bearing type with
human-chosen passwords.  The default `msDS-SupportedEncryptionTypes` of each type is listed
in [msDS-SupportedEncryptionTypes](msds-supported.md), and the full taxonomy is in
[SPN-Bearing Account Types](../index.md#spn-bearing-account-types).

---

## What to Monitor

### Configuration

| Setting | Where | Expected | If it drifts |
|---|---|---|---|
| `msDS-SupportedEncryptionTypes` | Every SPN-bearing account | `0x18` (24), plus documented exceptions | New unset or RC4 accounts appear |
| `DefaultDomainSupportedEncTypes` | Every DC | Absent or `0x18`, identical on all DCs | One DC serves RC4 for unconfigured accounts |
| `SupportedEncryptionTypes` | Every DC | The same value on all DCs | Inconsistent results by DC; applies only after a KDC restart |
| `RC4DefaultDisablementPhase` | Every DC | Absent | A leftover `0` or `1` keeps a DC on an April-June 2026 update issuing RC4 for unconfigured accounts; on later updates (per Microsoft) it is no longer read and only misleads audits |
| `KdcUseRequestedEtypesForTickets` | Every DC | Absent or `0` | Clients can pull a weaker etype from any account that lists one |

### Events

| Event ID | Log | What to look for |
|---|---|---|
| **4768** | Security | TGT requests.  Accounts whose available keys lack AES; RC4 pre-authentication. |
| **4769** | Security | Service ticket requests.  `Ticket Encryption Type` `0x17` (RC4 issued); `Status` `0xe` with `0xffffffff` (blocked). |
| **4771** | Security | Pre-authentication failures.  Bursts across many accounts indicate password spraying. |
| **203, 204, 208, 209** | System | The KDC refused a request under RC4 enforcement. |
| **205** | System | A DC started with a `DefaultDomainSupportedEncTypes` that includes a non-AES cipher. |
| **14, 16** | System | No suitable key or no common etype for an AS (14) or TGS (16) request.  Event 16 accompanies every blocked TGS request, whatever the cause. |
| **26, 27** | System | An etype mismatch on an AS (26) or TGS (27) request: the etypes the client requested cannot be used under the etype configuration of the account, `krbtgt` or the DC, even when a matching key exists.  Microsoft describes 27 as "disjoint encryption types between Kerberos clients and remote servers or services" ([KB5021131](https://support.microsoft.com/help/5021131)); the lab saw it for account/client etype mismatches on a DC left at its default etype policy (build 20348.3207). |
| **42** | System | The KDC lacks strong (AES) keys for an account, typically `krbtgt`. |

Diagnostic techniques are in [Troubleshooting](troubleshooting.md).

---

## The Goal

1. **AES-only encryption.**  RC4 and DES are not used for tickets or session keys.  See
   the [Standardization Guide](aes-standardization.md).
2. **Strong service account secrets.**  25+ character random passwords, or better, group
   Managed Service Accounts.  See [Mitigations](mitigations.md).
3. **Least-privilege delegation.**  No unconstrained delegation outside domain
   controllers, and no SPNs on accounts that do not need them.  See
   [Mitigations: Delegation Lockdown](mitigations.md#priority-6-delegation-lockdown).

---

## Section Map

### Start here

| Page | Use it for |
|---|---|
| [Quick Start Guide](quick-start.md) | The short narrative: how etypes are chosen, what changed in 2026, what to do. |
| [RC4 Enforcement: Am I Affected?](enforcement-triage.md) | The runbook: is each DC enforcing, what is failing, fastest safe fix. |

### RC4 enforcement and AES migration

| Page | Use it for |
|---|---|
| [RC4 Deprecation (CVE-2026-20833)](rc4-deprecation.md) | What shipped, how the KDC decides now, the Kdcsvc event reference, and how to keep RC4 for one account. |
| [Auditing Kerberos Keys](account-key-audit.md) | Finding accounts that have no AES keys. |
| [Standardization Guide](aes-standardization.md) | The step-by-step clean-up to AES-only. |

### Reference

| Page | Use it for |
|---|---|
| [Encryption Type Negotiation](etype-negotiation.md) | How the KDC picks an etype for each part of the AS and TGS exchanges. |
| [Etype Decision Guide](etype-decision-guide.md) | Every input to etype selection, with worked examples from a live DC. |
| [Algorithms & Keys](algorithms.md) | Key derivation, cracking speed, how keys are stored, `krbtgt`. |
| [msDS-SupportedEncryptionTypes](msds-supported.md) | The attribute: bit flags, defaults by account type, queries. |
| [Registry Settings](registry.md) | Every KDC and client registry value that affects etypes. |
| [Registry Audit](registry-audit.md) | Lab evidence for which registry paths work, and when changes take effect. |
| [Group Policy](group-policy.md) | The etype policy, ticket lifetimes, auditing policies. |

### Hardening and operations

| Page | Use it for |
|---|---|
| [Mitigations](mitigations.md) | Prioritized defenses: gMSA, Protected Users, SPN hygiene, delegation, `krbtgt` rotation. |
| [Troubleshooting](troubleshooting.md) | `klist`, event IDs, error codes, Wireshark, common scenarios. |

### Tools

| Tool | Use it for |
|---|---|
| [Encryption Type Calculator](etype-calculator.md) | Decoding and building `msDS-SET`, DDSET and GPO bitmask values. |
| [Event Decoder](event-decoder.md) | Turning a pasted 4768/4769/4771 event into labeled fields. |
