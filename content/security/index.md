# Kerberos Security Overview

A sysadmin-focused summary of Kerberos security posture in Active Directory: what is at
risk today, how to audit your environment, and what the 2026 RC4 deprecation means for
your domain.

Already familiar with Kerberos and just need to migrate?  Jump to the
[Standardization Guide](aes-standardization.md).

---

## Why This Matters

- **RC4 is the default.**  A fresh Active Directory domain -- even Server 2022 or Server 2025 --
  permits RC4-HMAC encryption for any account that does not have an explicit
  `msDS-SupportedEncryptionTypes` value.
- **RC4 is fast to crack.**  The RC4 key is the NTLM hash (`MD4(UTF-16LE(password))`, no salt).
  It cracks at roughly **800 times the speed** of AES.
  See [Algorithms & Keys](algorithms.md#cracking-speed-comparison) for benchmarks.
- **Any domain user can Kerberoast.**  Any authenticated user can request a service ticket for
  any SPN, take it offline, and crack the user service account password.
  See [Kerberoasting](../attacks/roasting/kerberoasting.md).
- **RC4 key = pass-the-hash.**  Because the RC4 Kerberos key is identical to the NTLM hash,
  a compromised RC4 key doubles as a pass-the-hash credential.

!!! danger "If you have user service accounts with SPNs and no explicit `msDS-SupportedEncryptionTypes`, they are exposed right now."

---

## RC4 Deprecation Timeline (CVE-2026-20833)

Microsoft is eliminating RC4 as the implicit default encryption type for Kerberos
service tickets.  This table tracks the full rollout:

| Date | Phase | What Changes | Rollback? |
|---|---|---|---|
| **November 2022** | CVE-2022-37966 | AES **session keys** become the default.  `DefaultDomainSupportedEncTypes` registry key introduced. | N/A |
| **January 2025** | Enhanced auditing | New fields added to events 4768/4769: `msDS-SupportedEncryptionTypes`, `Available Keys`, `Advertized Etypes`, `Session Encryption Type`. | N/A |
| **January 2026** | Audit | Kdcsvc events 201-209 begin logging when RC4 is used by default.  `RC4DefaultDisablementPhase = 1`. | N/A |
| **April 2026** | **Enforcement** | KDC defaults to AES-only (`0x18`) for accounts without explicit `msDS-SupportedEncryptionTypes`.  Accounts relying on implicit RC4 **will fail**. | `RC4DefaultDisablementPhase = 1` |
| **July 2026** | **Permanent** | `RC4DefaultDisablementPhase` registry key removed.  No rollback available.  RC4 only works if explicitly enabled per-account or per-DC. | None |

!!! warning "April 2026 can break authentication"
    Any SPN-bearing account that has no `msDS-SupportedEncryptionTypes` set **and** either
    lacks AES keys or has clients that only support RC4 will fail to authenticate after the
    April 2026 update.

**If you need to roll back during an outage**, set this on every DC:

```powershell title="Roll back RC4 enforcement to audit mode (before July 2026 only)"
Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "RC4DefaultDisablementPhase" -Value 1
```

For the full event ID reference and pre-enforcement checklist, see
[RC4 Deprecation](rc4-deprecation.md).

---

## Four Layers That Control Encryption

Kerberos encryption behavior is controlled at four layers.  Misunderstanding the
interaction between them is the most common cause of encryption-related authentication
failures.

| Priority | Setting | Where | What It Controls | Target Value |
|---|---|---|---|---|
| **1** (wins) | `msDS-SupportedEncryptionTypes` | AD attribute on each account | Which etypes the KDC uses for this account's service tickets.  **Always overrides layers below.** | `0x18` (24) = AES |
| **2** (fallback) | `DefaultDomainSupportedEncTypes` | Registry on each DC | Assumed etypes for accounts with `msDS-SupportedEncryptionTypes = 0`.  Per-DC, not replicated. | `0x18` (24) = AES |
| **3** (filter) | `SupportedEncryptionTypes` / GPO | Registry on each machine | Hard filter: the KDC will not issue a ticket with an etype absent from this list.  On clients, controls what the Kerberos client requests. | AES-only on DCs |
| **4** (2026) | `RC4DefaultDisablementPhase` | Registry on each DC | Overrides the KDC's internal default for accounts without explicit config.  `1` = audit, `2` = enforce. | `2` (enforce) |

**Layer 1 always wins.**  If `msDS-SupportedEncryptionTypes` is set on an account, layers
2-4 are irrelevant for that account's ticket encryption.  When the GPO (layer 3) is set on
a DC, it acts as a hard KDC filter (after KDC restart) that overrides
`DefaultDomainSupportedEncTypes` (layer 2) for ticket issuance — the filter takes
precedence, not an intersection.  For clean configuration, align both layers.

For the full 12-input decision logic with 14 worked examples, see
[Encryption Type Negotiation](etype-negotiation.md) and
[Etype Decision Guide](etype-decision-guide.md).

---

## Assess Your Environment

Run these five checks from a Domain Controller with RSAT to assess your current exposure.

### 1. SPN-Bearing Accounts by Encryption Configuration

How many accounts are using which etype configuration?  This cross-type overview covers
all five AD object types that can hold an SPN (user service accounts, computer accounts,
gMSA, MSA, dMSA):

--8<-- "includes/spn-overview-query.md"

Accounts showing `msDS-SET = 0` are using the domain default (which includes RC4).
Accounts showing `msDS-SET = 4` are explicitly RC4-only.  Both need remediation.

For user service accounts specifically -- the primary Kerberoasting target -- find those
with no config or RC4 enabled:

```powershell title="Find SPN-bearing user accounts exposed to Kerberoasting"
Get-ADUser -Filter 'servicePrincipalName -like "*"' `
  -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
  Where-Object {
    [int]$_.'msDS-SupportedEncryptionTypes' -eq 0 -or
    [int]$_.'msDS-SupportedEncryptionTypes' -band 4
  } |
  Select-Object sAMAccountName,
    @{N='msDS-SET (dec)'; E={[int]$_.'msDS-SupportedEncryptionTypes'}},
    @{N='msDS-SET (hex)'; E={'0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes'}},
    @{N='SPNs'; E={($_.servicePrincipalName | Select-Object -First 2) -join '; '}}
```

See [msDS-SupportedEncryptionTypes](msds-supported.md) for the full per-type breakdown and
bulk remediation commands.

### 2. DefaultDomainSupportedEncTypes on All DCs

Every DC must have the same value.  If any DC shows `0x27` (39) or blank, that DC still
permits RC4 as the fallback for unconfigured accounts.

```powershell title="Check DefaultDomainSupportedEncTypes across all DCs"
Get-ADDomainController -Filter * | ForEach-Object {
  $val = Invoke-Command -ComputerName $_.HostName -ScriptBlock {
    (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\KDC" `
      -Name DefaultDomainSupportedEncTypes -ErrorAction SilentlyContinue
    ).DefaultDomainSupportedEncTypes
  }
  [PSCustomObject]@{
    DC = $_.HostName
    'DDSET (dec)' = $val
    'DDSET (hex)' = if ($val) { '0x{0:X}' -f [int]$val } else { '(not set)' }
  }
} | Format-Table -AutoSize
```

See [Registry Settings](registry.md#defaultdomainsupportedenctypes) for the setting
commands and the full list of commonly confused registry keys.

### 3. Accounts with Old Passwords (Possibly Missing AES Keys)

--8<-- "includes/old-passwords-query.md"

Accounts in this list may lack AES keys entirely.  Setting `msDS-SupportedEncryptionTypes
= 0x18` on an account without AES keys causes ticket requests to **fail**.  Reset
passwords before changing etype configuration.  For definitive key verification (four
methods including offline ntds.dit analysis), see
[Auditing Kerberos Keys](account-key-audit.md).

### 4. Kdcsvc Events 201-209 (RC4 Deprecation Audit)

These events fire on DCs running the January 2026+ update whenever the KDC would use RC4
by default.  Any events here identify accounts that will break under enforcement.

```powershell title="Check for RC4 deprecation audit events on DCs"
Get-WinEvent -FilterHashtable @{
  LogName = 'System'; ProviderName = 'Kdcsvc'; Id = 201, 202, 205, 206, 207
} -MaxEvents 50 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message |
  Format-Table -AutoSize
```

See [RC4 Deprecation — Kdcsvc Event IDs](rc4-deprecation.md#kdcsvc-event-ids) for the full
event reference and remediation steps.

### 5. Kerberos Auditing Enabled

Without audit policies enabled, DCs do not generate the 4768/4769 events needed to
identify RC4 usage.

--8<-- "includes/verify-kerberos-auditing.md"

Both must show **Success and Failure**.  If not, configure via GPO -- see
[Group Policy — Kerberos Auditing Policies](group-policy.md#kerberos-auditing-policies).

---

## Who Is Exposed

Five AD object types can hold a `servicePrincipalName`.  Their risk profiles differ:

| Type | Kerberoastable? | Password | Default `msDS-SET` | Action |
|---|---|---|---|---|
| **User service account** | **Yes** -- human-set password | Human-set | `0` (unset) | Set `0x18`; enforce 25+ char passwords; or migrate to gMSA |
| Computer account | No -- machine password | Auto-rotated 30 d | `0x1F` (GPO-managed) | Managed by GPO automatically |
| gMSA | No -- 240-char auto | Auto-rotated | `0x1C` | Set `0x18` to eliminate RC4 traffic |
| MSA | No -- auto password | Auto-rotated | `0x1C` or `0` | Set `0x18` |
| dMSA (Server 2025+) | No -- auto password | Auto-rotated | `0` or `0x1C` | Set `0x18` |

**User service accounts are the primary target.**  They are the only SPN-bearing type with
human-set passwords and no automatic etype management.  gMSA/MSA/dMSA passwords are
uncrackable, but setting `msDS-SupportedEncryptionTypes = 0x18` on them eliminates RC4
traffic and satisfies the 2026 deprecation requirements.

For the full account type taxonomy and bulk update commands, see
[SPN-Bearing Account Types](../index.md#spn-bearing-account-types).

---

## What to Monitor

### Configuration Values

| Setting | Where | Target | Risk if Wrong |
|---|---|---|---|
| `msDS-SupportedEncryptionTypes` | AD attribute on every SPN-bearing account | `0x18` (24) | RC4 tickets issued; Kerberoasting at full speed |
| `DefaultDomainSupportedEncTypes` | `HKLM\...\Services\KDC` on every DC | `0x18` (24) | Unconfigured accounts fall back to RC4 |
| `SupportedEncryptionTypes` (GPO) | `HKLM\...\Kerberos\Parameters` on DCs | AES-only | KDC may issue RC4 tickets if allowed by this filter |
| `RC4DefaultDisablementPhase` | `HKLM\...\Kerberos\Parameters` on DCs | `2` (enforce) | RC4 remains the implicit default for unconfigured accounts |

### Event Log Monitoring

| Event ID | Log | Source | What to Look For |
|---|---|---|---|
| **4768** | Security | Kerberos KDC | TGT request -- check `Ticket Encryption Type` for `0x17` (RC4) |
| **4769** | Security | Kerberos KDC | Service ticket request -- check `Ticket Encryption Type` for `0x17` (RC4) |
| **4771** | Security | Kerberos KDC | Pre-auth failure -- may indicate password spray or Kerberoasting |
| **201-209** | System | Kdcsvc | RC4 deprecation audit/enforcement events (January 2026+) |
| **14, 16** | System | KDC | Etype mismatch -- account lacks keys for configured encryption type |
| **26, 27** | System | KDC | KDC etype not supported -- GPO filter blocking the needed etype |

For diagnostic techniques and error code reference, see [Troubleshooting](troubleshooting.md).
For the full Kdcsvc 201-209 event reference, see
[RC4 Deprecation — Kdcsvc Event IDs](rc4-deprecation.md#kdcsvc-event-ids).

---

## The Goal

A hardened Kerberos deployment has three properties:

1. **AES-only encryption** -- RC4 and DES are never used for tickets or session keys.
   See [Standardization Guide](aes-standardization.md).
2. **Strong user service account passwords** -- 25+ character random passwords, or (better) Group
   Managed Service Accounts with auto-rotating 240-character passwords.
   See [Mitigations](mitigations.md).
3. **Least-privilege delegation** -- no unconstrained delegation outside domain controllers,
   Resource-Based Constrained Delegation (RBCD) preferred, and SPNs removed from any account
   that does not need them.
   See [Mitigations — Delegation Lockdown](mitigations.md#priority-6-delegation-lockdown).

!!! tip "Just need to migrate to AES?"
    If you already understand Kerberos and just need the operational playbook, jump to the
    [Standardization Guide](aes-standardization.md).  Prerequisites:
    [RC4 Deprecation](rc4-deprecation.md) (timeline) and
    [Auditing Kerberos Keys](account-key-audit.md) (finding accounts without AES keys).

---

## Reading Order

For the full technical reference, the following pages are designed to be read in sequence.
Each page builds on concepts from the previous one.

### Understanding Encryption

| Page | What You Will Learn |
|---|---|
| [Encryption Type Negotiation](etype-negotiation.md) | How the KDC decides which algorithm to use for each part of the AS and TGS exchanges. |
| [Etype Decision Guide](etype-decision-guide.md) | Visual map of every input that determines which encryption type is used -- from account keys to registry to GPO.  Includes 14 worked examples validated against a live DC. |

### Keys and Algorithms

| Page | What You Will Learn |
|---|---|
| [Algorithms & Keys](algorithms.md) | Every encryption type family, key derivation (MD4 vs PBKDF2), cracking speed comparison, how keys are stored in AD, the double-reset problem, and KRBTGT considerations. |

### Configuration Reference

| Page | What You Will Learn |
|---|---|
| [msDS-SupportedEncryptionTypes](msds-supported.md) | The AD attribute that drives etype selection.  Bit flags, defaults, and how to set it. |
| [Registry Settings](registry.md) | Every KDC and client registry key that affects Kerberos encryption. |
| [Group Policy Settings](group-policy.md) | GPO paths for etype control, ticket lifetimes, and auditing. |

### Migration

| Page | What You Will Learn |
|---|---|
| [RC4 Deprecation (CVE-2026-20833)](rc4-deprecation.md) | Timeline, event IDs, and a step-by-step migration plan. |
| [Auditing Kerberos Keys](account-key-audit.md) | Four methods to find accounts missing AES keys: PowerShell date comparison, DSInternals, impacket secretsdump, and ntdsutil + ntdissector. |
| [Standardization Guide](aes-standardization.md) | Step-by-step playbook for moving your domain to AES-only, with every registry key, AD attribute, and PowerShell command. |

### Operations

| Page | What You Will Learn |
|---|---|
| [Mitigations](mitigations.md) | Priority-ordered best practices: gMSA, Protected Users, SPN hygiene, and more. |
| [Troubleshooting](troubleshooting.md) | Diagnostic tools, event IDs, error codes, and Wireshark tips. |
