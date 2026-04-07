---
---

# Registry Settings

Every registry key that affects Kerberos encryption behavior on domain controllers
and clients.  These settings interact with each other and with the
`msDS-SupportedEncryptionTypes` AD attribute -- understanding the precedence order
is critical.

---

## Precedence Order

When the KDC selects an etype for a service ticket, it checks in this order:

1. **`msDS-SupportedEncryptionTypes`** on the target account (always wins if set).
2. **`DefaultDomainSupportedEncTypes`** on the DC (used only when the attribute is 0 or absent).
3. The KDC's own allowed etype configuration (from Group Policy or `SupportedEncryptionTypes`
   on the DC) acts as a final filter -- the KDC will never issue a ticket with an etype it is
   not configured to allow.

---

## DefaultDomainSupportedEncTypes

The most important KDC-side registry key.  It controls the **assumed** encryption types for
every account that does not have an explicit `msDS-SupportedEncryptionTypes` value.

| Property | Value |
|---|---|
| **Path** | `HKLM\SYSTEM\CurrentControlSet\Services\KDC` |
| **Value name** | `DefaultDomainSupportedEncTypes` |
| **Type** | `REG_DWORD` |
| **Default (not set)** | `0x27` (39) = DES + RC4 + AES-SK |
| **Default (Server 2025)** | `0x24` (36) = RC4 + AES-SK (DES removed) |
| **Recommended** | `0x18` (24) = AES128 + AES256 |
| **Takes effect** | Immediately (no reboot required) |

### How It Works

When the KDC processes a TGS-REQ and the target account has `msDS-SupportedEncryptionTypes = 0`
(or not set), the KDC substitutes this registry value.  The etype selection then proceeds as
if the account had this value in its AD attribute.

### Common Values

| Value | Hex | Meaning |
|---|---|---|
| 24 | `0x18` | AES128 + AES256 (**recommended** -- blocks RC4 for unconfigured accounts) |
| 28 | `0x1C` | RC4 + AES128 + AES256 (transitional) |
| 36 | `0x24` | RC4 + AES-SK (Server 2025 default -- RC4 ticket, AES session key) |
| 39 | `0x27` | DES + RC4 + AES-SK (pre-2025 default) |
| 56 | `0x38` | AES128 + AES256 + AES-SK (AES-only with session key flag) |

### Setting It

```powershell title="Set DefaultDomainSupportedEncTypes to AES-only and verify"
# Set to AES-only (recommended)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KDC" `
  -Name "DefaultDomainSupportedEncTypes" `
  -Value 24 -PropertyType DWord -Force

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\KDC" `
  -Name "DefaultDomainSupportedEncTypes"
```

!!! warning "Set this on ALL domain controllers"
    This registry key is per-DC, not replicated through AD.  You must set it on every DC in
    the domain.  If one DC has `0x18` and another has `0x27`, clients will get different
    ticket etypes depending on which DC they reach.  Use Group Policy Preferences to push
    registry values consistently.

!!! info "Explicit msDS-SupportedEncryptionTypes always overrides"
    If an account has `msDS-SupportedEncryptionTypes` explicitly set to any non-zero value,
    `DefaultDomainSupportedEncTypes` is completely ignored for that account.

!!! warning "DDSET is filtered by the KDC's SupportedEncryptionTypes"
    `DefaultDomainSupportedEncTypes` and `SupportedEncryptionTypes` (GPO) are two
    independent mechanisms.  DDSET determines what etypes the KDC *considers* for the
    account; `SupportedEncryptionTypes` filters what the KDC will *actually issue*.

    The KDC does **not** intersect these values — `SupportedEncryptionTypes` overrides
    DDSET for ticket issuance.  If the GPO filter allows only AES and DDSET says RC4,
    the KDC issues AES tickets (not an error).  If the GPO filter allows only RC4 and
    DDSET says AES, the KDC issues RC4 tickets.  DDSET is honored only within the
    SupportedEncryptionTypes allowance.

    The Event 4769 `msDSSET` field reflects DDSET, but the actual ticket etype comes from
    the filter.  If these two values disagree, the `msDSSET` field and the ticket etype
    will show different etypes — this is expected behavior, not a bug.

---

## KdcUseRequestedEtypesForTickets

Controls whether the KDC honors the client's etype preference list when selecting the
**ticket** etype (not the session key).

| Property | Value |
|---|---|
| **Path** | `HKLM\SYSTEM\CurrentControlSet\Services\Kdc` |
| **Value name** | `KdcUseRequestedEtypesForTickets` |
| **Type** | `REG_DWORD` |
| **Default** | Not present (equivalent to `0`) |

| Value | Behavior |
|---|---|
| `1` | KDC uses the **client's** etype preference list to select the ticket etype.  Picks the first entry in the client's list that the KDC supports, **ignoring the target account's `msDS-SupportedEncryptionTypes` entirely**. |
| `0` or not set | KDC ignores the client's list and picks the **strongest** etype that the KDC and target account both support. |

!!! danger "KdcUseRequestedEtypesForTickets=1 bypasses per-account etype protection"
    When set to `1`, the KDC completely ignores the target account's
    `msDS-SupportedEncryptionTypes`.  An attacker can force RC4 tickets for any account —
    including accounts explicitly configured for AES-only (`msDS-SET = 0x18`) — by
    requesting RC4 in their TGS-REQ.  This makes Kerberoasting trivial even against
    hardened accounts.

    Lab-validated: `svc_val_03` (msDS-SET=24, AES-only) received an RC4 ticket when
    `KdcUseRequestedEtypesForTickets=1` and the client requested RC4.  Event 206 was
    logged, but the ticket was still issued.

    **Never set this to `1` in production.**  If this key exists in your environment,
    remove it immediately.

### When to Use It

**Never.**  Leave this at the default (`0`) or remove it entirely.  The documented use
case (debugging interoperability) does not justify the security risk.  Any debugging need
can be addressed with Wireshark captures or Event 4769 analysis instead.

---

## SupportedEncryptionTypes (GPO / KDC Filter)

Controls what encryption types the **Kerberos client** will advertise in AS-REQ and TGS-REQ
messages.  This affects what the client requests, not what the KDC issues.

| Property | Value |
|---|---|
| **Path** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` |
| **Value name** | `SupportedEncryptionTypes` |
| **Type** | `REG_DWORD` |
| **Default** | Not present (client advertises all available etypes) |

The Group Policy *Network security: Configure encryption types allowed for Kerberos* writes
to this path.  This is the only supported location for this setting.

!!! info "Legacy direct path: functional on Server 2022, deprecated in Server 2025"
    Older documentation references a second path at
    `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`.  On **Server 2022**,
    `SupportedEncryptionTypes` at this path IS functional — it acts as a KDC etype filter
    identical to the Policies path, but with **lower precedence** (when both are set, the
    Policies path wins).  It requires a KDC restart to take effect.

    Starting with **Windows Server 2025**, Kerberos no longer honors
    `SupportedEncryptionTypes` at the Lsa path.  For forward compatibility, always use the
    GPO or Group Policy Preferences to write the value to the Policies path shown above.

### Common Values

| Value | Hex | Meaning |
|---|---|---|
| 24 | `0x18` | Client requests AES only (blocks RC4 client-side) |
| 28 | `0x1C` | Client requests RC4 + AES (default behavior) |

!!! tip "Client-side vs. server-side"
    Setting `SupportedEncryptionTypes` on a **client** workstation only affects what that
    client requests.  It does not prevent the KDC from issuing RC4 tickets for services.  To
    block RC4 tickets, you must configure the **target account** (`msDS-SupportedEncryptionTypes`)
    or the **DC** (`DefaultDomainSupportedEncTypes`).  Setting it on a **DC** affects both its
    client behavior and, via GPO, the KDC's allowed etypes.

---

## Timing: When Changes Take Effect

Not all registry changes take effect at the same time.  Failing to account for this is a
common source of "I changed the value but nothing happened."

| Registry Value | Timing | Evidence |
|---|---|---|
| `DefaultDomainSupportedEncTypes` | **Immediate** — takes effect on the next TGS-REQ, no restart required. | Lab-validated: setting DDSET=24 changed ticket etype from RC4 to AES256 within seconds. Removing the value reverted immediately. |
| `SupportedEncryptionTypes` (Policies path) | **KDC restart required** — the KDC reads this value only at service start. | Lab-validated: Pol\SET=24 had no effect until `Restart-Service kdc`. Removing the value also had no effect until the next restart.  This filter affects both AS (pre-auth) and TGS exchanges -- setting AES-only blocks RC4 pre-auth for new logon sessions. |
| `SupportedEncryptionTypes` (Lsa path) | **KDC restart required** — same as the Policies path. | Lab-validated: identical behavior to Pol path. |
| `RC4DefaultDisablementPhase` | **KDC restart required** — unlike DDSET, enforcement phase changes are not picked up live. | Lab-validated: Phase=2 did not change ticket etype until KDC restart. |

!!! tip "DDSET for quick changes, GPO for persistent policy"
    `DefaultDomainSupportedEncTypes` changes are immediate — useful for testing and
    emergency remediation.  `SupportedEncryptionTypes` (GPO) changes require a KDC
    restart but are managed centrally through Group Policy.  Use both together for defense
    in depth.

---

## RC4DefaultDisablementPhase

Part of the CVE-2026-20833 rollout.  Controls whether the KDC applies the RC4 deprecation
audit or enforcement behavior.

| Property | Value |
|---|---|
| **Path** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` |
| **Value name** | `RC4DefaultDisablementPhase` |
| **Type** | `REG_DWORD` |

| Value | Behavior |
|---|---|
| `0` | No change -- RC4 behavior unchanged from pre-2026. |
| `1` | **Audit phase** -- RC4 is still allowed, but Kdcsvc events 201-209 are logged when RC4 would be used by default.  This is the default after the January 2026 update. |
| `2` | **Enforcement** -- KDC assumes AES-only (`0x18`) for accounts without explicit `msDS-SupportedEncryptionTypes`.  RC4 is blocked unless the account explicitly declares it. |

### Timeline

| Date | Default Value |
|---|---|
| January 2026 | `1` (audit) |
| April 2026 | `2` (enforcement), can be rolled back to `1` |
| July 2026 | Registry key **removed** -- enforcement is permanent |

!!! warning "KDC restart required"
    Unlike `DefaultDomainSupportedEncTypes` (which takes effect immediately),
    `RC4DefaultDisablementPhase` requires a KDC restart to take effect.  After setting or
    changing this value, run `Restart-Service kdc` on the DC.

### Setting It Manually

```powershell title="Enable RC4 enforcement or roll back to audit mode"
# Enable enforcement early
New-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "RC4DefaultDisablementPhase" `
  -Value 2 -PropertyType DWord -Force

# Roll back to audit (only before July 2026)
Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "RC4DefaultDisablementPhase" `
  -Value 1
```

---

## DefaultEncryptionType

A legacy key that sets the default encryption type for **pre-authentication**.

| Property | Value |
|---|---|
| **Path** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` |
| **Value name** | `DefaultEncryptionType` |
| **Type** | `REG_DWORD` |
| **Default** | `0x17` (23) = RC4-HMAC |

This key is rarely needed.  It was introduced to work around specific pre-authentication
failures (e.g., the NETWORK SERVICE account failing pre-auth after certain patches).  In
modern environments, leave it at the default or remove it entirely.

---

## LogLevel (Debugging)

Enables verbose Kerberos event logging on the client side.

| Property | Value |
|---|---|
| **Path** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` |
| **Value name** | `LogLevel` |
| **Type** | `REG_DWORD` |
| **Default** | `0` (disabled) |

| Value | Behavior |
|---|---|
| `0` | Normal logging |
| `1` | Verbose Kerberos logging in the System event log |

```powershell title="Enable and disable verbose Kerberos debug logging"
# Enable debug logging
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "LogLevel" -Value 1 -PropertyType DWord -Force

# Disable after debugging (performance impact)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "LogLevel" -Value 0
```

!!! warning "Disable after troubleshooting"
    Verbose Kerberos logging generates a high volume of events and can impact performance on
    busy systems.  Enable it only for the duration of your troubleshooting session, then set
    it back to `0`.

---

## Commonly Confused Keys

These registry values have similar names but different purposes, paths, and timing.
Confusing them is the most common cause of "I set AES-only but services still get RC4."

| Key | Full Path | Scope | Set By | Purpose | Timing |
|---|---|---|---|---|---|
| `SupportedEncryptionTypes` | `...\Policies\System\Kerberos\Parameters` | Any machine | Group Policy | Controls what etypes the machine's Kerberos client requests/accepts.  On a DC, also acts as the KDC's allowed-etype filter. | KDC restart |
| `SupportedEncryptionTypes` | `...\Lsa\Kerberos\Parameters` | Any machine | Manual | Same as above but lower precedence (Pol wins when both set).  Functional on Server 2022, deprecated in Server 2025. | KDC restart |
| `DefaultDomainSupportedEncTypes` | `...\Services\KDC` | DC only | Manual / GPP | Sets the **assumed** etypes for accounts with no `msDS-SupportedEncryptionTypes`.  Not set by any GPO -- must be configured manually or via Group Policy Preferences. | Immediate |

For the full list of non-functional value/path combinations (6 of 9 tested), see
[Registry Audit Results — Non-Functional Registry Paths](registry-audit.md#non-functional-registry-paths).

!!! warning "GPO does not set `DefaultDomainSupportedEncTypes`"
    Applying the *Configure encryption types allowed for Kerberos* GPO to domain controllers
    writes `SupportedEncryptionTypes` (the GPO policy cache path).  This restricts what etypes
    the KDC will **issue** (after KDC restart), but it does **not** change what etypes the KDC
    **assumes** for unconfigured accounts.  To change the default assumption, you must also set
    `DefaultDomainSupportedEncTypes` on every DC.

    **Example**: You apply an AES-only GPO to DCs and restart the KDC.  An account has
    `msDS-SupportedEncryptionTypes = 0`.  `DefaultDomainSupportedEncTypes` is still `0x27`
    (includes RC4).  The KDC considers RC4 for the account (DDSET says so), but the GPO filter
    overrides this and issues an AES ticket instead.  No authentication failure occurs — the
    filter takes precedence.  However, for clarity and forward compatibility, you should still
    align both settings by setting `DefaultDomainSupportedEncTypes = 0x18`.

---

## Quick Reference Table

| Key | Path | Default | Scope | Timing | Purpose |
|---|---|---|---|---|---|
| `DefaultDomainSupportedEncTypes` | `...\Services\KDC` | `0x27` | KDC (per-DC) | Immediate | Default etype for accounts with empty `msDS-SET` |
| `KdcUseRequestedEtypesForTickets` | `...\Services\Kdc` | Not set (= `0`) | KDC (per-DC) | Immediate | Whether to honor client etype preference (**never set to 1**) |
| `SupportedEncryptionTypes` | `...\Policies\...\Kerberos\Parameters` | Not set | Any machine | KDC restart | Machine's etype config (written by GPO).  On a DC, also the KDC's allowed-etype filter. |
| `SupportedEncryptionTypes` | `...\Lsa\Kerberos\Parameters` | Not set | Any machine | KDC restart | Same as above, lower precedence.  Functional on Server 2022, deprecated in Server 2025. |
| `RC4DefaultDisablementPhase` | `...\Policies\...\Kerberos\Parameters` | `1` (post-Jan 2026) | KDC (per-DC) | KDC restart | RC4 deprecation phase |
| `DefaultEncryptionType` | `...\Lsa\Kerberos\Parameters` | `0x17` | Client | — | Default pre-auth etype (no effect on KDC ticket issuance) |
| `LogLevel` | `...\Lsa\Kerberos\Parameters` | `0` | Client/Server | — | Verbose Kerberos logging |
