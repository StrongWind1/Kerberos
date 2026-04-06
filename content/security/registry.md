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

!!! warning "DDSET is filtered by the KDC's own allowed etypes"
    `DefaultDomainSupportedEncTypes` is **not** used in isolation — the KDC intersects it
    with the etypes it is configured to allow (via `SupportedEncryptionTypes` GPO or the
    KDC's built-in etype list).  If the KDC does not support RC4 (because Group Policy
    restricts it to AES-only), RC4 will **not** be used even if
    `DefaultDomainSupportedEncTypes` includes it.  Conversely, if
    `DefaultDomainSupportedEncTypes` is set to AES-only but the KDC's GPO allows RC4,
    the KDC will still only assume AES for unconfigured accounts — the DDSET value is the
    ceiling, not a floor.

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
| `1` | KDC uses the **client's** etype preference list to select the ticket etype.  Picks the first entry in the client's list that both the KDC and target account support. |
| `0` or not set | KDC ignores the client's list and picks the **strongest** etype that the KDC and target account both support. |

### When to Use It

In most environments, leave this at the default (`0`).  The default behavior (strongest
etype) is more secure.  Setting it to `1` can allow a malicious client to request weaker
encryption.

The only scenario where `1` is useful is debugging interoperability issues where a specific
client or service requires a particular etype order.

---

## SupportedEncryptionTypes (GPO / Client-Side)

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

!!! warning "Legacy direct path deprecated in Server 2025"
    Older documentation references a second path at
    `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`.  Starting with
    Windows Server 2025, Kerberos **no longer honors** `SupportedEncryptionTypes` at
    that path.  Always use the GPO or Group Policy Preferences to write the value to the
    policy cache path shown above.

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

These three registry values have similar names but completely different purposes and paths.
Confusing them is the most common cause of "I set AES-only but services still get RC4."

| Key | Full Path | Scope | Set By | Purpose |
|---|---|---|---|---|
| `SupportedEncryptionTypes` | `...\Policies\System\Kerberos\Parameters` | Any machine | Group Policy | Controls what etypes the machine's Kerberos client requests/accepts.  On a DC, also acts as the KDC's allowed-etype filter. |
| `DefaultDomainSupportedEncTypes` | `...\Services\KDC` | DC only | Manual / GPP | Sets the **assumed** etypes for accounts with no `msDS-SupportedEncryptionTypes`.  Not set by any GPO -- must be configured manually or via Group Policy Preferences. |

!!! warning "GPO does not set `DefaultDomainSupportedEncTypes`"
    Applying the *Configure encryption types allowed for Kerberos* GPO to domain controllers
    writes `SupportedEncryptionTypes` (the GPO policy cache path).  This restricts what etypes
    the KDC will **issue**, but it does **not** change what etypes the KDC **assumes** for
    unconfigured accounts.  To change the default assumption, you must also set
    `DefaultDomainSupportedEncTypes` on every DC.

    **Example**: You apply an AES-only GPO to DCs.  An account has
    `msDS-SupportedEncryptionTypes = 0` (not set).  `DefaultDomainSupportedEncTypes` is still
    the post-2022 default (`0x27`, which includes RC4).  The KDC tries to issue an RC4 ticket
    (because that is what the default says the account supports), but the GPO filter blocks RC4.
    Result: **authentication failure**, not an AES ticket.  You need both settings aligned.

---

## Quick Reference Table

| Key | Path | Default | Scope | Purpose |
|---|---|---|---|---|
| `DefaultDomainSupportedEncTypes` | `...\Services\KDC` | `0x27` | KDC (per-DC) | Default etype for accounts with empty `msDS-SET` |
| `KdcUseRequestedEtypesForTickets` | `...\Services\Kdc` | Not set (= `0`) | KDC (per-DC) | Whether to honor client etype preference |
| `SupportedEncryptionTypes` | `...\Policies\System\Kerberos\Parameters` | Not set | Any machine | Machine's etype config (written by GPO).  On a DC, also the KDC's allowed-etype filter. |
| `RC4DefaultDisablementPhase` | `...\Policies\System\Kerberos\Parameters` | `1` (post-Jan 2026) | KDC (per-DC) | RC4 deprecation phase |
| `DefaultEncryptionType` | `...\Lsa\Kerberos\Parameters` | `0x17` | Client | Default pre-auth etype |
| `LogLevel` | `...\Lsa\Kerberos\Parameters` | `0` | Client/Server | Verbose Kerberos logging |
