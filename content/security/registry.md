---
description: Every registry value that affects Kerberos encryption types on domain controllers and clients, with the path, timing, default by build, and lab evidence for each.
---

# Registry Settings

Every registry value that affects Kerberos encryption behavior on domain controllers
and clients.  These settings interact with each other and with the
`msDS-SupportedEncryptionTypes` AD attribute, so the order in which the KDC consults them
matters more than any single value.

Statements marked "lab" were observed on the builds listed under
[Registry Audit Results - Lab builds](registry-audit.md#lab-builds).  Nothing here has
been lab-verified on a July 2026 or later update; those statements cite Microsoft instead.

---

## Precedence Order

When the KDC selects an etype for a **service ticket**, it works through these in order:

1. **`msDS-SupportedEncryptionTypes`** on the target account.  If it is set and nonzero,
   it is the account's etype set and nothing below replaces it.
2. **`DefaultDomainSupportedEncTypes`** on the DC, used only when the attribute is 0 or
   absent.  If that registry value is also absent, the KDC uses a built-in default that
   depends on the installed update (see the table in the next section).
3. **The account's stored keys.**  The KDC picks the strongest etype in the set that the
   account actually has a key for.
4. **The KDC filter** (`SupportedEncryptionTypes` on the DC).  The KDC will not issue an
   etype the filter excludes.  How the filter combines with steps 1-2 is not a plain
   intersection; see [the filter matrix](#how-the-filter-combines).

The **session key** is chosen separately: it is an etype from the client's list that the
account's effective set and the KDC filter also allow, and where several qualify the lab
results follow the client's order of preference.  If the client's list and the account's
effective set share nothing, the request fails with `KDC_ERR_ETYPE_NOSUPP` (lab,
20348.5020).  The pre-April lab build was looser: it still gave an RC4-only client an RC4
session key for an AES-only account.

---

## DefaultDomainSupportedEncTypes

The KDC-side fallback.  It supplies the **assumed** encryption types for every account that
does not have an explicit `msDS-SupportedEncryptionTypes` value.

| Property | Value |
|---|---|
| **Path** | `HKLM\SYSTEM\CurrentControlSet\Services\Kdc` (key names are case-insensitive; Microsoft writes `services\KDC`) |
| **Value name** | `DefaultDomainSupportedEncTypes` |
| **Type** | `REG_DWORD` |
| **Default** | The value is not present.  What the KDC assumes instead depends on the installed update - see below. |
| **Recommended** | `0x18` (24) = AES128 + AES256 |
| **Takes effect** | Immediately, on the next TGS-REQ (lab) |
| **Scope** | Per DC.  Not replicated, and not written by any Group Policy setting. |

!!! warning "The path has no `Parameters` subkey"
    A value written under the `Lsa` path or under the `Policies` path is silently ignored
    (lab).  A `...\Services\Kdc\Parameters` subkey is not the documented location either; the
    lab tested that subkey only for `RC4DefaultDisablementPhase`, which was ignored there.
    If a DDSET change has no effect, check the path first.

### Default by build

--8<-- "includes/ddset-default-by-build.md"

The pre-April default on Server 2025 is often quoted as `0x24` (RC4 + AES-SK, because DES
was removed).  This site has **not lab-verified** that value and found no Microsoft source
for it; Microsoft's registry reference now lists the default as `0x18` for all versions.

### How It Works

When the KDC processes a TGS-REQ and the target account has `msDS-SupportedEncryptionTypes = 0`
(or not set), the KDC substitutes this registry value.  The etype selection then proceeds as
if the account had this value in its AD attribute.  An account with any nonzero attribute is
unaffected: in the lab an AES-only account stayed AES256 with DDSET set to RC4, and an
RC4-only account stayed RC4 with DDSET set to AES.

An explicit value also takes precedence over the April 2026 enforcement default.  On the
enforcing build, DDSET = `0x04` gave unset accounts RC4 tickets again (lab, June 2026), and
Microsoft's KB5073381 says explicitly configured values continue to be honored.  A DC with
RC4 in this value logs Kdcsvc event 205 each time the KDC starts.

### Common Values

--8<-- "includes/etype-values.md"

For this registry value, use `0x18`.  Microsoft's KB5021131 suggests `0x38` for AES-only
domains and `0x3C` as a transitional value; the lab saw no difference between `0x18` and
`0x38`.  If a legacy service must keep receiving RC4 tickets, Microsoft's guidance
(KB5073381) is to put `0x24` on **that account's** `msDS-SupportedEncryptionTypes`, and to
use DDSET = `0x24` only as a last resort because it applies to every unset account.

### Setting It

```powershell title="Set DefaultDomainSupportedEncTypes to AES-only and verify"
# Set to AES-only (recommended)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
    -Name "DefaultDomainSupportedEncTypes" `
    -Value 24 -PropertyType DWord -Force

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
    -Name "DefaultDomainSupportedEncTypes"
```

!!! warning "Set this on ALL domain controllers"
    This registry value is per-DC, not replicated through AD.  If one DC has `0x18` and
    another has a value that includes RC4, clients get different ticket etypes depending on
    which DC they reach.  Use Group Policy Preferences to push the value consistently.

---

## KdcUseRequestedEtypesForTickets

Controls whether the KDC honors the client's etype preference list when selecting the
**ticket** etype.

| Property | Value |
|---|---|
| **Path** | `HKLM\SYSTEM\CurrentControlSet\Services\Kdc` |
| **Value name** | `KdcUseRequestedEtypesForTickets` |
| **Type** | `REG_DWORD` |
| **Default** | Not present (equivalent to `0`) |
| **Takes effect** | Immediately (lab, June 2026) |

| Value | Behavior |
|---|---|
| `0` or not set | The KDC ignores the client's order and picks the **strongest** etype in the target account's effective set. |
| `1` | The KDC picks the ticket etype from the **client's** preference list.  How far that reaches depends on the build - see below. |

!!! danger "KdcUseRequestedEtypesForTickets=1 lets a client choose RC4"
    With the value at `1`, a client that asks for RC4 first gets an RC4 **ticket** for any
    account whose effective set still contains RC4, which makes those accounts trivially
    Kerberoastable.

    The reach is **build-dependent**:

    | Build | Account at `msDS-SET = 28` (RC4 + AES) | Account at `msDS-SET = 24` (AES-only) | Unset account |
    |---|---|---|---|
    | Pre-enforcement (the 6-7 April 2026 tests) | RC4 | **RC4** - the account's own setting was bypassed | not tested |
    | Enforcing (20348.5020, June 2026) | RC4 | AES256 | AES256 |

    On the enforcing build the override only reaches accounts that actually list RC4.

    **Never set this to `1` in production.**  If the value exists, remove it.

Only the TGS exchange was tested.  Whether the value changes the **TGT** etype in the AS
exchange is not lab-verified.  Kdcsvc event 206 appeared during the early tests because the
client advertised only RC4 against an AES-only account, which is what 206 reports; it is not
an indicator that this override is set.

### When to Use It

**Never.**  Leave it absent.  Any debugging need can be met with a packet capture or
Event 4769 instead.

---

## SupportedEncryptionTypes (GPO / KDC Filter)

One value name with two jobs, depending on the machine:

- **On any Windows machine** it is the list of etypes the machine's own Kerberos client may
  use and advertise (Microsoft's policy documentation; a change needs a new logon session).
  The machine also copies the cipher bits into its computer account's
  `msDS-SupportedEncryptionTypes`.
- **On a domain controller** it is additionally the **KDC filter**: the KDC will not issue,
  or accept pre-authentication with, an etype the value excludes (lab).

| Property | Value |
|---|---|
| **Value name** | `SupportedEncryptionTypes` |
| **Type** | `REG_DWORD` |
| **Default** | Not present (no filter; the client advertises its built-in list) |
| **Policies path** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` - written by the GPO *Network security: Configure encryption types allowed for Kerberos* |
| **Lsa path** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` - manual or Group Policy Preferences |
| **Takes effect (KDC filter)** | Only when the KDC service starts.  Adding, changing or removing the value does nothing until `Restart-Service kdc`. |

### Which path the KDC reads

Tested by writing an RC4-only value straight to the registry and requesting a ticket for an
AES-only account; `KDC_ERR_ETYPE_NOSUPP` means the filter was honored.

| Filter path | Server 2022 (20348.5020) | Server 2025 (26100.32522, March 2026 update) |
|---|---|---|
| `...\Policies\System\Kerberos\Parameters` | honored (it won when both paths were set, tested on the 6-7 April 2026 build only) | **ignored** |
| `...\Lsa\Kerberos\Parameters` | honored | honored |

!!! warning "Server 2025: the result above is from one pre-April build"
    On the Server 2025 build tested, a real *Configure encryption types* GPO wrote its value
    to the Policies path as usual, and the KDC did not filter on it; only a value at the Lsa
    path filtered.  That is the opposite of the often-repeated, unsourced claim that
    "Server 2025 drops the Lsa path".

    The build tested was the March 2026 update.  Microsoft's April 2026 update for Server
    2025 (KB5082063, build 26100.32690) lists a fix under which "Windows reads the
    configured policy settings as expected" for Kerberos encryption policies.  This site has
    **not retested** on that or any later build, so treat the Policies-path result as
    possibly fixed.  Whatever the build, verify per DC: apply the filter, restart the KDC,
    and request a ticket for a throwaway account set to an excluded etype.  It must fail.

### How the filter combines { #how-the-filter-combines }

--8<-- "includes/kdc-filter-matrix.md"

The service-ticket field in Event 4769 that shows the account's supported etypes
(`MSDS-SupportedEncryptionTypes` in the message text, `ServiceSupportedEncryptionTypes` in
the XML) is a **processed** value, not the raw AD attribute.  For an unset account it showed
the substituted value: `0x27` on the pre-April build, `0x18` on the enforcing build, and
`0x18` on the pre-April build when an AES-only filter was active.  When a request is
refused the field is empty and `TicketEncryptionType` is `0xFFFFFFFF`.

### Common filter values

| Decimal | Hex | Meaning |
|---|---|---|
| 24 | `0x18` | AES128 + AES256 only |
| 28 | `0x1C` | RC4 + AES128 + AES256 |
| 2147483640 | `0x7FFFFFF8` | AES128 + AES256 + "Future encryption types" (what the GPO writes when those three boxes are ticked) |

!!! tip "Client-side vs. server-side"
    Setting `SupportedEncryptionTypes` on a **client** only changes what that client offers.
    It does not change which etype the KDC uses for a service's ticket.  That is decided by
    the **target account** (`msDS-SupportedEncryptionTypes`), the DC's
    `DefaultDomainSupportedEncTypes`, and the DC's own filter.

---

## Timing: When Changes Take Effect

Not all registry changes take effect at the same time.  Failing to account for this is a
common source of "I changed the value but nothing happened."

| Registry Value | Timing | Evidence |
|---|---|---|
| `DefaultDomainSupportedEncTypes` | **Immediate** - the next TGS-REQ. | Lab: setting DDSET = 24 changed the ticket from RC4 to AES256 within seconds; removing it reverted immediately. |
| `KdcUseRequestedEtypesForTickets` | **Immediate**. | Lab: an RC4 + AES account flipped to RC4 as soon as the value was set. |
| `SupportedEncryptionTypes` (Policies path) | **KDC restart required**. | Lab: no effect until `Restart-Service kdc`; removing the value also had no effect until the next restart.  The filter applies to AS pre-authentication as well as TGS. |
| `SupportedEncryptionTypes` (Lsa path) | **KDC restart required**. | Lab: identical to the Policies path. |
| `RC4DefaultDisablementPhase` | **KDC restart required** (lab; Microsoft's KB5073381 says the same). | Lab: Phase = 2 did not change the ticket etype until the KDC restarted. |

!!! tip "DDSET for quick changes, the filter for persistent policy"
    `DefaultDomainSupportedEncTypes` changes are immediate, which makes it the right tool
    for testing and emergency remediation.  The `SupportedEncryptionTypes` filter needs a
    KDC restart on every DC but is delivered centrally.

---

## RC4DefaultDisablementPhase

A temporary value from the CVE-2026-20833 rollout that selected the KDC's behavior for
unset accounts during the audit and rollback period.  It is documented here for
reference and for cleaning up leftovers.

| Property | Value |
|---|---|
| **Path** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` |
| **Value name** | `RC4DefaultDisablementPhase` |
| **Type** | `REG_DWORD` |
| **Default** | Not present |
| **Takes effect** | KDC restart |

--8<-- "includes/phase-values.md"

Three things about this value are easy to get wrong:

- **It is normally absent.**  The updates changed what an absent value *means*; they never
  wrote a number.  You cannot read a DC's enforcement state from this value.  Check the
  build number, or request a ticket for an unset account.
- **It only ever applied to unset accounts** (`msDS-SupportedEncryptionTypes` blank or 0)
  on DCs with no explicit `DefaultDomainSupportedEncTypes`.  Accounts with an explicit
  value behaved identically at every phase (lab, 20348.5020).
- **It is no longer a control.**  Per Microsoft's published timeline (KB5073381, last
  revised 14 April 2026), Windows updates released in or after July 2026 remove support
  for this value: it is no longer read.  This site has not lab-verified a July-or-later
  build.  A value left behind from the rollback window should be deleted so that audits
  do not mistake it for a live setting.

--8<-- "includes/rc4-timeline.md"

??? note "Historical: the April-July 2026 rollback window"
    On a DC with an April, May or June 2026 update, setting the value to `0` or `1` and
    restarting the KDC returned unset accounts to the old `0x27` default (lab, 20348.5020).

    ```powershell title="Historical rollback (April-June 2026 updates only)"
    Set-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "RC4DefaultDisablementPhase" -Value 1 -Type DWord
    Restart-Service kdc
    ```

    On a current build, use an explicit per-account `msDS-SupportedEncryptionTypes` (or, as a
    last resort, an explicit `DefaultDomainSupportedEncTypes`) instead.

    Check the DC's build before removing a leftover value.  On a DC still on a
    January-March 2026 update, a `2` is what turns enforcement on: deleting it returns unset
    accounts to the `0x27` default at the next KDC restart.  On a DC that has only an
    April-June 2026 update, a `0` or `1` is still the rollback switch: deleting it turns
    enforcement on at the next KDC restart.  From the July 2026 update (Server 2022 build
    20348.5386, Server 2025 build 26100.33158, or higher) Microsoft's KB5073381 timeline
    says the value is no longer read (not lab-verified), so removing it should change
    nothing.  To remove it:

    ```powershell title="Remove a leftover RC4DefaultDisablementPhase value"
    Remove-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
        -Name "RC4DefaultDisablementPhase" -ErrorAction SilentlyContinue
    ```

---

## DefaultEncryptionType

A client-side value that sets the default encryption type for **pre-authentication**.  It is
not a KDC control.

| Property | Value |
|---|---|
| **Path** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` |
| **Value name** | `DefaultEncryptionType` |
| **Type** | `REG_DWORD` |
| **Default** | 18 (AES256).  Other values: 17 (AES128), 23 (RC4-HMAC). |

Source: Microsoft's [Kerberos registry reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-protocol-registry-kdc-configuration-keys),
which also says the value is no longer applicable from Server 2025 and Windows 11 24H2.
In the lab (Server 2022, 6-7 April 2026) the values 4, 18 and 24 at each of the three paths
changed nothing in KDC ticket issuance.  Of those only 18 is a value Microsoft documents,
and it is the default, so that test does not show what 17 or 23 would do.  Its client-side
effect on pre-authentication was not tested.  Leave it absent.

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
    Verbose Kerberos logging generates a high volume of events, including retries that
    later succeed, and can affect performance on busy systems.  Enable it only for the
    duration of a troubleshooting session.

### Other client-side values

These live under the same `Lsa\Kerberos\Parameters` key and are not etype controls, but they
come up in the same troubleshooting sessions.  Defaults are from Microsoft's
[Kerberos registry reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-protocol-registry-kdc-configuration-keys);
none were lab-tested here.

| Value | Default | Purpose |
|---|---|---|
| `MaxTokenSize` | 48000 (Windows 8 / Server 2012 and later) | Maximum Kerberos token size; relevant when users are in many groups |
| `MaxPacketSize` | 0 on Vista and later, so the Windows client always uses TCP | UDP size threshold |
| `FarKdcTimeout` | 10 minutes | How long a DC from another site stays in the client's DC cache |

`ksetup /getenctypeattr <domainname>` retrieves, and `ksetup /setenctypeattr <domainname>`
followed by one or more etype names sets, what Microsoft's `ksetup` reference calls "the
encryption type attribute for the domain".

---

## Commonly Confused Keys

These values have similar names but different purposes, paths, and timing.  Mixing them up
is the most common cause of "I set AES-only but nothing changed."

| Value | Path | Scope | Set by | Purpose | Timing |
|---|---|---|---|---|---|
| `SupportedEncryptionTypes` | `...\Policies\System\Kerberos\Parameters` | Any machine | Group Policy | The machine's allowed etypes.  On a DC, also the KDC filter (see the Server 2025 caveat above). | KDC restart |
| `SupportedEncryptionTypes` | `...\Lsa\Kerberos\Parameters` | Any machine | Manual / GPP | Same filter.  On the Server 2022 build tested with both set (6-7 April 2026), the Policies path won. | KDC restart |
| `DefaultDomainSupportedEncTypes` | `...\Services\Kdc` | DC only | Manual / GPP | The **assumed** etypes for accounts with no `msDS-SupportedEncryptionTypes`.  No GPO setting writes it. | Immediate |

For the value/path combinations that do nothing, see
[Registry Audit Results - Non-Functional Registry Paths](registry-audit.md#non-functional-registry-paths).

!!! warning "GPO does not set `DefaultDomainSupportedEncTypes`"
    Applying the *Configure encryption types allowed for Kerberos* GPO to domain controllers
    writes `SupportedEncryptionTypes`.  That restricts what the KDC will **issue** (after a
    KDC restart).  It does not change what the KDC **assumes** for unset accounts.

    **Example** (lab): an AES-only filter is active, an account is unset, and the assumed set
    for unset accounts includes RC4 (an old build, or an explicit DDSET with RC4).  The KDC
    issues an **AES** ticket; nothing fails, provided the account has AES keys.  The two
    settings still disagree on paper, so set `DefaultDomainSupportedEncTypes = 0x18` as well
    to keep Event 4769 and audits readable.

---

## Quick Reference Table

| Value | Path | When absent | Scope | Timing | Purpose |
|---|---|---|---|---|---|
| `DefaultDomainSupportedEncTypes` | `...\Services\Kdc` | `0x18` on the April 2026 update or later; `0x27` before (lab: Server 2022 only) | KDC (per DC) | Immediate | Assumed etypes for accounts with an empty `msDS-SET` |
| `KdcUseRequestedEtypesForTickets` | `...\Services\Kdc` | `0` | KDC (per DC) | Immediate | Whether the client's preference picks the ticket etype (**never set to 1**) |
| `SupportedEncryptionTypes` | `...\Policies\...\Kerberos\Parameters` | No filter | Any machine | KDC restart | Machine's etype list (written by GPO).  On a DC, the KDC filter. |
| `SupportedEncryptionTypes` | `...\Lsa\Kerberos\Parameters` | No filter | Any machine | KDC restart | Same filter; the only path honored on the Server 2025 build tested. |
| `RC4DefaultDisablementPhase` | `...\Policies\...\Kerberos\Parameters` | Behavior set by the installed update | KDC (per DC) | KDC restart | Historical audit / rollback switch; per Microsoft, not read from the July 2026 update on |
| `DefaultEncryptionType` | `...\Lsa\Kerberos\Parameters` | 18 (AES256) | Client | - | Default pre-auth etype (Microsoft); the values tried in the lab did not change KDC ticket issuance |
| `LogLevel` | `...\Lsa\Kerberos\Parameters` | `0` | Client / server | - | Verbose Kerberos logging |
