---
status: new
---

# RC4 Deprecation (CVE-2026-20833)

This page covers the technical details of how RC4 is selected, what each control does, the enforcement phase behavior, and what you need to be true before enforcement is safe.  For the step-by-step migration commands, see the [AES Standardization Guide](aes-standardization.md).

---

## Why RC4 Is Being Removed

RC4 has been a known liability in Kerberos for over a decade:

- **Kerberoasting**: any authenticated domain user can request a service ticket encrypted with the service account's RC4 key and crack it offline at roughly 800x the speed of AES.  See [Kerberoasting](../attacks/roasting/kerberoasting.md).
- **Key = NTLM hash**: the RC4 Kerberos key is derived identically to the NTLM hash.  Compromising one gives the attacker both.
- **No salt**: RC4 keys are unsalted MD4 hashes.  Rainbow tables work.  AES keys are salted with 4,096 PBKDF2 iterations per account, making precomputation infeasible.
- **Stream cipher weaknesses**: RFC 7465 banned RC4 from TLS in 2015.  RFC 8429 deprecated it for Kerberos in 2018.

Despite all this, RC4 remained the implicit default for any SPN-bearing account without an explicit `msDS-SupportedEncryptionTypes` value until April 2026.

---

## Historical Context

| Date | Change | Reference |
|---|---|---|
| **November 2022** | KDC defaults to AES session keys.  Introduces `AES256-CTS-HMAC-SHA1-96-SK` flag and `DefaultDomainSupportedEncTypes`. | KB5021131 |
| **January 2025** | New fields in Events 4768/4769: `Advertized Etypes`, `Available Keys`, `Session Encryption Type`, `msDS-SupportedEncryptionTypes`. | January 2025 CU |
| **January 2026** | Audit phase begins.  Kdcsvc events 201-209 introduced.  `RC4DefaultDisablementPhase` registry key added. | KB5073381 |
| **April 2026** | Enforcement active by default.  KDC defaults to AES-only (`0x18`) for accounts without explicit `msDS-SupportedEncryptionTypes`. | KB5078763 |
| **July 2026** | `RC4DefaultDisablementPhase` key removed.  Rollback no longer possible. | July 2026 CU |

---

## How the KDC Selects a Service Ticket Encryption Type

Understanding this is the foundation for everything else on this page.

### The decision algorithm

When a client requests a service ticket (TGS-REQ), the KDC selects the ticket encryption type using the target service account's declared encryption types, not the client's requested types.  The sequence:

1. **Check `msDS-SupportedEncryptionTypes`** on the target account.  If non-zero, this is the account's declared set.
2. **If zero or unset**: fall back to `DefaultDomainSupportedEncTypes` on the DC.  If that is also unset, use the internal default (0x27 pre-April 2026, 0x18 post-April 2026).
3. **Apply the `SupportedEncryptionTypes` GPO filter** on the DC.  This is a hard filter — the KDC will not issue a ticket with any etype excluded by this filter, regardless of what the account declares.
4. **Pick the strongest etype** from the resulting set that the KDC supports and the account has keys for.

### The source client does not determine the service ticket etype

The client's etype list (what it advertises in the TGS-REQ) does not control which etype the KDC uses for the service ticket.  The KDC picks the etype from the target account's configuration.  A modern Windows 10/11 client on an AES-only domain will receive an RC4 service ticket for a legacy service account that is configured for RC4 — the client handles RC4 just fine, it simply did not drive the etype selection.

The practical implication: **you do not need to configure the source machine to allow RC4 when adding RC4 exceptions for specific legacy services**.  The only configuration needed is on the DCs (the GPO filter must allow RC4) and on the target service account (its `msDS-SupportedEncryptionTypes` must include the RC4 bit).

!!! example "Mixed-etype scenario"
    A user on a modern workstation logs in and gets an **AES256 TGT** (determined by the user account and the DC, not the target service).  When that user accesses a legacy service whose account has `msDS-SET = 28` (RC4+AES), the KDC issues an **AES256 service ticket** (strongest available etype).  If the legacy service's account has `msDS-SET = 4` (RC4 only), the KDC issues an **RC4 service ticket** — and the modern workstation accepts it without issue.

### The AES session key flag (bit 0x20)

The `msDS-SupportedEncryptionTypes` bitmask includes a special flag at bit 5 (`0x20`, value 32): `AES256-CTS-HMAC-SHA1-96-SK`.  This flag does not add a new ticket etype — it instructs the KDC to use an AES256 session key even when the ticket body is encrypted with RC4.

This was introduced in November 2022 (KB5021131) as a transitional option.  An account with `msDS-SET = 36` (RC4 + AES-SK, value `0x24`) receives an RC4-encrypted ticket body but an AES256 session key.  The session key protects the actual communication between the client and service; encrypting it with AES reduces one of RC4's attack surfaces without requiring the service to support full AES ticket decryption.

The flag is included in the internal default `0x27` (which equals `0x7` | `0x20`).  Setting `DefaultDomainSupportedEncTypes = 0x27` is equivalent to RC4+DES+AES-SK — it enables the session key upgrade for unconfigured accounts without changing the ticket etype.

### TGT encryption type

The TGT encryption type is always determined by the `krbtgt` account's stored keys, not by `msDS-SupportedEncryptionTypes` on `krbtgt`.  The KDC reads `krbtgt`'s keys directly from `ntds.dit`.  On any domain at functional level 2008 or higher, `krbtgt` has AES256 keys, so TGTs are always AES256 regardless of any registry setting or AD attribute.

**Leave `msDS-SupportedEncryptionTypes` on the `krbtgt` account at 0 (unset).**  The KDC ignores this attribute for `krbtgt` and reads the stored keys directly.  Setting it has no effect and may cause confusion.

---

## The Four Controls

These are the levers that determine Kerberos encryption types.  They interact and have different precedence.  The [AES Standardization Guide](aes-standardization.md#what-affects-encryption) covers what to set these to; this section explains what each one actually does.

### `msDS-SupportedEncryptionTypes` (AD attribute, per account)

The per-account declaration of which etypes the account supports.  The KDC reads this when issuing service tickets for the account.

| Value | Meaning |
|---|---|
| blank / 0 | Not configured — KDC falls back to DDSET or enforcement default |
| 4 (`0x04`) | RC4 only |
| 24 (`0x18`) | AES128 + AES256 (recommended) |
| 28 (`0x1C`) | RC4 + AES128 + AES256 |
| 36 (`0x24`) | RC4 + AES session key upgrade |

Computer accounts: auto-updated by the Kerberos GPO when `gpupdate` runs.
User accounts, gMSA, MSA: must be set manually via PowerShell or ADUC.
`krbtgt`: leave at 0 — the KDC ignores this attribute for `krbtgt`.

### `DefaultDomainSupportedEncTypes` (registry, per DC)

Path: `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\Parameters`, value name `DefaultDomainSupportedEncTypes`, REG_DWORD.

The KDC-side fallback etype set.  Used when a target account's `msDS-SupportedEncryptionTypes` is blank or zero.  Takes effect immediately — no KDC restart.  Not replicated; must be set on every DC individually.

Lab testing (KB5078763, 2026-04-14) confirmed that under enforcement (Phase=absent or Phase=2), DDSET values that include RC4 do not re-enable RC4 for unconfigured accounts.  DDSET affects etype *selection* when multiple etypes are available, but the enforcement decision to block RC4 takes precedence over DDSET.

### `RC4DefaultDisablementPhase` (registry, per DC)

Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`, value name `RC4DefaultDisablementPhase`, REG_DWORD.  **Requires KDC restart.**

| Value | Behavior |
|---|---|
| absent | Same as 2.  After KB5078763, enforcement is active with no key present. |
| 0 | Full rollback — RC4 allowed for all accounts.  See phase matrix below. |
| 1 | Audit — RC4 allowed for all accounts.  Kdcsvc warning events logged per request. |
| 2 | Enforcement — RC4 blocked for accounts with blank/0 `msDS-SupportedEncryptionTypes`. |

Valid until July 2026.  The July 2026 update removes this key; rollback is no longer possible after that.

### `SupportedEncryptionTypes` GPO (per DC / per machine)

Group Policy: *Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Configure encryption types allowed for Kerberos.*

This writes `SupportedEncryptionTypes` to the registry at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`.  **Requires KDC restart** to take effect on DCs.

On a **domain controller**: acts as a hard KDC filter.  The KDC will not issue a ticket with any etype not in this value, regardless of what the account's `msDS-SupportedEncryptionTypes` or DDSET says.  Also controls what etypes the KDC accepts for pre-authentication.

On a **workstation or member server**: controls what etypes the client advertises.  Also auto-updates the computer account's `msDS-SupportedEncryptionTypes` in AD.

---

## Phase Behavior: What the Registry Setting Actually Does

Lab-verified results from a full 160-combination matrix test on KB5078763 (Build 20348 UBR 5020), testing all Phase × DDSET × msDS-SET combinations.

### Allow/block matrix for RC4 service tickets

DDSET had zero effect on allow/block outcomes across all 80 combinations where it was varied.  The results below are invariant across DDSET values.

| Phase | msDS=blank | msDS=0 | msDS=4 | msDS=24 | msDS=28 |
|---|---|---|---|---|---|
| **absent** | BLOCKED | BLOCKED | allowed | BLOCKED | allowed |
| **0** | allowed | allowed | allowed | **allowed** | allowed |
| **1** | allowed | allowed | allowed | **allowed** | allowed |
| **2** | BLOCKED | BLOCKED | allowed | BLOCKED | allowed |

Phase=absent and Phase=2 are operationally identical.  Phase=0 and Phase=1 are operationally identical.

### Critical finding: Phase=0 and Phase=1 allow RC4 even for explicit AES-only accounts

Accounts with `msDS-SupportedEncryptionTypes = 24` (AES-only, explicit) receive RC4 service tickets under Phase=0 and Phase=1.  This is broader than most administrators expect from a rollback operation — it does not only affect unconfigured (blank/0) accounts.

!!! danger "Phase=0/1 rollback re-enables RC4 for ALL accounts"
    Setting `RC4DefaultDisablementPhase = 0` or `= 1` re-enables RC4 for every account in
    the domain, including accounts explicitly configured as AES-only.  The only exception
    is accounts with `msDS-SET = 4` (RC4-only), which block AES regardless of phase.
    Use this rollback only as a temporary emergency measure and document the scope.

### DDSET does not override enforcement

Lab testing across DDSET values 4, 24, and 28 all produce identical allow/block results as DDSET=absent under enforcement.  Event 203 still fires and reports `DefaultDomainSupportedEncTypes: 0x18` regardless of the registry value.  The enforcement mechanism substitutes its own effective DDSET internally.

!!! note "Discrepancy with KB5073381"
    Microsoft's KB5073381 states that domains with an explicitly defined
    `DefaultDomainSupportedEncTypes` are "not functionally impacted" by enforcement, and
    that Event 205 (not an error) would be the only consequence.  Lab testing of KB5078763
    contradicts this — DDSET with RC4 is overridden by enforcement.  The discrepancy may
    reflect a behavioral difference between the intended design (documented in KB5073381)
    and the April 2026 implementation (KB5078763).

---

## Requirements Before Disabling RC4

These conditions must be true before enforcement is safe.  If any are not met, accounts will fail to authenticate after the April 2026 update is installed (or after setting Phase=2 manually).

### `krbtgt` account

`krbtgt` must have AES keys.  This is true on any domain that has been at functional level 2008 or higher and has had `krbtgt`'s password rotated at least once since the DFL upgrade.  Verify:

```powershell title="Verify krbtgt has AES keys"
Get-ADUser krbtgt -Properties PasswordLastSet |
  Select-Object PasswordLastSet
# Check that this date is after the domain reached DFL 2008.
# For definitive key verification, use DSInternals:
Get-ADReplAccount -SamAccountName krbtgt -Server dc01.corp.local |
  Select-Object -ExpandProperty Credentials | Select-Object Etype
```

If `krbtgt` lacks AES keys, rotate the password **twice** before proceeding.  See [Algorithms & Keys](algorithms.md#krbtgt-special-considerations).

### All SPN-bearing user service accounts

Every user account with a service principal name must have:

1. AES keys in `ntds.dit` (password reset after DFL 2008)
2. `msDS-SupportedEncryptionTypes` set to a value that includes AES (24 or 28 recommended)

Accounts that have AES keys but `msDS-SET = 0` (blank) will be treated as AES-only after enforcement — this is the correct behavior.  Accounts that have `msDS-SET = 4` (RC4-only) will continue getting RC4 tickets regardless of enforcement.

### All computer accounts

Computer accounts auto-update their `msDS-SupportedEncryptionTypes` via the Kerberos GPO.  Before enforcing:

- Deploy the AES Kerberos GPO to all workstation and server OUs.
- Verify every online machine has applied it (check `msDS-SupportedEncryptionTypes` is non-zero).
- Investigate any computer account still at 0 — it may be offline, in the wrong OU, or a non-Windows device.

### Non-Windows services with keytabs

Any non-Windows service (Apache Kerberos, Java services, Linux with `krb5.conf`) using a keytab must have AES keys in the keytab.  Generate new keytabs after resetting the service account password:

```bash title="Generate an AES-only keytab"
ktpass -out service.keytab \
  -princ HTTP/web.corp.local@CORP.LOCAL \
  -mapUser corp\svc_web -mapOp set \
  -pass <password> \
  -ptype KRB5_NT_PRINCIPAL \
  -crypto AES256-SHA1
```

### Regular user accounts (for AES-only DC GPO)

If you intend to apply an AES-only GPO to domain controllers (blocking RC4 at the KDC level), regular user accounts must also have AES keys, because the DC uses RC4 for the AS-REP encrypted portion of the TGT when the user's only key is RC4.  Without AES keys, those users cannot log in.

If some regular user accounts still lack AES keys, use [Path 2](aes-standardization.md#path-2-aes-opportunistic-with-rc4-fallback) (AES opportunistic with RC4 fallback), which keeps RC4 in the DC GPO for AS exchange while forcing AES for all service tickets.

---

## Timeline

| Phase | Date | What Happens |
|---|---|---|
| **Audit** | January 13, 2026 | Kdcsvc events 201-209 introduced.  `RC4DefaultDisablementPhase` registry key added.  RC4 still works.  Default behavior unchanged. |
| **Enforcement with rollback** | April 14, 2026 | KB5078763.  KDC defaults to AES-only for unconfigured accounts.  Rollback available via `RC4DefaultDisablementPhase`. |
| **Final enforcement** | July 2026 | `RC4DefaultDisablementPhase` key removed.  No rollback.  RC4 only available via explicit per-account `msDS-SupportedEncryptionTypes`. |

---

## Kdcsvc Event Reference

Logged in the **System** event log on domain controllers, source **Kdcsvc**.  Events fire per-request (201-204, 206-209) or per KDC start (205).

| Event | Phase | Trigger | Type | Result |
|---|---|---|---|---|
| **201** | 1 (audit) | Client RC4-only, service has no msDS-SET, no DDSET | Warning | RC4 ticket issued; event logged |
| **202** | 1 (audit) | Service lacks AES keys, no msDS-SET, no DDSET | Warning | RC4 ticket issued; event logged |
| **203** | absent/2 | Client RC4-only, service has no msDS-SET | Error | Ticket **blocked** |
| **204** | absent/2 | Service lacks AES keys, no msDS-SET | Error | Ticket **blocked** |
| **205** | any | DC has DDSET configured to include insecure ciphers | Warning (startup) | Never escalates to error |
| **206** | 1 (audit) | Service is AES-only (explicit msDS-SET=24), client RC4-only | Warning | RC4 ticket issued; event logged |
| **207** | 1 (audit) | Service is AES-only, account lacks AES keys | Warning | RC4 ticket issued; event logged |
| **208** | absent/2 | Service is AES-only (explicit msDS-SET=24), client RC4-only | Error | Ticket **blocked** |
| **209** | absent/2 | Service is AES-only, account lacks AES keys | Error | Ticket **blocked** |

### Events 201/203 vs 205 distinction

Events 201/203 fire when the service account has **no** `msDS-SupportedEncryptionTypes` defined AND the DC has no DDSET defined.  Event 205 fires when the DC **does** have DDSET defined and that value includes RC4.  These are mutually exclusive conditions for a given request.

!!! warning "Lab discrepancy with Events 201/203 conditions"
    KB5073381 states that Events 201/203 require "DC does NOT have DDSET defined."  In lab
    testing (KB5078763), these events fired even when DDSET was explicitly set to 4 or 28.
    Event 203 reported `DefaultDomainSupportedEncTypes: 0x18` regardless of the registry
    value.  Treat the documented conditions as the intent; actual behavior may differ.

### Remediation reference

| Event pair | Root cause | Fix |
|---|---|---|
| 201/203 | Client RC4-only + service no explicit config | Enable AES on client, or set `msDS-SET = 28` on service account |
| 202/204 | Account lacks AES keys + no explicit config | Reset password (twice if pre-DFL 2008) |
| 205 | DDSET includes RC4 | Set DDSET to `0x18` (AES-only) if safe; otherwise document the exception |
| 206/208 | Service is AES-only + client RC4-only | Upgrade client, or temporarily set `msDS-SET = 28` on service |
| 207/209 | Service AES-only + account lacks AES keys | Reset password (twice if pre-DFL 2008) |

---

## Post-July 2026: Keeping RC4 for Specific Services

After July 2026, the `RC4DefaultDisablementPhase` registry key no longer exists.  Enforcement is permanent and covers all accounts with `msDS-SupportedEncryptionTypes` of blank or 0.  The only supported way to issue RC4 service tickets is to explicitly configure the account and the DC.

Both conditions must be met:

1. **The target service account must declare RC4** in `msDS-SupportedEncryptionTypes` (bit 0x4).  The recommended value is `28` (0x1C = RC4 + AES128 + AES256) — this allows RC4 as a fallback while AES remains the preferred etype.
2. **The DC GPO must permit RC4** (`SupportedEncryptionTypes` must include the RC4 checkbox).  The GPO is the hard KDC filter.  If RC4 is not in the filter, the KDC will not issue RC4 tickets regardless of the account's `msDS-SET`.  A KDC restart is required after changing the GPO.

### Scenario A: Legacy service as the target

A legacy application running under a service account that cannot be upgraded to AES.  Modern clients connect to it.

| Component | Action |
|---|---|
| DC GPO | Include RC4 (RC4_HMAC_MD5 checkbox on) — restart KDC |
| Service account | `msDS-SET = 28` (RC4+AES) for user/gMSA/MSA; GPO for computer accounts |
| Client machines | No change needed — the KDC selects the ticket etype from the target account, not from the client |

The client gets an AES TGT (determined by the user and DC) and an RC4 service ticket (determined by the target service account).  The modern client handles RC4 service tickets without any special configuration.

### Scenario B: Legacy device as both source and target

A legacy device connects to services AND other machines connect to it.

| Component | Action |
|---|---|
| DC GPO | Include RC4 — restart KDC |
| Legacy device (computer account) | GPO must include RC4 for the device to authenticate with RC4 pre-auth |
| Legacy device's own service accounts | `msDS-SET = 28` for user accounts hosting SPNs; GPO for the computer account SPN |
| Target services the legacy device connects to | `msDS-SET = 28` if those services also need RC4 |

### GPO model for mixed environments

Most environments end up with three GPOs:

| GPO | Target OU | Etypes | Purpose |
|---|---|---|---|
| DC GPO | Domain Controllers | AES128 + AES256 (+ RC4 if any legacy users or services exist) | Controls KDC hard filter and AS exchange |
| AES-only machines | Workstations/Servers (modern) | AES128 + AES256 | Restricts client etype advertisement; auto-updates computer account msDS-SET |
| AES+RC4 machines | Workstations/Servers (legacy) | RC4 + AES128 + AES256 | Allows RC4 pre-auth for legacy devices; auto-updates computer account msDS-SET |

For any SPN-bearing account that is not a computer account (user service accounts, gMSA, MSA), set `msDS-SupportedEncryptionTypes` directly in AD.  A GPO cannot manage these accounts.

!!! warning "Explicit RC4 re-opens the Kerberoasting attack surface"
    Any user service account with RC4 in its `msDS-SupportedEncryptionTypes` is fully
    vulnerable to Kerberoasting.  Use 30+ character passwords for any account that must
    retain RC4.  Track every exception with the account name, the system requiring RC4,
    the vendor case or upgrade timeline, and a review date.

---

## Frequently Asked Questions

**Is RC4 being removed from Windows entirely?**

No.  DES was removed in Server 2025, but RC4 remains available and can be enabled explicitly.  What is changing is the *implicit default*: RC4 will no longer be assumed for accounts without explicit configuration.

**Will the April 2026 update break my environment immediately on install?**

Yes, if you have SPN-bearing accounts with `msDS-SupportedEncryptionTypes` blank or 0 that depend on RC4.  The enforcement is active as soon as the updated KDC starts.  Run the audit steps in the [AES Standardization Guide](aes-standardization.md) before deploying the April 2026 update, or roll back to Phase=1 (audit) immediately after install if failures occur.

**I set `DefaultDomainSupportedEncTypes = 28` on my DCs.  Does that protect me?**

Per Microsoft's documented intent (KB5073381), an explicit DDSET should not be overridden by enforcement.  In practice, lab testing of KB5078763 showed DDSET with RC4 is still overridden.  Do not rely on DDSET as a substitute for setting `msDS-SupportedEncryptionTypes` on individual accounts.

**Can I roll back after July 2026?**

No.  The `RC4DefaultDisablementPhase` registry key is removed by the July 2026 update.  Enforcement is permanent.  The only remaining way to use RC4 is to set `msDS-SupportedEncryptionTypes` to include the RC4 bit on the specific service account and allow RC4 in the DC GPO.

**Does `DefaultDomainSupportedEncTypes` need to include RC4 for legacy services?**

No.  DDSET is a KDC fallback for accounts with `msDS-SET = 0`.  If you are using per-account `msDS-SET = 28` for legacy services, DDSET is irrelevant for those accounts.  DDSET would only matter for accounts that you deliberately leave unconfigured (blank/0) and want to treat as RC4-capable — which is not recommended.
