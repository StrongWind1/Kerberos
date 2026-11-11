---
description: The lab evidence behind the registry reference - which builds were tested, which registry paths work, and the measured etype matrices for the KDC filter, DDSET and accounts without AES keys.
---

# Registry Audit Results

This is the **evidence page** for [Registry Settings](registry.md).  The rules live there;
this page records what was measured, on which build, so you can judge how far each rule
reaches.  Every path and value combination was tested in isolation with KDC restarts between
tests, then in combination.

To audit your own domain controllers against these findings, use
[`Get-KdcKerberosRegistryAudit.ps1`](https://github.com/StrongWind1/Kerberos/blob/main/scripts/Get-KdcKerberosRegistryAudit.ps1).
It is read-only and reports each value below per DC.

---

## Lab builds { #lab-builds }

--8<-- "includes/lab-builds.md"

---

## What was tested

**Registry paths:**

1. `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`
2. `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
3. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`

**Value names:** `DefaultDomainSupportedEncTypes`, `DefaultEncryptionType`,
`SupportedEncryptionTypes`.

Every combination (3 paths × 3 values = 9) was tested against an unset account
(`msDS-SupportedEncryptionTypes = 0`) on DC1, 6-7 April 2026.  Only 3 change what the KDC
issues.

---

## Functional Registry Paths

Three of the nine combinations affect KDC ticket issuance.  Two further values
(`KdcUseRequestedEtypesForTickets`, `RC4DefaultDisablementPhase`) control other KDC
behavior.  What each one does is described in [Registry Settings](registry.md).

| # | Path | Value name | Timing | Observed |
|---|------|-----------|--------|----------|
| 1 | `...\Services\Kdc` | `DefaultDomainSupportedEncTypes` | **Immediate** | Value 24 changed an unset account's ticket from RC4 to AES256 with no restart. |
| 2 | `...\Policies\System\Kerberos\Parameters` | `SupportedEncryptionTypes` | **KDC restart** | Value 24: no change before restart, AES256 after.  Written by the *Configure encryption types allowed for Kerberos* GPO. |
| 3 | `...\Control\Lsa\Kerberos\Parameters` | `SupportedEncryptionTypes` | **KDC restart** | Same filter as #2.  On the Server 2025 build tested, this was the only path the KDC honored. |
| 4 | `...\Services\Kdc` | `KdcUseRequestedEtypesForTickets` | Immediate | Value 1 let an RC4-first client downgrade an RC4 + AES account to an RC4 ticket. |
| 5 | `...\Policies\System\Kerberos\Parameters` | `RC4DefaultDisablementPhase` | **KDC restart** | On 20348.5020, values 0 and 1 returned unset accounts to RC4; absent and 2 gave AES256. |

---

## Non-Functional Registry Paths

The remaining 6 of 9 combinations had **zero effect** on KDC ticket issuance:

| # | Path | Value name | Values tested | Result |
|---|------|-----------|---------------|--------|
| 1 | `...\Control\Lsa\Kerberos\Parameters` | `DefaultEncryptionType` | 4, 18, 24 | No change in ticket etype, session key, or the Event 4769 supported-etypes field |
| 2 | `...\Services\Kdc` | `DefaultEncryptionType` | 4, 18, 24 | No change |
| 3 | `...\Policies\System\Kerberos\Parameters` | `DefaultEncryptionType` | 4, 18, 24 | No change |
| 4 | `...\Control\Lsa\Kerberos\Parameters` | `DefaultDomainSupportedEncTypes` | 4, 24, 28 | No change (only works under `Services\Kdc`) |
| 5 | `...\Policies\System\Kerberos\Parameters` | `DefaultDomainSupportedEncTypes` | 4, 24, 28 | No change (only works under `Services\Kdc`) |
| 6 | `...\Services\Kdc` | `SupportedEncryptionTypes` | 4, 24, 28 | No change (only works under the Policies and Lsa paths) |

The `DefaultEncryptionType` rows used the values 4, 18 and 24.  Microsoft's registry
reference documents 17, 18 and 23 for this value, with 18 as the default, and describes it as
the client's default pre-authentication etype.  These rows therefore show only that the
values tried changed nothing at the KDC; 17 and 23 were not tried.

Re-checked on 20348.5020 in June 2026: `DefaultDomainSupportedEncTypes` at the Lsa path,
`KdcUseRequestedEtypesForTickets` at the Lsa path, and `SupportedEncryptionTypes` under
`Services\Kdc` were all ignored.  `RC4DefaultDisablementPhase` under `Services\Kdc\Parameters`
was also ignored (April 2026).

!!! tip "Common mistake: wrong path"
    `DefaultDomainSupportedEncTypes` is frequently set at the wrong registry path (Policies,
    Lsa, or a `Parameters` subkey).  If your DDSET change has no effect, verify the path is
    `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`.

---

## Filter × account matrix { #how-they-interact }

--8<-- "includes/kdc-filter-matrix.md"

### Which filter path wins (Server 2022)

Both paths set, no DDSET, unset account, DC1, 6-7 April 2026:

| Policies value | Lsa value | Ticket |
|---|---|---|
| 4 (RC4) | 24 (AES) | RC4 |
| 24 (AES) | 4 (RC4) | AES256 |
| 4 (RC4) | 28 (RC4 + AES) | RC4 |
| 28 (RC4 + AES) | 4 (RC4) | RC4 |

The Policies value decided the outcome every time.  For the Server 2022 versus Server 2025
path comparison, see
[Registry Settings — Which path the KDC reads](registry.md#which-path-the-kdc-reads).

---

## Interaction Matrix (pre-April build)

Filter at the Policies path × DDSET, unset account, KDC restarted after each change.
DC1, 6-7 April 2026, **not enforcing**.  T = ticket etype, S = session key (the test client
listed RC4 first, so RC4 session keys here are a property of the client).

| Policies filter | DDSET = 4 (RC4) | DDSET = 24 (AES) | DDSET = 28 (RC4 + AES) |
|---|---|---|---|
| **4 (RC4)** | T=23 S=RC4 | T=23 S=RC4 **(superseded)** | T=23 S=RC4 |
| **24 (AES)** | T=18 S=AES256 | T=18 S=AES256 | T=18 S=AES256 |
| **28 (RC4 + AES)** | T=23 S=RC4 | T=18 S=RC4 | T=18 S=RC4 |

!!! warning "One cell is superseded: RC4-only filter over an AES fallback"
    Filter = 4 with DDSET = 24 produced an RC4 ticket on this build.  On the enforcing build
    20348.5020 the same combination returns `KDC_ERR_ETYPE_NOSUPP`: the KDC does **not**
    downgrade an AES fallback to RC4.  The other cells stand.

---

## DDSET sweep (enforcing build)

`DefaultDomainSupportedEncTypes` swept against an unset account on 20348.5020, June 2026.
No KDC restart between values.

| DDSET | Result | Note |
|---|---|---|
| `0x18` (AES128 + AES256) | AES256 | Strongest of the set |
| `0x10` (AES256) | AES256 | |
| `0x08` (AES128 only) | `KDC_ERR_ETYPE_NOSUPP` | The test client offered AES256 but not AES128, so no session key etype was shared |
| `0x04` (RC4) | RC4 | An explicit DDSET overrides the enforcement default |
| `0x1C` (RC4 + AES) | AES256 | |
| `0x27` (old default, set explicitly) | RC4 | |
| `0x100` | `KDC_ERR_ETYPE_NOSUPP` | No usable etype bit |

---

## Account without AES keys (enforcing build)

An account whose password was set from an NT hash, leaving only the RC4 key.  20348.5020,
June 2026.

| `msDS-SupportedEncryptionTypes` | Result | Event 4769 |
|---|---|---|
| `0x18` (AES-only) | `KDC_ERR_ETYPE_NOSUPP` | Service keys listed as RC4 only; **no RC4 fallback** |
| `0x1C` (RC4 + AES) | RC4 ticket | The KDC used the only key the account has |
| `0x04` (RC4) | RC4 ticket | |
| 0 (unset; enforcement default applies) | `KDC_ERR_ETYPE_NOSUPP` | No AES key to satisfy the `0x18` default |

On an enforcing DC, an account with no AES keys that is unset or AES-only cannot be issued a
service ticket at all.

---

## UF_USE_DES_KEY_ONLY (enforcing build)

Setting the `UF_USE_DES_KEY_ONLY` account flag on 20348.5020 produced a **DES** service
ticket (Event 4769 ticket etype `0x3`, supported etypes `0x3`).  The notes say the flag
overrode the account's `msDS-SupportedEncryptionTypes`, but they record neither the
attribute's value nor the state of the DC's etype filter during the run (the DC's baseline
filter, `0x7FFFFFFF`, allows DES).  An earlier run on 6-7 April 2026, on an unset account,
recorded a failure for the same flag; the notes do not explain the difference.  This is one
run on one build, not a general rule.  Server 2025, where Microsoft has removed DES, was not
tested.

---

## Timing Summary

| Setting | Timing | Evidence |
|---|---|---|
| `msDS-SupportedEncryptionTypes` (AD attribute) | Immediate | AD replication latency only |
| `DefaultDomainSupportedEncTypes` (`Services\Kdc`) | Immediate | Set, tested, confirmed within seconds |
| `SupportedEncryptionTypes` (Policies or Lsa) | KDC restart | No effect until `Restart-Service kdc`; removing the value also has no effect until restart |
| `RC4DefaultDisablementPhase` (Policies) | KDC restart | Phase = 2 had no effect until restart |
| `KdcUseRequestedEtypesForTickets` (`Services\Kdc`) | Immediate | Behavior changed on the next TGS-REQ |
