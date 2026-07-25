---
status: new
---

# Registry Audit Results

Lab-validated registry reference for Kerberos etype behavior on Windows Server 2022.
Every path and value combination was tested in isolation with KDC restarts between tests,
then in combination to map the full interaction model.

**Lab**: DC01 (Server 2022 Build 20348, KB5078763) | DFL 2016 | 80+ tests

**Registry paths tested:**

1. `HKLM\SYSTEM\CurrentControlSet\Services\KDC`
2. `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
3. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`

**Value names tested:**

- `DefaultDomainSupportedEncTypes`
- `DefaultEncryptionType`
- `SupportedEncryptionTypes`

Every combination (3 paths × 3 values = 9) was tested.  Only 3 are functional.

---

## Functional Registry Paths

Only **3 of 9** tested value/path combinations affect KDC ticket issuance.  Two additional
functional values (`KdcUseRequestedEtypesForTickets`, `RC4DefaultDisablementPhase`) control
other KDC behaviors.

| # | Full Path | Value Name | Timing | Mechanism |
|---|-----------|-----------|--------|-----------|
| 1 | `HKLM\SYSTEM\CurrentControlSet\Services\KDC` | `DefaultDomainSupportedEncTypes` | **Immediate** | Sets the fallback etype set for accounts with `msDS-SupportedEncryptionTypes = 0`.  The KDC reads this on every TGS-REQ. |
| 2 | `HKLM\SOFTWARE\...\Policies\System\Kerberos\Parameters` | `SupportedEncryptionTypes` | **KDC restart** | Hard filter: the KDC will not issue tickets with etypes absent from this value.  Also controls client etype advertisement and triggers computer account msDS-SET auto-update.  Written by the "Configure encryption types allowed for Kerberos" GPO. |
| 3 | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` | `SupportedEncryptionTypes` | **KDC restart** | Same filter as #2.  Honored on Server 2022; on Server 2025 the KDC reads **this** path and ignores #2 (lab-tested 26100.32522 — the reverse of the older, unsourced "Lsa deprecated in 2025" claim). |
| 4 | `HKLM\SYSTEM\CurrentControlSet\Services\Kdc` | `KdcUseRequestedEtypesForTickets` | Immediate | When set to `1`, KDC honors client etype preference for ticket encryption, overriding the target's `msDS-SupportedEncryptionTypes` (reach is build-dependent: on enforced builds it only downgrades accounts that still list RC4).  **Security risk** -- never set to `1`. |
| 5 | `HKLM\SOFTWARE\...\Policies\System\Kerberos\Parameters` | `RC4DefaultDisablementPhase` | **KDC restart** | Controls RC4 deprecation phase (0=off, 1=audit, 2=enforce).  Usually unset; on KB5078763+ an absent value behaves as enforce, so the registry alone cannot confirm enforcement -- check the build. |

---

## Non-Functional Registry Paths

The remaining 6 of 9 combinations have **zero effect** on KDC ticket issuance:

| # | Full Path | Value Name | Values Tested | Result |
|---|-----------|-----------|---------------|--------|
| 1 | `HKLM\...\Control\Lsa\Kerberos\Parameters` | `DefaultEncryptionType` | 4, 18, 24 | No change in ticket etype, session key, or msDSSET field |
| 2 | `HKLM\...\Services\KDC` | `DefaultEncryptionType` | 4, 18, 24 | No change |
| 3 | `HKLM\...\Policies\System\Kerberos\Parameters` | `DefaultEncryptionType` | 4, 18, 24 | No change |
| 4 | `HKLM\...\Control\Lsa\Kerberos\Parameters` | `DefaultDomainSupportedEncTypes` | 4, 24, 28 | No change (only works under `Services\KDC`) |
| 5 | `HKLM\...\Policies\System\Kerberos\Parameters` | `DefaultDomainSupportedEncTypes` | 4, 24, 28 | No change (only works under `Services\KDC`) |
| 6 | `HKLM\...\Services\KDC` | `SupportedEncryptionTypes` | 4, 24, 28 | No change (only works under Pol and Lsa paths) |

!!! tip "Common mistake: wrong path"
    `DefaultDomainSupportedEncTypes` is frequently set at the wrong registry path (Policies
    or Lsa instead of Services\KDC).  If your DDSET change has no effect, verify the path
    is `HKLM\SYSTEM\CurrentControlSet\Services\KDC`.

---

## Two-Mechanism Model

The KDC uses two independent systems for etype selection.  Understanding this separation
is essential for troubleshooting mismatches between Event 4769 fields and actual ticket
etypes.

### Mechanism 1: Etype Computation (DDSET / msDS-SET)

Determines what etypes the KDC **considers** for the account:

1. If the target account has `msDS-SupportedEncryptionTypes != 0`, use that value.
2. Otherwise, if `DefaultDomainSupportedEncTypes` is set, use that value.
3. Otherwise, use the built-in default `0x27` (DES + RC4 + AES-SK) -- or `0x18` (AES-only) on enforced KB5078763+ builds, where an absent `DefaultDomainSupportedEncTypes` resolves to AES-only for unconfigured accounts.

This computed etype set appears in the Event 4769 `msDSSET` field.

**Timing**: `msDS-SupportedEncryptionTypes` changes take effect on the next TGS-REQ.
`DefaultDomainSupportedEncTypes` changes also take effect immediately.

### Mechanism 2: Etype Filter (SupportedEncryptionTypes)

Filters what the KDC will **actually issue**:

1. If `SupportedEncryptionTypes` at the Policies path exists, use it as the filter.
2. Otherwise, if `SupportedEncryptionTypes` at the Lsa path exists, use it.
3. Otherwise, no filter is applied (all etypes allowed).

The filter **overrides** the computed etype set.  If DDSET says RC4 but the filter says
AES-only, the KDC issues AES tickets (not an error).

**Timing**: the KDC reads this value only at service start.  Changes require
`Restart-Service kdc`.

### How They Interact

The interaction is **asymmetric**: the filter can upgrade a fallback to AES, but it cannot downgrade one to RC4. Matrix-tested on the enforced build 20348.5020 (Round 3, 2026-06-26).

| Filter | explicit msDS=RC4 | explicit msDS=AES | msDS=0, DDSET=RC4 | msDS=0, DDSET=AES/enforced |
|---|---|---|---|---|
| AES-only (`0x18`) | NOSUPP | AES256 | **AES256** (upgraded) | AES256 |
| RC4-only (`0x04`) | RC4 | NOSUPP | RC4 | **NOSUPP** (no downgrade) |

For a `msDS-SupportedEncryptionTypes = 0` account, an AES-only filter over an RC4 DDSET issues an AES ticket rather than an error. The reverse does not hold: an RC4-only filter over an AES fallback returns `KDC_ERR_ETYPE_NOSUPP`, it does **not** silently issue an RC4 ticket.

For an account with an **explicit** `msDS-SupportedEncryptionTypes`, the filter never overrides the account. When the account's declared etypes and the filter share no etype, the result is `KDC_ERR_ETYPE_NOSUPP`.

---

## Interaction Matrix

Full 9-combination matrix from Round 2 testing on build 20348.4893 (Pol\SET + Kdc\DDSET, msDS-SET=0 account, KDC restarted after setting values):

| Pol\SET | DDSET=4 (RC4) | DDSET=24 (AES) | DDSET=28 (RC4+AES) |
|---|---|---|---|
| **4 (RC4)** | T=23 S=RC4 | T=23 S=RC4 **(superseded)** | T=23 S=RC4 |
| **24 (AES)** | T=18 S=AES256 | T=18 S=AES256 | T=18 S=AES256 |
| **28 (RC4+AES)** | T=23 S=RC4 | T=18 S=RC4 | T=18 S=RC4 |

!!! warning "One cell is superseded: RC4-only filter over an AES fallback"
    Pol=4 + DDSET=24 was recorded as an RC4 ticket in Round 2 on the pre-enforcement build. Re-tested in Round 3 on the enforced build 20348.5020, that combination returns `KDC_ERR_ETYPE_NOSUPP` — the KDC does **not** downgrade an AES fallback to RC4. The other cells stand: where the filter and the fallback share an etype, the filter still picks it. See [How They Interact](#how-they-interact) for the current model.

**Pattern**: a restrictive filter still determines the outcome regardless of DDSET, but only in the direction the account's available keys allow. Restricting to AES resolves to AES; restricting to RC4 when the fallback is AES fails rather than downgrading. When the filter is permissive (Pol=28), DDSET controls which etype is selected from the allowed set.

---

## Precedence Order

| Priority | Source | Controls |
|---|---|---|
| 1 (highest) | Target account `msDS-SupportedEncryptionTypes` | Etype list (overrides DDSET) |
| 2 | `DefaultDomainSupportedEncTypes` (Services\KDC) | Etype list (when msDS-SET=0) |
| 3 | `SupportedEncryptionTypes` (Policies path) | Etype **filter** (overrides etype list for issuance) |
| 4 | `SupportedEncryptionTypes` (Lsa path) | Etype **filter** (lower precedence than Pol) |
| 5 | Target account's stored keys | Must have key for chosen etype |

!!! warning "Rows 3 and 4 swap on Server 2025"
    The Policies-over-Lsa order holds on Server 2022 (20348), where both paths are honored. On Server 2025 (lab-tested 26100.32522) the KDC reads the **Lsa** path and ignores Policies entirely. Because the "Configure encryption types allowed for Kerberos" GPO writes only the Policies path, a standard Kerberos-encryption GPO does not filter etypes on a Server 2025 DC.

---

## Timing Summary

| Setting | Timing | Evidence |
|---|---|---|
| `msDS-SupportedEncryptionTypes` (AD attribute) | Immediate | AD replication latency only |
| `DefaultDomainSupportedEncTypes` (Services\KDC) | Immediate | Set → test → confirmed within seconds |
| `SupportedEncryptionTypes` (Pol or Lsa) | KDC restart | No effect until `Restart-Service kdc`; removing the value also has no effect until restart |
| `RC4DefaultDisablementPhase` (Pol) | KDC restart | Phase=2 had no effect until restart |
| `KdcUseRequestedEtypesForTickets` (Services\Kdc) | Immediate | Behavior changed on next TGS-REQ |
