# Full Etype Matrix Lab Results

Lab date: 2026-04-14. DC: Server 2022 Build 20348 UBR 5020 (KB5078763).
Domain: evil.corp, DFL Windows2016Domain. Tool: kw-roast with explicit `-e rc4` and `-e aes256`.

## Test accounts

| Account | msDS-SupportedEncryptionTypes | SPN |
|---------|-------------------------------|-----|
| svc_apr_01 | blank (no attribute) | HTTP/svc-apr-01.evil.corp |
| svc_apr_02 | 0 (explicit integer) | HTTP/svc-apr-02.evil.corp |
| svc_apr_03 | 4 (RC4 only) | HTTP/svc-apr-03.evil.corp |
| svc_apr_04 | 24 (AES only) | HTTP/svc-apr-04.evil.corp |
| svc_apr_05 | 28 (RC4+AES) | HTTP/svc-apr-05.evil.corp |

All accounts have both RC4 and AES keys in ntds.dit (passwords set post DFL 2008).

## What ALLOWED and BLOCKED mean here

- **ALLOWED** = kw-roast received a ticket of the requested type and extracted a hash
- **BLOCKED** = kw-roast received no ticket (KDC denied the request or etype mismatch)
- **ERROR(1)** = kw-roast failed before reaching the KDC (pre-auth blocked; see Pol=24 note)

This tests whether a specific etype is *allowed or denied* by the KDC, not which etype the KDC *selects* when the client doesn't specify one. For etype selection behavior (DDSET/getST.py), see `april-2026-findings.md`.

---

## Matrix 1: Phase × DDSET × msDS-SET (Pol=0x7fffffff, allow-all)

### Phase=absent (no key — enforcement active by default after KB5078763)

| msDS-SET | DDSET=absent | DDSET=4 | DDSET=24 | DDSET=28 |
|----------|-------------|---------|---------|---------|
| blank | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED |
| 0 | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED |
| 4 | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** |
| 24 | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED | RC4=**BLOCKED** AES=ALLOWED |
| 28 | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED |

**Finding:** DDSET has **zero effect** on allow/block under enforcement. The entire row is identical for all four DDSET values. RC4 is blocked for blank, 0, and 24. RC4 is allowed only for 4 and 28 (explicit msDS-SET includes RC4 bit).

### Phase=2 (explicitly set — identical to Phase=absent)

Identical to Phase=absent across all 20 combinations. Phase=2 and Phase=absent are operationally equivalent after KB5078763.

### Phase=0 (full rollback)

| msDS-SET | DDSET=absent | DDSET=4 | DDSET=24 | DDSET=28 |
|----------|-------------|---------|---------|---------|
| blank | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED |
| 0 | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED |
| 4 | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** |
| 24 | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED |
| 28 | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED | RC4=ALLOWED AES=ALLOWED |

**Finding:** Phase=0 allows RC4 for **all** accounts including explicitly AES-only (msDS=24). DDSET again has no effect. The only restriction that survives Phase=0 is the AES-blocked state for msDS=4 — because those accounts are declared RC4-only, the KDC will not issue an AES ticket for them regardless of phase.

!!! danger "Phase=0 wider than expected"
    Setting `RC4DefaultDisablementPhase = 0` as an emergency rollback re-enables RC4 not
    just for blank/0 accounts but also for accounts with `msDS-SET = 24` (explicit
    AES-only).  This is a broader regression than most administrators expect.  Consider
    Phase=1 (audit) instead, which has the same behavior but at least logs events.

### Phase=1 (audit)

Identical to Phase=0 across all 20 combinations. RC4 is allowed for all accounts (including msDS=24), DDSET has no effect. Events 201/202/206/207 are logged per request.

**Finding:** Phase=1 and Phase=0 are operationally identical from a ticket-issuance perspective. The only difference is that Phase=1 logs Kdcsvc warning events.

---

## Matrix 2: Pol\SupportedEncryptionTypes × DDSET × msDS-SET (Phase=absent)

### Pol=0x7fffffff (allow all — baseline GPO value)

Identical to Phase=absent results from Matrix 1. Pol=0x7fff acts as a pass-through.

### Pol=4 (RC4-only hard filter at KDC)

| msDS-SET | DDSET=absent | DDSET=4 | DDSET=24 | DDSET=28 |
|----------|-------------|---------|---------|---------|
| blank | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** |
| 0 | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** |
| 4 | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** |
| 24 | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** | RC4=**BLOCKED** AES=**BLOCKED** |
| 28 | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** | RC4=ALLOWED AES=**BLOCKED** |

**Finding:** Pol=4 blocks AES for **every** account regardless of msDS-SET or DDSET. Enforcement still blocks RC4 for blank/0/24. The result for blank/0 and 24 accounts is **both etypes blocked** — a complete service outage for those accounts. Only accounts with explicit RC4 in their msDS-SET (values 4 and 28) can communicate at all, and only via RC4.

!!! danger "Pol=4 + enforcement = complete outage for unconfigured accounts"
    This combination is catastrophic: AES is blocked by the Pol filter, RC4 is blocked by
    enforcement.  An account with no `msDS-SupportedEncryptionTypes` can issue neither
    ticket type.  Never set the DC Kerberos GPO to RC4-only while enforcement is active.

### Pol=24 (AES-only hard filter at KDC)

All results are ERROR(1) — kw-roast failed to authenticate.

**Finding:** Pol=24 blocks RC4 at the pre-authentication (AS exchange) level. kw-roast uses password authentication, which requires RC4 pre-auth by default. When the DC refuses RC4 pre-auth, kw-roast cannot obtain a TGT and all subsequent tests fail. This confirms the previous finding that Pol\SupportedEncryptionTypes affects the AS exchange, not just TGS.

To test Pol=24 behaviour for individual SPNs, pre-authenticate separately using AES (e.g. with an existing ccache) and then use getST.py.

### Pol=28 (RC4+AES filter)

Identical to Pol=0x7fffffff. Pol=28 passes both RC4 and AES through and is indistinguishable from allow-all for this test set.

---

## Key findings

### 1. Phase=absent == Phase=2

After KB5078763, enforcement is active with no key present. Setting `RC4DefaultDisablementPhase=2` explicitly produces identical results in every combination tested.

### 2. DDSET has no effect on allow/block decisions

`DefaultDomainSupportedEncTypes` values 4, 24, and 28 all produce identical allow/block results as the absent case across every Phase and every msDS-SET combination tested. DDSET affects which etype the KDC *selects* (etype preference ordering), but it does not override enforcement decisions. This has been confirmed across 80 combinations.

### 3. Phase=0 and Phase=1 are operationally identical for ticket issuance

Both allow RC4 for every account including explicitly AES-only (msDS=24). Neither enforces any restriction based on msDS-SET or DDSET. The only account type that can't get AES under Phase=0/1 is explicit RC4-only (msDS=4), because the KDC won't issue an AES ticket for an account declared as RC4-only.

### 4. Phase=0/1 allows RC4 even for explicit msDS=24 (AES-only) accounts

This contradicts the intuition that Phase=0 "only affects unconfigured accounts." Under Phase=0 and Phase=1, accounts with `msDS-SupportedEncryptionTypes=24` (AES-only) accept RC4 service tickets. This is a regression: pre-enforcement behavior (before January 2026) respected the AES-only declaration and blocked RC4 for msDS=24 accounts.

### 5. Pol=4 (RC4-only filter) + enforcement = complete outage for unconfigured accounts

Both etypes are blocked simultaneously. This is the most dangerous misconfiguration possible during an AES migration: blank/0/24 accounts cannot authenticate at all.

### 6. Pol=24 blocks pre-authentication

Setting `SupportedEncryptionTypes=24` at the DC Pol path blocks RC4 AS exchange. Tools that use RC4 pre-auth (including kw-roast) cannot authenticate to the domain at all. This confirms Pol\SET affects both the AS and TGS exchanges.

### 7. The enforcing variable is msDS-SET, not DDSET

Under enforcement, the only thing that determines whether RC4 is allowed is the account's `msDS-SupportedEncryptionTypes`:
- blank or 0 → RC4 blocked
- includes bit 0x4 (values 4, 28) → RC4 allowed
- 24 (AES-only explicit) → RC4 blocked

DDSET and Phase (when 0 or 1) cannot override these outcomes.

---

## Corrections to previous documentation

### "DDSET overrides enforcement" [still wrong, now proven across 80 combinations]

Every DDSET value (absent, 4, 24, 28) produces the same allow/block result under enforcement. The earlier finding and the MS KB5073381 claim that explicit DDSET bypasses enforcement are both contradicted by the full 80-combination matrix.

### "Phase=0 only restores behavior for blank/0 accounts" [wrong]

Phase=0 also restores RC4 for explicitly AES-only (msDS=24) accounts. The rollback is domain-wide and does not respect per-account AES declarations.

### "Phase=1 (audit) is a safe rollback that doesn't change ticket issuance" [wrong]

Phase=1 allows RC4 for all accounts including msDS=24, identical to Phase=0. Audit events are logged but no tickets are blocked. Using Phase=1 as a temporary measure re-enables RC4 more broadly than intended.

---

## What the interaction matrix should look like

For RC4 allow/block decisions (ignore DDSET — it has no effect on this):

| Phase | msDS=blank | msDS=0 | msDS=4 | msDS=24 | msDS=28 |
|-------|-----------|--------|--------|---------|---------|
| absent | BLOCKED | BLOCKED | ALLOWED | BLOCKED | ALLOWED |
| 0 | ALLOWED | ALLOWED | ALLOWED | ALLOWED | ALLOWED |
| 1 | ALLOWED | ALLOWED | ALLOWED | ALLOWED | ALLOWED |
| 2 | BLOCKED | BLOCKED | ALLOWED | BLOCKED | ALLOWED |

For AES256 allow/block (also ignore DDSET):

| Phase | msDS=blank | msDS=0 | msDS=4 | msDS=24 | msDS=28 |
|-------|-----------|--------|--------|---------|---------|
| absent | ALLOWED | ALLOWED | BLOCKED | ALLOWED | ALLOWED |
| 0 | ALLOWED | ALLOWED | BLOCKED | ALLOWED | ALLOWED |
| 1 | ALLOWED | ALLOWED | BLOCKED | ALLOWED | ALLOWED |
| 2 | ALLOWED | ALLOWED | BLOCKED | ALLOWED | ALLOWED |

AES256 allow/block is independent of Phase — it depends only on the account's msDS-SET and the Pol\SupportedEncryptionTypes filter.
