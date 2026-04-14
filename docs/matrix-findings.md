# Full Etype Matrix Lab Results (v2)

Lab date: 2026-04-14 (v1), corrected 2026-04-14 (v2).
DC: Server 2022 Build 20348 UBR 5020 (KB5078763). Domain: evil.corp, DFL Windows2016Domain.
Tool: kw-roast. Hash prefix checked to determine the **actual etype returned**, not just whether a hash was obtained.

## Test accounts

| Account | msDS-SupportedEncryptionTypes | SPN |
|---------|-------------------------------|-----|
| svc_apr_01 | blank (no attribute) | HTTP/svc-apr-01.evil.corp |
| svc_apr_02 | 0 (explicit integer) | HTTP/svc-apr-02.evil.corp |
| svc_apr_03 | 4 (RC4 only) | HTTP/svc-apr-03.evil.corp |
| svc_apr_04 | 24 (AES only) | HTTP/svc-apr-04.evil.corp |
| svc_apr_05 | 28 (RC4+AES) | HTTP/svc-apr-05.evil.corp |

All accounts have both RC4 and AES keys in ntds.dit (passwords set post DFL 2008).

## How to read the results

`kw-roast -e rc4` sends an RC4 etype request.  `kw-roast -e aes256` sends an AES256 request.
The DC is not required to honour either — it picks the etype from the account's effective
supported set and ignores the client's preference.  The hash prefix reveals what was actually
issued:

- `RC4` — DC returned `$krb5tgs$23$` (etype 23, RC4)
- `AES256` — DC returned `$krb5tgs$18$` (etype 18, AES256)
- `AES256(!≠req)` — DC returned AES256 when RC4 was requested (or vice versa)
- `BLOCKED` — no hash returned; the DC refused to issue a ticket of any type

!!! important "The DC ignores the requested etype"
    kw-roast only controls what etype is *requested*.  The DC picks the ticket etype from
    the account's effective supported set and returns the **strongest available**, regardless
    of what the client asked for.  A request for RC4 on an AES-only account returns an AES256
    ticket.  A request for AES256 on a blank/0 account under Phase=0/1 returns an RC4 ticket.

---

## Matrix 1: Phase × DDSET (Pol=0x7fffffff, allow-all)

DDSET had zero effect on outcomes across all 80 combinations — every DDSET value (absent, 4, 24, 28) produced identical results for a given Phase × msDS-SET pair.  The tables below show representative results (DDSET=absent); all other DDSET values match exactly.

### Phase=absent and Phase=2 — enforcement (identical results)

| msDS-SET | RC4 requested → actual | AES256 requested → actual |
|---------|----------------------|--------------------------|
| blank | **BLOCKED** | AES256 |
| 0 | **BLOCKED** | AES256 |
| 4 (RC4-only) | RC4 | **BLOCKED** |
| 24 (AES-only) | **BLOCKED** | AES256 |
| 28 (RC4+AES) | AES256 (!≠req) | AES256 |

**blank/0**: RC4 blocked entirely by enforcement.  AES256 works.
**msDS=4**: RC4 only — no AES key or declared support.  AES blocked.
**msDS=24**: AES-only — RC4 blocked by enforcement.
**msDS=28**: DC picks AES256 (strongest in set) regardless of whether RC4 or AES256 was requested.

### Phase=0 and Phase=1 — rollback/audit (identical results)

| msDS-SET | RC4 requested → actual | AES256 requested → actual |
|---------|----------------------|--------------------------|
| blank | RC4 | RC4 (!≠req) |
| 0 | RC4 | RC4 (!≠req) |
| 4 (RC4-only) | RC4 | **BLOCKED** |
| 24 (AES-only) | AES256 (!≠req) | AES256 |
| 28 (RC4+AES) | AES256 (!≠req) | AES256 |

**blank/0**: Internal default reverts to 0x27 (DES + RC4 + AES-SK flag, no AES128/AES256 bits).
DC can only issue RC4 tickets for these accounts.  Requesting AES256 still returns RC4.
**msDS=4**: Unchanged — RC4 only, AES blocked, same as enforcement.
**msDS=24**: Unchanged — DC still picks AES256.  Requesting RC4 returns AES256.
**msDS=28**: Unchanged — DC still picks AES256 (strongest in set).

---

## Matrix 2: Pol\SupportedEncryptionTypes × msDS-SET (Phase=absent)

DDSET again invariant — omitted from table.

### Pol=4 (RC4-only hard KDC filter)

| msDS-SET | RC4 req | AES256 req |
|---------|---------|-----------|
| blank | **BLOCKED** | **BLOCKED** |
| 0 | **BLOCKED** | **BLOCKED** |
| 4 | RC4 | **BLOCKED** |
| 24 | **BLOCKED** | **BLOCKED** |
| 28 | RC4 | **BLOCKED** |

Pol=4 forces AES to BLOCKED for every account regardless of msDS-SET.  Enforcement still blocks RC4 for blank/0/24.  blank/0 and 24 accounts are fully blocked (both etypes refused) — complete outage.  Only msDS=4 and 28 can communicate, RC4 only.

### Pol=28 (RC4+AES filter)

Identical to Pol=0x7fff — no observable difference from allow-all for these test cases.

---

## Key findings (corrected from v1)

### 1. The DC ignores the requested etype — it picks the strongest available

The most important finding from the v2 run.  kw-roast's `-e` flag sets what is *requested*.
The DC returns the strongest etype the account can support from its effective set, independent
of what was requested.  This has several consequences:

- msDS=28 (RC4+AES) always returns AES256 regardless of phase or what was requested.
  v1 reported this as "RC4=ALLOWED" — wrong.  The DC returned AES256 every time.
- msDS=24 under Phase=0/1: requesting RC4 returns AES256.  v1 reported this as "RC4 allowed
  for AES-only accounts under rollback" — wrong.  The account is still AES-only.
- blank/0 under Phase=0/1: requesting AES256 returns RC4.  The internal default 0x27 has no
  AES128/AES256 bits, so RC4 is the strongest etype available.

### 2. Phase=0/1 rollback only affects blank/0 (unconfigured) accounts

Contrary to v1, Phase=0/1 does **not** re-enable RC4 for explicitly configured accounts.
The rollback changes the effective set for blank/0 accounts from 0x18 (enforcement default)
back to 0x27 (old default, RC4-capable).  Accounts with an explicit msDS-SET behave
identically in all phases:

| Account type | Phase=absent/2 | Phase=0/1 | Change on rollback? |
|---|---|---|---|
| blank / 0 | AES256 only | RC4 only | Yes — rolls back to old 0x27 default |
| msDS=4 (RC4-only) | RC4 | RC4 | No |
| msDS=24 (AES-only) | AES256 | AES256 | No |
| msDS=28 (RC4+AES) | AES256 (strongest) | AES256 (strongest) | No |

The danger of Phase=0/1 is narrower than v1 claimed: it only affects blank/0 accounts,
and for those accounts it forces RC4 for all requests including AES256 requests.

### 3. Phase=absent == Phase=2

Confirmed.  Operationally identical across all 80 combinations in Matrix 1.

### 4. DDSET has no effect on which etype is returned

Across all Phase × msDS-SET combinations, DDSET values of absent, 4, 24, and 28 produced
identical results.  DDSET does not influence the etype selection or the enforcement decision
in any way detectable by explicit kw-roast etype requests.

### 5. msDS=28 (RC4+AES) always returns AES256

Under every phase and every DDSET value, an account with msDS=28 returns AES256 regardless
of whether RC4 or AES256 was requested.  The DC picks the strongest etype.  Kerberoasting
with RC4 against an msDS=28 account does not produce an RC4 hash.

### 6. Pol=4 (RC4-only filter) + enforcement = complete outage for blank/0 and msDS=24

Both etypes blocked simultaneously: Pol=4 blocks AES, enforcement blocks RC4.  msDS=4 and
msDS=28 accounts survive (RC4 only).

---

## Corrections to v1 matrix and site documentation

| Previous claim | Correct |
|---|---|
| "Phase=0/1 allows RC4 for msDS=24 (AES-only)" | False — DC returns AES256 regardless; requesting RC4 gets AES256, not RC4 |
| "Phase=0/1 re-enables RC4 for ALL accounts" | False — only blank/0 accounts are affected; explicitly configured accounts unchanged |
| "RC4=ALLOWED for msDS=28 under enforcement" | False — DC always returns AES256 for msDS=28; the v1 hash was AES256(!≠req), not RC4 |
| "AES=ALLOWED/BLOCKED for Phase=0 msDS=4" | Partially correct — AES is genuinely blocked (no AES support), RC4 is returned |
