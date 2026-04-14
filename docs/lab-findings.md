# Lab Findings

What we learned from ~80 registry tests, etype matrix tests, and Windows client
validation against Server 2022 (Build 20348, April 2026 CU).

---

## Registry: what works and what doesn't

### Functional paths (5 total)

| Path | Value | What it does | Timing |
|------|-------|-------------|--------|
| Services\Kdc | DefaultDomainSupportedEncTypes | Fallback etype set for msDS-SET=0 accounts | Immediate |
| Policies\...\Kerberos\Parameters | SupportedEncryptionTypes | Hard KDC etype filter (AS + TGS) | KDC restart |
| Lsa\Kerberos\Parameters | SupportedEncryptionTypes | Same filter, lower precedence than Pol | KDC restart |
| Services\Kdc | KdcUseRequestedEtypesForTickets | Client etype preference override | Immediate |
| Policies\...\Kerberos\Parameters | RC4DefaultDisablementPhase | RC4 deprecation phase control | KDC restart |

### Non-functional paths (6 combos, zero effect on KDC)

- DefaultEncryptionType at all 3 paths (Lsa, Kdc, Pol)
- DefaultDomainSupportedEncTypes at Lsa and Pol (only works at Services\Kdc)
- SupportedEncryptionTypes at Services\Kdc (only works at Pol and Lsa)

---

## The two-mechanism model

The KDC uses two independent systems. Understanding this separation explains
why Event 4769 fields can disagree with the actual ticket etype.

**Mechanism 1: Etype computation (DDSET / msDS-SET)**
Determines what etypes the KDC considers for the account. If the account has
msDS-SET != 0, that value is used. Otherwise DDSET is substituted. This
computed value appears in the Event 4769 msDSSET field. Changes take effect
immediately.

**Mechanism 2: Etype filter (SupportedEncryptionTypes at Pol or Lsa)**
Filters what the KDC will actually issue. Overrides mechanism 1 for ticket
issuance -- does not intersect with it. Requires KDC restart. Also affects
pre-auth (AS exchange), not just service tickets.

When they disagree: Pol=24 (AES) + DDSET default 0x27 (RC4) = AES ticket,
not an auth failure. Pol=4 (RC4) + DDSET=24 (AES) = RC4 ticket. The filter
always wins.

Precedence: Pol > Lsa > (nothing). When Pol exists, Lsa is ignored.

---

## What was wrong in the original documentation

### 1. GPO + DDSET conflict produces auth failure

**Claimed:** If GPO blocks RC4 but DDSET includes RC4, the KDC can't find an
overlap and returns KDC_ERR_ETYPE_NOSUPP.

**Actual:** The GPO filter overrides DDSET. The KDC issues the strongest etype
the filter allows. No error. Confirmed with getST.py, Event 4769, and the
fact that Pol=24 on the DC produced AES tickets for msDS-SET=0 accounts
whose DDSET default would normally select RC4.

### 2. AES-SK bit (0x20) only works in DDSET

**Claimed:** The 0x20 bit is only honored in DefaultDomainSupportedEncTypes.
Setting it on per-account msDS-SupportedEncryptionTypes has no effect.

**Actual:** 0x20 works in both DDSET and per-account msDS-SET. Setting
msDS-SET=36 (RC4 + AES-SK) on an individual account produces RC4 tickets
with AES256 session keys, even when DDSET lacks the 0x20 bit. Confirmed
via Windows klist on a domain-joined client and getST.py.

### 3. KdcUseRequestedEtypesForTickets=1 respects msDS-SET

**Claimed:** KdcUseReq=1 picks the first entry in the client's list that both
the KDC and target account support.

**Actual:** KdcUseReq=1 ignores the target account's msDS-SET entirely. An
account with msDS-SET=24 (AES only) received an RC4 ticket when the client
requested RC4. Event 4769 confirmed: ServiceSupportedEncryptionTypes=0x18
but TicketEncryptionType=0x17. This completely defeats per-account etype
hardening.

### 4. Session key is bounded by target's msDS-SET

**Claimed:** Session key = intersection of client + target + KDC.

**Actual:** The target's msDS-SET constrains ticket etype but does not
strictly bound the session key. An AES-only account (msDS-SET=24) can have
an RC4 session key if the client requests RC4. The session key comes from
the client/KDC intersection, independent of the target's declaration.

### 5. Lsa\SupportedEncryptionTypes is deprecated / non-functional

**Claimed:** Starting with Server 2025, Kerberos no longer honors this path.
(Implied: it doesn't work.)

**Actual:** On Server 2022, the Lsa path IS functional. It acts as a KDC
etype filter with lower precedence than the Pol path. Requires KDC restart.
Deprecated starting with Server 2025 (untested, lab is 2022).

### 6. SupportedEncryptionTypes filter requires KDC restart

**Not documented anywhere.** DDSET is immediate but the SupportedEncryptionTypes
filter (both Pol and Lsa) is only read at KDC service start. Changing the
value has zero effect until Restart-Service kdc. Removing the value also has
no effect until restart. This is the most common reason for "I changed the
GPO but nothing happened."

### 7. SupportedEncryptionTypes filter blocks pre-auth too

**Not documented.** The filter doesn't just control TGS ticket issuance -- it
also restricts what etypes the KDC will accept for AS exchange pre-auth.
Setting Pol=24 (AES only) blocked new Windows logon sessions that relied on
RC4 pre-auth. Confirmed when a scheduled task running as a domain user
failed to authenticate after the filter was applied.

---

## What was correct (confirmed by testing)

- DDSET immediate effect, no restart needed
- DDSET fallback behavior (substituted when msDS-SET=0) — **caveat: see April 2026 correction below**
- Explicit msDS-SET always overrides DDSET
- KDC picks strongest etype from the computed set (default behavior)
- GPO writes SupportedEncryptionTypes not DDSET
- GPO auto-updates computer account msDS-SET, strips high bits (0x7FFFFFFF -> 0x1F)
- GPO does not touch krbtgt or user service accounts
- Protected Users doesn't affect service ticket encryption
- TGT always AES256 on modern DCs (DFL >= 2008)
- Client etype preference doesn't affect ticket etype (when KdcUseReq=0)
- USE_DES_KEY_ONLY causes failure on Server 2022 (DES disabled)
- AES-SK split: RC4 ticket + AES256 session key for msDS-SET=0 accounts — **caveat: enforcement blocks RC4 for msDS-SET=0 after April 2026 patch**

### 8. Empty etype intersection produces KRB_ERROR

When the client's etype list and the target's supported etypes have no
overlap, the KDC returns KDC_ERR_ETYPE_NOSUPP. This is the expected
failure mode -- not a silent fallback:
- svc_val_02 (msDS-SET=4, RC4 only) with client requesting only AES256: FAIL
- svc_val_05 (msDS-SET=8, AES128 only) with client requesting only AES256: FAIL

---

## Kdcsvc events (201-209)

The April 2026 CU introduces Kdcsvc events in the System log.
Updated after April 2026 patch validation (2026-04-14) — see `april-2026-findings.md` for full event text.

| Event | Phase | Trigger | Type | Notes |
|-------|-------|---------|------|-------|
| 16 | any | TGS failure (any cause) | error | Pre-existing event; fires alongside 203/208 for blocked requests |
| 201 | 1 (audit) | RC4 request for blank/0 account | audit | RC4 allowed but logged; shows internal default 0x27 |
| 203 | absent/2 | RC4 request blocked, blank/0 account | block | RC4 denied; shows effective DDSET 0x18 |
| 205 | 0/1/2 | KDC startup when DDSET includes RC4 | startup | Fires once at KDC start, not per-request |
| 208 | absent/2 | RC4 request blocked, explicit AES-only account | block | msDS-SET=24 + RC4 client |

Events 202, 204, 206, 207, 209 not triggered in either testing session.

---

## Untestable claims (lab limitations)

| Claim | Why untestable |
|-------|---------------|
| Server 2025 default DDSET=0x24 | Lab DC is Server 2022 |
| Server 2025 deprecates Lsa path | Lab DC is Server 2022 |
| dMSA defaults | Requires Server 2025 / DFL 2025 |
| DES removed in Server 2025 | Lab DC is Server 2022 (DES disabled but not removed) |
| Per-DC replication test | Only one DC in lab |
| msDS-SET=0x18 without AES keys | All accounts in DFL 2016+ have AES keys |
| July 2026 final enforcement | Not yet July 2026 |

---

## Operational recommendations

### Priority actions

1. Audit all SPN-bearing user accounts with msDS-SupportedEncryptionTypes=0
2. Set msDS-SupportedEncryptionTypes=24 on all SPN-bearing service accounts
3. Set DefaultDomainSupportedEncTypes=24 on all DCs (immediate, no restart)
4. Enable RC4 audit mode (RC4DefaultDisablementPhase=1) and monitor Kdcsvc events
5. Verify KdcUseRequestedEtypesForTickets does NOT exist or is 0 on all DCs
6. Pre-July 2026: move to enforcement (RC4DefaultDisablementPhase=2) after audit is clean

### Monitoring events

| Event | Log | What to watch for |
|-------|-----|-------------------|
| 4769 | Security | Ticket Encryption Type: 0x17 = RC4, 0x12 = AES256 |
| 205 | System (Kdcsvc) | KDC start with RC4 in DDSET -- investigate |
| 206 | System (Kdcsvc) | Service is AES but client lacks AES -- upgrade client |
| 201-204 | System (Kdcsvc) | RC4 audit events -- identify accounts needing msDS-SET |

### Recommended DDSET values

| Value | Hex | Use case |
|-------|-----|----------|
| 24 | 0x18 | AES128 + AES256 (recommended, blocks RC4) |
| 56 | 0x38 | AES128 + AES256 + AES-SK (new deployments) |
| 60 | 0x3C | RC4 + AES + AES-SK (transitional only) |

Do NOT use 0x27 (39) or 0x24 (36) -- both include RC4 in the ticket etype set.

---

## RC4 deprecation status (updated 2026-04-14)

**All three statements below from the April 2026 session are wrong. See `april-2026-findings.md`.**

The April 2026 CU (KB5078763) enables enforcement by default. After installing
the patch, the KDC blocks RC4 for accounts with no `msDS-SupportedEncryptionTypes`
set (blank or 0). The `RC4DefaultDisablementPhase` key is absent by default,
which means enforcement is active — Phase=absent == Phase=2.

Corrected behavior:

| Phase | RC4 for blank/0 account | Internal fallback DDSET |
|-------|------------------------|-------------------------|
| absent (no key) | BLOCKED | 0x18 (AES-only) |
| 0 | ALLOWED | 0x27 (old RC4-inclusive) |
| 1 (audit) | ALLOWED | 0x27 (old RC4-inclusive) |
| 2 | BLOCKED (same as absent) | 0x18 (AES-only) |

Setting Phase=2 does not enable enforcement — it's already on. Phase=0 is the
rollback (allowed until July 2026). Phase=1 is audit-only (RC4 allowed, events logged).

DDSET cannot re-enable RC4 for blank/0 accounts regardless of its value. The
enforcement overrides DDSET entirely for unconfigured accounts. Phase=2 + DDSET=4
still blocks RC4 for blank/0 accounts.

Explicit `msDS-SupportedEncryptionTypes=4` (RC4-only) still works after the patch.
The enforcement only applies to accounts with no configuration (blank or 0).

---

## Comparison with Microsoft tools

### PSKerb module (Kerberos-Crypto repo)

PSKerb reads/writes the Pol path only. It describes itself as a "Windows
Kerberos client" tool, which is accurate -- the Pol path is where client
config lives. It doesn't cover KDC-side keys (DDSET, KdcUseReq,
RC4DefaultDisablementPhase) because those live at different registry paths
and are not client settings. PSKerb is not wrong, just different scope.

Two values PSKerb manages at the Pol path that may only work client-side:
- DefaultEncryptionType: no effect on KDC ticket issuance (tested). May
  affect client pre-auth etype selection (untested).
- LogLevel: typically documented at the Lsa path. Whether it works from
  the Pol path for client-side logging is untested.

### Etype calculator (etype-calc.html)

The calculator models ticket etype as a bitwise AND (intersection) of
target and KDC. Lab testing shows the SupportedEncryptionTypes filter
overrides rather than intersects. The calculator would show ETYPE_NOSUPP
when KDC=AES and target=RC4, but the actual KDC issues an AES ticket.

The calculator also:
- Uses 0x24 as the DDSET default (Server 2025). Server 2022 uses 0x27.
- Has no 0x20 checkbox and doesn't model per-account AES-SK behavior.
- Doesn't account for the filter being read only at KDC startup.

### RC4-ADAssessment tool

Get-KdcRegistryAssessment.ps1 reads RC4DefaultDisablementPhase from
Services\Kdc, but the actual value lives at Policies\...\Kerberos\Parameters.
It will never find it. The tool also doesn't check SupportedEncryptionTypes
(the KDC filter) or KdcUseRequestedEtypesForTickets (the bypass key).

---

## Testing methodology notes

### Tool-specific behavior

getST.py (Impacket) sends RC4 first in its TGS-REQ etype list. This means
session keys are consistently RC4 when using getST.py for cross-validation.
This is tool behavior, not a KDC anomaly. kw-roast's -e flag provides
precise etype control.

### The DISC-01 retraction

Early testing with kw-roast concluded that the GPO SupportedEncryptionTypes
didn't filter KDC behavior. This was wrong. kw-roast uses RC4 pre-auth,
and Pol=24 (AES only) blocks RC4 pre-auth after KDC restart. The
KRB_ERROR from blocked pre-auth masked the TGS-level filter behavior.
When retested with getST.py (which falls back to AES pre-auth), the
filter worked as expected.

Lesson: always test with a tool that handles pre-auth fallback, or the
pre-auth failure will mask the TGS behavior you're trying to observe.

### Windows client testing limitations

wmiexec creates ephemeral sessions without Kerberos tickets. To test
klist from a domain-joined client, we used scheduled tasks running under
the interactive Administrator session. This works for baseline tests but
has limitations:
- Cached tickets are reused within a logon session (klist get returns
  cached entries for the same SPN)
- Client SupportedEncryptionTypes changes don't take effect within an
  existing logon session
- If the KDC filter blocks pre-auth etypes, new scheduled task logon
  sessions will fail entirely

For tests requiring specific client etype lists, getST.py with Event 4769
correlation is more reliable than Windows klist.
