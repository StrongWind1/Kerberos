# April 2026 Patch Lab Findings

Lab validation of KB5078763 behavior on Server 2022 Build 20348 (UBR 5020), domain evil.corp, DFL Windows2016Domain.
Test date: 2026-04-14. All tests run with reg.py (impacket) and kw-roast.

Test accounts created for this session:

| Account | msDS-SupportedEncryptionTypes | SPN |
|---------|-------------------------------|-----|
| svc_apr_01 | blank (no attribute) | HTTP/svc-apr-01.evil.corp |
| svc_apr_02 | 0 (explicit integer) | HTTP/svc-apr-02.evil.corp |
| svc_apr_03 | 4 (RC4 only) | HTTP/svc-apr-03.evil.corp |
| svc_apr_04 | 24 (AES only) | HTTP/svc-apr-04.evil.corp |
| svc_apr_05 | 28 (RC4+AES) | HTTP/svc-apr-05.evil.corp |

---

## Finding 1: The patch enables RC4 enforcement by default

**Previous documentation said:** "The mechanism is ready, just not turned on." The key `RC4DefaultDisablementPhase` was absent and RC4 was allowed for unconfigured accounts.

**What the patch actually does:** After installing KB5078763, the KDC enforces AES-only for accounts with no `msDS-SupportedEncryptionTypes` set — without any explicit `RC4DefaultDisablementPhase` key in the registry.

Baseline test (clean registry — no DDSET, no Phase key, `Pol\SupportedEncryptionTypes=0x7fffffff`):

| Account | msDS-SET | RC4 forced (kw-roast) | AES256 forced | Ticket via getST.py |
|---------|----------|----------------------|---------------|---------------------|
| svc_apr_01 | blank | **BLOCKED** | ALLOWED | AES256 (etype 18) |
| svc_apr_02 | 0 | **BLOCKED** | ALLOWED | AES256 (etype 18) |
| svc_apr_03 | 4 | ALLOWED | BLOCKED | RC4 (etype 23) |
| svc_apr_04 | 24 | **BLOCKED** | ALLOWED | AES256 (etype 18) |
| svc_apr_05 | 28 | ALLOWED | ALLOWED | AES256 (etype 18), RC4 session |

Event 4769 confirms: for blank and 0 accounts, `SvcSET=0x18` (AES-only) is reported. Before the patch, these accounts showed `SvcSET=0x27` (DES+RC4+AES-SK).

**Implication:** Any SPN-bearing account without an explicit `msDS-SupportedEncryptionTypes` that has no AES keys will fail authentication after this patch. RC4-only services are broken on patch day if they are not configured.

---

## Finding 2: msDS-SET=blank and msDS-SET=0 are identical

Both treated as "no configuration" and subject to enforcement. Neither can receive RC4 tickets under enforcement.

Explicit `msDS-SET=0` is NOT the same as `msDS-SET=4 (RC4-only)`. Setting a 0 does not mean "RC4 is permitted" — it means "use the enforcement default" (AES-only after the patch).

---

## Finding 3: RC4DefaultDisablementPhase controls rollback, not enablement

With the patch installed, the key meaning has flipped from what was previously documented.

| Phase value | RC4 for blank/0 accounts | Events generated | Internal DDSET fallback |
|-------------|--------------------------|------------------|-------------------------|
| absent (no key) | **BLOCKED** (enforcement active) | 203/208 per blocked request | 0x18 (AES-only) |
| 0 | **ALLOWED** (rollback) | none | 0x27 (old RC4-inclusive) |
| 1 | **ALLOWED** (audit) | 201/202 per RC4 request | 0x27 (old RC4-inclusive) |
| 2 | **BLOCKED** (enforcement, same as absent) | 203/208 per blocked request | 0x18 (AES-only) |

Key observations:
- **Phase=absent == Phase=2.** The patch makes enforcement the default. The key is only needed to opt into rollback or audit.
- **Phase=0 is the emergency rollback.** Sets internal default back to 0x27, allows RC4 for all unconfigured accounts. Valid until July 2026.
- **Phase=1 is audit.** RC4 is allowed but Event 201/202 fire for each RC4 request on an unconfigured account.

Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\RC4DefaultDisablementPhase` (REG_DWORD). Requires KDC restart. The key at `Services\Kdc\Parameters` is silently ignored.

**Previous finding that is now wrong:**
> "Setting Phase=2 and restarting the KDC switches the default to AES-only."

Correct version: Phase=absent already does this. Phase=2 is redundant — it's the same as absent.

---

## Finding 4: DDSET cannot override enforcement

Previously documented as: "Explicit DDSET with RC4 overrides enforcement (Phase=2 + DDSET=4 = RC4 tickets)."

**This is wrong after KB5078763.**

DDSET tested against blank/0 accounts under enforcement (Phase=absent/2):

| DDSET value | RC4 for blank/0 account | Notes |
|-------------|------------------------|-------|
| not set | BLOCKED | enforcement applies |
| 4 (RC4 only) | BLOCKED | DDSET ignored for enforcement decision |
| 28 (RC4+AES) | BLOCKED | same |
| 39 / 0x27 (old default) | BLOCKED | same |
| 24 (AES only) | BLOCKED | consistent |

DDSET still affects which AES etype is selected (AES128 vs AES256), but it cannot restore RC4 for accounts without an explicit `msDS-SupportedEncryptionTypes`.

DDSET DOES still work as expected for explicit accounts:
- msDS-SET=4 + DDSET=24 → RC4 ticket (explicit msDS-SET wins over DDSET)

Event 203 under Phase=2 + DDSET=4 reports `DefaultDomainSupportedEncTypes: 0x18` — the enforcement effective DDSET — not the registry value of 4. The enforcement substitutes its own value regardless of what's in the registry.

---

## Finding 5: Explicit msDS-SET=4 still allows RC4 under enforcement

Accounts with `msDS-SupportedEncryptionTypes=4` (explicit RC4-only) continue to receive RC4 tickets regardless of Phase setting. This is by design — the enforcement only applies to **unconfigured** accounts (blank or 0).

| Account | msDS-SET | Phase=absent | Phase=2 |
|---------|----------|-------------|---------|
| blank | — | BLOCKED | BLOCKED |
| 0 | explicit 0 | BLOCKED | BLOCKED |
| 4 | RC4 only | ALLOWED | ALLOWED |
| 28 | RC4+AES | ALLOWED | ALLOWED |

Accounts with explicit msDS-SET=4 trigger Event 205 at KDC startup (DDSET contains insecure cipher warning), but are not blocked.

---

## Kdcsvc event reference (updated)

All events from `Microsoft-Windows-Kerberos-Key-Distribution-Center` in the System log.

### Per-request events (fire on each blocked/audited TGS or AS request)

| Event ID | Phase | Trigger | Message summary |
|----------|-------|---------|-----------------|
| 201 | 1 (audit) | RC4 request for blank/0 account | "detected RC4-HMAC-NT usage that will be unsupported in enforcement phase because msds-SupportedEncryptionTypes is not defined" |
| 202 | 1 (audit) | RC4 request for AES-configured account | Not triggered in this session (account had RC4 keys) |
| 203 | absent/2 | RC4 request blocked, blank/0 account | "blocked cipher usage because msds-SupportedEncryptionTypes is not defined and the client only supports insecure encryption types" |
| 208 | absent/2 | RC4 request blocked, explicit AES-only account | "blocked cipher usage because msds-SupportedEncryptionTypes is configured to only support AES-SHA1 but the client does not advertize AES-SHA1" |

### Startup event (fires once per KDC start, not per request)

| Event ID | Trigger | Message summary |
|----------|---------|-----------------|
| 205 | KDC start, DDSET contains RC4 | "detected explicit insecure cipher enablement in the DefaultDomainSupportedEncTypes policy configuration. Cipher(s): RC4-HMAC-NT" |

### Accompanying event (fires alongside 203/208)

| Event ID | Trigger | Message summary |
|----------|---------|-----------------|
| 16 | TGS failure (any cause) | "While processing a TGS request... did not have a suitable key for generating a Kerberos ticket. The requested etypes were 23. The accounts available etypes were 23 18 17." |

Event 16 is a pre-existing event. With enforcement, it fires alongside 203/208 for the same blocked request.

### Event 201 vs 203 field comparison

Event 201 (Phase=1 audit, RC4 allowed):
- `Service Information: msds-SupportedEncryptionTypes: 0x27 (DES, RC4, AES-Sk)` — old default shown
- `Domain Controller Information: DefaultDomainSupportedEncTypes: 0x27` — internal 0x27 in effect

Event 203 (Phase=absent/2 enforcement, RC4 blocked):
- `Service Information: msds-SupportedEncryptionTypes: 0x18 (AES128-SHA96, AES256-SHA96)` — enforcement default shown
- `Domain Controller Information: DefaultDomainSupportedEncTypes: 0x18` — internal 0x18 in effect (regardless of registry DDSET)

Both events include:
- `Account Information: Account Name, Supplied Realm Name` — who made the request
- `Service Information: Service Name, Service ID, Available Keys` — target account
- `Network Information: Client Address, Client Port, Advertized Etypes` — client's etype list

---

## Event 4769 behavior under enforcement

When an RC4 request is blocked, Event 4769 still fires but shows:
- `Service Name` = full SPN string (e.g. `HTTP/svc-apr-01.evil.corp`), not the resolved account name
- `TicketEncryptionType` = `0xffffffff` (failure indicator)
- `ServiceSupportedEncryptionTypes` = blank/dash

When allowed:
- `Service Name` = resolved account name (e.g. `svc_apr_01`)
- `TicketEncryptionType` = actual etype (e.g. `0x12` for AES256, `0x17` for RC4)
- `ServiceSupportedEncryptionTypes` = the effective bitmask (e.g. `0x18 (AES128-SHA96, AES256-SHA96)`)

`TicketEncryptionType=0xffffffff` in a 4769 event is a reliable indicator of an enforcement block.

---

## Corrections to previous lab-findings.md

### 1. DDSET can override enforcement [WRONG]

Previous: "Explicit DDSET with RC4 overrides enforcement (Phase=2 + DDSET=4 = RC4 tickets)."

Correct: DDSET cannot re-enable RC4 for blank/0 accounts under enforcement (Phase=absent or 2). The enforcement substitutes its own effective DDSET of 0x18, independent of the registry value.

### 2. Phase=absent means RC4 allowed [WRONG]

Previous: "The key is absent by default — the DC still uses the internal default of 0x27."

Correct after KB5078763: Phase=absent = Phase=2 = enforcement active. The old 0x27 internal default only applies under Phase=0 or Phase=1.

### 3. Phase=2 is a manual switch [WRONG]

Previous: "Manual enforcement works: setting Phase=2 and restarting the KDC switches the default to AES-only."

Correct: The patch makes enforcement the default state. Phase=2 is not a switch to enable enforcement — enforcement is already on. Phase=0 and Phase=1 are the switches to disable it.

---

## Rollback window

Microsoft has confirmed a rollback window between April and July 2026.

- Phase=0 → full rollback, RC4 allowed for all, no events
- Phase=1 → audit rollback, RC4 allowed for all, events logged
- July 2026 → `RC4DefaultDisablementPhase` key is removed from the OS; rollback no longer possible; enforcement is permanent

**Setting Phase=0 or Phase=1 requires a KDC restart to take effect.**

---

## Operational summary

### RC4 is blocked for these accounts immediately after the patch:
- msDS-SupportedEncryptionTypes = blank (no attribute ever set)
- msDS-SupportedEncryptionTypes = 0 (explicit integer 0)

### RC4 still works for these accounts after the patch:
- msDS-SupportedEncryptionTypes = 4 (explicit RC4-only)
- msDS-SupportedEncryptionTypes = 28 (RC4+AES)

### To re-enable RC4 temporarily (until July 2026):
```powershell
# On each DC, run as admin:
Set-ItemProperty `
  -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
  -Name RC4DefaultDisablementPhase -Value 1 -Type DWord
Restart-Service kdc
```

### To check current enforcement state:
```powershell
Get-ItemProperty `
  -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
  -Name RC4DefaultDisablementPhase -ErrorAction SilentlyContinue
# If the value is missing or is 2: enforcement is active
# If the value is 0 or 1: enforcement is disabled/audit
```

### To identify services that will break:
Event 203 fires for every blocked RC4 request. Monitor the System log for Event 203 to find which services are being blocked. Alternatively, set Phase=1 (audit) to generate Event 201 for all RC4 requests without blocking them.

```powershell
# Find accounts that have received blocked requests (Event 203)
Get-WinEvent -LogName System -FilterXPath `
  "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] and EventID=203]]" |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' } | Select-Object '#text'
  } | Sort-Object -Unique
```
