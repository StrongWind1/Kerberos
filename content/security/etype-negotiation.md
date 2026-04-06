---
---

# Encryption Type Negotiation

How the KDC decides which encryption algorithm to use for every part of the
AS and TGS exchanges.  This is the most misunderstood aspect of Kerberos
configuration -- and the root cause of most "no common etype" failures.

---

## Core Principle

Every Kerberos message that contains encrypted data carries an **etype** identifier that tells
the recipient which algorithm was used.  The KDC is responsible for choosing the etype at
ticket-issuance time.  It does so by intersecting what the **client** asks for, what the
**target account** supports, and what the **KDC itself** is configured to allow -- then
picking the strongest match.

There is no single "etype for this ticket."  A single AS-REP or TGS-REP contains **multiple
independently-selected etypes**: one for the ticket itself, one for the session key inside it,
and one for the encrypted portion of the reply.  These can all differ.

---

## AS Exchange (TGT Request)

### Step 1: Client Sends AS-REQ

The client sends a list of supported etypes in the `etype` field of the AS-REQ body, ordered
by preference (strongest first).  On a modern Windows 10/11 machine this list is typically:

```
AES256-CTS-HMAC-SHA1-96 (18)
AES128-CTS-HMAC-SHA1-96 (17)
RC4-HMAC (23)
DES-CBC-MD5 (3)
DES-CBC-CRC (1)
```

The list is controlled by the client-side **Network security: Configure encryption types
allowed for Kerberos** Group Policy or the `SupportedEncryptionTypes` registry value.

### Step 2: KDC Responds with PA-ETYPE-INFO2

If pre-authentication is required (the default in AD), the KDC replies with
`KDC_ERR_PREAUTH_REQUIRED` and includes **PA-ETYPE-INFO2** data.  This tells the client
which etypes the KDC will accept for pre-authentication and provides the **salt** needed
for AES key derivation.

The KDC builds this list by looking at the **user account's stored keys** in AD.  If the
account has AES256, AES128, and RC4 keys, the PA-ETYPE-INFO2 will list all three.  If the
account has only RC4 keys (because its password was never reset after DFL 2008), only RC4
will appear.

### Step 3: Pre-Authentication (PA-ENC-TIMESTAMP)

The client picks the **strongest etype from PA-ETYPE-INFO2 that it also supports** and
encrypts a timestamp with the corresponding key.  This etype determines the pre-auth etype.

### Step 4: KDC Builds the AS-REP

The KDC must now choose etypes for three distinct things:

| Component | How the Etype Is Chosen |
|---|---|
| **TGT ticket encryption** | Determined by the KRBTGT account's available keys and the KDC's own etype configuration.  On DFL 2008 and above, this is **always AES256** unless AES is explicitly disabled.  The `KdcUseRequestedEtypesForTickets` registry key can override this (see below). |
| **TGT session key** | Intersection of the client's requested etype list (from AS-REQ) and the KDC's supported etypes.  Strongest common etype wins.  Since the November 2022 update (CVE-2022-37966), the default is AES256 when the client supports it. |
| **AS-REP encrypted part** | Same etype as pre-authentication.  The KDC must use the same key the client used for PA-ENC-TIMESTAMP so the client can decrypt the reply. |

!!! info "TGT is always AES on modern DCs"
    The client never decrypts the TGT -- only the KDC does.  So the TGT ticket etype depends
    solely on KRBTGT's keys and the KDC's configuration.  On any domain with DFL >= 2008 and a
    KRBTGT password set after AES support was added, the TGT is AES256 regardless of what the
    client requested.

### KdcUseRequestedEtypesForTickets

This registry value at `HKLM\SYSTEM\CurrentControlSet\Services\Kdc` changes how the KDC
picks the **TGT ticket etype**:

| Value | Behavior |
|---|---|
| `1` | KDC honors the client's etype preference list and picks the first mutually-supported entry. |
| `0` or not set (default) | KDC ignores the client's list and picks the **strongest** etype from its own supported set. |

In practice, the default behavior (`0`) means the TGT is always AES256 on modern DCs, even
if the client listed RC4 first.

---

## TGS Exchange (Service Ticket Request)

### Step 1: Client Sends TGS-REQ

The TGS-REQ contains:

- The **TGT** (encrypted with KRBTGT's key -- the client just forwards it).
- An **Authenticator** encrypted with the TGT session key.
- An **etype list** of the client's supported etypes (same as in AS-REQ).

### Step 2: KDC Builds the TGS-REP

The KDC must choose etypes for three things:

| Component | How the Etype Is Chosen |
|---|---|
| **Service ticket encryption** | Determined by the **target account's** available keys and its `msDS-SupportedEncryptionTypes` attribute, intersected with the KDC's allowed etypes.  The strongest common etype wins.  The client's preference is **not** consulted. |
| **Service ticket session key** | Intersection of the **client's** etype list, the **target account's** `msDS-SupportedEncryptionTypes`, and the **KDC's** allowed etypes.  Strongest common etype wins. |
| **TGS-REP encrypted part** | Same etype as the TGT session key (since the client uses the TGT session key to decrypt this portion). |

!!! warning "Service ticket etype depends on the target account, not the client"
    This is the key insight.  A client can support AES, but if the target account has
    `msDS-SupportedEncryptionTypes = 0` (not set) and the KDC's
    `DefaultDomainSupportedEncTypes` includes RC4, the service ticket will be encrypted with
    **RC4**.  The client has no say in the service ticket etype.

### The November 2022 Change: Split Etypes

Before the November 2022 update (CVE-2022-37966), the session key etype and the ticket etype
were always the same.  After the update, they **can differ**:

- The **session key** defaults to AES when the client supports it (driven by the
  `AES256-CTS-HMAC-SHA1-96-SK` bit, `0x20`).
- The **ticket** may still use RC4 if the target account has no `msDS-SupportedEncryptionTypes`
  and the `DefaultDomainSupportedEncTypes` includes RC4.

This means you can see `klist` output like this:

```
KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
Session Key Type:           AES-256-CTS-HMAC-SHA1-96
```

The ticket itself is RC4, but the session key used between client and service is AES256.
While this improves session security, the ticket is still vulnerable to offline cracking
(Kerberoasting) because it is encrypted with the target account's RC4 key.

---

## Decision Reference Table

The following table summarizes what determines each etype:

| What | AS Exchange | TGS Exchange |
|---|---|---|
| **Ticket encryption** | KRBTGT's keys + KDC config (always AES256 on DFL >= 2008) | Target account's keys + `msDS-SupportedEncryptionTypes` + KDC config |
| **Session key** | Client etype list + KDC config (strongest common) | Client etype list + target account's `msDS-SupportedEncryptionTypes` + KDC config (strongest common) |
| **Reply encrypted part** | Same etype as pre-auth (client's key) | Same etype as TGT session key |

!!! tip "Reading klist output"
    When you run `klist` on a Windows client, the `KerbTicket Encryption Type` field shows
    the **ticket encryption** etype and the `Session Key Type` field shows the **session key**
    etype.  For TGTs (server = `krbtgt/DOMAIN`), the ticket etype should always be AES256.
    For service tickets, the ticket etype depends on the target account's configuration.

---

## Practical Example: Mixed Etypes

Consider a domain with these settings:

- Client: Windows 11, supports AES256 + AES128 + RC4
- Account `svc_sql`: `msDS-SupportedEncryptionTypes` not set (value = 0)
- KDC: `DefaultDomainSupportedEncTypes` = `0x27` (DES + RC4 + AES-SK, the post-Nov 2022 default)

**TGT request (AS exchange):**

| Component | Etype | Reason |
|---|---|---|
| TGT ticket | AES256 (18) | KRBTGT has AES256 keys, KDC picks strongest |
| TGT session key | AES256 (18) | Client supports AES256, KDC supports AES256 |
| AS-REP encrypted part | AES256 (18) | Same as pre-auth etype |

**Service ticket request (TGS exchange):**

| Component | Etype | Reason |
|---|---|---|
| Service ticket | RC4 (23) | `svc_sql` has no `msDS-SupportedEncryptionTypes`; default includes RC4; RC4 key exists |
| Session key | AES256 (18) | AES-SK bit (`0x20`) in default means session key uses AES; client supports it |
| TGS-REP encrypted part | AES256 (18) | Same etype as TGT session key |

The `klist` output for the service ticket would show:

```
Server:                  MSSQLSvc/sql01.corp.local:1433 @ CORP.LOCAL
KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
Session Key Type:           AES-256-CTS-HMAC-SHA1-96
```

The fix: set `msDS-SupportedEncryptionTypes = 0x18` (24) on `svc_sql` and reset its password
to generate AES keys.  After that, both the ticket and session key will use AES256.
