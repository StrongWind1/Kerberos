---

# Encryption Algorithms and Keys

The four algorithm families Windows Kerberos has used, how each one derives keys from
passwords, and what that means for security.  Ends with the operational side: how keys
are stored in AD, what encrypts what, and why some accounts silently break when you
try to move them to AES.

---

## Encryption Types at a Glance

Windows Active Directory has used four algorithm families over its history.  Each
combines a cipher, an integrity algorithm, and a key derivation method.

| Etype | Name | Key Bits | Salt | IANA # | Status |
|---|---|---|---|---|---|
| DES-CBC-CRC | DES with CRC32 | 56 | Yes | 1 | **Removed** (Server 2025) |
| DES-CBC-MD5 | DES with MD5 | 56 | Yes | 3 | **Removed** (Server 2025) |
| RC4-HMAC | RC4 with HMAC-MD5 | 128 (effective ~56–80) | **No** | 23 | **Deprecated** -- removed as implicit default July 2026 |
| AES128-CTS-HMAC-SHA1-96 | AES-128 in CTS mode | 128 | Yes | 17 | Current |
| AES256-CTS-HMAC-SHA1-96 | AES-256 in CTS mode | 256 | Yes | 18 | **Recommended** |
| AES256-CTS-HMAC-SHA1-96-SK | AES-256 session key variant | 256 | Yes | -- | Current (since Nov 2022) |

---

## DES-CBC-CRC / DES-CBC-MD5

DES uses a 56-bit effective key derived from the account password with a salt.  The
two variants differ only in the integrity check: CRC32 (etype 1) or MD5 (etype 3).

**Security assessment.** A 56-bit key is trivially brute-forceable on modern hardware
in hours.  DES is also vulnerable to known-plaintext attacks and weak-key collisions.
The CRC32 checksum (etype 1) provides no cryptographic integrity at all -- an attacker
can modify ciphertext and fix the CRC.

| Event | When |
|---|---|
| Default in Windows 2000 / Server 2003 | 2000–2007 |
| Disabled by default | Windows 7 / Server 2008 R2 (2009) |
| **Removed entirely** | Server 2025 / Windows 11 24H2 |

!!! warning "DES is gone"
    Windows Server 2025 and Windows 11 24H2 have completely removed DES support.  Any
    account or device that still requires DES will fail to authenticate against these
    systems.  Seeing DES in a modern environment means the account predates Server 2008
    and needs immediate attention.

---

## RC4-HMAC (Etype 23)

### Key derivation

The RC4 key is the **MD4 hash of the UTF-16LE encoded password** -- identical to the
NT (NTLM) hash:

```
RC4 key = MD4(UTF-16LE(password))
```

**No salt is used.**  The same password always produces the same RC4 key regardless
of username, domain, or realm.  This single property is the root of most of RC4's
security problems.

### Why RC4 is dangerous

**Precomputation attacks work directly.**  Rainbow tables and hash databases apply to
RC4 keys because there is no per-account salt.  The same dictionary that cracks NTLM
hashes cracks RC4 Kerberos keys.

**The key is interchangeable with the NTLM hash.**  Compromising an RC4 Kerberos key
gives you a pass-the-hash credential for free, and vice versa.  They are the same bytes.

**Fast to crack.**  RC4 key derivation is a single MD4 hash -- one operation per
password guess.  AES uses PBKDF2 with 4096 iterations, adding a fixed cost per guess
that makes brute force roughly 800 times slower:

### Cracking speed comparison

Approximate hashcat benchmarks on a single modern GPU (RTX 4090):

| Algorithm | Hashcat mode | Speed | Relative |
|---|---|---|---|
| RC4-HMAC (TGS-REP etype 23) | 13100 | ~2.5 billion H/s | baseline |
| AES128-CTS-HMAC-SHA1-96 (etype 17) | 19600 | ~6 million H/s | ~400× slower |
| AES256-CTS-HMAC-SHA1-96 (etype 18) | 19700 | ~3 million H/s | ~800× slower |

!!! info "800× is the key number"
    A password that falls to RC4 cracking in one hour would take roughly 33 days to
    crack via AES under the same conditions.  AES does not eliminate Kerberoasting --
    it makes strong passwords a viable defense.  Combined with a 25+ character random
    password, AES makes offline cracking infeasible in practice.

**Stream cipher weaknesses.**  RC4 has well-documented statistical biases in its
keystream output.  These do not directly apply to offline ticket cracking but
contributed to its deprecation in TLS (RFC 7465) and its classification as
cryptographically weak by NIST.

### Status

- RFC 8429 (2018) formally deprecated RC4 for Kerberos.
- CVE-2026-20833 phases out RC4 as the implicit default; final enforcement July 2026.
- RC4 is not being removed from Windows -- only the implicit fallback to it is ending.

---

## AES128-CTS-HMAC-SHA1-96 (Etype 17)

### Key derivation

AES keys use **PBKDF2-HMAC-SHA1** with a realm-and-principal salt and 4096 iterations:

```
AES128 key = PBKDF2(HMAC-SHA1, UTF-8(password), salt, 4096, 128 bits)
Salt = REALM + principal_name   e.g. "CORP.LOCALalice"
```

The salt includes both the uppercase realm name and the account's principal name
(the part of the UPN before the `@`).  The same password produces **different keys
for different accounts**, which defeats rainbow tables and precomputation.

The 4096 PBKDF2 iterations are fixed-cost per guess -- the main reason AES cracking
runs ~400× slower than RC4.

### When to use it

AES128 is fully supported and secure.  In practice, most deployments target
`msDS-SupportedEncryptionTypes = 0x18` (AES128 + AES256 together) to give the KDC
maximum flexibility -- the KDC will always pick AES256 when available.

---

## AES256-CTS-HMAC-SHA1-96 (Etype 18)

Identical derivation to AES128 with a 256-bit output:

```
AES256 key = PBKDF2(HMAC-SHA1, UTF-8(password), salt, 4096, 256 bits)
```

This is the **recommended default** for all accounts and services.

- 256-bit key provides a wide security margin, including against Grover's algorithm
  (which reduces effective symmetric key strength by half -- 128-bit equivalent is
  still considered secure).
- PBKDF2 with salt defeats rainbow tables and slows brute force by ~800× vs RC4.
- Well-studied block cipher; no known practical attacks on AES-256.
- Supported since Server 2008 / Vista; no compatibility barrier on any supported
  Windows version.

---

## AES256-CTS-HMAC-SHA1-96-SK (Session Key Variant)

This is not a new cipher -- it is a **configuration flag** (bit `0x20`) introduced
by the November 2022 update (CVE-2022-37966).  It tells the KDC:

> "Even if the service ticket must use RC4 because the target account lacks AES
> configuration, use AES256 for the **session key**."

This produces the split-etype output visible in `klist`:

```
KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
Session Key Type:           AES-256-CTS-HMAC-SHA1-96
```

Before November 2022, ticket etype and session key etype were always the same.  If a
ticket was RC4, the session key was also RC4, exposing the session to compromise.  The
`-SK` flag fixes the session while the ticket migration catches up.

The `0x20` bit is only honored in `DefaultDomainSupportedEncTypes`, not in
per-account `msDS-SupportedEncryptionTypes`.  Setting `0x20` on a per-account
attribute has no effect -- the KDC reads it only from the DC-level registry value.

!!! tip "AES-SK is a stopgap, not a solution"
    AES session keys protect the live session, but the ticket is still RC4 and still
    crackable via Kerberoasting.  The fix is setting `msDS-SupportedEncryptionTypes =
    0x18` on SPN-bearing accounts and ensuring they have AES keys.

---

## Algorithm Comparison

| Property | DES | RC4-HMAC | AES128 | AES256 |
|---|---|---|---|---|
| **Etype number** | 1 / 3 | 23 | 17 | 18 |
| **Key bits** | 56 | 128 | 128 | 256 |
| **Key derivation** | string-to-key + salt | MD4, no salt | PBKDF2 + salt, 4096 iter | PBKDF2 + salt, 4096 iter |
| **Salt** | Yes | **No** | Yes | Yes |
| **Cipher type** | Block | Stream | Block | Block |
| **Integrity** | CRC32 / MD5 | HMAC-MD5 | HMAC-SHA1-96 | HMAC-SHA1-96 |
| **Crack speed (relative)** | Trivial | 1× (baseline) | ~400× slower | ~800× slower |
| **NTLM-interchangeable** | No | **Yes** | No | No |
| **RFC deprecated** | RFC 6649 (2012) | RFC 8429 (2018) | -- | -- |
| **Recommended** | No | No | Acceptable | **Yes** |

---

## Keys in Active Directory

### Long-term keys vs session keys

Kerberos uses **symmetric keys** throughout.  They fall into two categories:

**Long-term keys** are derived from an account's password and persist until the
password changes.  They are stored in AD and used to prove identity.

| Key | Derived from | Stored | Rotation |
|---|---|---|---|
| User secret key | User's password (string-to-key) | `unicodePwd`, `supplementalCredentials` on the user object | Every password change |
| Computer/service key | Auto-generated computer password | Computer account object | Every 30 days by default |
| KRBTGT key | KRBTGT account password | KRBTGT account object | Manual only |
| Inter-realm (trust) key | Trust password shared between domains | Trust account objects in both domains | When trust password is reset |

!!! info "Multiple keys per account"
    When a password is set, AD generates keys for **every supported etype simultaneously**.
    A single account can have RC4, AES128, and AES256 keys all stored at once.  The KDC
    picks the appropriate key at ticket-issuance time based on the negotiated etype.

**Session keys** are randomly generated by the KDC for each AS or TGS exchange.  They
are embedded in the ticket (so the target service can extract them) and sent to the
client in the encrypted reply.  They are never stored in AD, and expire with the ticket
(default 10 hours).

### What encrypts what

| Message component | Encrypted with | Who decrypts it |
|---|---|---|
| **TGT** (ticket `enc-part`) | KRBTGT key | KDC (on each TGS-REQ) |
| **AS-REP encrypted part** (contains TGT session key) | User's long-term key | Client |
| **Service ticket** (ticket `enc-part`) | Target account's key | Target service |
| **TGS-REP encrypted part** (contains service session key) | TGT session key | Client |
| **AP-REQ Authenticator** | Service ticket session key | Target service |
| **AP-REP** (mutual auth) | Service ticket session key | Client |
| **PA-ENC-TIMESTAMP** (pre-auth) | User's long-term key | KDC |
| **TGS-REQ Authenticator** | TGT session key | KDC |

!!! tip "The client never decrypts tickets"
    The client receives TGTs and service tickets as opaque blobs.  It can only decrypt
    the **reply encrypted parts** (which deliver session keys to the client).  The ticket
    etype is entirely determined by the KDC and the target account -- the client's
    capabilities are irrelevant for ticket encryption.

---

## Key Generation on Password Change

When a password is set or changed, the DC generates keys for **all supported etypes at
once** and stores them in `supplementalCredentials` on the account object.  On a modern
DC (Server 2008+):

- DES-CBC-CRC key
- DES-CBC-MD5 key
- RC4-HMAC key (= NT hash)
- AES128-CTS-HMAC-SHA1-96 key
- AES256-CTS-HMAC-SHA1-96 key

`msDS-SupportedEncryptionTypes` tells the KDC which stored keys it should *consider
using*.  It does not control which keys are generated -- that depends entirely on the
domain functional level at the time the password was set.

**AES keys require DFL >= 2008.**  If an account's password was set while the domain
functional level was still at 2003, the DC only generated DES and RC4 keys.  No AES
keys were stored.  Changing `msDS-SupportedEncryptionTypes` to `0x18` on that account
does not create AES keys retroactively -- you must reset the password on a DC running
2008 or later.

### The Double-Reset Problem

Accounts whose passwords predate DFL 2008 may still fail after a single reset.  This
happens because the first reset writes AES keys into the `KerberosNew` credential set
but leaves the `Kerberos` (current) set unchanged.  The KDC checks the current set
first.  Only after a **second** password change are the new AES keys promoted from
`KerberosNew` into `Kerberos`.

!!! warning "Old accounts need two password resets"
    Any account created before your domain supported AES must have its password reset
    **twice** to reliably generate usable AES keys.  Use DSInternals or impacket
    secretsdump to confirm the keys exist before changing `msDS-SupportedEncryptionTypes`
    -- see [Auditing Kerberos Keys](account-key-audit.md) for all four methods.

    ```powershell title="Verify Kerberos key types stored for an account via DSInternals"
    Install-Module -Name DSInternals -Force
    Get-ADReplAccount -SamAccountName svc_sql -Server DC01 |
      Select-Object -ExpandProperty KerberosKeys
    ```

    Look for `AES256-CTS-HMAC-SHA1-96` and `AES128-CTS-HMAC-SHA1-96` entries.  If they
    are absent, the account needs another password reset.

### Finding the AES cutover date

The **Read-Only Domain Controllers** group (RID 521) was introduced with DFL 2008.
Its creation date marks the earliest point at which password changes generate AES keys:

```powershell title="Find the date AES keys became available in the domain"
(Get-ADGroup -Filter * -Properties SID, WhenCreated |
  Where-Object { $_.SID -like '*-521' }).WhenCreated
```

Any account with `passwordLastSet` earlier than this date definitely lacks AES keys.

---

## When Keys Are Missing

Setting `msDS-SupportedEncryptionTypes = 0x18` on an account that only has RC4 keys
causes the KDC to try to issue an AES ticket and fail.  The DC logs:

- **Event ID 14** (System log, `Kerberos-Key-Distribution-Center`) for AS requests
- **Event ID 16** for TGS requests

The event text identifies the mismatch explicitly:

```
The account <name> did not have a suitable key for generating a Kerberos ticket
(the missing key has an ID of <n>).
The requested etypes: 18 17.
The accounts available etypes: 23.
```

Etype 23 is RC4; 17 and 18 are AES128 and AES256.  The only fix is a password reset
(twice for pre-2008 accounts) to generate the missing AES keys.

---

## KRBTGT: Special Considerations

The KRBTGT key encrypts **every TGT in the domain**.  Unlike ordinary account keys,
it is never set by a human -- it is managed by the KDC.

- On DFL >= 2008, the KRBTGT key is AES256 by default.
- Rotating the KRBTGT password invalidates all outstanding TGTs in the domain.
  Users seamlessly obtain new TGTs at next authentication, but disconnected sessions
  holding cached TGTs will fail until they re-authenticate.
- The KRBTGT password should be rotated at least every 180 days, and immediately
  (twice, with replication time between rotations) after any suspected compromise.
- The same double-reset logic applies: rotate **twice** to ensure both the current and
  previous key slots are clean.  Use a controlled script (such as Microsoft's
  `Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1`) for safe rollout across
  multiple DCs.
- If the KRBTGT key is compromised, an attacker can forge Golden Tickets -- TGTs
  encrypted with the KRBTGT key and carrying arbitrary PAC contents.  See
  [Golden Ticket](../attacks/forgery/golden-ticket.md) for the attack mechanics.
