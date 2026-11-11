---
description: The Kerberos encryption algorithms Windows has used (DES, RC4, AES), how each derives keys from a password, how keys are stored in Active Directory, and what happens when AES keys are missing.
---

# Encryption Algorithms and Keys

The algorithm families Windows Kerberos has used, how each one derives keys from
passwords, and what that means for security.  Ends with the operational side: how keys
are stored in AD, what encrypts what, and why an account without AES keys cannot
authenticate once it is treated as AES-only.

---

## Encryption Types at a Glance

Each etype combines a cipher, an integrity algorithm, and a key derivation method.

| Etype | Name | Key Bits | Salt | IANA # | Status |
|---|---|---|---|---|---|
| DES-CBC-CRC | DES with CRC32 | 56 | Yes | 1 | **Removed** from Server 2025 / Windows 11 24H2; disabled by default since 2008 R2 |
| DES-CBC-MD5 | DES with MD5 | 56 | Yes | 3 | **Removed**, as above |
| RC4-HMAC | RC4 with HMAC-MD5 | 128 | **No** | 23 | **Deprecated.**  Explicit opt-in only on DCs with the April 2026 update: no longer assumed for unset accounts |
| AES128-CTS-HMAC-SHA1-96 | AES-128 in CTS mode | 128 | Yes | 17 | Current |
| AES256-CTS-HMAC-SHA1-96 | AES-256 in CTS mode | 256 | Yes | 18 | **Recommended** |
| AES256-CTS-HMAC-SHA1-96-SK | Not a cipher: a flag asking for AES256 **session keys** | -- | -- | -- | Legacy transitional flag (November 2022) |
| AES128-CTS-HMAC-SHA256-128 | AES-128 with SHA-2 (RFC 8009) | 128 | Yes | 19 | Supported in Server 2025 / Windows 11 24H2, **disabled by default** ([MS-KILE]); not lab-verified |
| AES256-CTS-HMAC-SHA384-192 | AES-256 with SHA-2 (RFC 8009) | 256 | Yes | 20 | As above |

The bit that selects each etype in `msDS-SupportedEncryptionTypes` and the related registry
values:

--8<-- "includes/etype-bits.md"

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
| Available, mainly for interoperability (RC4-HMAC was the Windows default) | Windows 2000 – Server 2008 |
| Disabled by default | Windows 7 / Server 2008 R2 (2009) |
| **Removed** | Server 2025 / Windows 11 24H2 and later |

!!! warning "DES is gone from current Windows"
    Microsoft's [removed-features list](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
    states that DES is removed from Windows 11 24H2 and Windows Server 2025 and later.  Any
    account or device that still requires DES cannot authenticate against those systems.
    This site has not lab-tested DES on Server 2025.  On Server 2022 DES is disabled by
    default but not removed.  In one lab run on build 20348.5020 an account flagged
    `UF_USE_DES_KEY_ONLY` was issued a DES ticket; an earlier run on a pre-April build
    recorded a failure.  The lab DC's baseline etype filter allows every type, DES included,
    and the notes do not record the filter state during the run, so this does not show what
    a default-configured DC does.

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
that makes brute force slower by roughly three orders of magnitude:

### Cracking speed comparison

Approximate hashcat figures for a single high-end GPU.  They are **indicative only**: this
site has not benchmarked them, and published results for the same card vary by a factor of
two or more with hashcat version and driver.  For real numbers, run `hashcat -b -m 13100`,
`hashcat -b -m 19600` and `hashcat -b -m 19700` on your own hardware, one mode per command
(when `-m` is repeated, hashcat benchmarks only the last mode).

| Algorithm | Hashcat mode | Speed | Relative |
|---|---|---|---|
| RC4-HMAC (TGS-REP etype 23) | 13100 | ~2.5 billion H/s | baseline |
| AES128-CTS-HMAC-SHA1-96 (etype 17) | 19600 | a few million H/s | ~400× slower or more |
| AES256-CTS-HMAC-SHA1-96 (etype 18) | 19700 | ~1.5-3 million H/s | ~800× slower or more |

!!! info "About 800× at least"
    This site quotes **~800×** as a conservative figure for RC4 versus AES256; the real ratio
    may be nearer 1,500×.  At 800×, a password that falls to RC4 cracking in one hour takes
    about 33 days via AES256 under the same conditions.  AES does not eliminate
    Kerberoasting -- it makes strong passwords a viable defense.  Combined with a 25+
    character random password, AES makes offline cracking infeasible in practice.

**Stream cipher weaknesses.**  RC4 has well-documented statistical biases in its
keystream output.  These do not directly apply to offline ticket cracking but
contributed to its deprecation in TLS (RFC 7465) and its classification as
cryptographically weak by NIST.

### Status

- RFC 8429 (2018) formally deprecated RC4 for Kerberos.
- CVE-2026-20833 ended RC4 as the **implicit default**.  Domain controllers with the April
  2026 update or later treat an unset service account as AES-only (`0x18`).
- RC4 has not been removed from Windows.  It is still issued where an account's
  `msDS-SupportedEncryptionTypes` or an explicit `DefaultDomainSupportedEncTypes` lists it
  (lab, enforcing build; Microsoft's KB5073381 says explicit configuration continues to be
  honored).
- See [RC4 Deprecation](rc4-deprecation.md) for the timeline.

---

## AES128-CTS-HMAC-SHA1-96 (Etype 17)

### Key derivation

AES keys use **PBKDF2-HMAC-SHA1** with a realm-and-principal salt and 4096 iterations,
followed by the Kerberos key-derivation step from RFC 3962:

```
tkey       = PBKDF2(HMAC-SHA1, UTF-8(password), salt, 4096, 128 bits)
AES128 key = DK(tkey, "kerberos")

Salt (user)     = REALM + user name             e.g. "CORP.LOCALalice"
Salt (computer) = REALM + "host" + name + "." + realm
                                                e.g. "CORP.LOCALhostws01.corp.local"
```

The salt is the uppercase realm followed by the account's user name (its
`sAMAccountName`); for a computer account it is the uppercase realm, the literal `host`,
the lowercase computer name without the trailing `$`, a dot, and the lowercase realm
([MS-KILE] section 3.1.1.2).  The same password produces **different keys for different
accounts**, which defeats rainbow tables and precomputation.

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
tkey       = PBKDF2(HMAC-SHA1, UTF-8(password), salt, 4096, 256 bits)
AES256 key = DK(tkey, "kerberos")
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

This is not a cipher -- it is a **configuration flag** (bit `0x20`) introduced by the
November 2022 update (CVE-2022-37966).  [MS-KILE] section 2.2.7 defines it as "Enforce AES
session keys when legacy ciphers are in use."  In effect it tells the KDC:

> "Even if the service ticket must use RC4 because the target account's etype set has no
> AES bits, use AES256 for the **session key**."

This produces the split-etype output visible in `klist`:

```
KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
Session Key Type:           AES-256-CTS-HMAC-SHA1-96
```

Ticket and session-key etypes are chosen separately ([RFC 4120] section 3.1.3 takes the
session key type from the client's etype list).  What the November 2022
update changed, per Microsoft's KB5021131, is the **default**: it "set AES as the default
encryption type for session keys on accounts that are not marked with a default encryption
type already", by making the built-in fallback `0x27` (DES + RC4 + AES-SK).  An unset
account then kept its RC4 ticket, and a client that listed AES256 first got an AES256
session key (in the lab, a client that listed RC4 first still received an RC4 one).

The `0x20` bit is honored in both `DefaultDomainSupportedEncTypes` and per-account
`msDS-SupportedEncryptionTypes`.  Setting `msDS-SupportedEncryptionTypes = 0x24`
(RC4 + AES-SK) on an individual account produced RC4 tickets with AES256 session keys even
when DDSET lacked the bit (lab, pre-April 2026 build).

Since the April 2026 update the built-in fallback is `0x18`, so the flag no longer does
anything for unset accounts.  It remains relevant only where RC4 is kept **explicitly**:
Microsoft's KB5073381 recommends `0x24` on the service account for a non-Windows device that
cannot accept AES tickets.  The split itself has not been reproduced here on an enforcing
build: the only test there used a client that lists RC4 first, which received an RC4 session
key.

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
| **Key derivation** | string-to-key + salt | MD4, no salt | PBKDF2 + salt, 4096 iter, then DK | PBKDF2 + salt, 4096 iter, then DK |
| **Salt** | Yes | **No** | Yes | Yes |
| **Cipher type** | Block | Stream | Block | Block |
| **Integrity** | CRC32 / MD5 | HMAC-MD5 | HMAC-SHA1-96 | HMAC-SHA1-96 |
| **Crack speed (relative, approximate)** | Trivial | 1× (baseline) | ~400× slower or more | ~800× slower or more |
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
| Computer/service key | Auto-generated computer password | Computer account object | Every 30 days by default (Microsoft's [machine account password age](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age) policy reference) |
| KRBTGT key | KRBTGT account password (random, generated by the DC) | KRBTGT account object | Only when an administrator triggers a reset |
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
DC (the lab's Server 2022 DCs showed DES-CBC-MD5, RC4, AES128 and AES256 keys; DES-CBC-CRC
was not recorded):

- DES-CBC-CRC key
- DES-CBC-MD5 key
- RC4-HMAC key (= NT hash)
- AES128-CTS-HMAC-SHA1-96 key
- AES256-CTS-HMAC-SHA1-96 key

`msDS-SupportedEncryptionTypes` tells the KDC which stored keys it should *consider
using*.  It does **not** control which keys are generated.  In the lab every service
account held DES, RC4, AES128 and AES256 keys whatever its attribute said.

**AES keys exist only if the password was set after the domain could generate them.**  If
an account's password was last set while the domain was still at the Windows Server 2003
functional level, the DC stored only DES and RC4 keys.  Changing
`msDS-SupportedEncryptionTypes` to `0x18` on that account does not create AES keys
retroactively -- the password must be set again.

**A password set from a hash creates no AES keys.**  AES keys are derived from the cleartext
password and a salt, so a tool that writes an NT hash directly (some migration and
synchronisation tools, impacket's `changepasswd.py -newhashes`) leaves the account with an
RC4 key only.  This was reproduced in the lab and is a common reason a "recently reset"
account still has no AES keys.

### Password resets and AES keys { #password-resets-and-aes-keys }

<a id="the-double-reset-problem"></a>**One password reset is enough.**  A single password set, with a cleartext password, on a
domain that generates AES keys writes the account's current AES128 and AES256 keys.
Microsoft's guidance is the same: "Changing the account password generates these keys."

Older versions of this page described a "double-reset problem" in which the first reset
wrote AES keys to a secondary credential set and only a second reset made them usable.  That
mechanism has **no source and was never reproduced in the lab**, and it is withdrawn.
`supplementalCredentials` does hold two Kerberos packages (`Primary:Kerberos` and
`Primary:Kerberos-Newer-Keys`), but both are written together on every password set; there
is no promotion step.

Where "reset twice" *is* correct is the **krbtgt** account and **trust** accounts.  Those
keep the previous password's keys so that tickets issued under the old key still validate,
and resetting twice is how you retire an old or compromised key.  See
[KRBTGT](#krbtgt-special-considerations).

!!! warning "Reset once, then verify"
    Do not assume a reset produced AES keys -- check.  If verification still shows no AES
    keys, find out why (password written as a hash, or by a tool that bypasses the DC's
    normal password-set path) before resetting again.  See
    [Auditing Kerberos Keys](account-key-audit.md) for all four methods.

    ```powershell title="Verify Kerberos key types stored for an account via DSInternals"
    Install-Module -Name DSInternals -Force
    $account = Get-ADReplAccount -SamAccountName svc_sql -Server DC1
    $account.SupplementalCredentials.KerberosNew.Credentials
    ```

    Look for `AES256_CTS_HMAC_SHA1_96` and `AES128_CTS_HMAC_SHA1_96` entries.

### Finding the AES cutover date

The **Read-Only Domain Controllers** group (RID 521) is created when the domain is prepared
for Windows Server 2008 domain controllers.  Its creation date is a workable estimate of
when the domain first could generate AES keys, but it is a heuristic: the group can predate
the functional-level raise.  A key audit is the authoritative check.

```powershell title="Find the date AES keys became available in the domain"
(Get-ADGroup -Filter * -Properties SID, WhenCreated |
    Where-Object { $_.SID -like '*-521' }).WhenCreated
```

An account with `passwordLastSet` earlier than this date almost certainly lacks AES keys.
An account with a later date *probably* has them, unless its password was written as a hash.

---

## When Keys Are Missing

An account that has only an RC4 key cannot be issued a service ticket once its effective
etype set is AES-only.  That happens when you set `msDS-SupportedEncryptionTypes = 0x18` on
it, and -- on a DC with the April 2026 update -- also when the account is simply **unset**,
because the default is now `0x18`.  The KDC returns `KDC_ERR_ETYPE_NOSUPP`; it does not fall
back to RC4 (lab, build 20348.5020).  The DC logs:

- **Event ID 14** (System log, `Kerberos-Key-Distribution-Center`) for AS requests
- **Event ID 16** for TGS requests.  Event 16 fires on any TGS failure of this kind,
  including a client/account etype mismatch, so read the etype lists in its text.
- Per Microsoft's KB5073381, **Kdcsvc 204** (unset account with only insecure keys) or
  **Kdcsvc 209** (AES-only account without AES keys).  Neither was triggered in the lab.

The event text identifies the mismatch explicitly:

```
While processing a TGS request for the target server <service>, the account <name> did
not have a suitable key for generating a Kerberos ticket (the missing key has an ID of <n>).
The requested etypes were 18 17. The accounts available etypes were 23. Changing or
resetting the password of <name> will generate a proper key.
```

Etype 23 is RC4; 17 and 18 are AES128 and AES256.  The fix is a password reset to generate
the missing AES keys.  If the service must keep working before that can happen, an explicit
`msDS-SupportedEncryptionTypes = 0x1C` lets the KDC use the RC4 key it has (lab).

---

## KRBTGT: Special Considerations

The KRBTGT key encrypts **every TGT in the domain**.  Nobody chooses its password: when an
administrator resets the account, the DC discards whatever was typed and generates a random
one (Microsoft's [krbtgt reset procedure](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password):
"the system generates a strong password automatically independent of the password that you
specify").  Nothing rotates it automatically.

- Where krbtgt has AES keys, TGTs are encrypted with AES256 (lab).  A krbtgt whose password
  has not been reset since before the domain generated AES keys has none; Microsoft's
  KB5021131 describes System event 42 ("The Kerberos Key Distribution Center lacks strong
  keys for account: accountname.") as the signal.
- The KDC keeps the **current and the previous** krbtgt key and accepts TGTs encrypted with
  either (Microsoft's reset procedure: "The password history value for the krbtgt account is
  2, meaning it includes the two most recent passwords").  A **single** rotation therefore does not invalidate outstanding TGTs; they keep
  working until they expire.
- Rotating **twice** removes the old key entirely.  Done back to back, the second rotation
  invalidates every TGT issued under the original key, so sessions must re-authenticate.
  Done with at least the maximum ticket lifetime (10 hours by default) and full replication
  between the two, nothing breaks.
- Rotate on a schedule (every 180 days is a common target), and twice in quick succession
  only when responding to a compromise, where invalidating existing TGTs is the point.
- Use a controlled script for the rollout across multiple DCs: Microsoft's
  `New-KrbtgtKeys.ps1`, or the community `Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1`.
  See [Mitigations — KRBTGT rotation](mitigations.md#priority-9-krbtgt-password-rotation).
- If the KRBTGT key is compromised, an attacker can forge Golden Tickets -- TGTs
  encrypted with the KRBTGT key and carrying arbitrary PAC contents.  See
  [Golden Ticket](../attacks/forgery/golden-ticket.md) for the attack mechanics.
