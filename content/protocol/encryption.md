---
description: The Kerberos encryption types Active Directory supports -- DES, RC4-HMAC, and AES -- with key derivation, salt construction, and the current status of each.
---

# Encryption Types

The cryptographic algorithms used to protect Kerberos messages.

An encryption type (etype) in Kerberos defines three things bundled together: the **cipher
algorithm** (how data is encrypted), the **integrity check** (how tampering is detected), and the
**key derivation method** (how a password becomes an encryption key). When you see a Kerberos
ticket encrypted with "AES-256", that shorthand actually refers to a specific combination of all
three.

Per [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961), the Kerberos encryption framework abstracts these details behind an etype number,
so the protocol can negotiate which combination to use without caring about the internals.

---

## Encryption Types in Active Directory

Five encryption types matter in practice for Active Directory Kerberos. Two are obsolete and
gone from current Windows, one is deprecated and no longer used by default, and two are the
current standard. Two further AES types exist in the specification but are disabled by default.

### The Full Table

| Etype | Number | Key Size | Cipher | Integrity | Salt | Status |
|---|---|---|---|---|---|---|
| DES-CBC-CRC | 1 | 56-bit | DES-CBC | CRC-32 | Yes | **Removed** -- disabled by default since Windows 7 / Server 2008 R2; removed from Windows 11 24H2 and Windows Server 2025 |
| DES-CBC-MD5 | 3 | 56-bit | DES-CBC | MD5 | Yes | **Removed** -- same timeline as DES-CBC-CRC |
| RC4-HMAC | 23 (0x17) | 128-bit | RC4 | HMAC-MD5 | **No** | **Deprecated** -- on DCs with the April 2026 cumulative update or later, used only where an account or an explicit `DefaultDomainSupportedEncTypes` lists it, or where the April-June 2026 rollback described [below](#rc4-hmac-etype-23) was applied |
| AES128-CTS-HMAC-SHA1-96 | 17 (0x11) | 128-bit | AES-128-CTS | HMAC-SHA1-96 | Yes | **Supported** -- since Server 2008 / Vista |
| AES256-CTS-HMAC-SHA1-96 | 18 (0x12) | 256-bit | AES-256-CTS | HMAC-SHA1-96 | Yes | **Preferred** -- strongest type in default use |
| AES128-CTS-HMAC-SHA256-128 | 19 (0x13) | 128-bit | AES-128-CTS | HMAC-SHA256-128 | Yes | **Disabled by default** -- [RFC 8009](https://datatracker.ietf.org/doc/html/rfc8009); per [MS-KILE &sect;2.2.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919), supported in Windows 11 24H2 and Windows Server 2025 and later |
| AES256-CTS-HMAC-SHA384-192 | 20 (0x14) | 256-bit | AES-256-CTS | HMAC-SHA384-192 | Yes | **Disabled by default** -- same as etype 19 |

The rest of this page covers etypes 1, 3, 17, 18, and 23. The two SHA-2 types are listed for
completeness: this site has not tested them, and nothing here depends on them.

---

## DES-CBC-CRC (Etype 1) and DES-CBC-MD5 (Etype 3)

These are the original Kerberos encryption types from the 1990s. Both use 56-bit DES encryption,
which has been trivially breakable for decades.

- **DES-CBC-CRC**: Uses a CRC-32 checksum for integrity. CRC-32 is not cryptographic -- it
  detects accidental corruption but not intentional tampering.
- **DES-CBC-MD5**: Uses an MD5 hash for integrity. Better than CRC-32, but the underlying 56-bit
  DES encryption is the real weakness.

!!! warning "Never use DES"
    DES was disabled by default starting with Windows 7 and Windows Server 2008 R2. Microsoft
    lists it as removed from Windows 11 version 24H2 and Windows Server 2025 and later. If you
    find DES enabled on older systems in your environment, disable it immediately. Any account
    using DES keys is trivially compromised.

    The `USE_DES_KEY_ONLY` bit (`0x200000`) in the `userAccountControl` attribute forces an
    account to use only DES. Check for it:

    ```powershell
    Get-ADUser -Filter 'UserAccountControl -band 0x200000'
    ```

---

## RC4-HMAC (Etype 23)

RC4-HMAC is the encryption type introduced with Windows 2000. For over two decades, it was the
default encryption type for user accounts in Active Directory.

### Key Derivation

```
password --> UTF-16LE encoding --> MD4 hash --> 16-byte key
```

That is it. The key is the **NT hash** of the password. No salt, no iterations, no key stretching.

- `password = "Example-Passw0rd"` produces the same key regardless of which domain the user is in,
  what their username is, or what realm they belong to.
- The key is identical to the NTLM authentication hash. If you have the NT hash, you have the
  RC4-HMAC key, and vice versa.

### Why RC4 Is Dangerous

**No salt**
:   Two users with the same password in different domains have the same RC4 key. This means
    precomputed rainbow tables work across all domains. AES keys include the realm and username in
    the salt, making precomputation infeasible.

**Identical to the NT hash**
:   The RC4 key is the NT hash. An attacker who extracts NT hashes from a domain controller
    (via DCSync, NTDS.dit extraction, or memory dumping) immediately has the RC4-HMAC keys. This
    enables [Pass-the-Key](../attacks/credential-theft/pass-the-key.md) attacks directly.

**Fast to crack**
:   RC4-HMAC keys are dramatically faster to brute-force than AES keys because MD4 is a single
    pass with no iterations, while AES key derivation uses PBKDF2 with 4,096 iterations.
    See [Algorithms — Cracking Speed](../security/algorithms.md#cracking-speed-comparison) for
    benchmarks.

**Stream cipher weaknesses**
:   RC4 is a stream cipher with known biases. While these biases are mostly relevant to TLS
    (where large amounts of ciphertext are available), they add to the overall weakness profile.

!!! warning "RC4 is no longer the default"
    Microsoft began moving Active Directory off RC4-HMAC in November 2022 (KB5021131) and
    changed the default in 2026 (CVE-2026-20833):

    - On domain controllers with the **April 2026 cumulative update or later**, an account with
      no `msDS-SupportedEncryptionTypes` value is treated as `0x18` (AES128 and AES256 only),
      unless `DefaultDomainSupportedEncTypes` is set explicitly on the DC.
    - The April, May and June 2026 updates left one more exception.
      [KB5073381](https://support.microsoft.com/help/5073381) calls 14 April 2026 the "Enforcement Phase with manual rollback": on those
      updates an administrator could set the temporary `RC4DefaultDisablementPhase` registry
      value back to `0` or `1`, and such a DC kept the old `0x27` default (observed in this
      site's lab on Server 2022 build 20348.5020). The same article says updates released in or
      after July 2026 remove support for that value.
    - Before the April 2026 update, the built-in default for such accounts was `0x27`, which
      includes RC4.
    - The change is gated by the update installed on each DC, not by the calendar. A domain with
      DCs at different patch levels behaves differently depending on which DC answers.
    - Apart from that rollback window, RC4 remains available only where an account's
      `msDS-SupportedEncryptionTypes` or an explicit `DefaultDomainSupportedEncTypes` lists it.

    This site has not lab-verified any build released after July 2026. The
    [Security section](../security/rc4-deprecation.md) covers the timeline, the events to look
    for, and how to handle systems that still need RC4.

---

## AES128-CTS-HMAC-SHA1-96 (Etype 17)

AES-128 support was introduced in Windows Server 2008 and Windows Vista. It uses:

- **AES-128** in CTS (Cipher Text Stealing) mode for encryption
- **HMAC-SHA1-96** (truncated to 96 bits) for integrity
- **PBKDF2-HMAC-SHA1** with **4,096 iterations** for key derivation

### Key Derivation

```
tkey = random-to-key(PBKDF2(HMAC-SHA1, password, salt, 4096, 16))
key  = DK(tkey, "kerberos")                                        --> 16-byte key
```

The PBKDF2 output is an intermediate value, not the key. [RFC 3962 &sect;4](https://datatracker.ietf.org/doc/html/rfc3962#section-4) passes it through the
`DK` key-derivation function of [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961) with the constant string `"kerberos"` to produce the
long-term key. A tool that stops at PBKDF2 computes the wrong key.

The salt prevents precomputation. The 4,096 PBKDF2 iterations add computational cost to each
password guess, making brute-force attacks significantly slower than RC4.

---

## AES256-CTS-HMAC-SHA1-96 (Etype 18)

AES-256 is the same as AES-128 but with a 256-bit key:

- **AES-256** in CTS mode for encryption
- **HMAC-SHA1-96** (truncated to 96 bits) for integrity
- **PBKDF2-HMAC-SHA1** with **4,096 iterations** for key derivation

### Key Derivation

```
tkey = random-to-key(PBKDF2(HMAC-SHA1, password, salt, 4096, 32))
key  = DK(tkey, "kerberos")                                        --> 32-byte key
```

This is the **strongest encryption type in default use** in Active Directory Kerberos and should
be the preferred choice in all modern deployments.

---

## Salt Composition

For AES encryption types, the salt is constructed per [MS-KILE &sect;3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/7a7b081d-c0c6-46f4-acbf-a439664270b8):

| Account Type | Salt Format | Example |
|---|---|---|
| User account | Realm DNS name in uppercase + user name | `CORP.LOCALalice` |
| Computer account | Realm DNS name in uppercase + `host` + computer name in lowercase without the trailing `$` + `.` + realm DNS name in lowercase | `CORP.LOCALhostws01.corp.local` |

There is no slash in the computer form: the literal string `host` is followed directly by the
computer name. [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9) defines only these two forms. gMSA and MSA objects are derived from the
computer class, and the `krbtgt` account and trust accounts are user objects, but this site has
not verified the salts of managed service accounts, `krbtgt`, or trust accounts in a lab. Read
the real value as described below instead of assuming it.

!!! info "The salt is stored with the keys"
    Active Directory computes an account's keys **when its password is set** and stores them
    together with the salt that was used ([MS-SAMR &sect;3.1.1.8.11.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/f3fd5c77-7a63-43dc-ac8d-598ca374a5a3) for the computation,
    [&sect;2.2.10.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/08cb3ca7-954b-45e3-902e-77512fe3ba8e) for the stored `DefaultSalt` field). The KDC hands that stored salt to the client in
    `PA-ETYPE-INFO2` during the [AS exchange](as-exchange.md), which is why a client never has
    to guess it.

    Renaming an account therefore changes nothing by itself: the stored keys and salt stay as
    they were until the next password change, at which point new keys are computed with a salt
    built from the new name. This is the classic source of keytab trouble: a tool that builds
    a keytab by deriving the salt from the account's *current* name produces keys that do not
    match the directory if the account was renamed since its last password change. When in
    doubt, capture the `PA-ETYPE-INFO2` from a pre-authentication error and use the salt the
    KDC actually sends.

---

## How Encryption Types Are Negotiated

The client includes a list of supported etypes in AS-REQ and TGS-REQ messages, but that list is
not the whole story.  The etype of a **ticket** is chosen from what the *target* account supports
and has keys for -- the client cannot decrypt the ticket and its preference does not pick it.
The etype of the **session key** has to be one the client listed as well, because the client
uses that key.  So different parts of a single exchange can use different etypes -- the ticket,
the session key, and the reply each have independently selected etypes.  The [Encryption Type Negotiation](../security/etype-negotiation.md) page in the
Security section covers the full negotiation rules, and the
[Etype Decision Guide](../security/etype-decision-guide.md) maps every input that affects the
outcome.

!!! tip "Different etypes in the same ticket"
    Always check both the `KerbTicket Encryption Type` and the `Session Key Type` in `klist`
    output -- they can differ.

    The best-known example is historical.  On DCs patched between November 2022
    (CVE-2022-37966) and the April 2026 cumulative update, a service account with no explicit
    `msDS-SupportedEncryptionTypes` got the built-in default `0x27`: the service ticket was
    encrypted with RC4 while the session key inside it was AES256.  "RC4 by default" in older
    write-ups refers to that **ticket** encryption, not to the session key.

    On a DC with the April 2026 cumulative update or later, the same unconfigured account is
    treated as `0x18`, and both the ticket and the session key are AES.  An RC4 ticket now
    means RC4 was asked for by configuration: the account's `msDS-SupportedEncryptionTypes`
    lists RC4 and the account has no usable AES alternative, or the account is unconfigured and
    an explicit `DefaultDomainSupportedEncTypes` on the DC still selects RC4, or the DC is on an
    April-June 2026 update with the `RC4DefaultDisablementPhase` rollback in effect.  The
    [Etype Decision Guide](../security/etype-decision-guide.md) has the exact rules.

---

## Configuration

Encryption type selection in Active Directory is controlled by the per-account
[`msDS-SupportedEncryptionTypes`](../security/msds-supported.md) attribute,
[registry keys](../security/registry.md) on domain controllers, and
[Group Policy](../security/group-policy.md).  Getting these aligned is the single most important
step in securing Kerberos -- see the [Security section](../security/index.md) for the full
treatment.

---

## Summary

- An encryption type bundles a cipher, integrity check, and key derivation method under a single
  etype number
- DES (etypes 1 and 3) is dead -- removed from Windows 11 24H2 and Windows Server 2025
- RC4-HMAC (etype 23) is dangerous: no salt, key equals the NT hash, fast to crack. On DCs with
  the April 2026 cumulative update or later it is used only where explicitly configured, or
  where the temporary rollback offered by the April-June 2026 updates was applied
- AES-128 (etype 17) and AES-256 (etype 18) are the current standard: salted, PBKDF2 with 4,096
  iterations followed by DK, significantly harder to crack
- The salt is stored with the keys and changes only when the password is set
- For a deep comparison of each algorithm's key derivation, cracking speed, and status, see
  [Algorithms](../security/algorithms.md)
- The KDC picks the ticket etype from what the target account supports and the session-key
  etype from what the client also supports, within what the domain policy allows -- see
  [Encryption Type Negotiation](../security/etype-negotiation.md) for the full rules
- Removing the remaining RC4 use requires verifying all accounts have AES keys and updating
  policies -- see the [RC4 Deprecation](../security/rc4-deprecation.md) timeline and the
  [Standardization Guide](../security/aes-standardization.md) for the operational playbook

Next: [S4U Extensions](s4u.md), how a service obtains tickets on behalf of a user.
