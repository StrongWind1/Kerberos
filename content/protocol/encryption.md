# Encryption Types

The cryptographic algorithms used to protect Kerberos messages.

An encryption type (etype) in Kerberos defines three things bundled together: the **cipher
algorithm** (how data is encrypted), the **integrity check** (how tampering is detected), and the
**key derivation method** (how a password becomes an encryption key). When you see a Kerberos
ticket encrypted with "AES-256", that shorthand actually refers to a specific combination of all
three.

Per [RFC 3961], the Kerberos encryption framework abstracts these details behind an etype number,
so the protocol can negotiate which combination to use without caring about the internals.

---

## Encryption Types in Active Directory

Active Directory Kerberos supports five encryption types. Two are obsolete, one is being
deprecated, and two are the current standard.

### The Full Table

| Etype | Number | Key Size | Cipher | Integrity | Salt | Status |
|---|---|---|---|---|---|---|
| DES-CBC-CRC | 1 | 56-bit | DES-CBC | CRC-32 | Yes | **Removed** -- disabled since Windows 7 / Server 2008 R2; removed entirely in Server 2025 |
| DES-CBC-MD5 | 3 | 56-bit | DES-CBC | MD5 | Yes | **Removed** -- same timeline as DES-CBC-CRC |
| RC4-HMAC | 23 (0x17) | 128-bit | RC4 | HMAC-MD5 | **No** | **Deprecated** -- still supported but being phased out |
| AES128-CTS-HMAC-SHA1-96 | 17 (0x11) | 128-bit | AES-128-CTS | HMAC-SHA1-96 | Yes | **Supported** -- since Server 2008 / Vista |
| AES256-CTS-HMAC-SHA1-96 | 18 (0x12) | 256-bit | AES-256-CTS | HMAC-SHA1-96 | Yes | **Preferred** -- strongest available, default in modern deployments |

---

## DES-CBC-CRC (Etype 1) and DES-CBC-MD5 (Etype 3)

These are the original Kerberos encryption types from the 1990s. Both use 56-bit DES encryption,
which has been trivially breakable for decades.

- **DES-CBC-CRC**: Uses a CRC-32 checksum for integrity. CRC-32 is not cryptographic -- it
  detects accidental corruption but not intentional tampering.
- **DES-CBC-MD5**: Uses an MD5 hash for integrity. Better than CRC-32, but the underlying 56-bit
  DES encryption is the real weakness.

!!! warning "Never use DES"
    DES was disabled by default starting with Windows 7 and Windows Server 2008 R2. It was
    completely removed in Windows Server 2025. If you find DES enabled in your environment, disable
    it immediately. Any account using DES keys is trivially compromised.

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

- `password = "Password1!"` produces the same key regardless of which domain the user is in,
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

!!! warning "RC4 deprecation timeline"
    Microsoft has been phasing out RC4-HMAC since November 2022 (KB5021131). Starting with the
    enforcement phase, domain controllers will no longer issue RC4-encrypted tickets when AES is
    available. Plan your migration to AES now.

    The [Security section](../security/rc4-deprecation.md) covers the full deprecation timeline
    and migration steps.

---

## AES128-CTS-HMAC-SHA1-96 (Etype 17)

AES-128 support was introduced in Windows Server 2008 and Windows Vista. It uses:

- **AES-128** in CTS (Cipher Text Stealing) mode for encryption
- **HMAC-SHA1-96** (truncated to 96 bits) for integrity
- **PBKDF2-HMAC-SHA1** with **4,096 iterations** for key derivation

### Key Derivation

```
password + salt --> PBKDF2(HMAC-SHA1, password, salt, 4096, 16) --> 16-byte key
```

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
password + salt --> PBKDF2(HMAC-SHA1, password, salt, 4096, 32) --> 32-byte key
```

This is the **strongest encryption type** available in Active Directory Kerberos and should be the
preferred choice in all modern deployments.

---

## Salt Composition

For AES encryption types, the salt is constructed per [MS-KILE &sect;3.1.5.2]:

| Account Type | Salt Format | Example |
|---|---|---|
| User account | `REALM` (uppercase) + `sAMAccountName` | `CORP.LOCALalice` |
| Computer account | `REALM` (uppercase) + `host/` + hostname`.`realm (lowercase) | `CORP.LOCALhost/ws01.corp.local` |

!!! info "Salt is deterministic"
    The salt is not stored separately -- it is derived from the account's realm and principal name.
    This means renaming an account changes the salt, which changes the AES key, even if the
    password stays the same. When renaming accounts with keytab files, the keytab must be
    regenerated. See [MS-KILE &sect;3.1.5.2] for the full salt construction rules.

---

## How Encryption Types Are Negotiated

The client includes a list of supported etypes in AS-REQ and TGS-REQ messages, and the KDC
selects the strongest type that both sides support.  Different parts of a single exchange can use
different etypes -- the TGT ticket, the session key, and the reply each have independently
selected etypes.  The [Encryption Type Negotiation](../security/etype-negotiation.md) page in the
Security section covers the full negotiation rules, and the
[Etype Decision Guide](../security/etype-decision-guide.md) maps every input that affects the
outcome.

!!! tip "Different etypes in the same ticket"
    It is common to see a service ticket encrypted with RC4 (because the target account has no
    explicit `msDS-SupportedEncryptionTypes`) while the session key inside it is AES256.  Since
    the November 2022 update (CVE-2022-37966), the KDC defaults to AES256 session keys even when
    the ticket itself is RC4.  "RC4 by default" refers to **service ticket encryption**, not the
    session key.  Always check both the `KerbTicket Encryption Type` and `Session Key Type` in
    `klist` output -- they can differ.

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
- DES (etypes 1 and 3) is dead -- removed in Server 2025
- RC4-HMAC (etype 23) is dangerous: no salt, key equals the NT hash, fast to crack, being
  deprecated
- AES-128 (etype 17) and AES-256 (etype 18) are the current standard: salted, PBKDF2 with 4,096
  iterations, significantly harder to crack
- For a deep comparison of each algorithm's key derivation, cracking speed, and status, see
  [Algorithms](../security/algorithms.md)
- The KDC negotiates the encryption type based on what the client supports, what the target
  account supports, and what the domain policy allows -- see
  [Encryption Type Negotiation](../security/etype-negotiation.md) for the full rules
- Migrating from RC4 to AES requires verifying all accounts have AES keys and updating policies --
  see the [RC4 Deprecation](../security/rc4-deprecation.md) timeline and the
  [Standardization Guide](../security/aes-standardization.md) for the operational playbook
