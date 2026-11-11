# Roasting Attacks

Offline credential cracking from Kerberos encrypted material.

Roasting attacks exploit a fundamental property of the Kerberos protocol: certain message fields
are encrypted with keys derived from user passwords. Any party that receives these encrypted
fields can attempt to crack them offline -- testing candidate passwords until one produces a
valid decryption. The KDC does not rate-limit or log the offline cracking phase, making these
attacks difficult to prevent once the encrypted material is obtained.

The cracking difficulty depends heavily on the encryption type. RC4-HMAC (etype 23) uses the
unsalted MD4 hash of the password as the key, making it
[dramatically faster to crack](../../security/algorithms.md#cracking-speed-comparison) than
AES-256, which derives the key through 4096 iterations of PBKDF2. Enforcing AES and
deprecating RC4 (see [RC4 Deprecation](../../security/rc4-deprecation.md)) is the single most
impactful mitigation across all roasting attacks.

What "enforcing AES" takes differs by attack. For Kerberoasting it is the target account's
`msDS-SupportedEncryptionTypes`; since the April 2026 updates (CVE-2026-20833), a domain
controller also treats an SPN-bearing account with no value as AES-only, so RC4 service tickets
are issued only where RC4 is still configured explicitly. That change covers service tickets
only. The AS exchange that AS-REP and AS-REQ Roasting target is not affected by it. In this
site's lab, removing RC4 from the domain controllers' Kerberos encryption-type policy also
blocked RC4 pre-authentication (one pre-April 2026 Server 2022 build, not re-run on later
builds), and for AS-REP Roasting the fix is removing `DONT_REQUIRE_PREAUTH`
rather than an encryption-type setting.

--8<-- "includes/authorized-use.md"

---

## Attacks in This Category

| Attack | Target | Auth Required | Encrypted Material | Hashcat Modes |
|--------|--------|---------------|--------------------|---------------|
| [Kerberoasting](kerberoasting.md) | User service accounts with SPNs | Domain user (or no-preauth account) | TGS-REP `enc-part` (encrypted with target account key) | 13100 (RC4), 19600 (AES128), 19700 (AES256) |
| [AS-REP Roasting](asrep-roasting.md) | Accounts with `DONT_REQUIRE_PREAUTH` | None | AS-REP outer `enc-part` (encrypted with target user's key) | 18200 (RC4), 32100 (AES128), 32200 (AES256) |
| [AS-REQ Roasting](asreq-roasting.md) | All authenticating users (passive capture) | Network position only | `PA-ENC-TIMESTAMP` from AS-REQ | 7500 (RC4), 19800 (AES128), 19900 (AES256) |

---

## Common Defenses

All three roasting attacks share overlapping defenses:

- **Enforce AES encryption** -- eliminate RC4 to make cracking dramatically harder (per
  account for service tickets; in the domain controllers' encryption-type policy for
  pre-authentication)
- **Strong passwords** -- 25+ random characters for user service accounts; use gMSA where possible
- **Honeypot accounts** -- detect enumeration and roasting attempts with decoy SPNs or
  no-preauth accounts
- **Network segmentation** -- limit access to Kerberos traffic (port 88) to reduce passive
  capture risk
