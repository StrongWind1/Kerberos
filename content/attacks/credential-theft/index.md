# Credential Theft and Reconnaissance

Using Kerberos to discover, test, and reuse credentials.

These attacks use the Kerberos protocol as an oracle for credential validation and account
discovery, or reuse stolen Kerberos artifacts (tickets and keys) to impersonate users. Unlike
[roasting attacks](../roasting/index.md), which require offline cracking, the attacks in this
category either test credentials in real time against the KDC or replay stolen material directly.

Most of these attacks require nothing more than network access to the domain controller on
port 88 -- no domain membership, no LDAP bind, and no existing credentials.

---

## Attacks in This Category

| Attack | Technique | Auth Required | Description |
|--------|-----------|---------------|-------------|
| [Pass-the-Ticket](pass-the-ticket.md) | Ticket injection | Stolen ticket | Extract cached TGTs or service tickets and inject them into a new session to impersonate the original user |
| [Pass-the-Key / Overpass-the-Hash](pass-the-key.md) | AS-REQ with stolen key | Stolen NT hash or AES key | Use a stolen encryption key to request a legitimate TGT from the KDC, converting an NTLM hash into Kerberos access |
| [Password Spraying](password-spraying.md) | AS-REQ pre-authentication | None (network access only) | Test common passwords against many accounts using Kerberos error codes as an oracle |
| [User Enumeration](user-enumeration.md) | AS-REQ error code analysis | None (network access only) | Discover valid Active Directory usernames by distinguishing `PRINCIPAL_UNKNOWN` from `PREAUTH_REQUIRED` |

---

## Tool Coverage

[CredWolf](https://github.com/) supports Kerberos-based credential testing and user enumeration:

- **`credwolf kerberos`** -- test passwords, NT hashes, AES keys, and ticket files against
  the KDC via pre-authentication (see [CredWolf Kerberos usage](https://github.com/))
- **`credwolf userenum`** -- enumerate valid usernames via bare AS-REQs without triggering
  login attempts or incrementing the bad-password counter

kerbwolf tools handle the offensive side:

- **`kw-tgt`** -- request TGTs with passwords, NT hashes, or AES keys (pass-the-key /
  overpass-the-hash)
- **`kw-asrep`** -- AS-REP Roasting with implicit user enumeration

---

## Common Defenses

- **Credential Guard** -- isolate LSASS secrets to prevent ticket and key extraction
- **Protected Users group** -- disable NTLM caching, reduce TGT lifetime to 4 hours, force AES
- **Short TGT lifetimes** -- limit the window during which a stolen ticket is usable
- **Account lockout policies** -- limit password spraying attempts (but beware of lockout-based
  denial of service)
- **Network rate limiting** -- restrict AS-REQ volume per source IP on port 88
