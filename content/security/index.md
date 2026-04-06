# Configuring Kerberos Security

Practical guidance for securing Kerberos in your Active Directory environment.

---

## Why Defaults Matter

A fresh Active Directory domain -- even one running Server 2022 or Server 2025 -- permits
**RC4-HMAC** encryption by default for any account that does not have an explicit
`msDS-SupportedEncryptionTypes` value.  That single default is what makes
[Kerberoasting](../attacks/roasting/kerberoasting.md) devastating: any domain user can request a
service ticket, take it offline, and crack the user service account password.  When the ticket uses
RC4-HMAC, cracking runs at roughly **800 times the speed** of AES -- but AES tickets are still
crackable given weak passwords or sufficient time.  The default RC4 setting turns a slow attack
into a fast one.

The RC4 key is also identical to the NTLM hash (MD4 of the password), which means a
compromised RC4 key doubles as a pass-the-hash credential.  Out of the box, every user
account with a Service Principal Name (SPN) is exposed.

!!! warning "RC4 is being removed"
    Microsoft is eliminating RC4 as an implicit default through
    [CVE-2026-20833](rc4-deprecation.md).  The April 2026 update enforces AES-only for
    accounts without explicit configuration, and July 2026 makes that permanent.  Preparing
    now is not optional.

## Configuration Surface

Kerberos encryption behavior is controlled at **four layers**, each of which can override the
others.  Misunderstanding the interaction between them is the single most common cause of
encryption-related authentication failures.

| Layer | Where It Lives | What It Controls |
|---|---|---|
| **AD attribute** | `msDS-SupportedEncryptionTypes` on each account | Declares which etypes an account supports.  Always overrides the domain default. |
| **Registry (KDC)** | `DefaultDomainSupportedEncTypes` on each DC | Sets the assumed etypes for accounts with no `msDS-SupportedEncryptionTypes`. |
| **Registry (client)** | `SupportedEncryptionTypes` on each workstation/server | Controls what the Kerberos client will request in AS-REQ and TGS-REQ. |
| **Group Policy** | *Network security: Configure encryption types allowed for Kerberos* | Sets the allowed etypes on whichever machine the GPO targets (DC, client, or server). |

The attribute always wins.  If `msDS-SupportedEncryptionTypes` is set on an account, the
`DefaultDomainSupportedEncTypes` registry value has no effect for that account.  Group Policy,
when applied to a domain controller, restricts what the KDC will issue regardless of what any
account attribute says.

## The Goal

A hardened Kerberos deployment has three properties:

1. **AES-only encryption** -- RC4 and DES are never used for tickets or session keys.
2. **Strong user service account passwords** -- 25+ character random passwords, or (better) Group
   Managed Service Accounts with auto-rotating 240-character passwords.
3. **Least-privilege delegation** -- no unconstrained delegation outside domain controllers,
   Resource-Based Constrained Delegation (RBCD) preferred, and SPNs removed from any account
   that does not need them.

!!! tip "Just need to migrate to AES?"
    If you already understand Kerberos and just need the operational playbook, jump to the
    [Standardization Guide](aes-standardization.md).  Prerequisites:
    [RC4 Deprecation](rc4-deprecation.md) (timeline) and
    [Auditing Kerberos Keys](account-key-audit.md) (finding accounts without AES keys).

## Reading Order

This section is designed to be read in sequence.  Each page builds on concepts from the
previous one.

### Understanding Encryption

| Page | What You Will Learn |
|---|---|
| [Encryption Type Negotiation](etype-negotiation.md) | How the KDC decides which algorithm to use for each part of the AS and TGS exchanges. |
| [Etype Decision Guide](etype-decision-guide.md) | Visual map of every input that determines which encryption type is used -- from account keys to registry to GPO.  Includes 14 worked examples validated against a live DC. |

### Keys and Algorithms

| Page | What You Will Learn |
|---|---|
| [Algorithms & Keys](algorithms.md) | Every encryption type family, key derivation (MD4 vs PBKDF2), cracking speed comparison, how keys are stored in AD, the double-reset problem, and KRBTGT considerations. |

### Configuration Reference

| Page | What You Will Learn |
|---|---|
| [msDS-SupportedEncryptionTypes](msds-supported.md) | The AD attribute that drives etype selection.  Bit flags, defaults, and how to set it. |
| [Registry Settings](registry.md) | Every KDC and client registry key that affects Kerberos encryption. |
| [Group Policy Settings](group-policy.md) | GPO paths for etype control, ticket lifetimes, and auditing. |

### Migration

| Page | What You Will Learn |
|---|---|
| [RC4 Deprecation (CVE-2026-20833)](rc4-deprecation.md) | Timeline, event IDs, and a step-by-step migration plan. |
| [Auditing Kerberos Keys](account-key-audit.md) | Four methods to find accounts missing AES keys: PowerShell date comparison, DSInternals, impacket secretsdump, and ntdsutil + ntdissector. |
| [Standardization Guide](aes-standardization.md) | Step-by-step playbook for moving your domain to AES-only, with every registry key, AD attribute, and PowerShell command. |

### Operations

| Page | What You Will Learn |
|---|---|
| [Mitigations](mitigations.md) | Priority-ordered best practices: gMSA, Protected Users, SPN hygiene, and more. |
| [Troubleshooting](troubleshooting.md) | Diagnostic tools, event IDs, error codes, and Wireshark tips. |
