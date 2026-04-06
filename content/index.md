# Kerberos in Active Directory

A comprehensive guide to Kerberos authentication in Microsoft Windows Active Directory -- how the protocol works, how to configure it securely, and how attackers exploit it.

---

## Who This Is For

This site is written for three audiences:

- **System administrators and network engineers** who manage Active Directory and need to understand what happens when a user logs in, how encryption types are negotiated, and how to harden their environment against modern attacks.
- **Security teams** responsible for detecting and preventing Kerberos-based attacks, configuring encryption policies, and preparing for the RC4 deprecation timeline.
- **Red teamers and penetration testers** who need a deep understanding of the protocol to execute and explain Kerberos attacks, and who want to understand exactly *why* each attack works at the protocol level.

No prior Kerberos knowledge is required. The site starts from first principles and builds up.

Already familiar with Kerberos and just need to get your domain to AES? Jump straight to the
[Standardization Guide](security/aes-standardization.md).

---

## Three Sections

<div class="grid cards" markdown>

-   **[Protocol](protocol/index.md)**

    ---

    How Kerberos works from the ground up: the three-party model, AS/TGS/AP exchanges, ticket structure, pre-authentication, encryption types, cross-realm authentication, and delegation.

    Start here if you are new to Kerberos.

-   **[Security](security/index.md)**

    ---

    Configuring Kerberos for security: encryption type negotiation, key derivation, the `msDS-SupportedEncryptionTypes` attribute, registry and Group Policy settings, the RC4 deprecation timeline (CVE-2026-20833), and mitigations.

    Start here if you need to secure an existing AD environment.

-   **[Attacks](attacks/index.md)**

    ---

    Every major Kerberos attack targeting key-based authentication: roasting (Kerberoast, AS-REP, AS-REQ), credential theft (pass-the-ticket, pass-the-key, spraying), ticket forgery (golden, silver, diamond, sapphire), and delegation abuse (unconstrained, constrained, RBCD, S4U, SPN-jacking). Each page covers how it works, how to defend, how to detect, and how to exploit.

    Start here if you already understand the protocol and want to focus on offensive or defensive techniques.

</div>

---

## Key Concepts

### SPN-Bearing Account Types { #spn-bearing-account-types }

--8<-- "includes/spn-account-types.md"

---

## Prerequisites

To get the most out of this guide, you should be comfortable with:

- Basic TCP/IP networking (DNS, ports, client-server communication)
- Windows domain concepts (Active Directory, domain controllers, user accounts, group membership)
- Command-line tools (PowerShell, Linux shell)

No cryptography background is needed -- encryption concepts are explained as they come up.

---

## Authoritative References

This guide is grounded in the official protocol specifications. Inline references like `[RFC 4120 §3.1]` or `[MS-KILE §3.3.5.7]` point to the source material throughout the site.

### Kerberos Protocol

| Document | Description |
|---|---|
| [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) | The Kerberos Network Authentication Service (V5) -- the authoritative base protocol specification |
| [RFC 6806](https://datatracker.ietf.org/doc/html/rfc6806) | Kerberos Principal Name Canonicalization and Cross-Realm Referrals |
| [RFC 4556](https://datatracker.ietf.org/doc/html/rfc4556) | Public Key Cryptography for Initial Authentication in Kerberos (PKINIT) |
| [RFC 6113](https://datatracker.ietf.org/doc/html/rfc6113) | A Generalized Framework for Kerberos Pre-Authentication (FAST) |

### Cryptographic Specifications

| Document | Description |
|---|---|
| [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961) | Encryption and Checksum Specifications for Kerberos 5 -- the cryptographic framework |
| [RFC 3962](https://datatracker.ietf.org/doc/html/rfc3962) | Using AES Encryption with Kerberos 5 (AES-CTS-HMAC-SHA1-96) |
| [RFC 6649](https://datatracker.ietf.org/doc/html/rfc6649) | Deprecate DES, RC4-HMAC-EXP, and Other Weak Cryptographic Algorithms in Kerberos |
| [RFC 7465](https://datatracker.ietf.org/doc/html/rfc7465) | Prohibiting RC4 Cipher Suites |
| [RFC 8429](https://datatracker.ietf.org/doc/html/rfc8429) | Deprecate Triple-DES (3DES) and RC4 within Kerberos |

### Microsoft Open Specifications

| Document | Description |
|---|---|
| [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) | Kerberos Protocol Extensions -- Windows-specific additions to the base protocol |
| [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) | Privilege Attribute Certificate Data Structure -- the authorization data inside Kerberos tickets |
| [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) | Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol |
| [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) | Active Directory Technical Specification -- AD object classes, attributes, and protocol behavior |
| [MS-APDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/) | Authentication Protocol Domain Support -- how domain controllers process authentication requests |
| [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) | Directory Replication Service Remote Protocol -- used by DCSync and key extraction techniques |
| [MS-RPRN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/) | Print System Remote Protocol -- abused for authentication coercion (Printer Bug) |
| [MS-EFSRPC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsrpc/) | Encrypting File System Remote Protocol -- abused for authentication coercion (PetitPotam) |
| [MS-DFSNM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/) | Distributed File System (DFS): Namespace Management Protocol -- abused for authentication coercion |

### Security Advisories

| Advisory | Title | Impact |
|---|---|---|
| [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) | Windows LSA Spoofing (PetitPotam) | Unauthenticated NTLM relay via EFS RPC coercion |
| [CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) | AD Elevation of Privilege (sAMAccountName spoofing) | PAC_REQUESTOR validation; noPAC attack |
| [KB5008380](https://support.microsoft.com/help/5008380) | Authentication updates (CVE-2021-42287) | Introduced PAC re-validation on TGS exchanges |
| [CVE-2022-26923](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923) | AD Domain Services Elevation of Privilege | Certificate-based machine account privilege escalation |
| [CVE-2022-37966](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37966) | Windows Kerberos RC4-HMAC Elevation of Privilege | KDC defaults to AES session keys; introduces `DefaultDomainSupportedEncTypes` |
| [CVE-2022-37967](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37967) | Windows Kerberos Elevation of Privilege | PAC SID filtering enforcement |
| [KB5021131](https://support.microsoft.com/help/5021131) | Kerberos protocol changes (CVE-2022-37966) | November 2022 etype behavior changes |
| [KB5020009](https://support.microsoft.com/help/5020009) | Kerberos and Netlogon errors after November 2022 updates | Enforcement guidance for CVE-2022-37967 |
| [CVE-2026-20833](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20833) | Windows Kerberos RC4 Default Removal | Removes RC4 as the implicit default etype for accounts without explicit `msDS-SupportedEncryptionTypes` |
| [KB5073381](https://support.microsoft.com/help/5073381) | Kerberos RC4 default removal (CVE-2026-20833) | Audit and enforcement timeline; Kdcsvc events 201--209 |
| [CVE-2026-20849](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20849) | Windows Kerberos S4U PA-FOR-USER Deprecation | Replaces `PA-FOR-USER` with `PA-S4U-X509-USER` in S4U2Self requests |

---

## Tools

Attack pages use [kerbwolf](https://github.com/StrongWind1/KerbWolf) and [impacket](https://github.com/fortra/impacket) for examples. See the [Tools Setup](attacks/tools.md) page for installation instructions.

### kerbwolf

[kerbwolf](https://github.com/StrongWind1/KerbWolf) -- Kerberos roasting and TGT attack toolkit:

| Tool | Purpose |
|---|---|
| `kw-roast` | TGS-REP roasting (Kerberoasting) |
| `kw-asrep` | AS-REP roasting |
| `kw-extract` | Offline hash extraction from pcap captures |
| `kw-tgt` | TGT acquisition (pass-the-key / overpass-the-hash) |

### Microsoft Kerberos-Crypto

[Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto) -- Microsoft's official PowerShell scripts for assessing RC4 usage and key readiness:

| Script | Purpose |
|---|---|
| `Get-KerbEncryptionUsage.ps1` | Detect RC4 usage from Event IDs 4768/4769 across all KDCs |
| `List-AccountKeys.ps1` | List Kerberos key types stored for each account |

See [Detect Kerberos RC4 usage](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4) for Microsoft's official usage guidance.  These scripts are used directly in the [RC4 Deprecation](security/rc4-deprecation.md#step-2-identify-rc4-usage) pre-enforcement checklist.
