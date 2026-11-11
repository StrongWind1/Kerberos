---
description: How Kerberos works in Active Directory, how to configure it securely after the 2026 RC4 default removal, and how the well-known attacks against it work.
---

# Kerberos in Active Directory

A comprehensive guide to Kerberos authentication in Microsoft Windows Active Directory - how the protocol works, how to configure it securely, and how attackers exploit it.

---

## Who This Is For

This site is written for three audiences:

- **System administrators and network engineers** who manage Active Directory and need to understand what happens when a user logs in, how encryption types are negotiated, and how to harden their environment against modern attacks.
- **Security teams** responsible for detecting and preventing Kerberos-based attacks, configuring encryption policies, and operating a domain after the 2026 removal of RC4 as the default Kerberos encryption type.
- **Red teamers and penetration testers** who need a deep understanding of the protocol to execute and explain Kerberos attacks, and who want to understand exactly *why* each attack works at the protocol level.

No prior Kerberos knowledge is required. The site starts from first principles and builds up.

!!! warning "RC4 is no longer the default"
    Domain controllers with the April 2026 cumulative update or later treat accounts that have no
    explicit `msDS-SupportedEncryptionTypes` as AES-only (CVE-2026-20833), unless
    `DefaultDomainSupportedEncTypes` is set explicitly or, on the April-June 2026 updates, the
    temporary `RC4DefaultDisablementPhase` rollback was applied. If a service started
    failing with `KDC_ERR_ETYPE_NOSUPP`, or you want to confirm you are not affected, start with
    [RC4 enforcement: am I affected?](security/enforcement-triage.md).

Already familiar with Kerberos and just need to finish moving your domain to AES? Jump straight to
the [Standardization Guide](security/aes-standardization.md).

---

## Three Sections

<div class="grid cards" markdown>

-   **[Protocol](protocol/index.md)**

    ---

    How Kerberos works from the ground up: the three-party model, AS/TGS/AP exchanges, ticket structure, pre-authentication, encryption types, S4U, cross-realm authentication, and delegation.

    Start here if you are new to Kerberos.

-   **[Security](security/index.md)**

    ---

    Configuring Kerberos for security: encryption type negotiation, key derivation, the `msDS-SupportedEncryptionTypes` attribute, registry and Group Policy settings, the RC4 default removal (CVE-2026-20833), and mitigations.

    New to encryption types? Start with the [Quick Start Guide](security/quick-start.md).
    Something broke after patching? Go to [enforcement triage](security/enforcement-triage.md).
    Two interactive tools help along the way: the
    [Encryption Type Calculator](security/etype-calculator.md) and the
    [Event Decoder](security/event-decoder.md).

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

No cryptography background is needed - encryption concepts are explained as they come up.

---

## Tools

Attack pages use [kerbwolf](https://github.com/StrongWind1/KerbWolf) and [impacket](https://github.com/fortra/impacket) for examples. See the [Tools Setup](attacks/tools.md) page for installation instructions.

### kerbwolf

[kerbwolf](https://github.com/StrongWind1/KerbWolf) - Kerberos roasting and TGT attack toolkit:

| Tool | Purpose |
|---|---|
| `kw-roast` | TGS-REP roasting (Kerberoasting) |
| `kw-asrep` | AS-REP roasting |
| `kw-extract` | Offline hash extraction from pcap captures |
| `kw-tgt` | TGT acquisition (pass-the-key / overpass-the-hash) |

### Microsoft Kerberos-Crypto

[Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto) - Microsoft's official PowerShell scripts for assessing RC4 usage and key readiness:

| Script | Purpose |
|---|---|
| `Get-KerbEncryptionUsage.ps1` | Detect RC4 usage from Event IDs 4768/4769 across all KDCs |
| `List-AccountKeys.ps1` | List Kerberos key types stored for each account |

See [Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos) for Microsoft's official usage guidance.  They complement the audit queries in the [AES Standardization Guide](security/aes-standardization.md#step-1-audit-current-state).

### KDC registry audit script

[`Get-KdcKerberosRegistryAudit.ps1`](https://github.com/StrongWind1/Kerberos/blob/main/scripts/Get-KdcKerberosRegistryAudit.ps1) - this site's read-only audit of the Kerberos registry values on every domain controller: which values are set, whether they sit at a path the KDC actually reads, and whether the DC's build enforces the RC4 default removal.  See the [script README](https://github.com/StrongWind1/Kerberos/blob/main/scripts/README.md) for download and usage notes, and [Registry Audit](security/registry-audit.md) for the lab results behind it.

### PSKerb

[PSKerb](https://github.com/microsoft/Kerberos-Crypto/tree/main/PSKerb) - PowerShell module for reading and writing Kerberos client registry configuration on Windows:

```powershell
Install-Module -Name PSKerb
```

| Command | Purpose |
|---|---|
| `Get-KerbConfig` | Display all Kerberos client registry settings with human-readable values |
| `Set-KerbConfig` | Set one or more Kerberos registry settings (e.g. `-SupportedEncryptionTypes AES256-SHA96`) |
| `Clear-KerbConfig` | Remove registry overrides, reverting settings to defaults |

Covers 22 settings under `HKLM\...\Policies\System\Kerberos\Parameters` including `SupportedEncryptionTypes`, `DefaultEncryptionType`, `MaxTokenSize`, and timeout/retry tuning.  See [Registry Settings](security/registry.md) for the security-relevant subset.

---

## Authoritative References

This guide is grounded in the official protocol specifications. Inline references such as RFC 4120 §3.1 or MS-KILE §3.3.5.7 point to the source material throughout the site.

### Kerberos Protocol

| Document | Description |
|---|---|
| [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) | The Kerberos Network Authentication Service (V5) - the authoritative base protocol specification |
| [RFC 6806](https://datatracker.ietf.org/doc/html/rfc6806) | Kerberos Principal Name Canonicalization and Cross-Realm Referrals |
| [RFC 4556](https://datatracker.ietf.org/doc/html/rfc4556) | Public Key Cryptography for Initial Authentication in Kerberos (PKINIT) |
| [RFC 6113](https://datatracker.ietf.org/doc/html/rfc6113) | A Generalized Framework for Kerberos Pre-Authentication (FAST) |

### Cryptographic Specifications

| Document | Description |
|---|---|
| [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961) | Encryption and Checksum Specifications for Kerberos 5 - the cryptographic framework |
| [RFC 3962](https://datatracker.ietf.org/doc/html/rfc3962) | Using AES Encryption with Kerberos 5 (AES-CTS-HMAC-SHA1-96) |
| [RFC 6649](https://datatracker.ietf.org/doc/html/rfc6649) | Deprecate DES, RC4-HMAC-EXP, and Other Weak Cryptographic Algorithms in Kerberos |
| [RFC 7465](https://datatracker.ietf.org/doc/html/rfc7465) | Prohibiting RC4 Cipher Suites - a TLS document, not a Kerberos one; listed as background on RC4 |
| [RFC 8429](https://datatracker.ietf.org/doc/html/rfc8429) | Deprecate Triple-DES (3DES) and RC4 in Kerberos |

### Microsoft Open Specifications

| Document | Description |
|---|---|
| [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) | Kerberos Protocol Extensions - Windows-specific additions to the base protocol |
| [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) | Privilege Attribute Certificate Data Structure - the authorization data inside Kerberos tickets |
| [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) | Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol |
| [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) | Active Directory Technical Specification - AD object classes, attributes, and protocol behavior |
| [MS-APDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/) | Authentication Protocol Domain Support - how domain controllers process authentication requests |
| [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) | Directory Replication Service Remote Protocol - used by DCSync and key extraction techniques |
| [MS-RPRN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/) | Print System Remote Protocol - abused for authentication coercion (Printer Bug) |
| [MS-EFSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/) | Encrypting File System Remote (EFSRPC) Protocol - abused for authentication coercion (PetitPotam) |
| [MS-DFSNM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/) | Distributed File System (DFS): Namespace Management Protocol - abused for authentication coercion |

### Security Advisories

| Advisory | Title | Impact |
|---|---|---|
| [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) | Windows LSA Spoofing (PetitPotam) | Unauthenticated NTLM relay via EFS RPC coercion |
| [CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) | AD Elevation of Privilege (sAMAccountName spoofing) | PAC_REQUESTOR validation; noPAC attack |
| [KB5008380](https://support.microsoft.com/help/5008380) | Authentication updates (CVE-2021-42287) | Adds `PAC_REQUESTOR` and `PAC_ATTRIBUTES_INFO` to the PAC; the KDC checks the requestor SID on TGS requests |
| [CVE-2022-26923](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923) | AD Domain Services Elevation of Privilege | Certificate-based machine account privilege escalation |
| [CVE-2022-37966](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37966) | Windows Kerberos RC4-HMAC Elevation of Privilege | KDC defaults to AES session keys; introduces `DefaultDomainSupportedEncTypes` |
| [CVE-2020-17049](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049) | Kerberos KDC Security Feature Bypass (Bronze Bit) | Adds the PAC ticket signature so a service cannot alter its own ticket flags |
| [CVE-2022-37967](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37967) | Windows Kerberos Elevation of Privilege | Adds the full (extended KDC) PAC signature |
| [KB5021131](https://support.microsoft.com/help/5021131) | Kerberos protocol changes (CVE-2022-37966) | November 2022 etype behavior changes |
| [KB5020805](https://support.microsoft.com/help/5020805) | How to manage Kerberos protocol changes related to CVE-2022-37967 | Deployment and enforcement phases for the full PAC signature |
| [KB5037754](https://support.microsoft.com/help/5037754) | How to manage PAC Validation changes related to CVE-2024-26248 and CVE-2024-29056 | PAC validation hardening and its enforcement phases |
| [CVE-2026-20833](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20833) | Windows Kerberos Information Disclosure Vulnerability | The fix removes RC4 as the implicit default etype for accounts without explicit `msDS-SupportedEncryptionTypes` |
| [KB5073381](https://support.microsoft.com/help/5073381) | How to manage Kerberos KDC usage of RC4 for service account ticket issuance changes related to CVE-2026-20833 | Audit and enforcement timeline; Kdcsvc events 201--209 |
| [CVE-2026-20849](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20849) | Windows Kerberos Elevation of Privilege Vulnerability | MS-SFU ties this update to the `PhaseOutOldStyleS4U` setting, under which a service sends `PA-S4U-X509-USER` instead of `PA-FOR-USER` in S4U2Self requests. Whether a patched DC rejects `PA-FOR-USER` is not confirmed; see [S4U Extensions](protocol/s4u.md#request-structure) |
