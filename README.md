<h1 align="center">Kerberos in Active Directory</h1>

<p align="center"><strong>How Kerberos works in Active Directory, how to harden it, and how it gets attacked.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/Kerberos/actions/workflows/docs.yml"><img src="https://github.com/StrongWind1/Kerberos/actions/workflows/docs.yml/badge.svg" alt="Docs build"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/Kerberos/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/Kerberos/protocol/">Protocol</a> &bull;
  <a href="https://strongwind.dev/Kerberos/security/">Security</a> &bull;
  <a href="https://strongwind.dev/Kerberos/attacks/">Attacks</a> &bull;
  <a href="https://strongwind.dev/Kerberos/">Documentation</a>
</p>

---

A reference for Kerberos in Active Directory, written for administrators, defenders, and penetration testers. It starts from first principles, cites RFC 4120 and MS-KILE down to the section, and backs the encryption type and registry guidance with lab results from Server 2022 and Server 2025 domain controllers.

## RC4 enforcement

**RC4 is no longer a Kerberos default.** A domain controller with the April 2026 cumulative update or later treats any account without an explicit `msDS-SupportedEncryptionTypes` as AES-only (CVE-2026-20833, [KB5073381](https://support.microsoft.com/help/5073381)). Each DC follows its installed update, not the calendar. Per Microsoft, updates from July 2026 onward also remove the `RC4DefaultDisablementPhase` rollback value; the lab results here cover builds up to June 2026.

- Something broke, or you want to confirm you are not affected: [RC4 enforcement: am I affected?](https://strongwind.dev/Kerberos/security/enforcement-triage/)
- The 5-minute overview: [Quick start guide](https://strongwind.dev/Kerberos/security/quick-start/)
- Finishing the move to AES and retiring RC4 exceptions: [AES standardization guide](https://strongwind.dev/Kerberos/security/aes-standardization/)

## Protocol

How Kerberos works on the wire in Active Directory: the exchanges, ticket structures, and key derivation.

| Page | What it covers |
| --- | --- |
| [Active Directory components](https://strongwind.dev/Kerberos/protocol/active-directory/) | DCs, KDCs, the Global Catalog, and how AD maps to Kerberos concepts |
| [Principals and realms](https://strongwind.dev/Kerberos/protocol/principals/) | UPNs, SPNs, realm trust, and principal naming |
| [Protocol overview](https://strongwind.dev/Kerberos/protocol/overview/) | The three-party model and the full AS/TGS/AP exchange sequence |
| [AS exchange](https://strongwind.dev/Kerberos/protocol/as-exchange/) | TGT acquisition, pre-authentication, PA-ETYPE-INFO2, and the krbtgt key |
| [TGS exchange](https://strongwind.dev/Kerberos/protocol/tgs-exchange/) | Service ticket issuance, etype selection, and the KDC's decision logic |
| [AP exchange](https://strongwind.dev/Kerberos/protocol/ap-exchange/) | Authenticator construction, mutual authentication, and session key establishment |
| [Ticket structure](https://strongwind.dev/Kerberos/protocol/tickets/) | Wire format, PAC contents, PAC signatures, and the impact of KB5008380 |
| [Pre-authentication](https://strongwind.dev/Kerberos/protocol/preauth/) | PA-DATA types, FAST armoring, and what happens when pre-auth is disabled |
| [Encryption types](https://strongwind.dev/Kerberos/protocol/encryption/) | DES, RC4, AES128, AES256: key derivation, usage, and negotiation rules |
| [S4U extensions](https://strongwind.dev/Kerberos/protocol/s4u/) | S4U2Self, S4U2Proxy, the FORWARDABLE flag, and RBCD vs constrained delegation |
| [Cross-realm auth](https://strongwind.dev/Kerberos/protocol/cross-realm/) | Inter-forest referrals, trust keys, and cross-realm ticket flow |
| [Delegation](https://strongwind.dev/Kerberos/protocol/delegation/) | Unconstrained, constrained, and resource-based constrained delegation |

## Security

How the KDC picks an encryption type, what each setting does, and how to run a domain where RC4 is opt-in only: audit, configure, migrate, and keep exceptions small.

### Encryption

| Page | What it covers |
| --- | --- |
| [Encryption negotiation](https://strongwind.dev/Kerberos/security/etype-negotiation/) | How KDC, client, and service account flags combine to select an etype |
| [Etype decision guide](https://strongwind.dev/Kerberos/security/etype-decision-guide/) | Every input that decides which etype appears in a ticket |
| [Algorithms and keys](https://strongwind.dev/Kerberos/security/algorithms/) | DES, RC4, and AES key derivation, cracking speed compared, and the double-reset problem |

### Configuration

| Page | What it covers |
| --- | --- |
| [msDS-SupportedEncryptionTypes](https://strongwind.dev/Kerberos/security/msds-supported/) | Bit flags, defaults per account type, bulk queries, and bulk update scripts |
| [Registry settings](https://strongwind.dev/Kerberos/security/registry/) | Every Kerberos-relevant registry value on DCs and clients, with safe defaults |
| [Registry audit](https://strongwind.dev/Kerberos/security/registry-audit/) | Lab-validated registry reference with the observed behavior of each key |
| [Group Policy](https://strongwind.dev/Kerberos/security/group-policy/) | GPO settings that affect Kerberos, override precedence, and gotchas |

### Hardening

| Page | What it covers |
| --- | --- |
| [RC4 enforcement: am I affected?](https://strongwind.dev/Kerberos/security/enforcement-triage/) | Symptom-to-fix runbook for `KDC_ERR_ETYPE_NOSUPP` and Kdcsvc 203/204/208/209 |
| [RC4 deprecation](https://strongwind.dev/Kerberos/security/rc4-deprecation/) | CVE-2026-20833: what shipped, Kdcsvc events 201-209, and how to scope RC4 exceptions |
| [Auditing Kerberos keys](https://strongwind.dev/Kerberos/security/account-key-audit/) | Finding accounts with weak or missing AES keys |
| [AES standardization guide](https://strongwind.dev/Kerberos/security/aes-standardization/) | AES migration playbook: two paths, every command, every verification step |
| [Mitigations](https://strongwind.dev/Kerberos/security/mitigations/) | Defenses ranked by impact, from gMSA deployment to KRBTGT rotation |

### Start here and troubleshooting

| Page | What it covers |
| --- | --- |
| [Quick start guide](https://strongwind.dev/Kerberos/security/quick-start/) | 5-minute encryption type overview with diagrams |
| [Troubleshooting](https://strongwind.dev/Kerberos/security/troubleshooting/) | Common Kerberos errors, event IDs, and diagnostic procedures |

## Interactive tools

| Tool | What it does |
| --- | --- |
| [Encryption type calculator](https://strongwind.dev/Kerberos/security/etype-calculator/) | Computes the winning etype for any combination of account flags and registry settings |
| [Event decoder](https://strongwind.dev/Kerberos/security/event-decoder/) | Decodes Kerberos events 4768, 4769, 4770, and 4771 into readable output |
| [`Get-KdcKerberosRegistryAudit.ps1`](scripts/Get-KdcKerberosRegistryAudit.ps1) | Read-only PowerShell audit of the Kerberos registry values on every domain controller ([usage](scripts/README.md)) |

## Attacks

Each major Kerberos attack, with why it works at the protocol level, how to defend against it, and how to detect it. Tool installation is on the [Tools setup](https://strongwind.dev/Kerberos/attacks/tools/) page.

### Roasting (offline credential cracking)

| Attack | Target | Hashcat mode |
| --- | --- | --- |
| [Kerberoasting](https://strongwind.dev/Kerberos/attacks/roasting/kerberoasting/) | TGS-REP enc-part (user service account key) | 13100 (RC4), 19700 (AES256) |
| [AS-REP roasting](https://strongwind.dev/Kerberos/attacks/roasting/asrep-roasting/) | AS-REP enc-part (accounts without pre-auth) | 18200 (RC4), 32200 (AES256) |
| [AS-REQ roasting](https://strongwind.dev/Kerberos/attacks/roasting/asreq-roasting/) | PA-ENC-TIMESTAMP (passive capture) | 7500 (RC4), 19900 (AES256) |

### Credential theft

| Attack | What it abuses |
| --- | --- |
| [Pass-the-ticket](https://strongwind.dev/Kerberos/attacks/credential-theft/pass-the-ticket/) | A stolen TGT or service ticket injected into a session |
| [Pass-the-key](https://strongwind.dev/Kerberos/attacks/credential-theft/pass-the-key/) | An RC4 or AES key used directly, without the plaintext password |
| [Password spraying](https://strongwind.dev/Kerberos/attacks/credential-theft/password-spraying/) | AS-REQ pre-auth failures as a low-noise enumeration oracle |
| [User enumeration](https://strongwind.dev/Kerberos/attacks/credential-theft/user-enumeration/) | KDC error codes that tell valid usernames from invalid ones |

### Ticket forgery

| Attack | What it forges |
| --- | --- |
| [Golden ticket](https://strongwind.dev/Kerberos/attacks/forgery/golden-ticket/) | An arbitrary TGT, using the krbtgt key |
| [Silver ticket](https://strongwind.dev/Kerberos/attacks/forgery/silver-ticket/) | An arbitrary service ticket, using the target account key |
| [Diamond ticket](https://strongwind.dev/Kerberos/attacks/forgery/diamond-ticket/) | A legitimate TGT modified with a forged PAC |
| [Sapphire ticket](https://strongwind.dev/Kerberos/attacks/forgery/sapphire-ticket/) | A forged TGT carrying a legitimate PAC obtained via S4U2Self |

### Delegation abuse

| Attack | What it abuses |
| --- | --- |
| [Delegation attacks](https://strongwind.dev/Kerberos/attacks/delegation/delegation-attacks/) | Unconstrained, constrained, and RBCD misconfigurations |
| [S4U2Self abuse](https://strongwind.dev/Kerberos/attacks/delegation/s4u2self-abuse/) | Computer account S4U for local privilege escalation |
| [SPN-jacking](https://strongwind.dev/Kerberos/attacks/delegation/spn-jacking/) | Redirecting delegation by moving SPNs between accounts |

## Development

```sh
git clone https://github.com/StrongWind1/Kerberos.git && cd Kerberos
uv sync --group docs   # install dependencies
make serve             # live preview at http://127.0.0.1:8000
make docs              # strict build: broken internal links and anchors fail
make check             # build, lint, JS and PowerShell tests, HTML and accessibility checks
```

Page sources live in `content/` (not `docs/`), shared snippets and tables in `includes/`, the browser tools in `content/javascripts/` (tests in `tests/js/`), and the audit script in `scripts/` (tests in `tests/ps/`). `docs/` holds the unpublished lab notes the security pages are built from.

## Credits

Built from [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120), [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961), [RFC 3962](https://datatracker.ietf.org/doc/html/rfc3962), [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/), [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/), and [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/). Attack examples use [impacket](https://github.com/fortra/impacket), and the RC4 audit pages use Microsoft's [Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto) scripts. The full list is under [Authoritative references](https://strongwind.dev/Kerberos/#authoritative-references).

## Related tools

- [**CredWolf**](https://github.com/StrongWind1/CredWolf): Validate AD passwords, hashes, keys, and tickets over NTLM and Kerberos
- [**KerbWolf**](https://github.com/StrongWind1/KerbWolf): Kerberos roasting and TGT attack toolkit for Active Directory
- [**NTDSWolf**](https://github.com/StrongWind1/NTDSWolf): Offline NTDS.dit parser and credential extractor for NT/LM hashes, Kerberos keys, LAPS, and gMSA
- [**PassWolf**](https://github.com/StrongWind1/PassWolf): Spec-compliant AD password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, LDAP
- [**AD-SecretGen**](https://github.com/StrongWind1/AD-SecretGen): Derive every password-derived AD secret (NT/LM, Kerberos keys, WDigest) from a password
- [**ntcompress**](https://github.com/StrongWind1/ntcompress): Pure-Python ESE record compression and ntdll RtlCompressBuffer/RtlDecompressBuffer formats

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

This material is for authorized security testing, research, and education. Use it only against systems and networks you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
