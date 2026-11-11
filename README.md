<h1 align="center">
  <a href="https://strongwind.dev/Kerberos/">Kerberos in Active Directory</a>
</h1>

<p align="center">
  <a href="https://github.com/StrongWind1/Kerberos/actions/workflows/docs.yml"><img src="https://github.com/StrongWind1/Kerberos/actions/workflows/docs.yml/badge.svg" alt="Docs build"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/Kerberos/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/Kerberos/protocol/">Protocol</a> &bull;
  <a href="https://strongwind.dev/Kerberos/security/">Security</a> &bull;
  <a href="https://strongwind.dev/Kerberos/attacks/">Attacks</a>
</p>

Protocol internals, security configuration, and attack techniques for Kerberos in Active Directory.

## Quick start

**RC4 is no longer a Kerberos default.** Domain controllers with the April 2026 cumulative update or later treat accounts that have no explicit `msDS-SupportedEncryptionTypes` as AES-only (CVE-2026-20833, [KB5073381](https://support.microsoft.com/help/5073381)). Enforcement follows the update installed on each DC, not the calendar. Per Microsoft's timeline, updates from July 2026 onward also remove the `RC4DefaultDisablementPhase` rollback value; this site's lab results cover builds up to June 2026.

- Something broke, or you want to confirm you are unaffected: [RC4 enforcement: am I affected?](https://strongwind.dev/Kerberos/security/enforcement-triage/)
- The 5-minute overview: [Quick Start Guide](https://strongwind.dev/Kerberos/security/quick-start/)
- Finishing the move to AES and retiring RC4 exceptions: [Standardization Guide](https://strongwind.dev/Kerberos/security/aes-standardization/)

## Protocol

How Kerberos actually works in Active Directory. Wire protocol, ticket structures, key derivation, grounded in RFC 4120 and the MS-KILE spec.

| Page | What it covers |
|---|---|
| [Active Directory Components](https://strongwind.dev/Kerberos/protocol/active-directory/) | DCs, KDCs, the Global Catalog, and how AD maps to Kerberos concepts |
| [Principals & Realms](https://strongwind.dev/Kerberos/protocol/principals/) | UPNs, SPNs, realm trust, and principal naming conventions |
| [Protocol Overview](https://strongwind.dev/Kerberos/protocol/overview/) | The three-party model and the full AS/TGS/AP ticket exchange sequence |
| [AS Exchange](https://strongwind.dev/Kerberos/protocol/as-exchange/) | TGT acquisition, pre-authentication, PA-ETYPE-INFO2, and the krbtgt key |
| [TGS Exchange](https://strongwind.dev/Kerberos/protocol/tgs-exchange/) | Service ticket issuance, etype selection, and the KDC's decision logic |
| [AP Exchange](https://strongwind.dev/Kerberos/protocol/ap-exchange/) | Authenticator construction, mutual authentication, and session key establishment |
| [Ticket Structure](https://strongwind.dev/Kerberos/protocol/tickets/) | Wire format, PAC contents, PAC signatures, and the impact of KB5008380 |
| [Pre-Authentication](https://strongwind.dev/Kerberos/protocol/preauth/) | PA-DATA types, FAST armoring, and what happens when pre-auth is disabled |
| [Encryption Types](https://strongwind.dev/Kerberos/protocol/encryption/) | DES, RC4, AES128, AES256: key derivation, usage, and negotiation rules |
| [S4U Extensions](https://strongwind.dev/Kerberos/protocol/s4u/) | S4U2Self, S4U2Proxy, FORWARDABLE flag, and RBCD vs constrained delegation |
| [Cross-Realm Auth](https://strongwind.dev/Kerberos/protocol/cross-realm/) | Inter-forest referrals, trust keys, and cross-realm ticket flow |
| [Delegation](https://strongwind.dev/Kerberos/protocol/delegation/) | Unconstrained, constrained, and resource-based constrained delegation |

## Security

How the KDC picks an encryption type, what each setting really does, and how to run a domain now that RC4 is opt-in only: audit, configure, migrate, and keep exceptions small.

### Encryption

| Page | What it covers |
|---|---|
| [Encryption Negotiation](https://strongwind.dev/Kerberos/security/etype-negotiation/) | How the KDC, client, and service account flags combine to select an etype |
| [Etype Decision Guide](https://strongwind.dev/Kerberos/security/etype-decision-guide/) | Every input that determines which etype appears in a ticket |
| [Algorithms & Keys](https://strongwind.dev/Kerberos/security/algorithms/) | DES / RC4 / AES key derivation, cracking speed comparison, the double-reset problem |

### Configuration

| Page | What it covers |
|---|---|
| [msDS-SupportedEncryptionTypes](https://strongwind.dev/Kerberos/security/msds-supported/) | Bit flags, defaults per account type, bulk queries, and bulk update scripts |
| [Registry Settings](https://strongwind.dev/Kerberos/security/registry/) | Every Kerberos-relevant registry value on DCs and clients with safe defaults |
| [Registry Audit](https://strongwind.dev/Kerberos/security/registry-audit/) | Lab-validated registry reference with per-key observed behavior |
| [Group Policy](https://strongwind.dev/Kerberos/security/group-policy/) | GPO settings that affect Kerberos, override precedence, and gotchas |

### Hardening

| Page | What it covers |
|---|---|
| [RC4 Enforcement: Am I Affected?](https://strongwind.dev/Kerberos/security/enforcement-triage/) | Symptom-to-fix runbook for `KDC_ERR_ETYPE_NOSUPP` and Kdcsvc 203/204/208/209 |
| [RC4 Deprecation](https://strongwind.dev/Kerberos/security/rc4-deprecation/) | CVE-2026-20833: what shipped, Kdcsvc events 201-209, and how to scope RC4 exceptions |
| [Auditing Kerberos Keys](https://strongwind.dev/Kerberos/security/account-key-audit/) | Finding accounts with weak or missing AES keys |
| [Standardization Guide](https://strongwind.dev/Kerberos/security/aes-standardization/) | AES migration playbook: two paths, every command, every verification step |
| [Mitigations](https://strongwind.dev/Kerberos/security/mitigations/) | Defenses ranked by impact, from gMSA deployment to KRBTGT rotation |

### Start here and troubleshooting

| Page | What it covers |
|---|---|
| [Quick Start Guide](https://strongwind.dev/Kerberos/security/quick-start/) | 5-minute encryption type overview with diagrams, for people who want the short version |
| [Troubleshooting](https://strongwind.dev/Kerberos/security/troubleshooting/) | Common Kerberos errors, event IDs, and diagnostic procedures |

## Interactive tools

| Tool | What it does |
|---|---|
| [Encryption Type Calculator](https://strongwind.dev/Kerberos/security/etype-calculator/) | Compute the winning etype given any combination of account flags and registry settings |
| [Event Decoder](https://strongwind.dev/Kerberos/security/event-decoder/) | Decode Kerberos event log entries (IDs 4768, 4769, 4770, 4771) into human-readable output |
| [`Get-KdcKerberosRegistryAudit.ps1`](scripts/Get-KdcKerberosRegistryAudit.ps1) | Read-only PowerShell audit of the Kerberos registry values on every domain controller ([usage](scripts/README.md)) |

## Attacks

Every major Kerberos attack with enough detail to understand why it works, not just how to run the tool. Each page covers how it works, how to defend, and how to detect. Tool installation is on the [Tools Setup](https://strongwind.dev/Kerberos/attacks/tools/) page.

### Roasting (offline credential cracking)

| Attack | Target | Hashcat mode |
|---|---|---|
| [Kerberoasting](https://strongwind.dev/Kerberos/attacks/roasting/kerberoasting/) | TGS-REP enc-part (user service account key) | 13100 (RC4), 19700 (AES256) |
| [AS-REP Roasting](https://strongwind.dev/Kerberos/attacks/roasting/asrep-roasting/) | AS-REP enc-part (no pre-auth accounts) | 18200 (RC4), 32200 (AES256) |
| [AS-REQ Roasting](https://strongwind.dev/Kerberos/attacks/roasting/asreq-roasting/) | PA-ENC-TIMESTAMP (passive capture) | 7500 (RC4), 19900 (AES256) |

### Credential theft

| Attack | What it abuses |
|---|---|
| [Pass-the-Ticket](https://strongwind.dev/Kerberos/attacks/credential-theft/pass-the-ticket/) | Stolen TGT or service ticket injected into a session |
| [Pass-the-Key](https://strongwind.dev/Kerberos/attacks/credential-theft/pass-the-key/) | RC4/AES key used directly without the plaintext password |
| [Password Spraying](https://strongwind.dev/Kerberos/attacks/credential-theft/password-spraying/) | AS-REQ pre-auth failures as a low-noise enumeration oracle |
| [User Enumeration](https://strongwind.dev/Kerberos/attacks/credential-theft/user-enumeration/) | KDC error codes that distinguish valid from invalid usernames |

### Ticket forgery

| Attack | What it forges |
|---|---|
| [Golden Ticket](https://strongwind.dev/Kerberos/attacks/forgery/golden-ticket/) | Arbitrary TGT using the krbtgt key |
| [Silver Ticket](https://strongwind.dev/Kerberos/attacks/forgery/silver-ticket/) | Arbitrary service ticket using the target account key |
| [Diamond Ticket](https://strongwind.dev/Kerberos/attacks/forgery/diamond-ticket/) | Modified legitimate TGT with a forged PAC |
| [Sapphire Ticket](https://strongwind.dev/Kerberos/attacks/forgery/sapphire-ticket/) | Forged TGT carrying a legitimate PAC via S4U2Self |

### Delegation abuse

| Attack | What it abuses |
|---|---|
| [Delegation Attacks](https://strongwind.dev/Kerberos/attacks/delegation/delegation-attacks/) | Unconstrained, constrained, and RBCD misconfigurations |
| [S4U2Self Abuse](https://strongwind.dev/Kerberos/attacks/delegation/s4u2self-abuse/) | Computer account S4U for local privilege escalation |
| [SPN-jacking](https://strongwind.dev/Kerberos/attacks/delegation/spn-jacking/) | Delegation redirect by moving SPNs between accounts |

## Development

```bash
git clone https://github.com/StrongWind1/Kerberos.git
cd Kerberos
uv sync --group docs                              # install dependencies
make serve                                        # live preview at http://127.0.0.1:8000
make docs                                         # strict build: broken internal links and anchors fail
make check                                        # everything CI runs: build, lint, JS and PowerShell tests
```

Layout: page sources live in `content/` (not `docs/`), shared snippets and tables in `includes/`, the browser tools in `content/javascripts/` with tests in `tests/js/`, and the audit script in `scripts/` with tests in `tests/ps/`. `docs/` holds the lab notes the security pages are built from; it is not published.

## Related tools

Other projects in this collection:

- [AD-SecretGen](https://github.com/StrongWind1/AD-SecretGen) - derive AD password hashes and Kerberos keys from a password
- [NTDSWolf](https://github.com/StrongWind1/NTDSWolf) - offline NTDS.dit parser and credential extractor
- [CredWolf](https://github.com/StrongWind1/CredWolf) - Active Directory credential validation
- [KerbWolf](https://github.com/StrongWind1/KerbWolf) - Kerberos roasting and hash extraction toolkit

## Disclaimer

This material documents Kerberos attack techniques for authorized security testing, research, and education only. You must have explicit written permission before testing any technique against systems you do not own. Unauthorized access to computer systems is illegal.

## License

[Apache License 2.0](LICENSE)
