<h1 align="center">
  <a href="https://strongwind1.github.io/Kerberos/">Kerberos in Active Directory</a>
</h1>

<p align="center">
  <a href="https://github.com/StrongWind1/Kerberos/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/Kerberos/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://strongwind1.github.io/Kerberos/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind1.github.io/Kerberos/protocol/">Protocol</a> &bull;
  <a href="https://strongwind1.github.io/Kerberos/security/">Security</a> &bull;
  <a href="https://strongwind1.github.io/Kerberos/attacks/">Attacks</a>
</p>

Protocol internals, security configuration, and attack techniques for Kerberos in Active Directory.

## Quick Start

**RC4 enforcement starts April 2026.** Accounts without `msDS-SupportedEncryptionTypes` explicitly set will stop getting RC4 tickets. July 2026 makes it permanent with no rollback. The fix is two settings: `msDS-SupportedEncryptionTypes = 24` on every SPN-bearing account, and `DefaultDomainSupportedEncTypes = 24` on every DC.

Not sure where your domain stands? The [Quick Start Guide](https://strongwind1.github.io/Kerberos/security/quick-start/) covers what you need to know in 5 minutes. Ready to run the migration? Go straight to the [Standardization Guide](https://strongwind1.github.io/Kerberos/security/aes-standardization/).

## Protocol

How Kerberos actually works in Active Directory. Wire protocol, ticket structures, key derivation, grounded in RFC 4120 and the MS-KILE spec.

| Page | What it covers |
|---|---|
| [Active Directory Components](https://strongwind1.github.io/Kerberos/protocol/active-directory/) | DCs, KDCs, the Global Catalog, and how AD maps to Kerberos concepts |
| [Principals & Realms](https://strongwind1.github.io/Kerberos/protocol/principals/) | UPNs, SPNs, realm trust, and principal naming conventions |
| [Protocol Overview](https://strongwind1.github.io/Kerberos/protocol/overview/) | The three-party model and the full AS/TGS/AP ticket exchange sequence |
| [AS Exchange](https://strongwind1.github.io/Kerberos/protocol/as-exchange/) | TGT acquisition, pre-authentication, PA-ETYPE-INFO2, and the krbtgt key |
| [TGS Exchange](https://strongwind1.github.io/Kerberos/protocol/tgs-exchange/) | Service ticket issuance, etype selection, and the KDC's decision logic |
| [AP Exchange](https://strongwind1.github.io/Kerberos/protocol/ap-exchange/) | Authenticator construction, mutual authentication, and session key establishment |
| [Ticket Structure](https://strongwind1.github.io/Kerberos/protocol/tickets/) | Wire format, PAC contents, PAC signatures, and the impact of KB5008380 |
| [Pre-Authentication](https://strongwind1.github.io/Kerberos/protocol/preauth/) | PA-DATA types, FAST armoring, and what happens when pre-auth is disabled |
| [Encryption Types](https://strongwind1.github.io/Kerberos/protocol/encryption/) | DES, RC4, AES128, AES256: key derivation, usage, and negotiation rules |
| [S4U Extensions](https://strongwind1.github.io/Kerberos/protocol/s4u/) | S4U2Self, S4U2Proxy, FORWARDABLE flag, and RBCD vs constrained delegation |
| [Cross-Realm Auth](https://strongwind1.github.io/Kerberos/protocol/cross-realm/) | Inter-forest referrals, trust keys, and cross-realm ticket flow |
| [Delegation](https://strongwind1.github.io/Kerberos/protocol/delegation/) | Unconstrained, constrained, and resource-based constrained delegation |

## Security

The RC4 deprecation deadline is April 2026 with permanent enforcement in July. This section covers how to audit your domain, what to configure, and how to migrate before it matters.

### Encryption

| Page | What it covers |
|---|---|
| [Encryption Negotiation](https://strongwind1.github.io/Kerberos/security/etype-negotiation/) | How the KDC, client, and service account flags combine to select an etype |
| [Etype Decision Guide](https://strongwind1.github.io/Kerberos/security/etype-decision-guide/) | All 12 inputs that determine which etype appears in a ticket |
| [Algorithms & Keys](https://strongwind1.github.io/Kerberos/security/algorithms/) | DES / RC4 / AES key derivation, cracking speed comparison, the double-reset problem |

### Configuration

| Page | What it covers |
|---|---|
| [msDS-SupportedEncryptionTypes](https://strongwind1.github.io/Kerberos/security/msds-supported/) | Bit flags, defaults per account type, bulk queries, and bulk update scripts |
| [Registry Settings](https://strongwind1.github.io/Kerberos/security/registry/) | Every Kerberos-relevant registry value on DCs and clients with safe defaults |
| [Registry Audit](https://strongwind1.github.io/Kerberos/security/registry-audit/) | Lab-validated registry reference with per-key observed behavior |
| [Group Policy](https://strongwind1.github.io/Kerberos/security/group-policy/) | GPO settings that affect Kerberos, override precedence, and gotchas |

### Hardening

| Page | What it covers |
|---|---|
| [RC4 Deprecation](https://strongwind1.github.io/Kerberos/security/rc4-deprecation/) | CVE-2026-20833 timeline, Kdcsvc events 201-209, and pre-enforcement checklist |
| [Auditing Kerberos Keys](https://strongwind1.github.io/Kerberos/security/account-key-audit/) | Finding accounts with weak or missing AES keys before enforcement hits |
| [Standardization Guide](https://strongwind1.github.io/Kerberos/security/aes-standardization/) | AES migration playbook: two paths, every command, every verification step |
| [Mitigations](https://strongwind1.github.io/Kerberos/security/mitigations/) | Defenses ranked by impact, from gMSA deployment to KRBTGT rotation |

### Reference

| Page | What it covers |
|---|---|
| [Troubleshooting](https://strongwind1.github.io/Kerberos/security/troubleshooting/) | Common Kerberos errors, event IDs, and diagnostic procedures |
| [Quick Start Guide](https://strongwind1.github.io/Kerberos/security/quick-start/) | 5-minute encryption type overview with diagrams, for people who want the short version |

## Interactive Tools

| Tool | What it does |
|---|---|
| [Encryption Type Calculator](https://strongwind1.github.io/Kerberos/security/etype-calculator/) | Compute the winning etype given any combination of account flags and registry settings |
| [Event Decoder](https://strongwind1.github.io/Kerberos/security/event-decoder/) | Decode Kerberos event log entries (IDs 4768, 4769, 4770) into human-readable output |

## Attacks

Every major Kerberos attack with enough detail to understand why it works, not just how to run the tool.

### Roasting (Offline Credential Cracking)

| Attack | Target | Hashcat mode |
|---|---|---|
| [Kerberoasting](https://strongwind1.github.io/Kerberos/attacks/roasting/kerberoasting/) | TGS-REP enc-part (user service account key) | 13100 (RC4), 19700 (AES256) |
| [AS-REP Roasting](https://strongwind1.github.io/Kerberos/attacks/roasting/asrep-roasting/) | AS-REP enc-part (no pre-auth accounts) | 18200 (RC4), 32200 (AES256) |
| [AS-REQ Roasting](https://strongwind1.github.io/Kerberos/attacks/roasting/asreq-roasting/) | PA-ENC-TIMESTAMP (passive capture) | 7500 (RC4), 19900 (AES256) |

### Credential Theft

| Attack | What it abuses |
|---|---|
| [Pass-the-Ticket](https://strongwind1.github.io/Kerberos/attacks/credential-theft/pass-the-ticket/) | Stolen TGT or service ticket injected into a session |
| [Pass-the-Key](https://strongwind1.github.io/Kerberos/attacks/credential-theft/pass-the-key/) | RC4/AES key used directly without the plaintext password |
| [Password Spraying](https://strongwind1.github.io/Kerberos/attacks/credential-theft/password-spraying/) | AS-REQ pre-auth failures as a low-noise enumeration oracle |
| [User Enumeration](https://strongwind1.github.io/Kerberos/attacks/credential-theft/user-enumeration/) | KDC error codes that distinguish valid from invalid usernames |

### Ticket Forgery

| Attack | What it forges |
|---|---|
| [Golden Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/golden-ticket/) | Arbitrary TGT using the krbtgt key |
| [Silver Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/silver-ticket/) | Arbitrary service ticket using the target account key |
| [Diamond Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/diamond-ticket/) | Modified legitimate TGT with a forged PAC |
| [Sapphire Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/sapphire-ticket/) | Forged TGT carrying a legitimate PAC via S4U2Self |

### Delegation Abuse

| Attack | What it abuses |
|---|---|
| [Delegation Attacks](https://strongwind1.github.io/Kerberos/attacks/delegation/delegation-attacks/) | Unconstrained, constrained, and RBCD misconfigurations |
| [S4U2Self Abuse](https://strongwind1.github.io/Kerberos/attacks/delegation/s4u2self-abuse/) | Computer account S4U for local privilege escalation |
| [SPN-jacking](https://strongwind1.github.io/Kerberos/attacks/delegation/spn-jacking/) | Delegation redirect by moving SPNs between accounts |

## Development

```bash
git clone https://github.com/StrongWind1/Kerberos.git
cd Kerberos
uv sync --group docs                              # install dependencies
uv run --group docs mkdocs serve                  # live preview at http://127.0.0.1:8000
uv run --group docs mkdocs build --strict         # full build with link checking
```

## License

[Apache License 2.0](LICENSE)
