# [Kerberos in Active Directory](https://strongwind1.github.io/Kerberos/)

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

Comprehensive reference for Kerberos authentication in Microsoft Active Directory -- how the protocol works, how to configure it securely, and how attackers exploit it.

## Protocol

The full AS/TGS/AP exchange, ticket structure, encryption type negotiation, pre-authentication, S4U extensions, cross-realm authentication, and delegation -- grounded in RFC 4120 and the Microsoft Open Specifications.

| Page | What it covers |
|---|---|
| [Protocol Overview](https://strongwind1.github.io/Kerberos/protocol/overview/) | The three-party model, principal names, realms, and the ticket exchange sequence |
| [AS Exchange](https://strongwind1.github.io/Kerberos/protocol/as-exchange/) | TGT acquisition, pre-authentication, PA-ETYPE-INFO2, and the krbtgt key |
| [TGS Exchange](https://strongwind1.github.io/Kerberos/protocol/tgs-exchange/) | Service ticket issuance, etype selection, and the KDC's decision logic |
| [Ticket Structure](https://strongwind1.github.io/Kerberos/protocol/tickets/) | Wire format, PAC contents, PAC signatures, and the impact of KB5008380 |
| [S4U Extensions](https://strongwind1.github.io/Kerberos/protocol/s4u/) | S4U2Self, S4U2Proxy, FORWARDABLE flag, and RBCD vs constrained delegation |
| [Delegation](https://strongwind1.github.io/Kerberos/protocol/delegation/) | Unconstrained, constrained, and resource-based constrained delegation |

## Security

`msDS-SupportedEncryptionTypes`, registry and GPO settings, RC4 deprecation timeline, AES key generation, and the complete migration playbook.

| Page | What it covers |
|---|---|
| [Etype Decision Guide](https://strongwind1.github.io/Kerberos/security/etype-decision-guide/) | All 12 inputs that determine which etype appears in a ticket |
| [Algorithms & Keys](https://strongwind1.github.io/Kerberos/security/algorithms/) | DES / RC4 / AES key derivation, cracking speed comparison, the double-reset problem |
| [msDS-SupportedEncryptionTypes](https://strongwind1.github.io/Kerberos/security/msds-supported/) | Bit flags, defaults per account type, bulk queries, and bulk update scripts |
| [RC4 Deprecation](https://strongwind1.github.io/Kerberos/security/rc4-deprecation/) | CVE-2026-20833 timeline, Kdcsvc events 201-209, and pre-enforcement checklist |
| [Standardization Guide](https://strongwind1.github.io/Kerberos/security/aes-standardization/) | Full AES migration playbook: two paths, every command, every verification step |
| [Mitigations](https://strongwind1.github.io/Kerberos/security/mitigations/) | Priority-ordered defenses from gMSA deployment to KRBTGT rotation |

## Attacks

Every major Kerberos attack -- mechanics, detection, exploitation, and defense.

| Attack | Target | Hashcat mode |
|---|---|---|
| [Kerberoasting](https://strongwind1.github.io/Kerberos/attacks/roasting/kerberoasting/) | TGS-REP enc-part (user service account key) | 13100 (RC4), 19700 (AES256) |
| [AS-REP Roasting](https://strongwind1.github.io/Kerberos/attacks/roasting/asrep-roasting/) | AS-REP enc-part (no pre-auth accounts) | 18200 (RC4), 32200 (AES256) |
| [AS-REQ Roasting](https://strongwind1.github.io/Kerberos/attacks/roasting/asreq-roasting/) | PA-ENC-TIMESTAMP (passive capture) | 7500 (RC4), 19900 (AES256) |
| [Pass-the-Ticket](https://strongwind1.github.io/Kerberos/attacks/credential-theft/pass-the-ticket/) | Stolen TGT or service ticket | -- |
| [Pass-the-Key](https://strongwind1.github.io/Kerberos/attacks/credential-theft/pass-the-key/) | RC4/AES key without plaintext password | -- |
| [Golden Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/golden-ticket/) | Forged TGT using krbtgt key | -- |
| [Silver Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/silver-ticket/) | Forged service ticket using target account key | -- |
| [Diamond Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/diamond-ticket/) | Modified legitimate TGT with forged PAC | -- |
| [Sapphire Ticket](https://strongwind1.github.io/Kerberos/attacks/forgery/sapphire-ticket/) | Forged TGT with legitimate S4U2Self PAC | -- |
| [Delegation Attacks](https://strongwind1.github.io/Kerberos/attacks/delegation/delegation-attacks/) | Unconstrained, constrained, RBCD abuse | -- |
| [S4U2Self Abuse](https://strongwind1.github.io/Kerberos/attacks/delegation/s4u2self-abuse/) | Local privilege escalation via computer account S4U | -- |
| [SPN-jacking](https://strongwind1.github.io/Kerberos/attacks/delegation/spn-jacking/) | Delegation redirect by moving SPNs | -- |

## Development

```bash
git clone https://github.com/StrongWind1/Kerberos.git
cd Kerberos
uv sync --group docs          # install dependencies
uv run --group docs mkdocs serve          # live preview at http://127.0.0.1:8000
uv run --group docs mkdocs build --strict # full build with link checking
```

## License

[Apache License 2.0](LICENSE)
