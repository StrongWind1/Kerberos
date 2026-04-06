# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-04-06

Initial release.

### Added

**Protocol section** (13 pages):

- Protocol Overview -- the three-party model, ticket exchange sequence, and session key flow
- Active Directory -- how AD maps onto Kerberos principals and realms
- Principals & Realms -- naming format, SPN structure, and all five AD account types that can bear SPNs
- AS Exchange -- TGT acquisition, pre-authentication, PA-ETYPE-INFO2, and krbtgt key handling
- TGS Exchange -- service ticket issuance and etype selection logic
- AP Exchange -- client-to-service authentication and mutual auth
- Ticket Structure -- wire format, PAC contents, PAC signatures, and KB5008380 impact
- Pre-Authentication -- PA-ENC-TIMESTAMP, FAST, and no-preauth accounts
- Encryption Types -- per-etype number reference and the November 2022 split-etype behavior
- S4U Extensions -- S4U2Self, S4U2Proxy, FORWARDABLE flag, and RBCD vs constrained delegation
- Cross-Realm Auth -- referral flow and inter-realm trust keys
- Delegation -- unconstrained, constrained, and resource-based constrained delegation mechanics

**Security section** (10 pages):

- Encryption Type Negotiation -- step-by-step KDC decision logic for AS and TGS exchanges
- Etype Decision Guide -- all 12 inputs with decision flowcharts and worked examples
- Algorithms & Keys -- DES/RC4/AES key derivation, cracking speed comparison, key storage in AD, the double-reset problem, and KRBTGT considerations
- msDS-SupportedEncryptionTypes -- bit flags, defaults per account type, bulk queries, and bulk update scripts for all five SPN-bearing account types
- Registry Settings -- DefaultDomainSupportedEncTypes, KdcUseRequestedEtypesForTickets, RC4DefaultDisablementPhase
- Group Policy -- etype GPO mechanics, SYSVOL scanner, and per-DC verification
- RC4 Deprecation (CVE-2026-20833) -- full timeline through July 2026, Kdcsvc events 201-209, pre-enforcement checklist
- Auditing Kerberos Keys -- four methods: PowerShell date comparison, DSInternals, impacket secretsdump, ntdissector
- Standardization Guide -- complete AES migration playbook with two paths (AES-only and RC4 fallback), all commands, all verification steps
- Mitigations -- ten prioritized defenses from gMSA deployment to KRBTGT rotation

**Attacks section** (14 pages):

- Roasting: Kerberoasting (TGS-REP), AS-REP Roasting, AS-REQ Roasting
- Credential Theft: Pass-the-Ticket, Pass-the-Key, Password Spraying, User Enumeration
- Ticket Forgery: Golden Ticket, Silver Ticket, Diamond Ticket, Sapphire Ticket
- Delegation: Delegation Attacks (unconstrained/constrained/RBCD), S4U2Self Abuse, SPN-jacking

**Vocabulary standardization** across all pages:

- Five SPN-bearing account types consistently named: user service accounts, computer accounts, gMSA, MSA, dMSA
- "Computer account" used throughout (replacing "machine account")
- "User service account" for objectCategory=person with manually registered SPNs
- "SPN-bearing account" as the umbrella for all five types
- "Managed service accounts" as the collective for gMSA + MSA + dMSA

**Site infrastructure:**

- MkDocs Material with dark/light mode, navigation tabs, tooltips, code select, and custom gold theme
- Shared PowerShell snippets via pymdownx.snippets (`spn-overview-query.md`, `old-passwords-query.md`)
- Abbreviation tooltips auto-appended to every page
- GitHub Actions CI: docs build on PR, deploy to GitHub Pages on merge to main
- Dependabot: weekly updates for GitHub Actions and uv dependencies
