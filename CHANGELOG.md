# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Site-wide review and rewrite for the period after Microsoft's 2026 removal of RC4 as the
Kerberos default (CVE-2026-20833). Nothing here has been lab-verified on a July 2026 or later
cumulative update; pages say so wherever it matters.

### Added

- **RC4 Enforcement: Am I Affected?** (`security/enforcement-triage.md`) - symptom-to-fix runbook for `KDC_ERR_ETYPE_NOSUPP` and Kdcsvc 203/204/208/209
- `scripts/Get-KdcKerberosRegistryAudit.ps1` 1.0.0, now linked from the site, with a README, exit codes (`-FailOn`), per-DC effective state, a build map for Server 2016-2025, and 88 Pester tests
- Shared includes so each rule is stated once: etype bit table, common values, default by DC patch level, KDC filter matrix, lab build table, RC4 timeline, `RC4DefaultDisablementPhase` values, Kdcsvc events, PAC hardening timeline, spec link references
- One guarded bulk-update script for all account types (dry run by default, CSV backup, allow-list, `krbtgt` and exception exclusions) and a restore script
- MITRE ATT&CK technique references on every attack page, and an authorized-use notice on the Attacks section
- Audit prerequisites beside each detection (audit subcategories, the SACL that event 5136 needs)
- Tests and lint for the browser tools (`tests/js/`, ESLint), and for all PowerShell (`tools/Test-PowerShellStyle.ps1`, `tools/ps_snippets.py`): every script file and every PowerShell block in the docs is unchanged by `Invoke-Formatter` and clean under `Invoke-ScriptAnalyzer`
- Built-site checks: Nu HTML Checker (zero messages) and pa11y at WCAG 2 AAA on every page and on the tools' interactive states, in light and dark schemes
- CI jobs for PowerShell, JavaScript and the built site; deployment requires all of them. Scheduled external link check. CodeQL now also scans JavaScript and Python
- `make check` runs everything CI runs

### Changed

- Security pages rewritten in past tense around current behavior on patched domain controllers; the April-July 2026 rollback material is collapsed into historical sections
- Enforcement is described as gated by the installed cumulative update, not the calendar, with the Server 2022 enforcing build corrected to 20348.5020 (KB5082142)
- The AES Standardization Guide is now a clean-up playbook: service-side AES pre-check, KDC restart with a canary DC, positive tests, rollback steps, Server 2025 verification
- Calculator: toggling a checkbox no longer drops bits that have no checkbox; values are never rewritten while typing; state lives in the query string with a Copy link button
- Event decoder: Ticket Options decoded as KDC options (bit 14 is the S4U2Proxy marker); accepts Event Viewer text and wrapped XML; no longer writes the pasted event into the URL; new diagnostics for the AES-SK split, missing AES keys and RC4-only clients
- Theme colors are opaque and meet AAA contrast in both schemes; inactive header tabs are no longer dimmed
- Protocol pages: spec citations are links to the exact section; consistent summary and next-page footers; descriptions on every page
- Site banner, home page and README no longer count down to dates that have passed

### Fixed

- `DefaultDomainSupportedEncTypes` registry path (`Services\Kdc`, not `Services\Kdc\Parameters`)
- Bulk "set AES" commands that matched `krbtgt`, overwrote deliberate exceptions and had no backup; two snippets that did not parse; queries that silently returned nothing (`-eq 0` on an unset attribute, wrong event provider name, a filter matching `klist` text in event logs)
- PAC history: four signatures with the right CVE for each; `PAC_REQUESTOR_SID` check described correctly; the "group membership refresh" claim no longer stated as fact (MS-KILE and the one lab run are both given)
- Computer-account salt format, TCP as the Windows default transport, `KDC_ERR_TGT_REVOKED` (20, not 33), GPO "Future encryption types" mask (`0x7FFFFFE0`), `0x1F` no longer described as containing AES-SK
- S4U and Protected Users restated from the current MS-SFU text; for RBCD and the forwardable flag the pages now quote both MS-SFU sections, which disagree, instead of picking one
- The double-reset "promotion" explanation withdrawn: one password reset generates AES keys; resetting twice is `krbtgt` and trust key-history hygiene
- Audit script: no clean verdict for a DC that still issues RC4, for an unknown build, or for a member server; read errors are no longer reported as "not set"
- Contradictory statements about account-type defaults, the KDC filter, `RC4DefaultDisablementPhase` values and RC4 exception values
- CI: a queued pull-request build could displace a pending deployment; `actionlint` and `yamllint` are now pinned; builds use `uv --locked`
- Attack-page detections that could not fire as written: RC4 pre-authentication keyed on the 4768 ticket etype, S4U2Self keyed on Transited Services, password spraying counted from 4768 instead of 4771, a 4738 string that never appears, a 4769 failure code the lab did not see for a rejected forged TGT (KDC System event 38 is the evidence)
- `ValidateKdcPacSignature` no longer offered as a Silver or Golden Ticket mitigation; PAC validation for services described as off by default; Kerberoasting patch history corrected for November 2022 and April 2026
- Protocol pages: transited-policy checking, `HW-AUTHENT` and postdated tickets per MS-KILE; cross-forest TGT delegation risk direction; strong certificate mapping (KB5014754) added
- Lab results restated to the builds they were seen on: value `36`, the `28` emergency fix (its only recorded run was blocked), RC4-only logon, Decision Guide Example 5, session-key selection (client's order of preference, not strongest common)
- Kdcsvc 205/206 and System 26/27 descriptions; Microsoft's statement that Server 2025 domain controllers do not issue RC4 TGTs, with the unreconciled lab observation beside it
- Scripts: the same-password reset proves the typed password before resetting; `DefaultDomainSupportedEncTypes` is set one DC first, dry run by default, with previous values saved and a restore that survives an unreachable DC; the bulk script is one block that stops on a failed guard and works pasted line by line; backup CSV is UTF-8 and keyed on `objectGUID`; `krbtgt` AES keys are checked before the AES-only filter; the KDC-filter test can fail and cleans up its account
- Advice to delete a leftover `RC4DefaultDisablementPhase` value now depends on the DC's build
- Calculator and decoder: no false "client offered no AES" on events whose field is `-`; pasted text events are split, not merged; multiple `<Event>` elements are reported; the calculator never generates a command that writes `0`; `0x3C` and KDC-filter warnings follow MS-KILE and the measured filter matrix
- Display: wide tables no longer scroll sideways at desktop width; diagrams keep readable text and scroll when wide; diagram arrowheads and labels legible in both schemes; visible keyboard focus on the scheme switch and content tabs; legacy `.html` addresses keep `#fragment` and `?query`; a real "Page not found" page
- No page requests `api.github.com` any more, and Mermaid loads from the build itself
- Two dead external links; the documentation URL in `pyproject.toml`; the pull-request template's nonexistent `make check`

### Known gaps

- Attack pages: detection and mitigation guidance was corrected from Microsoft's event documentation but not run against real logs or a SIEM; tool syntax and hash modes have not been reviewed
- PowerShell in the playbook was executed against stub cmdlets on PowerShell 7 only, not on Windows PowerShell 5.1 or a domain
- Open questions that need a lab capture: RBCD and the forwardable flag, whether a Windows client's first AS-REQ carries pre-authentication, PAC group refresh at TGS time, RC4 TGTs on Server 2025, `UF_USE_DES_KEY_ONLY` precedence
- No lab results for July 2026 or later updates, for Server 2025 after its April 2026 update, or for the account-type defaults
- Not yet written: PAC and PKINIT reference pages, non-Windows and trust guidance, SIEM detection queries

## [0.1.0] - 2026-04-06

Initial release.

### Added

**Protocol section** (13 pages):

- Protocol Overview - the three-party model, ticket exchange sequence, and session key flow
- Active Directory - how AD maps onto Kerberos principals and realms
- Principals & Realms - naming format, SPN structure, and all five AD account types that can bear SPNs
- AS Exchange - TGT acquisition, pre-authentication, PA-ETYPE-INFO2, and krbtgt key handling
- TGS Exchange - service ticket issuance and etype selection logic
- AP Exchange - client-to-service authentication and mutual auth
- Ticket Structure - wire format, PAC contents, PAC signatures, and KB5008380 impact
- Pre-Authentication - PA-ENC-TIMESTAMP, FAST, and no-preauth accounts
- Encryption Types - per-etype number reference and the November 2022 split-etype behavior
- S4U Extensions - S4U2Self, S4U2Proxy, FORWARDABLE flag, and RBCD vs constrained delegation
- Cross-Realm Auth - referral flow and inter-realm trust keys
- Delegation - unconstrained, constrained, and resource-based constrained delegation mechanics

**Security section** (10 pages):

- Encryption Type Negotiation - step-by-step KDC decision logic for AS and TGS exchanges
- Etype Decision Guide - all 12 inputs with decision flowcharts and worked examples
- Algorithms & Keys - DES/RC4/AES key derivation, cracking speed comparison, key storage in AD, the double-reset problem, and KRBTGT considerations
- msDS-SupportedEncryptionTypes - bit flags, defaults per account type, bulk queries, and bulk update scripts for all five SPN-bearing account types
- Registry Settings - DefaultDomainSupportedEncTypes, KdcUseRequestedEtypesForTickets, RC4DefaultDisablementPhase
- Group Policy - etype GPO mechanics, SYSVOL scanner, and per-DC verification
- RC4 Deprecation (CVE-2026-20833) - full timeline through July 2026, Kdcsvc events 201-209, pre-enforcement checklist
- Auditing Kerberos Keys - four methods: PowerShell date comparison, DSInternals, impacket secretsdump, ntdswolf
- Standardization Guide - complete AES migration playbook with two paths (AES-only and RC4 fallback), all commands, all verification steps
- Mitigations - ten prioritized defenses from gMSA deployment to KRBTGT rotation

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
