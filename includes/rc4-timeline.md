Each change arrives with a cumulative update (CU), so a domain controller's behavior depends on the CU it has installed, not on the calendar date.

| When | Delivered by | What changed | Rollback |
|---|---|---|---|
| **November 8, 2022** | November 2022 CU ([KB5021131](https://support.microsoft.com/help/5021131), CVE-2022-37966) | AES session keys became the default.  `DefaultDomainSupportedEncTypes` was introduced; its built-in default was `0x27` (DES + RC4 + AES session keys). | n/a |
| **January 2025** | January 2025 CU | Security events 4768/4769 gained the per-principal etype fields (supported encryption types, available keys, advertised etypes, session key etype). | n/a |
| **January 13, 2026** | January 2026 CU ([KB5073381](https://support.microsoft.com/help/5073381), CVE-2026-20833) | Audit phase.  Kdcsvc events 201-209 and the temporary `RC4DefaultDisablementPhase` registry value were added.  Ticket issuance did not change. | n/a |
| **April 14, 2026** | April 2026 CU (Server 2022: KB5082142, build 20348.5020; Server 2025: KB5082063, build 26100.32690) | Enforcement on by default.  The built-in default for accounts with no `msDS-SupportedEncryptionTypes` changed from `0x27` to `0x18` (AES-only).  Lab-verified on Server 2022 build 20348.5020. | `RC4DefaultDisablementPhase` = `0` or `1` plus a KDC restart, until the July update |
| **July 14, 2026** | July 2026 CU | Audit mode ended and support for the `RC4DefaultDisablementPhase` rollback value was removed: the value is no longer read (a leftover value is inert); enforcement is the only supported behavior (Microsoft Message Center MC1427604, KB5073381).  **Not lab-verified on this site.** | None |
