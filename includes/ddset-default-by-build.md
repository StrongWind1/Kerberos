What the KDC assumes for a target account whose `msDS-SupportedEncryptionTypes` is unset or `0`.  The switch is the installed cumulative update, not the calendar date, so a mixed fleet behaves differently per DC.

| DC state | Assumed etypes | Ticket for an unset account that has AES keys | Evidence |
|---|---|---|---|
| `DefaultDomainSupportedEncTypes` set explicitly | The registry value | Strongest etype in that value | Lab: Server 2022 only, the pre-April build of 6-7 April 2026 and 20348.5020 (June 2026).  Microsoft: KB5073381 says an explicit value is honored. |
| No DDSET, update older than April 2026 | `0x27` (DES + RC4 + AES-SK) on Server 2022 and the earlier versions KB5021131 covers | **RC4** ticket; AES256 session key for a client that lists AES256 first (an RC4-first client received RC4) | Lab: Server 2022 only.  Ticket and split: 20348.4893 (March 2026 update).  Session key by client order: the pre-April build of 6-7 April 2026.  Microsoft: KB5021131, which does not list Server 2025.  The pre-April default on Server 2025 was not lab-verified. |
| No DDSET, April 2026 update or later (Server 2022: build 20348.5020 / KB5082142; Server 2025: build 26100.32690 / KB5082063) | `0x18` (AES128 + AES256) | **AES256** ticket and session key | Lab: 20348.5020 only.  Microsoft: KB5073381 and the April 2026 release notes.  Server 2025 not lab-verified. |
| No DDSET, April-June 2026 update, `RC4DefaultDisablementPhase` = `0` or `1` | `0x27` | RC4 ticket (rollback) | Lab: 20348.5020, April and June 2026. |
| No DDSET, July 2026 update or later | `0x18`; Microsoft's published timeline says `RC4DefaultDisablementPhase` is no longer read | AES256 | **Not lab-verified.**  KB5073381 (last revised 14 April 2026). |
