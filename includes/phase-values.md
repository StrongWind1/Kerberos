**Historical.**  `RC4DefaultDisablementPhase` was a temporary deployment gate (REG_DWORD at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`, read at KDC start) that, per KB5073381 and Message Center MC1427604, is no longer read on DCs with the July 2026 cumulative update or later (not lab-verified here).

| Value | Built-in default for accounts with no `msDS-SupportedEncryptionTypes` | Kdcsvc events | Notes |
|---|---|---|---|
| absent | January-March 2026 CUs: behaves as `1`, per KB5073381 (`0x27` on the Server 2022 lab build 20348.4893; Server 2025 not lab-verified).  April 2026 CU or later: `0x18` (behaves as `2`; lab-verified on build 20348.5020). | As for the value it behaves as | The shipped state: the value does not exist unless an administrator created it. |
| `0` | `0x27` (RC4 tickets) | None of 201-204 or 206-209 | "No audit, no change."  Was the full rollback during April-July 2026. |
| `1` | `0x27` (RC4 tickets) | Warnings 201, 202, 206, 207 per request | Audit mode.  Was the audit rollback during April-July 2026. |
| `2` | `0x18` (AES-only) | Blocks 203, 204, 208, 209 per request | Enforcement.  Identical to "absent" on the April 2026 CU or later. |
