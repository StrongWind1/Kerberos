How the KDC filter (`SupportedEncryptionTypes` on the DC) combines with the account's effective etype set.  Measured on Server 2022 build 20348.5020 (enforcing), June 2026; KDC restarted after each filter change.

| KDC filter | Explicit `msDS-SET` = RC4 | Explicit `msDS-SET` = AES | `msDS-SET` 0, DDSET = RC4 | `msDS-SET` 0, DDSET = AES or enforcement default |
|---|---|---|---|---|
| none | RC4 | AES256 | RC4 | AES256 |
| AES-only (`0x18`) | `KDC_ERR_ETYPE_NOSUPP` | AES256 | **AES256** (upgraded) | AES256 |
| RC4-only (`0x04`) | RC4 | `KDC_ERR_ETYPE_NOSUPP` | RC4 | **`KDC_ERR_ETYPE_NOSUPP`** (no downgrade) |

The filter never overrides an explicit `msDS-SupportedEncryptionTypes`: no shared etype means the request fails.  For an unset account the filter can lift an RC4 fallback to AES, but it will not push an AES fallback down to RC4.  On the pre-April build (April 2026 tests) an RC4-only filter did produce RC4 tickets for AES-configured accounts; that result is superseded for enforcing builds.
