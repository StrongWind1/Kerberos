The same bit layout is used by `msDS-SupportedEncryptionTypes`, `DefaultDomainSupportedEncTypes` and `SupportedEncryptionTypes`.  Flag letters are from [MS-KILE] section 2.2.7 (checked against revision 49.0, 28 September 2026).

| Bit | Hex | Decimal | Name | Notes | Source |
|---|---|---|---|---|---|
| 0 | `0x1` | 1 | DES-CBC-CRC | Disabled by default since Windows 7 / Server 2008 R2; removed from Server 2025 and Windows 11 24H2 | MS-KILE flag A; Microsoft removed-features list |
| 1 | `0x2` | 2 | DES-CBC-MD5 | Same as bit 0 | MS-KILE flag B |
| 2 | `0x4` | 4 | RC4-HMAC | No longer assumed for unset accounts on DCs with the April 2026 update; still usable when set explicitly | MS-KILE flag C; KB5073381 |
| 3 | `0x8` | 8 | AES128-CTS-HMAC-SHA1-96 | | MS-KILE flag D |
| 4 | `0x10` | 16 | AES256-CTS-HMAC-SHA1-96 | **Recommended** | MS-KILE flag E |
| 5 | `0x20` | 32 | AES256-CTS-HMAC-SHA1-96-SK | Not a cipher.  "Enforce AES session keys when legacy ciphers are in use."  Honored in DDSET and in a per-account value. | MS-KILE flag J; lab (Server 2022, pre-enforcement build) |
| 6 | `0x40` | 64 | AES128-CTS-HMAC-SHA256-128 | Etype 19 (RFC 8009).  Supported in Server 2025 / Windows 11 24H2 and later, **disabled by default**.  Not lab-verified. | MS-KILE flag K, note 14 |
| 7 | `0x80` | 128 | AES256-CTS-HMAC-SHA384-192 | Etype 20 (RFC 8009).  Same status as bit 6.  Not lab-verified. | MS-KILE flag L, note 15 |
| 8-15 | | | Reserved | Must be zero.  A DDSET of `0x100` produced `KDC_ERR_ETYPE_NOSUPP` on Server 2022. | MS-KILE; lab (20348.5020) |
| 16 | `0x10000` | 65536 | FAST-supported | Feature flag, not an etype.  Meaningful only on the AD attribute. | MS-KILE flag F |
| 17 | `0x20000` | 131072 | Compound-identity-supported | Feature flag | MS-KILE flag G |
| 18 | `0x40000` | 262144 | Claims-supported | Feature flag | MS-KILE flag H |
| 19 | `0x80000` | 524288 | Resource-SID-compression-disabled | Feature flag | MS-KILE flag I |
| 20-30 | | | Reserved | Set by the GPO "Future encryption types" checkbox, which writes bits 5-30 (`0x7FFFFFE0`) to the registry.  They never reach the AD attribute. | Lab (GPO value read back as `0x7FFFFFE0`) |
| 31 | `0x80000000` | 2147483648 | Reserved | Not set by the "Future encryption types" checkbox.  [MS-KILE] says bits it does not define "MUST be ignored when they are received". | Lab (GPO value read back as `0x7FFFFFE0`); MS-KILE section 2.2.7 |
