Results are for a target account that **has AES keys**, requested by a client that advertises AES and lists it ahead of RC4, unless a row says otherwise.  The session key follows the client's order of preference: in the lab a client that listed RC4 first received an RC4 session key wherever the account's set and the KDC filter allowed RC4.  "Lab" means the Server 2022 lab DCs listed in the build table on the Registry Audit Results page.

| Decimal | Hex | Bits set | Service ticket | Session key | Notes |
|---|---|---|---|---|---|
| 0 | `0x0` | none (unset) | Depends on the DC: see the default-by-build table | Same | Treated identically to an absent attribute (lab). |
| 4 | `0x4` | RC4 | RC4 | RC4 | Explicit RC4 keeps working on enforcing builds (lab, 20348.5020).  A client that offers only AES gets `KDC_ERR_ETYPE_NOSUPP`. |
| 8 | `0x8` | AES128 | AES128 | AES128 | The client must offer AES128; an AES256-only request fails (lab). |
| 16 | `0x10` | AES256 | AES256 | AES256 | |
| 24 | `0x18` | AES128 + AES256 | AES256 | AES256 | **Recommended.**  An RC4-only client is refused on enforcing builds (Kdcsvc 208, lab); on the pre-April build it received an AES256 ticket with an RC4 session key. |
| 28 | `0x1C` | RC4 + AES128 + AES256 | AES256 | AES256 (RC4 for a client that offers only RC4 or lists RC4 first) | The KDC picks the strongest etype, so the ticket is AES256, not RC4 (lab, every Server 2022 build tested).  The ticket is RC4 only if the account has no AES keys, or if `KdcUseRequestedEtypesForTickets = 1`. |
| 31 | `0x1F` | DES + RC4 + AES128 + AES256 | AES256 | AES256 | No AES-SK bit.  What a computer account writes for itself when all five cipher boxes are allowed. |
| 36 | `0x24` | RC4 + AES-SK | RC4 | AES256 | Microsoft's suggested explicit value for a service that cannot accept AES tickets (KB5073381).  Split etype observed in the lab on the pre-April build (Windows `klist`, and a client offering only AES256).  With DDSET at `0x24`, a client that listed RC4 first received an RC4 session key on the pre-April build and on 20348.5020; the split has not been reproduced on an enforcing build. |
| 39 | `0x27` | DES + RC4 + AES-SK | RC4 | AES256 | The built-in default before the April 2026 update (KB5021131).  Do not set it. |
| 56 | `0x38` | AES128 + AES256 + AES-SK | AES256 | AES256 | Microsoft's suggested DDSET for AES-only domains (KB5021131).  No observed difference from `0x18` in the lab. |
| 60 | `0x3C` | RC4 + AES128 + AES256 + AES-SK | AES256 | AES256 | Microsoft's suggested transitional DDSET (KB5021131).  Lab-tested only with clients whose list includes AES256; behavior with an RC4-only client is **not lab-verified**. |
| 2147483640 | `0x7FFFFFF8` | AES128 + AES256 + bits 5-30 | - | - | Registry value written by the GPO with AES128, AES256 and "Future encryption types" ticked.  The computer account's AD attribute becomes `0x18`. |
| 2147483647 | `0x7FFFFFFF` | every checkbox | - | - | Registry value with all GPO boxes ticked.  The computer account's AD attribute becomes `0x1F` (lab). |
