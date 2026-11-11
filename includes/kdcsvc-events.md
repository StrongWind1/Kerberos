Logged in the **System** log on domain controllers.  Microsoft's KB lists the event source as `Kdcsvc`; query them with the provider name `Microsoft-Windows-Kerberos-Key-Distribution-Center`.  Conditions are from KB5073381; the last column says whether this site's lab reproduced the event.

| Event | Mode | Logged when | Outcome | What to do | Lab-observed |
|---|---|---|---|---|---|
| **201** | Audit | Client advertises only RC4; service has no `msDS-SupportedEncryptionTypes`; DC has no `DefaultDomainSupportedEncTypes` | Request allowed, warning logged | Historical.  Becomes 203 under enforcement. | Yes |
| **202** | Audit | Service account has no AES keys; service has no `msDS-SupportedEncryptionTypes`; DC has no `DefaultDomainSupportedEncTypes` | Warning logged | Historical.  Becomes 204 under enforcement. | No |
| **203** | Enforce | Same conditions as 201 | **Request blocked** | Make the client offer AES.  If it cannot, add RC4 to that service account's `msDS-SupportedEncryptionTypes`. | Yes |
| **204** | Enforce | Same conditions as 202 | **Request blocked** | Reset the service account's password to generate AES keys. | No |
| **205** | Audit and Enforce (at KDC start) | `DefaultDomainSupportedEncTypes` is explicitly set and includes anything other than AES-SHA1.  KB5073381 lists it for `RC4DefaultDisablementPhase` `1` and `2`; the lab notes also record it at `0` (build 20348.5020) | Warning only; never becomes an error; the explicit value is still honored | Remove RC4 from the value once exceptions are configured per account. | Yes |
| **206** | Audit | Client advertises only RC4; the service's `msDS-SupportedEncryptionTypes` (or the DC's `DefaultDomainSupportedEncTypes`) is AES-only | Warning logged | Historical.  Becomes 208 under enforcement. | Yes, on the pre-April build only (6-7 April 2026) |
| **207** | Audit | Service account has no AES keys; the service's `msDS-SupportedEncryptionTypes` (or the DC's `DefaultDomainSupportedEncTypes`) is AES-only | Warning logged | Historical.  Becomes 209 under enforcement. | No |
| **208** | Enforce | Same conditions as 206 | **Request blocked** | Make the client offer AES.  If it cannot, add RC4 to that service account's `msDS-SupportedEncryptionTypes` so a session key can be agreed. | Yes |
| **209** | Enforce | Same conditions as 207 | **Request blocked** | Reset the service account's password to generate AES keys. | No |
