Five AD object types can have `servicePrincipalName` registered.  Each type has a
different default `msDS-SupportedEncryptionTypes` value, a different password
management model, and a different remediation path.

| Type | AD objectClass | SPNs | Password | GPO manages msDS-SET? | Default msDS-SET | Target |
|------|---------------|------|----------|-----------------------|-----------------|--------|
| User service account | `user` (objectCategory=person) | Manual | Human-set | No | `0` (unset) | `0x18` |
| Computer account | `computer` | Auto at domain join | Auto-rotated | Yes | `0` | `0x18` (GPO) |
| gMSA | `msDS-GroupManagedServiceAccount` | Explicit | Auto-rotated 240-char | No | `0` | `0x18` |
| MSA | `msDS-ManagedServiceAccount` | Explicit | Auto-rotated | No | `0` | `0x18` |
| dMSA | `msDS-DelegatedManagedServiceAccount` | Explicit | Auto-rotated (Server 2025+) | No | `0` | `0x18` |

**Vocabulary used throughout this site:**

- **SPN-bearing accounts** — umbrella term for all five types when discussing msDS-SET,
  etype management, or any context where all types apply.
- **User service accounts** — `user` objects (objectCategory=person) with manually
  registered SPNs; the primary Kerberoasting target.
- **Managed service accounts** — collective for gMSA, MSA, and dMSA when discussing
  auto-rotating passwords.
- **Computer accounts** — objectCategory=computer; GPO manages their msDS-SET
  automatically.

**GPO-managed vs manually-managed:**

- **GPO-managed:** computer accounts only.  The Kerberos GPO auto-writes the AD
  attribute when the machine processes policy.
- **Manually-managed:** user service accounts, gMSA, MSA, and dMSA.  You must set
  `msDS-SupportedEncryptionTypes` explicitly on each one via PowerShell or ADUC.

!!! info "Why managed service accounts still need AES enforcement"
    gMSA, MSA, and dMSA passwords are auto-generated and uncrackable, so Kerberoasting
    is not a meaningful threat.  However, if `msDS-SupportedEncryptionTypes` is not set
    to `0x18`, the KDC issues RC4-encrypted tickets for those accounts.  RC4 traffic is
    visible on the wire and contributes to the domain's overall RC4 footprint.  Setting
    `msDS-SET = 0x18` eliminates that traffic, ensures compliance with RC4 deprecation
    timelines, and keeps the audit baseline clean.
