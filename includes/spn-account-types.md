Five AD object types can have `servicePrincipalName` registered.  Each type gets its
`msDS-SupportedEncryptionTypes` value a different way, has a different password
management model, and a different remediation path.

| Type | AD objectClass | SPNs | Password | Who writes msDS-SET | Value you usually find | Target |
|------|---------------|------|----------|---------------------|------------------------|--------|
| User service account | `user` (objectCategory=person) | Manual | Human-set | Nobody, until an admin does | Unset (`0`) | `0x18` |
| Computer account | `computer` | Auto at domain join | Auto-rotated | The machine itself, from its local Kerberos etype policy | `0x1C` on Windows with no etype policy[^spn-defaults]; unset on non-Windows or pre-staged objects | `0x18` (via GPO) |
| gMSA | `msDS-GroupManagedServiceAccount` | Explicit | Auto-rotated, random | Set at creation; nothing maintains it afterwards | `0x1C`[^spn-defaults] | `0x18` |
| MSA | `msDS-ManagedServiceAccount` | Explicit | Auto-rotated, random | Set at creation; nothing maintains it afterwards | `0x1C` or unset[^spn-defaults] | `0x18` |
| dMSA | `msDS-DelegatedManagedServiceAccount` | Explicit | Auto-rotated, random (Server 2025+) | Set at creation; nothing maintains it afterwards | Unset or `0x1C`[^spn-defaults] | `0x18` |

[^spn-defaults]: Typical values, **not lab-verified** on this site.  Microsoft's KB5021131 confirms the mechanism for computers ("A computer that is running a supported version of the Windows operating system automatically sets the msds-SupportedEncryptionTypes for that machines account in Active Directory.") and that user accounts and gMSAs are not set automatically.  Query your own domain rather than relying on this column.

**Vocabulary used throughout this site:**

- **SPN-bearing accounts** — umbrella term for all five types when discussing msDS-SET,
  etype management, or any context where all types apply.
- **User service accounts** — `user` objects (objectCategory=person) with manually
  registered SPNs; the primary Kerberoasting target.
- **Managed service accounts** — collective for gMSA, MSA, and dMSA when discussing
  auto-rotating passwords.
- **Computer accounts** — objectCategory=computer; a Windows machine keeps its own
  msDS-SET in step with its Kerberos etype policy.

**Self-managed vs manually-managed:**

- **Self-managed:** Windows computer accounts.  The machine rewrites its own AD
  attribute from the etypes its Kerberos policy allows, so you change the policy (GPO),
  not the attribute.  Microsoft's `New-ADServiceAccount` reference puts clustering in the
  same group: "Domain-joined Windows systems and services such as clustering manage their
  own msDS-SupportedEncryptionTypes attribute", and a change made by hand is overwritten.
- **Manually-managed:** user service accounts, gMSA, MSA, dMSA, and computer objects that
  are not Windows machines (NAS filers, Linux hosts).  Set
  `msDS-SupportedEncryptionTypes` explicitly on each one.

!!! info "Why managed service accounts are still worth setting to `0x18`"
    gMSA, MSA, and dMSA passwords are long and random, so Kerberoasting them is not a
    practical threat, and an account at `0x1C` that has AES keys already receives
    **AES256** tickets — the KDC picks the strongest etype in the set.  Setting `0x18`
    removes what `0x1C` still leaves open: an RC4 session key for a client that offers only
    RC4, an RC4 ticket if `KdcUseRequestedEtypesForTickets` is ever set to `1`, and an RC4
    ticket if the account ever ends up without AES keys.  An account left **unset** is a
    different case: on a DC without the April 2026 update it does get RC4 tickets.
