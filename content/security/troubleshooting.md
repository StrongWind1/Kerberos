# Troubleshooting

Practical diagnostic tools, event IDs, error codes, and techniques for resolving
Kerberos authentication and encryption issues.

---

## klist: Listing Cached Tickets

`klist` is the primary client-side tool for inspecting Kerberos tickets.

### Common Commands

| Command | Purpose |
|---|---|
| `klist` | List all cached tickets for the current user session |
| `klist tgt` | Show detailed TGT information |
| `klist get krbtgt` | Force a TGT refresh |
| `klist get HTTP/web.corp.local` | Request a service ticket for a specific SPN |
| `klist purge` | Clear all cached tickets (forces re-authentication) |
| `klist -li 0x3e7` | List tickets for the SYSTEM (computer) account |

### Reading klist Output

```
#1>     Client: alice @ CORP.LOCAL
        Server: MSSQLSvc/sql01.corp.local:1433 @ CORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40810000 -> forwardable renewable name_canonicalize
        Start Time: 4/3/2026 9:15:22 (local)
        End Time:   4/3/2026 19:15:22 (local)
        Renew Time: 4/10/2026 9:15:22 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.corp.local
```

| Field | Meaning |
|---|---|
| `KerbTicket Encryption Type` | Etype used to encrypt the **ticket** itself.  Should be AES-256 for hardened accounts. |
| `Session Key Type` | Etype of the **session key** shared between client and service.  Can differ from ticket etype since Nov 2022. |
| `Ticket Flags` | Ticket options: `forwardable`, `renewable`, `pre_authent`, `name_canonicalize`, etc. |
| `Start Time` / `End Time` | Ticket validity window (default 10 hours). |
| `Renew Time` | Latest time the ticket can be renewed (default 7 days from issuance). |
| `Kdc Called` | The DC that issued this ticket. |

!!! tip "UAC affects which tickets you see"
    On Windows with User Account Control, running `klist` from a normal command prompt shows
    tickets for the standard token.  Running from an elevated (administrator) prompt shows
    tickets for the elevated token.  These are separate sessions with separate ticket caches.

### Diagnosing Mixed Etypes

If you see:

```
KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
Session Key Type:           AES-256-CTS-HMAC-SHA1-96
```

This means the service ticket is encrypted with RC4, but the session key is AES256.  The
target account either has no `msDS-SupportedEncryptionTypes` set (falling back to the domain
default that includes RC4) or explicitly includes RC4 in its etype configuration.  See
[msDS-SupportedEncryptionTypes](msds-supported.md) for remediation.

---

## setspn: SPN Management

SPNs determine which account the KDC looks up when issuing service tickets.

| Command | Purpose |
|---|---|
| `setspn -Q HTTP/web.corp.local` | Find which account owns an SPN |
| `setspn -F -Q */*` | Forest-wide SPN search (slow on large forests) |
| `setspn -L svc_sql` | List all SPNs registered to an account |
| `setspn -S HTTP/web.corp.local svc_web` | Register an SPN (fails if duplicate exists) |
| `setspn -D HTTP/old.corp.local svc_old` | Remove an SPN from an account |

### Duplicate SPN Detection

Duplicate SPNs cause authentication failures -- the KDC cannot determine which account to
use.  Check for duplicates across the domain:

```batch
setspn -X
```

This scans the entire domain for duplicate SPNs and reports any conflicts.

### LDAP-Based SPN Queries with Ldifde

For more targeted SPN searches (e.g., exporting all SPNs to a file for offline analysis),
use `Ldifde.exe`:

```batch
ldifde -f spns.txt -d "DC=corp,DC=local" -r "(servicePrincipalName=*)" -l "dn,servicePrincipalName"
```

This exports every account with at least one SPN, along with the SPN values, to a text file.
Useful for auditing SPN sprawl or identifying orphaned SPNs that `setspn -X` alone would
not flag.

---

## nltest: DC Discovery

| Command | Purpose |
|---|---|
| `nltest /dsgetdc:corp.local` | Find the DC the client is using |
| `nltest /dclist:corp.local` | List all DCs in the domain |
| `nltest /dsgetdc:corp.local /force` | Force a new DC discovery |

Useful when you need to verify which DC is issuing tickets (especially when testing per-DC
registry changes).

---

## Event ID Reference

### Security Log (4768, 4769, 4771)

These are the primary Kerberos audit events.  They require
[auditing to be enabled](group-policy.md#kerberos-auditing-policies).

| Event ID | Log | Description | When It Fires |
|---|---|---|---|
| **4768** | Security | Kerberos TGT request (AS exchange) | Every time a client requests a TGT |
| **4769** | Security | Kerberos service ticket request (TGS exchange) | Every time a client requests a service ticket |
| **4771** | Security | Kerberos pre-authentication failed | Wrong password, locked account, clock skew, etype mismatch |
| **4624** | Security | Successful logon | After successful Kerberos or NTLM authentication (type 3 = network logon) |

#### Reading Event 4769 (Service Ticket)

Key fields to examine:

| Field | What It Shows |
|---|---|
| `Account Name` | The user requesting the ticket |
| `Service Name` | The target account (SPN lookup result) |
| `Ticket Encryption Type` | `0x12` = AES256, `0x11` = AES128, `0x17` = RC4, `0x3` = DES |
| `Session Encryption Type` | Same codes; may differ from ticket etype since Nov 2022 |
| `Failure Code` | `0x0` = success; other values indicate specific errors |
| `Client Address` | IP address of the requesting client |

#### New Fields (January 2025+)

| Field | What It Shows |
|---|---|
| `msDS-SupportedEncryptionTypes` | Etype config for both client and target accounts |
| `Available Keys` | Which key types the account actually has (e.g., `AES-SHA1, RC4`) |
| `Advertized Etypes` | What the client advertised it supports in the request |

### System Log: KDC Errors (14, 16, 26, 27)

These events appear in the System log on DCs, under source
**Microsoft-Windows-Kerberos-Key-Distribution-Center**.

| Event ID | Description | Common Cause |
|---|---|---|
| **14** | No common etype between client and target (AS exchange) | Client only supports AES but account only has RC4 keys |
| **16** | No common etype between client and target (TGS exchange) | Account set to AES-only but only has RC4 keys |
| **26** | Etype not supported by KDC (AS exchange) | Client requests an etype the DC is not configured to allow |
| **27** | Etype not supported by KDC (TGS exchange) | Service requests an etype the DC is not configured to allow |

#### Reading the Event Text

```
While processing a TGS request for target service MSSQLSvc/sql01.corp.local,
the account svc_sql did not have a suitable key for generating a Kerberos
ticket (the missing key has an ID of 9). The requested etypes were 18 17 23 3 1.
The accounts available etypes were 23.
```

Breakdown:

- **Missing key ID 9**: indicates "service ticket encryption" failed (ID values are
  undocumented by Microsoft, but 9 = service ticket encryption, 8 = missing AES key, 1 = key
  operation failure).
- **Requested etypes `18 17 23 3 1`**: the client supports AES256, AES128, RC4, DES-MD5,
  DES-CRC.
- **Available etypes `23`**: the account only has an RC4 key.
- **Fix**: reset the account password to generate AES keys.

### System Log: Kdcsvc Events (201-209)

Introduced with the January 2026 update (CVE-2026-20833).  See the
[RC4 Deprecation](rc4-deprecation.md#kdcsvc-event-reference) page for the complete reference.

| Event ID | Phase | Description |
|---|---|---|
| **201** | Audit | Client only supports RC4, service has no `msDS-SET` |
| **202** | Audit | Service lacks AES keys, no `msDS-SET` |
| **203** | Enforce | RC4 blocked: client only supports RC4, no `msDS-SET` |
| **204** | Enforce | RC4 blocked: service lacks AES keys, no `msDS-SET` |
| **205** | Both | `DefaultDomainSupportedEncTypes` includes RC4 |
| **206** | Audit | Service AES-only, client lacks AES |
| **207** | Audit | Service AES-only, account lacks AES keys |
| **208** | Enforce | RC4 blocked: service AES-only, client lacks AES |
| **209** | Enforce | RC4 blocked: service AES-only, account lacks AES keys |

### Querying Events via PowerShell

```powershell title="Find KDC etype mismatch errors across all DCs"
# Find KDC etype errors across all DCs
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
$Events = foreach ($dc in $dcs) {
  Get-WinEvent -ComputerName $dc -FilterHashtable @{
    LogName = 'System'
    Id      = 14, 16, 26, 27
  } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq "Microsoft-Windows-Kerberos-Key-Distribution-Center" } |
    Select-Object TimeCreated, MachineName, Id, Message
}
$Events | Sort-Object TimeCreated -Descending | Out-GridView
```

```powershell title="Find RC4-encrypted service ticket events across all DCs"
# Find RC4 service tickets across all DCs
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
$Events = foreach ($dc in $dcs) {
  Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath `
    "Event[System[(EventID=4769)]] and Event[EventData[Data[@Name='TicketEncryptionType']='0x17']]" `
    -ErrorAction SilentlyContinue |
    Select-Object `
      @{N='Time';      E={ $_.TimeCreated.ToString('g') }},
      @{N='User';      E={ $_.Properties[0].Value }},
      @{N='Service';   E={ $_.Properties[2].Value }},
      @{N='IP';        E={ $_.Properties[6].Value }},
      @{N='EType';     E={ $_.Properties[5].Value }},
      MachineName
}
$Events | Sort-Object Time -Descending | Out-GridView
```

---

## Wireshark: Kerberos Protocol Analysis

Wireshark can decode Kerberos messages on the wire, which is invaluable when event logs do
not provide enough detail.

### Display Filter

```
kerberos
```

### Key Fields to Examine

| Message | Field to Check | What to Look For |
|---|---|---|
| AS-REQ | `etype` list in body | What etypes the client advertises |
| AS-REQ | `padata > PA-ENC-TIMESTAMP > etype` | Pre-auth etype |
| AS-REP | `ticket > enc-part > etype` | TGT encryption etype (should be 18 = AES256) |
| AS-REP | `padata > PA-ETYPE-INFO2` | Etypes and salt the KDC offers |
| TGS-REQ | `etype` list in body | Client's supported etypes for this request |
| TGS-REP | `ticket > enc-part > etype` | Service ticket encryption etype |
| KRB-ERROR | `error-code` | See error code table below |

### Decrypting Kerberos Traffic

Wireshark can decrypt Kerberos messages if you provide a keytab file:

1. Edit > Preferences > Protocols > KRB5.
2. Set the keytab file path.
3. Wireshark will decrypt the encrypted parts of messages for accounts whose keys are in the
   keytab.

---

## Debug Logging

For deeper client-side investigation, enable verbose Kerberos logging:

```powershell title="Enable Kerberos debug logging, query events, then disable"
# Enable
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "LogLevel" -Value 1 -PropertyType DWord -Force

# Check the System event log for detailed Kerberos events
Get-WinEvent -LogName System -FilterXPath `
  "Event[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] or Provider[@Name='Kerberos']]]" `
  -MaxEvents 50 | Format-List TimeCreated, Id, Message

# Disable when done
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "LogLevel" -Value 0
```

---

## Common Error Codes

Kerberos error codes appear in event logs (as hex `Failure Code` or `Result Code` values) and
in Wireshark captures.

| Error Name | Code (Dec) | Code (Hex) | Meaning | Common Fix |
|---|---|---|---|---|
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 6 | `0x6` | Client principal not found in AD | Verify account name and domain |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | 7 | `0x7` | Service SPN not found in AD | Register SPN with `setspn -S` |
| `KDC_ERR_ETYPE_NOSUPP` | 14 | `0xE` | No common encryption type between client and KDC/service | Check `msDS-SupportedEncryptionTypes`, reset password for AES keys |
| `KDC_ERR_PREAUTH_FAILED` | 24 | `0x18` | Wrong password in pre-authentication | Verify password; check for account lockout |
| `KDC_ERR_PREAUTH_REQUIRED` | 25 | `0x19` | Pre-authentication needed | Normal -- not an error.  Client should retry with PA-ENC-TIMESTAMP |
| `KRB_AP_ERR_TKT_EXPIRED` | 32 | `0x20` | Ticket has expired | Purge tickets (`klist purge`) and re-authenticate |
| `KRB_AP_ERR_SKEW` | 37 | `0x25` | Clock skew too large (> 5 minutes) | Sync client clock with NTP (`w32tm /resync`) |
| `KRB_AP_ERR_MODIFIED` | 41 | `0x29` | Ticket integrity check failed | Duplicate SPNs, service key mismatch, or keytab out of sync |
| `KDC_ERR_TGT_REVOKED` | 33 | `0x21` | TGT has been revoked | KRBTGT password was rotated; re-authenticate |
| `KDC_ERR_KEY_EXPIRED` | 23 | `0x17` | Account password has expired | Reset the account password |

---

## Cached Ticket Invalidation

Kerberos tickets are cached on the client and contain a snapshot of the user's authorization
data (group memberships, account flags) at the time the ticket was issued.  Several common
administrative changes are **not** reflected in existing cached tickets:

**AD group membership changes**
:   Adding a user to a group (or removing them) does not affect their already-cached TGT or
    service tickets.  The user must obtain a new TGT for the updated group membership to appear
    in the PAC.  This means: `klist purge` followed by re-authentication (log off / log on), or
    wait for the TGT to expire naturally (default 10 hours).

**User service account password changes**
:   Rotating a user service account password invalidates all service tickets that were encrypted with
    the old key.  Clients presenting those tickets receive `KRB_AP_ERR_MODIFIED` until they purge
    their ticket cache and request fresh service tickets from the KDC.

**SPN remapping**
:   Changing which account an SPN is registered to (e.g., moving `HTTP/web.corp.local` from the
    computer account to a gMSA) is not picked up by clients until their cached tickets for that
    SPN expire or are purged.

!!! tip "Force a ticket refresh"
    On the client: `klist purge` clears all cached tickets.  The next authentication attempt
    will request fresh tickets from the KDC with current authorization data.

---

## Kerberos Password Change Port

Kerberos password change operations (e.g., `kpasswd`) use **port 464/TCP** on the Domain
Controller, separate from the main Kerberos port 88.  If firewall rules block 464/TCP,
password changes via the Kerberos protocol will fail even though normal authentication works.

Ensure port 464/TCP is open between clients and DCs, and between DCs in different domains
if cross-domain password changes are needed.

---

## Common Scenarios and Fixes

### Scenario: Service Ticket Uses RC4 Despite AES Configuration

**Symptom**: `klist` shows `KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)` even though
`msDS-SupportedEncryptionTypes = 0x18` on the account.

**Possible causes**:

1. The account lacks AES keys (password not reset since DFL 2008).  Check Event ID 16 on the DC.
2. The DC is pre-Server 2019 and adds RC4 automatically for compatibility.
3. Cached tickets from before the change are still in use.

**Fix**: Reset password ([twice for old accounts](algorithms.md#the-double-reset-problem)), purge
client tickets (`klist purge`), re-authenticate.

### Scenario: KDC_ERR_ETYPE_NOSUPP After Blocking RC4

**Symptom**: clients get `KDC_ERR_ETYPE_NOSUPP` (error code 14), Event ID 14 or 26 on the DC.

**Possible causes**:

1. Client only supports RC4 (old Windows, old keytab, GPO forcing RC4).
2. Account only has RC4 keys.

**Fix**: check the DC event for "requested etypes" and "available etypes."  If the account
shows `available etypes: 23` (RC4 only), reset the password.  If the client only advertises
RC4, update the client's etype configuration or GPO.

### Scenario: Authentication Fails After KRBTGT Password Rotation

**Symptom**: widespread authentication failures after rotating the KRBTGT password.

**Cause**: all outstanding TGTs are encrypted with the old KRBTGT key.

**Fix**: this is expected behavior.  Users will get new TGTs automatically when they next
authenticate.  For disconnected sessions, users must re-enter credentials.  Allow time for
AD replication to propagate the new key to all DCs before the second rotation.

### Scenario: Clock Skew Errors (KRB_AP_ERR_SKEW)

**Symptom**: Event 4771 with failure code `0x25`, or Wireshark shows `KRB_AP_ERR_SKEW`.

**Fix**: sync the client clock:

```powershell title="Force NTP sync and verify clock status"
w32tm /resync /force
w32tm /query /status
```

Verify the client is using the correct NTP source (typically the PDC emulator for domain
members).
