---
description: Symptom-to-cause table for Kerberos encryption failures after the 2026 RC4 enforcement, plus klist, event IDs, error codes, Wireshark and common scenarios.
---

# Troubleshooting

Practical diagnostic tools, event IDs, error codes, and techniques for resolving
Kerberos authentication and encryption issues.

---

## Start Here: Symptom to Cause

Most encryption-type failures seen since the 2026 RC4 enforcement fall into one of these
rows.  The fixes are worked through in
[RC4 Enforcement: Am I Affected?](enforcement-triage.md).

!!! info "As of 2026-11-10"
    Lab observations on this page come from Server 2022 builds up to 20348.5020 (the April
    2026 update), last re-run on 2026-06-26.  Nothing here is lab-verified on a July 2026
    or later cumulative update, or on a Server 2025 DC.

| Symptom | Where you see it | Likely cause | Fix |
|---|---|---|---|
| `KDC_ERR_ETYPE_NOSUPP` (`0xE`) requesting a **service ticket** | Client error; Security 4769 with `Status` `0xe` and `Ticket Encryption Type` `0xffffffff`; System Event 16 | No usable etype: the client and the service account's effective set share none, or the account has no key for the etype its set requires | Read the Kdcsvc event logged alongside (rows below) |
| Kdcsvc **203** | System log on the DC | Client offered only RC4; the service account has no `msDS-SupportedEncryptionTypes`; the enforced default is AES-only | Make the client offer AES, or add RC4 to that account's attribute |
| Kdcsvc **204** | System log on the DC | The service account has no AES keys and no `msDS-SupportedEncryptionTypes` | Reset the account's password to generate AES keys |
| Kdcsvc **208** | System log on the DC | Client offered only RC4; the service account is AES-only | Make the client offer AES, or add RC4 to that account's attribute |
| Kdcsvc **209** | System log on the DC | The service account is AES-only but has no AES keys | Reset the account's password |
| System **Event 16** on its own | System log on the DC | A TGS request failed for lack of a suitable key or common etype, for any reason.  Compare "requested etypes" with "available etypes" in the text | If available etypes lack 17/18: reset the password.  If requested etypes lack 17/18: fix the client |
| `KDC_ERR_ETYPE_NOSUPP` at **logon** (4768/4771, System Event 14 or 26) | Client error; DC logs | Not the 2026 enforcement, which covers service tickets only.  Usually a DC etype filter that excludes RC4 meeting a user who has no AES keys | Reset the user's password; or allow RC4 in the DC filter and restart the KDC.  Do not count on this for Server 2025 DCs: Microsoft states they "don't issue RC4 Ticket Granting Tickets".  This site's one Server 2025 check (build 26100.32522) did not show that and the two are not reconciled (see [TGT encryption type](rc4-deprecation.md#tgt-encryption-type)), so plan on the password reset there |
| The KDC issues the ticket (4769 `Status` `0x0`, etype `0x12`) but the **service rejects it** (`KRB_AP_ERR_MODIFIED`, application errors) | Service or client side; nothing on the DC | The service's keytab holds only RC4 keys, or holds keys for an older key version | Regenerate the keytab with AES keys; as a stopgap set the account to `36` or `4` |
| Works against one DC, fails against another | Intermittent client errors | DCs differ in update level, `DefaultDomainSupportedEncTypes`, or etype filter | Compare DCs with the per-DC table in the [triage runbook](enforcement-triage.md#step-1-is-each-dc-enforcing) |

`Ticket Encryption Type` `0xffffffff` in a 4769 event means no ticket was issued.  In the
lab, a request blocked by enforcement also showed the full SPN string in `Service Name`
instead of the resolved account name.

!!! warning "Before you reset a service account's password"
    A reset changes the account's keys and raises its key version number.  Every service
    that runs under the account needs the new password, and **every keytab exported for
    the account stops working** until it is regenerated.  Plan the reset as in
    [Fix 3 of the triage runbook](enforcement-triage.md#fix-3-password-reset-for-accounts-without-aes-keys);
    if the service cannot take a change right now, a per-account RC4 exception
    ([Fix 1](enforcement-triage.md#fix-1-per-account-exception)) keeps it running in the
    meantime.

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
        Server: MSSQLSvc/db01.corp.local:1433 @ CORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/3/2026 9:15:22 (local)
        End Time:   4/3/2026 19:15:22 (local)
        Renew Time: 4/10/2026 9:15:22 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC1.corp.local
```

| Field | Meaning |
|---|---|
| `KerbTicket Encryption Type` | Etype used to encrypt the **ticket** itself.  Should be AES-256 for hardened accounts. |
| `Session Key Type` | Etype of the **session key** shared between client and service.  Can differ from the ticket etype. |
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
target account's effective etype set includes RC4 together with the AES session key bit
(`0x20`).  That happens when:

- the account's `msDS-SupportedEncryptionTypes` is explicitly `36` (`0x24`) or similar;
- the account is unset and the DC that answered still uses the old `0x27` default (it has
  not received the April 2026 update); or
- the account is unset and that DC has an explicit `DefaultDomainSupportedEncTypes` such as
  `0x24` or `0x27`.

`Kdc Called` in the `klist` output tells you which DC to inspect.  See
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

Duplicate SPNs cause authentication failures - the KDC cannot determine which account to
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
| `Service Name` | The target account (SPN lookup result).  On a blocked request the lab saw the full SPN string here instead |
| `Ticket Encryption Type` | `0x12` = AES256, `0x11` = AES128, `0x17` = RC4, `0x3` = DES, `0xffffffff` = no ticket issued |
| `Session Encryption Type` | Same codes; may differ from the ticket etype |
| `Failure Code` (`Status` in the XML) | `0x0` = success; other values are Kerberos error codes (see [Common Error Codes](#common-error-codes)) |
| `Client Address` | IP address of the requesting client |

#### New Fields (January 2025+)

These appear as **distinct per-principal fields**, not one combined value.  Captured live on
build 20348.5020.  Microsoft describes the supported-etype fields as *processed* values:
they show what the KDC used, which is not always what is stored in AD.

| Field | What It Shows |
|---|---|
| `AccountSupportedEncryptionTypes` / `AccountAvailableKeys` | The requesting account's etype config and stored key types (often `N/A` on a TGS-REQ) |
| `ServiceSupportedEncryptionTypes` / `ServiceAvailableKeys` | The target service account's etypes and keys.  Reflects the **effective** value after DDSET / enforcement substitution - a `msDS-SET = 0` account shows `0x18` here on an enforced DC, not `0` |
| `DCSupportedEncryptionTypes` / `DCAvailableKeys` | What the DC/KDC itself supports and has keys for |
| `ClientAdvertizedEncryptionTypes` | The etypes the client advertised in the request (a list of etype names in a single field) |
| `SessionKeyEncryptionType` | The session key etype, which may differ from the ticket etype |

### System Log: KDC Errors (14, 16, 26, 27, 42)

These events appear in the System log on DCs, under source
**Microsoft-Windows-Kerberos-Key-Distribution-Center**.

| Event ID | Description | Common Cause |
|---|---|---|
| **14** | No suitable key for an AS request | The account has only RC4 keys and the client, or the DC's etype filter, allows only AES |
| **16** | No suitable key for a TGS request | Any failed service-ticket request: an AES-only account with no AES keys, **or** a client that offers only RC4 to an AES-only account.  Logged alongside Kdcsvc 203/208 under RC4 enforcement |
| **26** | Etype mismatch on an AS request | The etypes the client requested do not match what the account, `krbtgt` and the DC are configured to use, even where the keys exist.  Microsoft's Directory Services team describes it as "The DC, krbtgt account, and client have a Kerberos Encryption Type mismatch" ([AskDS](https://techcommunity.microsoft.com/blog/askds/what-happened-to-kerberos-authentication-after-installing-the-november-2022oob-u/3696351)) |
| **27** | Etype mismatch on a TGS request | "Disjoint encryption types between Kerberos clients and remote servers or services" ([KB5021131](https://support.microsoft.com/help/5021131)).  In the lab it was logged for requests to service accounts whose etype configuration did not match the client's, on a DC left at its default etype policy (build 20348.3207).  It does not by itself point to a DC etype filter |
| **42** | The KDC lacks strong keys for an account | Typically `krbtgt` has no AES keys; rotate it (see [Mitigations](mitigations.md#priority-9-krbtgt-password-rotation)) |

#### Reading the Event Text

```
While processing a TGS request for target service MSSQLSvc/db01.corp.local,
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
- **Fix**: reset the account password to generate AES keys.  Regenerate every keytab
  exported for the account afterwards (see the warning under
  [Start Here](#start-here-symptom-to-cause)).

Event 16 does not always mean missing keys.  If the text reads "requested etypes were 23"
and "available etypes were 23 18 17", the account has every key and the **client** offered
only RC4; the fix is on the client, or an RC4 exception on the account.

### System Log: Kdcsvc Events (201-209)

Introduced with the January 2026 update (CVE-2026-20833).  On an enforcing DC only the
block events (203, 204, 208, 209) and the start-up warning (205) appear.  Background and
remediation are on the [RC4 Deprecation](rc4-deprecation.md#kdcsvc-event-reference) page.

--8<-- "includes/kdcsvc-events.md"

### Querying Events via PowerShell

--8<-- "includes/kdcsvc-event-query.md"

```powershell title="Find KDC key and etype errors (14, 16, 26, 27, 42) across all DCs"
$since = (Get-Date).AddDays(-7)
$dcs = (Get-ADDomainController -Filter *).HostName

$events = foreach ($dc in $dcs) {
    try {
        Get-WinEvent -ComputerName $dc -ErrorAction Stop -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'
            Id           = 14, 16, 26, 27, 42
            StartTime    = $since
        } | Select-Object @{N = 'DC'; E = { $dc } }, TimeCreated, Id, Message
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            Write-Warning "${dc}: NOT CHECKED - $($_.Exception.Message)"
        }
    }
}
$events | Sort-Object TimeCreated -Descending | Out-GridView
```

```powershell title="Find RC4-encrypted service tickets across all DCs"
$since = (Get-Date).AddDays(-1).ToUniversalTime().ToString('o')
$xpath = "*[System[EventID=4769 and TimeCreated[@SystemTime>='$since']] " +
"and EventData[Data[@Name='TicketEncryptionType']='0x17']]"
$dcs = (Get-ADDomainController -Filter *).HostName

$events = foreach ($dc in $dcs) {
    try {
        Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath -ErrorAction Stop |
            ForEach-Object {
                $d = @{}
                ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                [PSCustomObject]@{
                    DC      = $dc
                    Time    = $_.TimeCreated            # kept as DateTime so it sorts correctly
                    User    = $d['TargetUserName']
                    Service = $d['ServiceName']
                    IP      = $d['IpAddress']
                    EType   = $d['TicketEncryptionType']
                    Session = $d['SessionKeyEncryptionType']
                }
            }
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            Write-Warning "${dc}: NOT CHECKED - $($_.Exception.Message)"
        }
    }
}
$events | Sort-Object Time -Descending | Out-GridView
```

To find requests the KDC **refused**, filter on `Status` `0xe` instead; that query is in
the [triage runbook](enforcement-triage.md#failed-service-ticket-requests).

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

```powershell title="Enable Kerberos debug logging, query events, then remove the setting"
# Enable (takes effect immediately)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
    -Name "LogLevel" -Value 1 -PropertyType DWord -Force

# Check the System event log for Kerberos events, whichever Kerberos source wrote them
Get-WinEvent -LogName System -MaxEvents 2000 |
    Where-Object ProviderName -Like '*Kerberos*' |
    Select-Object -First 50 |
    Format-List TimeCreated, ProviderName, Id, Message

# When done, remove the value (Microsoft's instruction; logging costs performance)
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
    -Name "LogLevel"
```

The steps follow Microsoft's
[How to enable Kerberos event logging](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging).
Detailed logging also records expected errors such as `KDC_ERR_PREAUTH_REQUIRED`, which
are not problems.

---

## Common Error Codes

Kerberos error codes appear in event logs (as hex `Failure Code` or `Result Code` values) and
in Wireshark captures.

| Error Name | Code (Dec) | Code (Hex) | Meaning | Common Fix |
|---|---|---|---|---|
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 6 | `0x6` | Client principal not found in AD | Verify account name and domain |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | 7 | `0x7` | Service SPN not found in AD | Register SPN with `setspn -S` |
| `KDC_ERR_ETYPE_NOSUPP` | 14 | `0xE` | No usable encryption type for the request | See [Start Here](#start-here-symptom-to-cause) |
| `KDC_ERR_TGT_REVOKED` | 20 | `0x14` | TGT has been revoked or is no longer valid | Re-authenticate to get a new TGT |
| `KDC_ERR_KEY_EXPIRED` | 23 | `0x17` | Account password has expired | Reset the account password |
| `KDC_ERR_PREAUTH_FAILED` | 24 | `0x18` | Wrong password in pre-authentication | Verify password; check for account lockout |
| `KDC_ERR_PREAUTH_REQUIRED` | 25 | `0x19` | Pre-authentication needed | Normal - not an error.  Client should retry with PA-ENC-TIMESTAMP |
| `KRB_AP_ERR_TKT_EXPIRED` | 32 | `0x20` | Ticket has expired | Purge tickets (`klist purge`) and re-authenticate |
| `KRB_AP_ERR_TKT_NYV` | 33 | `0x21` | Ticket not yet valid | Check clock synchronisation between client, DC and service |
| `KRB_AP_ERR_SKEW` | 37 | `0x25` | Clock skew too large (> 5 minutes) | Sync client clock with NTP (`w32tm /resync`) |
| `KRB_AP_ERR_MODIFIED` | 41 | `0x29` | The service could not decrypt or verify the ticket | Duplicate SPNs, service password changed, keytab out of date, or keytab lacks the ticket's etype (for example an RC4-only keytab receiving an AES ticket) |

---

## Cached Ticket Invalidation

Kerberos tickets are cached on the client and contain a snapshot of the user's authorization
data (group memberships, account flags) at the time the ticket was issued.  Several common
administrative changes are **not** reflected in existing cached tickets:

**AD group membership changes**
:   Adding a user to a group (or removing them) does not affect their already-cached TGT or
    service tickets.  Whether a *new* service ticket requested with the *old* TGT picks up
    the change is not settled here.  MS-KILE §3.3.5.7 says the KDC copies the PAC fields
    from the TGT into the service ticket and adds only the domain-local groups of the
    service's domain, so a group change needs a new TGT.  One lab run (Server 2022 build
    20348.3207) concluded that the new group did appear without a new TGT, but it read the
    PAC through a fresh S4U2Self request, not from a ticket issued on the old TGT.  To be
    sure the change has applied: `klist purge` followed by re-authentication (log off /
    log on), or wait for the TGT to expire naturally (default 10 hours).

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

Kerberos password change operations (e.g., `kpasswd`) use **port 464** (TCP and UDP) on the
Domain Controller, separate from the main Kerberos port 88.  If firewall rules block port
464, password changes via the Kerberos protocol fail even though normal authentication
works.

Ensure port 464 is open between clients and DCs, and between DCs in different domains if
cross-domain password changes are needed.

---

## Common Scenarios and Fixes

### Scenario: Service Ticket Uses RC4 Despite AES Configuration

**Symptom**: `klist` shows `KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)` even though
`msDS-SupportedEncryptionTypes = 0x18` on the account.

An AES-only account that lacks AES keys does **not** fall back to RC4; it fails.  So an RC4
ticket here means the KDC did not use `0x18` for this request.

**Possible causes**:

1. The ticket is cached from before the change.  Run `klist purge` and retry.
2. The attribute change has not replicated to the DC that issued the ticket (`Kdc Called`
   in `klist`).
3. `KdcUseRequestedEtypesForTickets = 1` is set on that DC.  On a pre-April 2026 Server
   2022 build (tested 6-7 April 2026, revision not recorded) this let a client pull an RC4
   ticket even for an AES-only account; on the enforcing build (20348.5020) it only
   affected accounts whose attribute lists RC4.
4. The SPN belongs to a different account than the one you changed.  Check with
   `setspn -Q`.

**Fix**: purge and retry, confirm the attribute on the issuing DC, and remove
`KdcUseRequestedEtypesForTickets` if present.

### Scenario: KDC_ERR_ETYPE_NOSUPP on a Service Ticket Request

**Symptom**: clients get `KDC_ERR_ETYPE_NOSUPP` (error code 14); the DC logs Event 16,
usually with a Kdcsvc 203, 204, 208 or 209 event.

**Possible causes**:

1. The client offers only RC4 (old software, an old keytab, or a policy forcing RC4) and
   the service account's effective set is AES-only.
2. The service account has only RC4 keys and its effective set is AES-only, either
   explicitly or through the enforced default.
3. The service account is explicitly RC4-only and the client, or the DC's etype filter,
   allows only AES.

**Fix**: read "requested etypes" and "available etypes" in Event 16.  If the account shows
`available etypes: 23` (RC4 only), reset its password, after reading the warning under
[Start Here](#start-here-symptom-to-cause): the reset invalidates every keytab exported
for the account.  If the client requested only `23`,
update the client's etype configuration.  Step-by-step fixes are in the
[triage runbook](enforcement-triage.md#step-3-symptom-cause-fastest-safe-fix).

### Scenario: Authentication Fails After KRBTGT Password Rotation

**Symptom**: widespread authentication failures after rotating the KRBTGT password.

**Cause**: a single rotation should not cause this.  AD keeps the previous `krbtgt` key, so
TGTs issued before the rotation stay valid.  Widespread failures follow when the password
is reset **twice in quick succession** (the key that outstanding TGTs were issued under is
gone), or when a DC has not yet received the new key through replication.

**Fix**: affected users and services get new TGTs when they next authenticate; disconnected
sessions need credentials re-entered, and some services need a restart.  For next time,
follow the rotation procedure in
[Mitigations](mitigations.md#priority-9-krbtgt-password-rotation): confirm replication,
then wait at least the maximum ticket lifetime before the second reset.

### Scenario: Clock Skew Errors (KRB_AP_ERR_SKEW)

**Symptom**: Event 4771 with failure code `0x25`, or Wireshark shows `KRB_AP_ERR_SKEW`.

**Fix**: sync the client clock:

```powershell title="Force NTP sync and verify clock status"
w32tm /resync /force
w32tm /query /status
```

Verify the client is using the correct NTP source (typically the PDC emulator for domain
members).
