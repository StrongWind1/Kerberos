---
---

# Mitigations

Best practices for securing Kerberos in Active Directory, organized by impact and
priority.  Start at the top and work down.

---

## Priority 1: Group Managed Service Accounts (gMSA)

gMSA is the single most effective defense against Kerberoasting.

### What gMSA Provides

- **Auto-generated 240-character passwords** that are cryptographically random.
- **Automatic rotation** every 30 days (configurable) without any manual intervention.
- **AES by default**: `msDS-SupportedEncryptionTypes` defaults to `0x1C` (RC4 + AES128 +
  AES256).  Set it explicitly to `0x18` (AES-only) to eliminate RC4 traffic, or `0x3C`
  (RC4 + AES + AES256-SK) if RC4 fallback is needed.  The password complexity makes RC4
  cracking infeasible regardless, but removing RC4 eliminates the attack surface entirely.
- **No human knows the password**: it is managed entirely by AD and retrieved only by
  authorized computer accounts.

### Why It Defeats Kerberoasting

Even if an attacker obtains an RC4-encrypted service ticket for a gMSA, cracking a
240-character random password is computationally impossible.  A brute-force search space of
`95^240` characters is beyond the reach of any current or foreseeable technology.

### How to Deploy

```powershell title="Create KDS root key, security group, gMSA, then install on hosts"
# One-time: create the KDS root key.
# -EffectiveImmediately backdates the effective time by 10 hours; it does NOT
# bypass the 10-hour DC replication wait. Safe for single-DC labs only.
# In production, omit -EffectiveImmediately and wait 10+ hours before creating gMSAs.
Add-KdsRootKey -EffectiveImmediately

# Create a security group for servers that will use the gMSA
New-ADGroup -Name "gMSA_SQL_Hosts" -GroupScope DomainLocal -GroupCategory Security
Add-ADGroupMember -Identity "gMSA_SQL_Hosts" -Members "SQL01$", "SQL02$"

# Create the gMSA
New-ADServiceAccount -Name "gMSA_SQL" `
  -DNSHostName "gMSA_SQL.corp.local" `
  -PrincipalsAllowedToRetrieveManagedPassword "gMSA_SQL_Hosts" `
  -KerberosEncryptionType AES128, AES256

# On each host: install and test
Install-ADServiceAccount gMSA_SQL
Test-ADServiceAccount gMSA_SQL
```

!!! tip "Use gMSA for every service that supports it"
    SQL Server, IIS application pools, scheduled tasks, Windows services, and many
    third-party applications support gMSA.  There is no reason to use a regular service
    account for any of these.

---

## Priority 2: AES Enforcement on Manually-Managed SPN-Bearing Accounts

For all SPN-bearing accounts that are manually managed (user service accounts, gMSA, MSA,
and dMSA), enforce AES encryption.  Computer accounts are handled by GPO (Priority 4 below).

### Steps

1. **Reset the password** ([twice for pre-2008 accounts](algorithms.md#the-double-reset-problem)) to generate AES keys.
2. **Set `msDS-SupportedEncryptionTypes = 0x18`** (AES128 + AES256) on the account.
3. **Verify** that service tickets are issued with AES:

```powershell
# On a client machine, purge cached tickets and reconnect to the service
klist purge
# Access the service, then check
klist
```

Look for `KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96`.

### Bulk Enforcement

!!! tip "Cross-type overview"
    Before running the per-type blocks below, use the
    [overview query](msds-supported.md#all-spn-bearing-accounts-overview-all-5-types)
    in `msds-supported.md` to see the full distribution across all five account types.

**User service accounts** (objectCategory=person with SPNs):

--8<-- "includes/set-aes-user-accounts.md"

**gMSA accounts:**

--8<-- "includes/set-aes-gmsa.md"

**MSA accounts:**

--8<-- "includes/set-aes-msa.md"

**dMSA accounts:**

--8<-- "includes/set-aes-dmsa.md"

---

## Priority 3: Strong Password Policies for User Service Accounts

For any user service account, the password is the last line of defense.

| Recommendation | Details |
|---|---|
| **Minimum length** | 25 characters (30+ preferred) |
| **Complexity** | Random mix of upper, lower, digits, symbols |
| **No dictionary words** | Avoid any word that appears in common password lists |
| **Rotation** | At least annually; immediately if compromise is suspected |
| **Storage** | Use a privileged access management (PAM) vault, not a spreadsheet |

A 25-character random password with AES256 encryption is effectively uncrackable.  Even with
RC4 (if temporarily needed), a 30+ character random password pushes cracking time into
decades at current GPU speeds.

---

## Priority 4: Protected Users Group

The **Protected Users** security group provides additional hardening for privileged accounts.

### What It Enforces

| Protection | Detail |
|---|---|
| No NTLM authentication | The account cannot authenticate via NTLM. |
| No DES or RC4 pre-authentication | Only AES is used for the AS exchange. |
| TGT lifetime: 4 hours | Non-renewable.  Limits the window for TGT theft. |
| No long-term credential caching | Long-term credentials are not cached (DPAPI itself is not disabled). |
| No delegation | The account cannot be delegated (constrained or unconstrained). |

### What It Does NOT Protect Against

!!! warning "Protected Users does not prevent Kerberoasting"
    Kerberoasting targets the **service ticket** (TGS-REP), not the TGT.  The service
    ticket is encrypted with the **target account's** key, and the requesting user's group
    membership has no effect on the service ticket encryption.  Even if a target account is
    in Protected Users, an attacker requesting a ticket *for* that service will get a ticket
    encrypted with whatever etype the target account supports.

    Protected Users also does not prevent AS-REP roasting if the account has
    `DONT_REQUIRE_PREAUTH` set.

### Who to Add

- All Domain Admins
- All Enterprise Admins
- All Schema Admins
- Administrative user accounts (help desk, PAM, etc.)
- Any account with Tier 0 access

### Who NOT to Add

- User service accounts that run on servers (they cannot authenticate because delegation and
  credential caching are disabled)
- Accounts that need NTLM authentication (legacy apps)
- Computer accounts (use computer-specific hardening instead)

```powershell
# Add an account to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "admin_jdoe"
```

!!! note "PAC staleness and TGS-time revalidation"
    On Server 2022+ with KB5008380+, the KDC re-validates PAC contents during TGS exchanges,
    reducing the effective staleness window. The TGT itself still carries the old PAC, but
    **service tickets derived from it get updated group membership**. This means adding a user
    to Protected Users takes effect on new service tickets even before the user's TGT expires,
    though the TGT-level protections (4-hour lifetime, AES-only pre-auth) still require a fresh
    TGT.

!!! note "Protected Users + RC4 edge case"
    Protected Users group membership overrides per-account `msDS-SupportedEncryptionTypes` for
    the **AS exchange** -- pre-authentication and TGT encryption are forced to AES regardless of
    the account's etype configuration.

    However, Protected Users does **not** affect service ticket encryption. A Protected Users
    member can still receive RC4-encrypted service tickets if the target account only
    supports RC4. The Protected Users protections apply to the member's own authentication
    (AS-REQ/AS-REP), not to service tickets issued on behalf of the member to other services.

!!! warning "Group membership changes require new tickets"
    Adding a user to Protected Users (or any AD security group) does **not** take effect in
    their existing Kerberos tickets.  The user's cached TGT still contains the old group
    membership in its PAC.  The user must log out and log back in -- or run `klist purge` and
    re-authenticate -- for the new group membership to appear in fresh tickets.

    This is a common gotcha when implementing hardening: you add an account to Protected Users,
    but the protections (no NTLM, no delegation, 4-hour TGT, AES-only) do not activate until
    the user obtains a new TGT.  In the worst case, this means waiting up to 10 hours (the
    default TGT lifetime) for existing tickets to expire.

---

## Priority 5: SPN Hygiene

Every Service Principal Name (SPN) on a user account is a potential Kerberoasting target.

### Audit SPNs

```powershell title="Find all user accounts with SPNs and their admin group memberships"
# Find all user accounts with SPNs
Get-ADUser -Filter 'servicePrincipalName -like "*"' `
  -Properties servicePrincipalName, MemberOf |
  Select-Object sAMAccountName, servicePrincipalName,
    @{N='AdminGroup'; E={
      ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
    }}
```

### Forest-Wide SPN Search

```batch
setspn -F -Q */*
```

### Rules

1. **Remove SPNs from admin accounts.** Domain Admins, Enterprise Admins, and Schema Admins
   should never have SPNs.  If a privileged account has an SPN, an attacker can Kerberoast it
   and gain domain admin access.
2. **Remove SPNs from accounts that do not run services.** Some SPNs are set by accident
   (e.g., failed service configurations that were never cleaned up).
3. **Only set SPNs on the minimum necessary accounts.**  If a service uses a computer account,
   the SPN belongs on the computer account, not a user account.

```powershell
# Remove an SPN from a user account
Set-ADUser -Identity svc_old -ServicePrincipalNames @{Remove="HTTP/old.corp.local"}
```

---

## Priority 6: Delegation Lockdown

Misconfigured delegation is a gateway to domain compromise.

### Unconstrained Delegation

Accounts with **TRUSTED_FOR_DELEGATION** can impersonate any user to any service.  Only
domain controllers should have this flag.

```powershell title="Find non-DC accounts and users with unconstrained delegation"
# Find all non-DC accounts with unconstrained delegation
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation |
  Where-Object { $_.DistinguishedName -notlike "*Domain Controllers*" } |
  Select-Object Name, DistinguishedName

Get-ADUser -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation |
  Select-Object Name, DistinguishedName
```

**Fix**: Remove unconstrained delegation and replace with constrained delegation or RBCD.

### Constrained Delegation with Protocol Transition

Accounts with `msDS-AllowedToDelegateTo` and the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag can
request tickets on behalf of any user to the services listed in the attribute.

Audit these accounts and limit the target services to the absolute minimum:

```powershell title="Audit constrained delegation accounts with protocol transition"
Get-ADObject -Filter 'msDS-AllowedToDelegateTo -like "*"' `
  -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation |
  Select-Object Name, ObjectClass, msDS-AllowedToDelegateTo, TrustedToAuthForDelegation
```

### Resource-Based Constrained Delegation (RBCD)

RBCD is the preferred delegation model.  The **target** service controls who can delegate to
it (via `msDS-AllowedToActOnBehalfOfOtherIdentity`), rather than the **source** account
controlling where it can delegate.

Monitor changes to this attribute:

```powershell title="Find computers with RBCD configured"
Get-ADComputer -Filter 'msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"' `
  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Select-Object Name, msDS-AllowedToActOnBehalfOfOtherIdentity
```

---

## Priority 7: Disable DONT_REQUIRE_PREAUTH

Accounts with the `DONT_REQUIRE_PREAUTH` flag are vulnerable to
[AS-REP roasting](../attacks/roasting/asrep-roasting.md).  The KDC sends an encrypted response
without verifying the client's identity, and the attacker can crack it offline.

```powershell title="Find accounts with DONT_REQUIRE_PREAUTH and re-enable pre-auth"
# Find accounts with pre-auth disabled
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' `
  -Properties DoesNotRequirePreAuth |
  Select-Object sAMAccountName, Enabled, DoesNotRequirePreAuth

# Fix: re-enable pre-auth
Set-ADAccountControl -Identity vulnerable_user -DoesNotRequirePreAuth $false
```

There is almost no legitimate reason for this flag in a modern environment.

---

## Priority 8: Honeypot Accounts

Create decoy user service accounts that exist solely to detect Kerberoasting reconnaissance.

### Setup

1. Create a user account with an enticing name (e.g., `svc_backup`, `svc_admin`).
2. Set an SPN on it:
   ```powershell
   Set-ADUser -Identity svc_honeypot -ServicePrincipalNames @{
     Add = "MSSQLSvc/honeypot.corp.local:1433"
   }
   ```
3. Set `msDS-SupportedEncryptionTypes = 0x18` (AES-only).
4. Set a 50+ character random password.
5. **Do not use this account for any real service.**

### Detection

Any Event ID 4769 for this account's SPN is a Kerberoasting indicator:

```powershell title="Query Event 4769 for honeypot SPN requests"
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id      = 4769
} | Where-Object {
  $_.Properties[2].Value -eq 'svc_honeypot'
} | Select-Object TimeCreated, @{
  N = 'Client'
  E = { $_.Properties[0].Value }
}, @{
  N = 'IP'
  E = { $_.Properties[6].Value }
}
```

Configure your SIEM to alert on any 4769 event targeting this account.

---

## Priority 9: KRBTGT Password Rotation

The KRBTGT account encrypts every TGT in the domain.  If compromised, an attacker can forge
Golden Tickets.

### Rotation Schedule

- **Routine**: at least every 180 days (quarterly is better).
- **After compromise**: immediately, **twice**, with replication time between rotations.

### Why Twice

AD retains the current and previous KRBTGT key.  After one rotation, TGTs encrypted with the
old key are still valid (using the previous key).  The second rotation invalidates the
original key entirely.

### Safe Rotation Process

1. Verify replication health: `repadmin /replsummary`
2. Reset the KRBTGT password using Microsoft's
   [`New-KrbtgtKeys.ps1`](https://github.com/microsoft/New-KrbtgtKeys.ps1) script.
3. Force replication and verify it completes on **every** DC:
   ```powershell
   repadmin /syncall /e /d /A /P
   repadmin /replsummary
   ```
4. **Wait at least 10-12 hours** (2x the default TGT lifetime of 10 hours) before the
   second rotation.  This ensures all outstanding TGTs encrypted with the now-previous
   key have expired.
5. Reset the KRBTGT password a second time.
6. Wait for replication again and verify:
   ```powershell
   repadmin /syncall /e /d /A /P
   ```
7. Validate the new key version and last password set time:
   ```powershell
   Get-ADUser krbtgt -Properties msDS-KeyVersionNumber, PasswordLastSet |
     Select-Object Name, msDS-KeyVersionNumber, PasswordLastSet
   ```
8. Monitor for authentication failures (users may need to re-authenticate).

!!! note "AzureADKerberos (Entra Cloud Kerberos Trust)"
    If your domain uses Azure AD / Entra Cloud Kerberos Trust, there will be a computer
    object named `AzureADKerberos` in the Domain Controllers OU.  This is a **proxy
    object**, not a real domain controller — exclude it from DC counts and encryption
    assessments.

    The `AzureADKerberos` object has its own `krbtgt_AzureAD` account whose keys are
    **not** rotated by the standard KRBTGT rotation process.  Rotate it separately:

    ```powershell
    Set-AzureADKerberosServer -Domain "corp.local" -RotateServerKey
    ```

    Similarly, each **Read-Only Domain Controller** has its own `krbtgt_XXXXX` account
    (where `XXXXX` is the RODC's connection ID).  These must be rotated independently of
    the primary KRBTGT — the `New-KrbtgtKeys.ps1` script handles RODCs when run with the
    `-RODC` parameter.

!!! note "Linux keytab impact"
    Password rotation on any service account — including KRBTGT — **invalidates existing
    Kerberos keytab files** that contain the old key.  This affects any Linux or Unix
    service authenticating via AD Kerberos: Apache (`mod_auth_gssapi`), SSSD, Samba,
    PostgreSQL, and others.

    After rotating a service account password, regenerate the keytab on each host:

    ```bash
    # Windows: generate keytab
    ktpass -out /etc/krb5.keytab -princ HTTP/web.corp.local@CORP.LOCAL \
      -mapUser corp\svc_web -mapOp set -pass <password> \
      -ptype KRB5_NT_PRINCIPAL -crypto AES256-SHA1

    # Linux: verify the keytab works
    kinit -kt /etc/krb5.keytab HTTP/web.corp.local@CORP.LOCAL
    ```

    For KRBTGT specifically, this is less of an operational concern (services do not hold
    KRBTGT keytabs), but the principle applies to any Priority 2 password reset.

---

## Priority 10: DefaultDomainSupportedEncTypes

Set [`DefaultDomainSupportedEncTypes`](registry.md#defaultdomainsupportedenctypes) `= 0x18`
on **every** domain controller to enforce AES as the default for accounts without explicit
`msDS-SupportedEncryptionTypes`.  This eliminates the most common Kerberoasting vector:
SPN-bearing accounts with no explicit etype configuration falling back to RC4.  See
[Registry Settings](registry.md#defaultdomainsupportedenctypes) for the commands and the
[Standardization Guide](aes-standardization.md#step-5-set-defaultdomainsupportedenctypes-on-every-dc)
for the full per-DC verification workflow.

---

## Priority 11: Trust Encryption Types

Cross-domain and cross-forest trusts have their own `msDS-SupportedEncryptionTypes` value
on the Trusted Domain Object (TDO).  After the November 2022 update (KB5021131 /
CVE-2022-37966), trusts with `msDS-SupportedEncryptionTypes = 0` default to **AES** — a
change from the previous RC4 default.  This means most trusts created or updated after
November 2022 already use AES with no action required.

However, trusts that have an **explicit** value containing DES or RC4 bits will continue
using those weaker algorithms regardless of the new default behavior.

### Find Trusts with Explicit RC4 or DES

```powershell title="Find trust objects with explicit RC4 or DES encryption types"
Get-ADObject -Filter 'objectClass -eq "trustedDomain"' `
  -Properties msDS-SupportedEncryptionTypes, trustDirection, trustType, flatName |
  Where-Object {
    $set = [int]$_.'msDS-SupportedEncryptionTypes'
    # Bit 0x4 = RC4, bits 0x1/0x2 = DES
    $set -gt 0 -and ($set -band 0x7)
  } |
  Select-Object flatName, trustDirection, trustType,
    @{N='msDS-SET (dec)'; E={[int]$_.'msDS-SupportedEncryptionTypes'}},
    @{N='msDS-SET (hex)'; E={'0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes'}} |
  Format-Table -AutoSize
```

### Remediation

For trusts that show RC4 or DES in the output above, either:

1. **Clear the attribute** to let it default to AES (recommended for post-November 2022
   DCs):
   ```powershell
   Set-ADObject -Identity "CN=PARTNER,CN=System,DC=corp,DC=local" `
     -Clear 'msDS-SupportedEncryptionTypes'
   ```

2. **Set it explicitly to AES-only** (`0x18`):
   ```powershell
   Set-ADObject -Identity "CN=PARTNER,CN=System,DC=corp,DC=local" `
     -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
   ```

After changing trust encryption, reset the trust password from both sides (`netdom trust
/resetOnTrust`) and verify cross-domain authentication still works.

---

## Summary Checklist

| Priority | Action | Protects Against |
|---|---|---|
| 1 | Deploy gMSA for all eligible services | Kerberoasting |
| 2 | Set `msDS-SupportedEncryptionTypes = 0x18` on all manually-managed SPN-bearing accounts (user service accounts, gMSA, MSA, dMSA) | Kerberoasting + RC4 traffic |
| 3 | Enforce 25+ char passwords on user service accounts | Kerberoasting |
| 4 | Add privileged accounts to Protected Users | Credential theft, NTLM relay |
| 5 | Remove SPNs from admin and unused accounts | Kerberoasting of high-value targets |
| 6 | Remove unconstrained delegation from non-DCs | Delegation attacks |
| 7 | Disable `DONT_REQUIRE_PREAUTH` everywhere | AS-REP roasting |
| 8 | Deploy honeypot SPN accounts | Kerberoast detection |
| 9 | Rotate KRBTGT password regularly | Golden Ticket |
| 10 | Set `DefaultDomainSupportedEncTypes = 0x18` on all DCs | Kerberoasting (domain-wide default) |
| 11 | Audit and remediate trust encryption types | RC4/DES on cross-domain trusts |
