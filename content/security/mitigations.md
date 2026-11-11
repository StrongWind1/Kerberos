---
description: Prioritized Kerberos hardening for Active Directory - gMSA, AES on service accounts, Protected Users, SPN hygiene, delegation lockdown, krbtgt rotation, and trust encryption types.
---

# Mitigations

Best practices for securing Kerberos in Active Directory, organized by impact and
priority.  Start at the top and work down.

!!! info "As of 2026-11-10"
    Domain controllers with the April 2026 update or later already treat unconfigured
    accounts as AES-only (see [RC4 Deprecation](rc4-deprecation.md)).  The priorities below
    assume that state: they are about removing the RC4 that is still *explicitly*
    configured, and about the defenses that have nothing to do with encryption types.

---

## Priority 1: Group Managed Service Accounts (gMSA)

gMSA is the single most effective defense against Kerberoasting.

### What gMSA Provides

- **Auto-generated passwords**: 240 bytes, randomly generated
  ([Microsoft](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)).
- **Automatic rotation** every 30 days (configurable) without any manual intervention.
- **AES-capable from creation**: create the account with
  `-KerberosEncryptionType AES128, AES256` (as below) so its
  `msDS-SupportedEncryptionTypes` is `0x18`, and check existing gMSAs for a value that
  still lists RC4 (defaults by account type are in
  [msDS-SupportedEncryptionTypes](msds-supported.md)).  The random password makes cracking
  infeasible either way; removing RC4 from the declared set keeps the account consistent
  with the rest of the domain.
- **No human knows the password**: it is managed entirely by AD and retrieved only by
  authorized computer accounts.

### Why It Defeats Kerberoasting

Even if an attacker obtains an RC4-encrypted service ticket for a gMSA, the key behind it
comes from a 240-byte random password.  There is no dictionary to try, and a brute-force
search of that space is beyond any current or foreseeable technology.

### How to Deploy

```powershell title="Create KDS root key, security group, gMSA, then install on hosts"
# One-time: create the KDS root key.
# DCs wait up to 10 hours after creation before they hand out gMSA passwords, so
# that the key can replicate everywhere.  -EffectiveImmediately does not remove
# that wait: create the key, then wait 10 hours before creating gMSAs.
Add-KdsRootKey -EffectiveImmediately

# Single-DC test lab only: backdate the key so it is usable at once.
# Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

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
and dMSA), declare AES explicitly.  On an enforcing DC an unset account already gets AES,
so the remaining work is the accounts that still **list RC4**, and the accounts that have
**no AES keys**.  Windows computer accounts maintain their own value.

### Steps

1. **Confirm the account has AES keys.**  If its password predates the domain's move to
   functional level 2008, reset the password once and verify the keys
   (see [Auditing Kerberos Keys](account-key-audit.md)).  A reset raises the key version
   number, so regenerate any keytab exported for the account.
2. **Set `msDS-SupportedEncryptionTypes = 0x18`** (AES128 + AES256) on the account.
   Doing this on an account without AES keys makes every request for it fail.
3. **Verify** that service tickets are issued with AES:

```powershell
# On a client machine, purge cached tickets and reconnect to the service
klist purge
# Access the service, then check
klist
```

Look for `KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96`.

### Bulk Enforcement

!!! warning "Review before you run"
    Bulk changes must leave `krbtgt` and your documented RC4 exceptions alone, and must not
    set AES-only on an account that has no AES keys.  Run the scripts below in their
    dry-run mode first and read the plan.  The
    [Standardization Guide](aes-standardization.md) walks through them step by step.

!!! tip "Cross-type overview"
    Before running the per-type blocks below, use the
    [overview query](msds-supported.md#all-spn-bearing-accounts-overview-all-5-types)
    on the msDS-SupportedEncryptionTypes page to see the full distribution across all five account types.

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

The domain-controller side of these protections requires the domain functional level to be
Windows Server 2012 R2 or higher.

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

Test before adding a whole privileged group.  Microsoft's
[Protected Users guidance](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
says not to add accounts that are already members of highly privileged groups "until you
can guarantee that adding them won't have negative consequences", because "it's possible
to accidentally lock out their accounts".  Members can only authenticate with Kerberos
using AES, so each account needs AES keys first.

### Who NOT to Add

- User service accounts that run on servers.  Microsoft: "Never add accounts for services
  and computers to the Protected Users group. For those accounts, membership doesn't
  provide local protections because the password and certificate is always available on
  the host."
- Accounts that need NTLM authentication (legacy apps)
- Computer accounts (use computer-specific hardening instead)
- Every privileged account at once: keep at least one tightly controlled break-glass
  administrator outside the group, in case an AES or Kerberos problem locks the others out

```powershell
# Add an account to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "admin_jdoe"
```

!!! note "PAC hardening and group membership"
    KB5008380 (CVE-2021-42287) added `PAC_REQUESTOR_SID` and `PAC_ATTRIBUTES_INFO` to TGTs.
    During the TGS exchange the KDC verifies that the TGT's client name still resolves to
    the requestor SID and returns `KDC_ERR_TGT_REVOKED` if not.  It applies to all supported
    Windows Server versions.  Per MS-KILE §3.3.5.7 this check does not refresh group
    membership: the KDC copies the PAC fields from the TGT and adds only the domain-local
    groups of the service's domain, so a group change takes effect when the user gets a
    new TGT.  One lab run on Server 2022 build 20348.3207 concluded the opposite, that a
    service ticket requested with an old TGT carried a newly added group.  That run read
    the PAC through a fresh S4U2Self request, not from a ticket issued on the old TGT, so
    it does not settle the question.  Until it is retested, assume a new TGT is needed.

??? info "PAC hardening timeline"

    --8<-- "includes/pac-hardening-timeline.md"

!!! note "Protected Users + RC4 edge case"
    Protected Users group membership overrides per-account `msDS-SupportedEncryptionTypes` for
    the **AS exchange** - pre-authentication and TGT encryption are forced to AES regardless of
    the account's etype configuration.

    However, Protected Users does **not** affect service ticket encryption. A Protected Users
    member can still receive RC4-encrypted service tickets if the target account only
    supports RC4. The Protected Users protections apply to the member's own authentication
    (AS-REQ/AS-REP), not to service tickets issued on behalf of the member to other services.

!!! warning "Group membership changes require new tickets"
    Adding a user to Protected Users (or any AD security group) does **not** take effect in
    their existing Kerberos tickets.  The user's cached TGT still contains the old group
    membership in its PAC.  The user must log out and log back in - or run `klist purge` and
    re-authenticate - for the new group membership to appear in fresh tickets.

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
    @{N='AdminGroup'; E= {
            ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
        }
    }
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
Set-ADUser -Identity svc_old -ServicePrincipalNames @{Remove = "HTTP/old.corp.local" }
```

---

## Priority 6: Delegation Lockdown

Misconfigured delegation is a gateway to domain compromise.

### Unconstrained Delegation

Accounts with **TRUSTED_FOR_DELEGATION** can impersonate any user to any service.  Only
domain controllers should have this flag.

```powershell title="Find non-DC accounts and users with unconstrained delegation"
# Computers with unconstrained delegation, excluding DCs (primary group 516)
# and RODCs (521).  Matching on the DN would miss a DC moved out of its OU and
# hide any computer whose path happens to contain "Domain Controllers".
Get-ADComputer -Properties primaryGroupID -LDAPFilter `
    '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))' |
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
# TRUSTED_TO_AUTH_FOR_DELEGATION is bit 0x1000000 of userAccountControl.
# (TrustedToAuthForDelegation is not an LDAP attribute, so Get-ADObject cannot return it.)
Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' `
    -Properties msDS-AllowedToDelegateTo, userAccountControl |
    Select-Object Name, ObjectClass,
    @{N = 'ProtocolTransition'; E = { [bool]($_.userAccountControl -band 0x1000000) } },
    @{N = 'AllowedToDelegateTo'; E = { $_.'msDS-AllowedToDelegateTo' -join '; ' } }
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

Any Event ID 4769 for this account's SPN is a Kerberoasting indicator.  The request can
land on any DC, and each DC only logs its own, so the query has to ask every DC.  It also
needs Success **and** Failure auditing for *Kerberos Service Ticket Operations*: in the lab
(Server 2022 build 20348.5020) a request the KDC refused was logged with the SPN string in
`ServiceName` instead of the account name, so the filter matches both.

```powershell title="Query Event 4769 for honeypot requests on every DC (last 24 hours)"
$since = (Get-Date).AddDays(-1).ToUniversalTime().ToString('o')
$xpath = "*[System[EventID=4769 and TimeCreated[@SystemTime>='$since']] and EventData[" +
"Data[@Name='ServiceName']='svc_honeypot' or " +
"Data[@Name='ServiceName']='MSSQLSvc/honeypot.corp.local:1433']]"
$dcs = (Get-ADDomainController -Filter *).HostName

$hits = foreach ($dc in $dcs) {
    try {
        Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath -ErrorAction Stop |
            ForEach-Object {
                $d = @{}
                ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                [PSCustomObject]@{
                    DC      = $dc
                    Time    = $_.TimeCreated
                    Client  = $d['TargetUserName']
                    IP      = $d['IpAddress']
                    Service = $d['ServiceName']
                    EType   = $d['TicketEncryptionType']
                    Status  = $d['Status']
                }
            }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Write-Information "${dc}: no honeypot requests since $since" -InformationAction Continue
        }
        else {
            Write-Warning "${dc}: NOT CHECKED - $($_.Exception.Message)"
        }
    }
}
$hits | Sort-Object Time -Descending | Format-Table -AutoSize
```

A DC that prints `NOT CHECKED` has told you nothing.  Configure your SIEM to alert on any
4769 event targeting this account, collected from every DC.

---

## Priority 9: KRBTGT Password Rotation

The KRBTGT account encrypts every TGT in the domain.  If compromised, an attacker can forge
Golden Tickets.

### Rotation Schedule

- **Routine**: at least every 180 days.
- **After compromise**: immediately, **twice**, with replication and a full ticket lifetime
  between the two resets.
- **If the KDC logs System event 42** ("The Kerberos Key Distribution Center lacks strong
  keys for account: krbtgt"): the account has no AES keys.  Rotate it.

### Why Twice

AD retains the current and the previous KRBTGT key.  After one rotation, TGTs issued under
the old key are still accepted, because that key is now the "previous" one.  The second
rotation pushes the original key out of the history, which is what invalidates a stolen
key or forged tickets.  It is also why the second reset must not follow the first
immediately: every TGT still in use would become invalid at once.

### Safe Rotation Process

1. Verify replication health: `repadmin /replsummary`
2. Reset the KRBTGT password.  Microsoft's `New-KrbtgtKeys.ps1` is an interactive,
   menu-driven script whose repository is
   [archived](https://github.com/microsoftarchive/New-KrbtgtKeys.ps1); its README points
   to the maintained successor,
   [`Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1`](https://github.com/zjorz/Public-AD-Scripts).
   Both offer informational and simulation modes; run those first.
3. Force replication and verify it completes on **every** DC:

    ```powershell
    repadmin /syncall /e /d /A /P
    repadmin /replsummary
    ```

4. **Wait at least the maximum TGT lifetime** before the second rotation: 10 hours by
   default, longer if your Kerberos policy sets a longer *Maximum lifetime for user
   ticket*.  Many teams wait 24 hours.  Outstanding TGTs issued under the old key expire
   in that time, so the second reset does not cut anyone off.
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
    object**, not a real domain controller - exclude it from DC counts and encryption
    assessments.

    The `AzureADKerberos` object has its own `krbtgt_AzureAD` account whose keys are
    **not** rotated by the standard KRBTGT rotation process.  Rotate it separately, with
    the cmdlet from Microsoft's `AzureADHybridAuthenticationManagement` module.  It needs a
    cloud credential and a domain credential as well as the domain name:

    ```powershell
    $domain = 'corp.local'
    $cloudCred = Get-Credential -Message 'A Microsoft Entra ID Hybrid Identity Administrator'
    $domainCred = Get-Credential -Message 'A Domain Admins member who is also an Enterprise Admin'

    Set-AzureADKerberosServer -Domain $domain -CloudCredential $cloudCred `
        -DomainCredential $domainCred -RotateServerKey
    ```

    The other sign-in forms (`-UserPrincipalName` for modern authentication, or omitting
    `-DomainCredential` on a domain-joined machine) are in
    [Microsoft's how-to](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-on-premises#rotate-the-microsoft-entra-kerberos-server-key).
    Microsoft warns that other krbtgt tools must not be used for this key, so that it is
    updated in both Active Directory and Microsoft Entra ID.

!!! note "Read-only domain controllers"
    Each RODC has its own `krbtgt_<number>` account, linked from the RODC's computer
    object through `msDS-KrbTgtLink`.  These are rotated independently of the main
    KRBTGT account.  The reset script has no `-RODC` switch: you choose the RODC scope
    (one, a list, or all) from its interactive prompts.

!!! note "Linux keytab impact"
    Resetting a **service account's** password invalidates every keytab that holds its old
    key.  This affects any Linux or Unix service authenticating via AD Kerberos: Apache
    (`mod_auth_gssapi`), SSSD, Samba, PostgreSQL, and others.  Rotating KRBTGT does not
    touch service keytabs; this note is about the Priority 2 password resets.

    After resetting a service account password, export a new keytab on a Windows host and
    copy it to the service:

    ```bat
    ktpass /out service.keytab /princ HTTP/web.corp.local@CORP.LOCAL ^
      /mapuser CORP\svc_web /mapop set /pass * ^
      /ptype KRB5_NT_PRINCIPAL /crypto AES256-SHA1
    ```

    `ktpass /pass` itself **sets the account's password** to the value you enter (unless
    you add `-setpass`), so run it as the password change, not after one.

    ```bash
    # On the Linux host: check the key types, then test the keytab
    klist -ke /etc/krb5.keytab
    kinit -kt /etc/krb5.keytab HTTP/web.corp.local@CORP.LOCAL
    ```

---

## Priority 10: DefaultDomainSupportedEncTypes

[`DefaultDomainSupportedEncTypes`](registry.md#defaultdomainsupportedenctypes) decides what
the KDC assumes for accounts with no `msDS-SupportedEncryptionTypes`.  With the April 2026
update or later, a DC that has no value already assumes AES-only, so this is no longer
something you must set.  It is something you must **keep consistent and watch**:

- **Target state**: absent, or `0x18`, and identical on every DC.  Absent is only a safe
  target once every DC has the April 2026 update or later.
- **Pin it to `0x18`** on every DC if patch levels are mixed.  A DC that has not received
  the April 2026 update still assumes an RC4 default when the value is absent (`0x27` per
  KB5021131; seen in the lab on Server 2022 build 20348.4893).
- **Alert on drift**: a DC whose value differs from the others; any value that includes
  RC4 or DES; and Kdcsvc event 205, which the KDC logs at start-up when the value includes
  a non-AES cipher.
- **Remove emergency values.**  A value such as `0x1C` or `0x24`, set to get through an
  outage, re-enables RC4 for every unconfigured account until someone removes it.
- **Clear out leftover `RC4DefaultDisablementPhase` values, by build.**  Per Microsoft they
  are no longer read after the July 2026 update (Server 2022 build 20348.5386, Server 2025
  build 26100.33158, or higher); on those DCs delete them, because they mislead audits.
  On a DC that has only an April-June 2026 update, a `0` or `1` is still the rollback
  switch: deleting it turns enforcement on at the next KDC restart, so follow
  [the removal steps in the triage runbook](enforcement-triage.md#removing-exceptions-afterwards).

See [Registry Settings](registry.md#defaultdomainsupportedenctypes) for the commands and the
[Standardization Guide](aes-standardization.md#step-5-set-defaultdomainsupportedenctypes-on-every-dc)
for the per-DC verification workflow.

---

## Priority 11: Trust Encryption Types

Cross-domain and cross-forest trusts have their own `msDS-SupportedEncryptionTypes` value
on the Trusted Domain Object (TDO).  It governs the **referral ticket** a client receives
when it crosses the trust; the service ticket in the other domain is still chosen from the
target service account by that domain's own DCs.

- A trust with an **explicit** value that contains RC4 or DES bits keeps using those
  algorithms for referral tickets.
- For a trust whose value is **unset**, third-party testing reports that DCs with the
  November 2022 update (KB5021131) issue AES referral tickets where they previously used
  RC4.  That behavior is not stated in the KB and has not been verified in this site's
  lab; confirm it on your own trusts with a cross-trust `klist`.  Microsoft's two
  descriptions differ: the
  [Event 4769 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
  says "For Domain Controllers, Read-Only Domain Controllers, and Trusts, AES is
  supported-by-default unless the account's msds-SET has been manually changed", while the
  ["Unsupported etype" troubleshooting article](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/unsupported-etype-error-accessing-trusted-domain)
  says "By default, the trust supports RC4 encryption but not AES128 or AES256
  encryption".
- Per KB5073381, the 2026 RC4 change "only impacts Windows domain controllers" and the
  "trust and referral flow ... is unaffected".

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
    @{N = 'msDS-SET (dec)'; E = { [int]$_.'msDS-SupportedEncryptionTypes' } },
    @{N = 'msDS-SET (hex)'; E = { '0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes' } } |
    Format-Table -AutoSize
```

### Remediation

For trusts that show RC4 or DES in the output above, either:

1. **Clear the attribute** to let it fall back to the trust default.  This relies on that
   default being AES, which Microsoft's two descriptions above do not agree on, so check
   the referral ticket afterwards:

    ```powershell
    Set-ADObject -Identity "CN=PARTNER,CN=System,DC=corp,DC=local" `
        -Clear 'msDS-SupportedEncryptionTypes'
    ```

2. **Set it explicitly to AES-only** (`0x18`):

    ```powershell
    Set-ADObject -Identity "CN=PARTNER,CN=System,DC=corp,DC=local" `
        -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
    ```

A TDO exists on **both** sides of a trust.  Make the same change in the other domain or
forest, or its DCs keep issuing referral tickets as before.  The setting is the same one
shown in *Active Directory Domains and Trusts* as **The other domain supports Kerberos AES
Encryption**
([Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/unsupported-etype-error-accessing-trusted-domain)).

Changing the attribute does not require resetting the trust password.  Afterwards, verify
the secure channel and test real cross-domain access:

```batch
netdom trust corp.local /domain:partner.local /verify
```

Then request a ticket for a service in the other domain and check the referral ticket
(`krbtgt/PARTNER.LOCAL`) with `klist`.

---

## Summary Checklist

| Priority | Action | Protects Against |
|---|---|---|
| 1 | Deploy gMSA for all eligible services | Kerberoasting |
| 2 | Set `msDS-SupportedEncryptionTypes = 0x18` on all manually-managed SPN-bearing accounts that have AES keys (user service accounts, gMSA, MSA, dMSA) | Fast (RC4) Kerberoasting |
| 3 | Enforce 25+ char passwords on user service accounts | Kerberoasting |
| 4 | Add privileged accounts to Protected Users | Credential theft, NTLM relay |
| 5 | Remove SPNs from admin and unused accounts | Kerberoasting of high-value targets |
| 6 | Remove unconstrained delegation from non-DCs | Delegation attacks |
| 7 | Disable `DONT_REQUIRE_PREAUTH` everywhere | AS-REP roasting |
| 8 | Deploy honeypot SPN accounts | Kerberoast detection |
| 9 | Rotate KRBTGT password regularly | Golden Ticket |
| 10 | Keep `DefaultDomainSupportedEncTypes` absent or `0x18` on every DC; alert on drift and event 205 | RC4 returning as the domain-wide default |
| 11 | Audit and remediate trust encryption types | RC4/DES on cross-domain trusts |
