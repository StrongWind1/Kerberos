---
status: new
---

# RC4 Deprecation (CVE-2026-20833)

Microsoft is removing RC4 as the implicit default encryption type for Kerberos
service tickets.  This page covers the full timeline, the event IDs you need to
monitor, and a step-by-step action plan to prepare your environment.

---

## Why RC4 Is Being Removed

RC4 has been a known liability in Kerberos for over a decade:

- **Kerberoasting**: attackers request service tickets encrypted with RC4, take them offline,
  and crack the user service account password at ~800x the speed of AES.
- **Weak key derivation**: RC4 keys are unsalted MD4 hashes, identical to NTLM hashes.
  Compromising an RC4 key gives the attacker a pass-the-hash credential for free.
- **Stream cipher weaknesses**: RC4 has known statistical biases (RFC 7465 banned it from TLS
  in 2015) and was formally deprecated for Kerberos by RFC 8429 in 2018.

Despite all this, RC4 remained the **default** for any SPN-bearing account without an explicit
`msDS-SupportedEncryptionTypes` value -- until now.

---

## Historical Context

| Date | Change | Reference |
|---|---|---|
| **November 2022** | CVE-2022-37966: KDC defaults to AES **session keys** (not ticket encryption).  Introduces `AES256-CTS-HMAC-SHA1-96-SK` flag and `DefaultDomainSupportedEncTypes`. | KB5021131 |
| **January 2025** | New fields added to 4768/4769 events: `Advertized Etypes`, `Available Keys`, `Session Encryption Type`, `msDS-SupportedEncryptionTypes`. | January 2025 CU |
| **January 2026** | CVE-2026-20833: Audit phase begins.  Kdcsvc events 201-209 introduced.  `RC4DefaultDisablementPhase` registry key added. | KB5073381 |
| **April 2026** | Enforcement phase with rollback.  KDC defaults to AES-only (`0x18`) for accounts without explicit `msDS-SupportedEncryptionTypes`. | April 2026 CU |
| **July 2026** | Final enforcement.  `RC4DefaultDisablementPhase` registry key removed.  Audit mode no longer available. | July 2026 CU |

---

## Timeline Details

### January 2026 -- Audit Phase

**What happens**: after installing the January 2026 update on domain controllers, the KDC
begins logging Kdcsvc events (201-209) in the System event log whenever it would use RC4
for a service ticket based on the implicit default.

**What breaks**: nothing.  RC4 still works.  This phase is purely informational.

**What you must do**:

1. Install the update on all DCs.
2. Monitor the System event log for events 201-209.
3. Begin remediating any accounts identified by these events.

### April 2026 -- Enforcement with Rollback

!!! success "Lab verified (2026-04-14): enforcement is on by default"
    KB5078763 enables enforcement without any manual configuration.  After installing the
    April 2026 update, `RC4DefaultDisablementPhase` is **absent** from the registry — and
    absent means enforcement.  RC4 is blocked for accounts with no
    `msDS-SupportedEncryptionTypes` set immediately after install and KDC restart.
    Setting `RC4DefaultDisablementPhase = 2` explicitly is redundant; the key is only
    useful to **roll back** to audit (`= 1`) or pre-enforcement (`= 0`) mode.

**What happens**: the KDC changes its default behavior for accounts without
`msDS-SupportedEncryptionTypes`.  Instead of assuming RC4 is acceptable, it assumes
AES-only (`0x18`).  Accounts that still depend on RC4 implicitly will fail.

**What breaks**: any SPN-bearing account or computer account that:

- Has no `msDS-SupportedEncryptionTypes` set, AND
- Only has RC4 keys (password never reset after DFL 2008), OR
- The client only supports RC4

**Rollback option**: set `RC4DefaultDisablementPhase = 1` on DCs to revert to audit mode.

!!! warning "KDC restart required"
    `RC4DefaultDisablementPhase` requires a KDC restart to take effect, unlike
    `DefaultDomainSupportedEncTypes` which is immediate.  After setting or changing this
    value, run `Restart-Service kdc` on the DC.

```powershell title="Roll back RC4 enforcement to audit mode"
# Roll back to audit mode
Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "RC4DefaultDisablementPhase" -Value 1
Restart-Service kdc
```

### July 2026 -- Final Enforcement

**What happens**: the `RC4DefaultDisablementPhase` registry key is removed.  Enforcement is
permanent.  RC4 will only be used if an account **explicitly** includes bit `0x4` in its
`msDS-SupportedEncryptionTypes` (e.g. `msDS-SET = 4` or `28`).  Setting
`DefaultDomainSupportedEncTypes` to a value that includes RC4 does **not** re-enable RC4
for accounts with no `msDS-SupportedEncryptionTypes` — the enforcement override ignores
DDSET for unconfigured accounts.  See the
[interaction matrix](aes-standardization.md#interaction-matrix).

**What breaks**: everything that broke in April 2026 if you did not remediate.

**No rollback**: the only ways to use RC4 after July 2026 are to explicitly set
`msDS-SupportedEncryptionTypes` to include `0x4` on specific accounts, or to explicitly
set `DefaultDomainSupportedEncTypes` to include RC4 on every DC.  Both approaches are
strongly discouraged.

!!! warning "Explicit RC4 is insecure by design"
    After July 2026, if you explicitly enable RC4 on a user service account, that account remains
    fully vulnerable to Kerberoasting.  This should only be used as a temporary measure for
    legacy systems that cannot support AES, with a documented remediation plan and a strong
    password (30+ characters).

---

## Kdcsvc Event IDs

These events are logged in the **System** event log on domain controllers, under the source
**Kdcsvc**.  They were introduced with the January 2026 update.

### Audit Phase Events (RC4DefaultDisablementPhase = 1)

| Event ID | Type | Condition | Transitions To |
|---|---|---|---|
| **201** | Warning | Client advertises only RC4, service has no `msDS-SupportedEncryptionTypes`, DC has no `DefaultDomainSupportedEncTypes` | 203 (enforcement) |
| **202** | Warning | Account lacks AES keys, service has no `msDS-SupportedEncryptionTypes`, DC has no `DefaultDomainSupportedEncTypes` | 204 (enforcement) |
| **205** | Warning | `DefaultDomainSupportedEncTypes` is explicitly set to include RC4 | Never becomes an error |
| **206** | Warning | Service is configured AES-only, but client does not advertise AES | 208 (enforcement) |
| **207** | Warning | Service is configured AES-only, but account lacks AES keys | 209 (enforcement) |

### Enforcement Phase Events (RC4DefaultDisablementPhase = 2)

| Event ID | Type | Condition | Result |
|---|---|---|---|
| **203** | Error | Client advertises only RC4, service has no `msDS-SupportedEncryptionTypes` | Ticket request **blocked** |
| **204** | Error | Account lacks AES keys, service has no `msDS-SupportedEncryptionTypes` | Ticket request **blocked** |
| **208** | Error | Service is configured AES-only, client does not advertise AES | Ticket request **blocked** |
| **209** | Error | Service is configured AES-only, account lacks AES keys | Ticket request **blocked** |

### Event 205: Special Case

Event 205 is logged whenever the KDC starts (Kdcsvc service start) if
`DefaultDomainSupportedEncTypes` includes RC4.  It is a **permanent warning** -- it does not
escalate to an error in enforcement mode.  Its purpose is to remind administrators that they
have explicitly allowed insecure algorithms at the domain level.

### Remediation Reference

| Event Pair | Root Cause | Fix |
|---|---|---|
| 201 / 203 | Client only supports RC4 + service has no explicit config | Enable AES on client, OR set `msDS-SupportedEncryptionTypes = 28` on service |
| 202 / 204 | Account lacks AES keys + no explicit config | Reset account password (twice if pre-2008) |
| 205 | `DefaultDomainSupportedEncTypes` includes RC4 | Set to `0x18` (AES-only) if safe, or remove the key |
| 206 / 208 | Client cannot do AES + service requires AES | Upgrade client, OR temporarily add RC4 to service (`0x1C`) |
| 207 / 209 | Service configured for AES but lacks AES keys | Reset account password (twice if pre-2008) |

---

## Pre-Enforcement Checklist

Follow these steps **before** the April 2026 update to avoid authentication outages.

### Step 1: Enable Auditing

Ensure events 4768 and 4769 are being logged on all DCs:

--8<-- "includes/verify-kerberos-auditing.md"

Both should show "Success and Failure."  If not, configure via GPO (see
[Group Policy Settings](group-policy.md)).

### Step 2: Identify RC4 Usage

Run Microsoft's `Get-KerbEncryptionUsage.ps1` script from the
[Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto) repository:

```powershell title="Collect RC4 usage events from all KDCs"
.\Get-KerbEncryptionUsage.ps1 -Encryption RC4 -Searchscope AllKdcs |
  Export-Csv -Path .\RC4_Usage.csv -NoTypeInformation -Encoding UTF8
```

This collects all 4768 and 4769 events where RC4 was used for either the ticket or session
key.

### Step 3: Identify Accounts Missing AES Keys

Run Microsoft's `List-AccountKeys.ps1`:

```powershell title="List accounts missing AES256 keys"
.\List-AccountKeys.ps1 | Where-Object { $_.Keys -notcontains 'AES256-SHA96' }
```

Accounts that show only `RC4` in the `Keys` column need a password reset.

For definitive verification beyond this script, see
[Auditing Kerberos Keys](account-key-audit.md) which covers four methods including
DSInternals, impacket secretsdump, and offline ntds.dit analysis.

### Step 4: Reset Passwords on Old Accounts

For accounts created before DFL 2008, reset the password **twice** to generate AES keys:

```powershell title="Find accounts with passwords predating AES key generation"
# Find the AES cutover date
$AESdate = (Get-ADGroup -Filter * -Properties SID, WhenCreated |
  Where-Object { $_.SID -like '*-521' }).WhenCreated

# Find accounts with passwords older than the AES date
Get-ADUser -Filter * -Properties passwordLastSet |
  Where-Object { $_.PasswordLastSet -lt $AESdate -and $_.Enabled } |
  Sort-Object PasswordLastSet |
  Format-Table sAMAccountName, passwordLastSet
```

### Step 5: Set msDS-SupportedEncryptionTypes on All Manually-Managed SPN-Bearing Accounts

Five AD object types can hold SPNs.  Computer accounts are handled by GPO (Step 4 above).
The remaining four types must be updated manually: user service accounts, gMSA, MSA, and
dMSA.

Start with the cross-type overview to see the current distribution:

--8<-- "includes/spn-overview-query.md"

**User service accounts** (SPN-bearing user objects, the primary Kerberoasting target):

```powershell title="Set AES-only on SPN-bearing user accounts with no config or RC4 enabled"
Get-ADUser -Filter 'servicePrincipalName -like "*"' `
  -Properties msDS-SupportedEncryptionTypes |
  Where-Object {
    [int]$_.'msDS-SupportedEncryptionTypes' -eq 0 -or
    [int]$_.'msDS-SupportedEncryptionTypes' -band 4
  } |
  Set-ADUser -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

For the full per-type bulk queries (gMSA, MSA, dMSA) and verification steps, see
[Step 3](aes-standardization.md#step-3-set-msds-supportedencryptiontypes-on-manually-managed-spn-bearing-accounts)
of the Standardization Guide.

### Step 6: Update Keytab Files

Non-Windows services that use keytab files (Apache, Tomcat, Linux services) need new keytab
files generated with AES keys:

```bash title="Generate an AES-only keytab for a non-Windows service"
ktpass -out service.keytab \
  -princ HTTP/web.corp.local@CORP.LOCAL \
  -mapUser corp\svc_web -mapOp set \
  -pass <password> \
  -ptype KRB5_NT_PRINCIPAL \
  -crypto AES256-SHA1
```

Verify the keytab contains AES keys:

```bash title="Verify keytab encryption types"
klist -ke service.keytab
```

### Step 7: Test in a Pilot Group

After installing the April 2026 update, enforcement is already active on all DCs that have
received the patch.  To test the impact before it hits your full population:

1. Install the April 2026 update on a **single** DC.
2. Direct a subset of clients to that DC (via DNS or site assignment).
3. Monitor for failures (events 203, 204, 208, 209) — these mean RC4 is being blocked.
4. Resolve any accounts that generate failures.
5. Roll out the update to remaining DCs once the pilot is clean.

If a failure is urgent, roll back enforcement on that DC to audit mode:

```powershell title="Roll back a single DC to audit mode (RC4 allowed, events logged)"
Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "RC4DefaultDisablementPhase" -Value 1
Restart-Service kdc
```

### Step 8: Verify Enforcement is Active

Once all Kdcsvc audit events (201, 202, 206, 207) have been resolved and the April 2026
update is installed on all DCs, verify that enforcement is running everywhere.  The key
should be **absent** (enforcement) or explicitly set to `2`:

```powershell title="Check RC4DefaultDisablementPhase on every DC"
(Get-ADDomainController -Filter *).HostName | ForEach-Object {
    $dc = $_
    $phase = Invoke-Command -ComputerName $dc -ScriptBlock {
        (Get-ItemProperty `
          'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
          -EA 0).RC4DefaultDisablementPhase
    }
    [PSCustomObject]@{
        DC    = $dc
        Phase = if ($null -eq $phase) { '(absent = enforcement active)' } else { $phase }
    }
} | Format-Table -AutoSize
```

A value of `(absent)` or `2` means enforcement is on.  A value of `0` or `1` means a DC
was rolled back and still allows RC4.

### Step 9: Managing RC4 Exceptions

Some accounts will not migrate cleanly to AES — legacy hardware, third-party appliances,
or software that hard-codes RC4.  Use this workflow to handle exceptions without
undermining the domain-wide AES migration.

**Step 1: Try AES first.**  For every account flagged by Kdcsvc events 201/202, attempt
the standard remediation:

1. Set `msDS-SupportedEncryptionTypes = 0x18` (AES-only).
2. Reset the password to generate AES keys (or use the
   [FGPP same-password technique](account-key-audit.md#generating-aes-keys-without-changing-the-password)).
3. Purge cached tickets on the client: `klist purge`.
4. Test the service.

**Step 2: If AES fails**, add a per-account RC4 exception.  Set
`msDS-SupportedEncryptionTypes = 0x1C` (RC4 + AES128 + AES256) on **that specific
account only**:

```powershell title="Add a per-account RC4 exception for a legacy service"
Set-ADUser -Identity svc_legacy -Replace @{
  'msDS-SupportedEncryptionTypes' = 28  # 0x1C = RC4 + AES128 + AES256
}
```

This keeps AES as the preferred etype while allowing RC4 fallback for clients that
require it.

**Step 3: Document and plan removal.**  Every RC4 exception should be tracked with:

- The account name and SPN
- The system or vendor that requires RC4
- The vendor case or upgrade timeline for AES support
- A review date (no more than 6 months out)

!!! danger "Never use domain-wide RC4 as a permanent fix"
    Setting `DefaultDomainSupportedEncTypes = 0x1C` on all DCs re-enables RC4 for
    **every** account that lacks explicit `msDS-SupportedEncryptionTypes` — undoing all
    hardening work.  Always use per-account exceptions (`msDS-SupportedEncryptionTypes =
    0x1C` on the specific account) instead of domain-wide rollback.

---

## Frequently Asked Questions

**Is RC4 being removed from Windows entirely?**

No.  As of January 2026, Microsoft has no plans to remove RC4 from the OS.  DES was removed
in Server 2025, but RC4 remains available.  What is changing is the **default behavior**: RC4
will no longer be assumed as a supported etype for accounts that lack explicit configuration.

**I have `DefaultDomainSupportedEncTypes` set to `0x1C` on all DCs.  Am I affected?**

If you have an **explicit** `DefaultDomainSupportedEncTypes` value set, the April/July 2026
changes will not alter that value.  However, Event 205 will be logged on every KDC start to
warn you that your configuration includes RC4.

**Will the April 2026 update break my environment immediately?**

It can.  Any account that relies on the implicit RC4 default (no `msDS-SupportedEncryptionTypes`
set) will be treated as AES-only.  If the account lacks AES keys, ticket requests will fail.
This is why the pre-enforcement checklist above is essential.

For the complete operational playbook -- every setting, every command, every verification
step -- see the [Standardization Guide](aes-standardization.md).
