---
search:
  boost: 3
description: Runbook for the 2026 Kerberos RC4 enforcement. Check whether your domain controllers enforce, find what is failing, and apply the fastest safe fix.
---

# RC4 Enforcement Is Live: Am I Affected?

A runbook for the state every patched domain is in now: the KDC no longer assumes RC4 for
accounts that do not declare their encryption types.  Use it to answer three questions in
order: is each DC enforcing, what is failing, and what is the fastest safe fix.

For the background on why this happened, see [RC4 Deprecation](rc4-deprecation.md).  For
the planned clean-up to AES-only, see the [Standardization Guide](aes-standardization.md).

!!! info "As of 2026-11-10"
    Microsoft's guidance ([KB5073381](https://support.microsoft.com/help/5073381) and
    Message Center post MC1427604) was last checked on 2026-11-10.  The lab results quoted
    here were last re-run on 2026-06-26 on Server 2022 builds 20348.4893 and 20348.5020 and
    Server 2025 build 26100.32522.  **Nothing on this page is lab-verified on a July 2026
    or later cumulative update**; statements about that update are Microsoft's.

---

## What Changed, in Five Lines

- A DC with the **April 2026 cumulative update or later** treats an SPN-bearing account
  whose `msDS-SupportedEncryptionTypes` is unset or `0` as **AES-only** (`0x18`).  Before
  that update the built-in default was `0x27`, which produced RC4 tickets.
- The change is **per DC and gated on the installed update**, not on the date.  A DC on an
  older update still issues RC4 for those accounts.
- Only **service tickets** (the TGS exchange) changed.  Logon and TGT issuance (the AS
  exchange) were not touched by this enforcement.
- Per Microsoft, the **July 2026 update removed audit mode and the
  `RC4DefaultDisablementPhase` rollback setting**.  There is no domain-wide "undo" switch
  any more.
- **Explicit configuration is still honored**: an account whose
  `msDS-SupportedEncryptionTypes` includes RC4 still gets RC4 (lab: Server 2022 build
  20348.5020; for the July update, Microsoft's
  [Windows message center](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center)
  says that phase blocks RC4 requests "when no explicit configuration is present"), and KB5073381 states that an administrator-set
  `DefaultDomainSupportedEncTypes` is honored too.

--8<-- "includes/rc4-timeline.md"

---

## Step 1: Is Each DC Enforcing?

Enforcement cannot be read from the registry: `RC4DefaultDisablementPhase` is normally
absent on both enforcing and non-enforcing DCs.  Use the build number, then confirm with a
real ticket.

--8<-- "includes/ddset-per-dc-check.md"

What to look for beyond that:

| Column | What it tells you |
|---|---|
| `Build` | The OS build and update revision.  A DC enforces once it has its OS's April 2026 cumulative update or later.  In the lab, Server 2022 `20348.5020` enforced and `20348.4893` did not.  KB5073381 covers Server 2012 through Server 2025; for a version not listed in the timeline above, look up the 14 April 2026 update in that version's update history. |
| `DDSET` | `(absent)` means the build's own default applies (`0x18` when enforcing, `0x27` when not).  Any explicit value replaces that default on this DC. |
| `Phase key` | Should be `(absent)`.  A leftover `0x0` or `0x1` is still live on a DC that has only an April-June 2026 update: that DC is not enforcing.  Per Microsoft it is no longer read after the July 2026 update (Server 2022 build `20348.5386`, Server 2025 build `26100.33158`, or higher). |
| `UseReqEtypes` | `KdcUseRequestedEtypesForTickets` under `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`.  Should be `(absent)` or `0x0` on every DC (see [Registry Settings](registry.md#kdcuserequestedetypesfortickets)). |

--8<-- "includes/lab-builds.md"

For a fuller per-DC report (every relevant registry path, wrong-path detection, the DC's
own `msDS-SupportedEncryptionTypes`), run
[`Get-KdcKerberosRegistryAudit.ps1`](https://github.com/StrongWind1/Kerberos/blob/main/scripts/Get-KdcKerberosRegistryAudit.ps1)
from the repository.

**Confirm with a live request.**  Request a service ticket for any account whose
`msDS-SupportedEncryptionTypes` is unset, then read the matching Event 4769 on the DC that
answered.  `ServiceSupportedEncryptionTypes` shows the *effective* value: `0x18` on an
enforcing DC, `0x27` on a non-enforcing one.  Those two values are from the Server 2022
lab DCs (builds 20348.5020 and 20348.4893).  Server 2025 was not tested at this step, and
Microsoft notes that the processed values in these fields are displayed differently
there, so on a 2025 DC go by the ticket etype (`TicketEncryptionType` `0x12` for AES256,
`0x17` for RC4).  The [Event Decoder](event-decoder.md) labels the fields.

!!! warning "Mixed fleets produce intermittent failures"
    If some DCs enforce and others do not, or one DC has a different
    `DefaultDomainSupportedEncTypes` or filter, the same client succeeds or fails depending
    on which DC answers.  Compare the rows above before you look at individual accounts.

---

## Step 2: Find What Is Failing

### KDC block events

--8<-- "includes/kdcsvc-events.md"

--8<-- "includes/kdcsvc-event-query.md"

Open the full event text for the service name, the client address and the advertised
etypes.

### Failed service-ticket requests

A blocked request also writes Security Event 4769 with `Status` `0xe`
(`KDC_ERR_ETYPE_NOSUPP`) and `TicketEncryptionType` `0xffffffff`, usually next to System
Event 16.  In the lab, a blocked 4769 showed the full SPN string in `Service Name` rather
than the account name.

These events are only written where **Failure** auditing for *Kerberos Service Ticket
Operations* is on.  [Check auditing on the DCs](index.md#5-is-kerberos-auditing-on) before
you read an empty result as "nothing is failing".  On a blocked request the lab saw
`ServiceSupportedEncryptionTypes` blank (build 20348.5020); treat an empty `Advertised` or
`ServiceKeys` column as missing data.

```powershell title="4769 failures with KDC_ERR_ETYPE_NOSUPP on every DC (last 7 days)"
$since = (Get-Date).AddDays(-7).ToUniversalTime().ToString('o')
$xpath = "*[System[EventID=4769 and TimeCreated[@SystemTime>='$since']] " +
"and EventData[Data[@Name='Status']='0xe']]"

Get-ADDomainController -Filter * | ForEach-Object {
    $dc = $_.HostName
    try {
        Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath -ErrorAction Stop |
            ForEach-Object {
                $d = @{}
                ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                [PSCustomObject]@{
                    DC = $dc; Time = $_.TimeCreated
                    Client = $d['TargetUserName']; Service = $d['ServiceName']
                    ClientAddress = $d['IpAddress']; Advertised = $d['ClientAdvertizedEncryptionTypes']
                    ServiceKeys = $d['ServiceAvailableKeys']
                }
            }
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                Write-Warning "$dc : $($_.Exception.Message)"
            }
        }
    } | Sort-Object Time -Descending | Format-Table -AutoSize
```

### Failures the KDC never sees

Microsoft's KB is explicit that the audit and block events only cover cases where the KDC
itself cannot issue AES.  A service whose **keytab holds only RC4 keys** is different: the
account has AES keys in AD, so the KDC now issues an AES256 ticket, the request succeeds
at the KDC (4769 `Status` `0x0`), and the **service** rejects the ticket.  Microsoft's
wording is that this "will most likely manifest in the form of authentication failures
from the target service rather than from the KDC".  You see errors
on the service or the client (`KRB_AP_ERR_MODIFIED`, application-level authentication
errors), not on the DC.  This is the most likely cause when a non-Windows service broke
after a DC was patched and the DC logs look clean.

---

## Step 3: Symptom, Cause, Fastest Safe Fix

| Symptom | Cause | Fastest safe fix | Permanent fix |
|---|---|---|---|
| Kdcsvc **203** (with Event 16 and 4769 `0xe`) | Client offers only RC4; the service account has no `msDS-SupportedEncryptionTypes`; no session key can be agreed | [Per-account exception](#fix-1-per-account-exception): add RC4 to that service account (`28`) | Make the client offer AES, then set the account to `24` |
| Kdcsvc **204** | The service account has no AES keys and no `msDS-SupportedEncryptionTypes`; the enforced default needs an AES key | [Per-account exception](#fix-1-per-account-exception) (`28`) to keep it running on its RC4 key | [Reset the password](#fix-3-password-reset-for-accounts-without-aes-keys) to generate AES keys, then set `24` |
| Kdcsvc **208** | Client offers only RC4; the service account is explicitly AES-only | Add RC4 to that account (`28`) | Make the client offer AES, then return the account to `24` |
| Kdcsvc **209** | The service account is explicitly AES-only but has no AES keys | Add RC4 to that account (`28`), or reset the password now | [Reset the password](#fix-3-password-reset-for-accounts-without-aes-keys) |
| No KDC error; a non-Windows or keytab-based service rejects tickets after the DC was patched | The keytab has only RC4 keys; the KDC now issues AES256 | Set that service account to `36` (`0x24`), Microsoft's recommended value, or `4` | [Regenerate the keytab](#fix-4-keytab-regeneration-for-non-windows-services) with AES keys, then set `24` |
| Many unrelated services failing at once and no time to triage | Many unset accounts depended on RC4 | [Temporary domain-wide default](#fix-2-temporary-domain-wide-default), tried on one DC first: its effect for RC4-only clients is not lab-proven | Work through the accounts individually, then remove the default |
| User **logons** fail (4768/4771, System Event 14) | Not this enforcement, which is TGS-only.  Usually an AES-only DC etype filter meeting users who have no AES keys | Add RC4 back to the DC filter and restart the KDC.  Do not count on this for Server 2025 DCs: Microsoft states they "don't issue RC4 Ticket Granting Tickets".  This site's one Server 2025 check (build 26100.32522) did not show that and the two are not reconciled (see [TGT encryption type](rc4-deprecation.md#tgt-encryption-type)), so plan on the password reset there | Reset those users' passwords, then tighten the filter again |
| Works against some DCs, fails against others | DCs differ in update level, `DefaultDomainSupportedEncTypes` or filter | Compare the [Step 1](#step-1-is-each-dc-enforcing) table | Align every DC |

Start with Fix 1: it changes one account.  Fix 2 changes the default for the whole domain
and is for emergencies only.  Fixes 3 and 4 are the permanent repairs that let you remove
the exceptions again.

### Fix 1: Per-account exception

Change only the affected service account.  It takes effect as soon as the change has
replicated to the DC that answers; clients need new tickets (`klist purge`, or wait for
the cached ticket to expire).

```powershell title="Add RC4 to one service account, recording the old value first"
$name = 'svc_legacy'
$acct = Get-ADUser $name -Properties 'msDS-SupportedEncryptionTypes'
$old = $acct.'msDS-SupportedEncryptionTypes'   # $null means "unset"
"{0} {1} old value: {2}" -f (Get-Date -Format s), $name, $(if ($null -eq $old) { 'unset' } else { $old }) |
    Add-Content .\rc4-exceptions.log

# 28 = RC4 + AES128 + AES256.  See the decision table for 4 and 36.
Set-ADUser $acct -Replace @{ 'msDS-SupportedEncryptionTypes' = 28 } -ErrorAction Stop
```

To put it back, write the logged value with the same `Set-ADUser -Replace` line, or run
`Set-ADUser svc_legacy -Clear 'msDS-SupportedEncryptionTypes'` if the log says `unset`.
The script handles a **user** service account.  For a non-Windows computer object or a
managed service account, read and write the same attribute with `Get-ADComputer` /
`Set-ADComputer` or `Get-ADServiceAccount` / `Set-ADServiceAccount`.

Which value to use depends on *why* the account needs RC4.  The full decision table is in
[RC4 Deprecation: Keeping RC4 for specific accounts](rc4-deprecation.md#rc4-exceptions).
In short:

| Situation | Value | Result |
|---|---|---|
| The service cannot decrypt AES tickets (RC4-only keytab) | `36` (`0x24`), Microsoft's recommended value, or `4` | RC4 ticket.  `36` adds an AES256 session key: Microsoft's guidance (KB5073381), seen in the lab only on a pre-April 2026 Server 2022 build.  `4` needs clients that still offer RC4 (lab: 20348.5020). |
| The account has no AES keys yet | `28` (`0x1C`) as a bridge; the fix is a [password reset](#fix-3-password-reset-for-accounts-without-aes-keys) | RC4 ticket from the only key it has (lab: Server 2022 build 20348.5020). |
| The client can only do RC4 | `28` (`0x1C`) | AES256 ticket, RC4 session key (lab: Server 2022 build 20348.5020). |

Every account that keeps RC4 is Kerberoastable at RC4 speed.  Give it a 30+ character
random password and record an owner and a review date.

### Fix 2: Temporary domain-wide default

If too much is failing to fix account by account, set an explicit
`DefaultDomainSupportedEncTypes` that includes RC4.  It applies immediately, with no KDC
restart, and only to accounts whose `msDS-SupportedEncryptionTypes` is unset.  The lab
confirmed on an enforcing Server 2022 build (20348.5020) that an explicit value takes
precedence over the enforced default, and KB5073381 says Microsoft honors an administrator-set value.

The value is per DC and not replicated, so it has to be written on every DC.  Do one DC
first, test, then widen.  The script reads each DC's current value before it writes, and
saves it to `ddset-before-fix2.csv` as soon as that DC answers:

```powershell title="Record each DC's current value, then set 28 (0x1C)"
# Start with one DC.  After the test below passes, widen to every DC:
# $targets = (Get-ADDomainController -Filter *).HostName
$targets = @('dc1.corp.local')

$results = foreach ($dc in $targets) {
    try {
        $r = Invoke-Command -ComputerName $dc -ErrorAction Stop -ScriptBlock {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
            $name = 'DefaultDomainSupportedEncTypes'
            $key = Get-Item -LiteralPath $path
            $old = if ($key.GetValueNames() -contains $name) { '0x{0:X}' -f $key.GetValue($name) }
            else { '(absent)' }
            if ($old -ne '0x1C') {
                $null = New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value 28 -Force
            }
            [PSCustomObject]@{ OldValue = $old; NewValue = '0x1C' }
        } | Select-Object @{N = 'DC'; E = { $dc } }, OldValue, NewValue
        # Save the old value straight away.  A DC that already had 0x1C is not recorded again.
        if ($r.OldValue -ne '0x1C') {
            $r | Export-Csv .\ddset-before-fix2.csv -NoTypeInformation -Append
        }
        $r
    }
    catch {
        Write-Warning "${dc}: NOT SET - $($_.Exception.Message)"
    }
}
$results | Format-Table -AutoSize
```

```powershell title="Put every recorded DC back to the value it had"
Import-Csv .\ddset-before-fix2.csv | ForEach-Object {
    $row = $_
    try {
        Invoke-Command -ComputerName $row.DC -ErrorAction Stop -ArgumentList $row.OldValue -ScriptBlock {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
            $name = 'DefaultDomainSupportedEncTypes'
            if ($args[0] -eq '(absent)') {
                Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
            }
            else {
                $value = [int]$args[0]    # '0x18' converts to 24
                $null = New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force
            }
        }
        "$($row.DC): restored to $($row.OldValue)"
    }
    catch {
        Write-Warning "$($row.DC): NOT RESTORED - $($_.Exception.Message)"
    }
}
```

A DC that prints `NOT RESTORED` still has `0x1C`: fix the connection and run the block again.
When every DC is restored, rename or delete `ddset-before-fix2.csv`, because the next restore
replays every row in it.

**Test before you rely on it.**  From one affected client, purge tickets (`klist purge`),
request the failing service again, and confirm in `klist` that the ticket came from the DC
you changed (`Kdc Called`).  The evidence for `28` (`0x1C`) is uneven:

- **Microsoft (KB5073381)**: a DC with a defined `DefaultDomainSupportedEncTypes` "will not
  be functionally impacted by these changes".  The block events 203 and 204 are listed
  only for a DC with no value defined, and 208 and 209 only for an AES-only value.
- **Lab, Server 2022 build 20348.5020**: with `0x1C` set, an unset account that has AES
  keys received an AES256 ticket, and an explicit `0x04` produced RC4 tickets (26 June
  2026).  The explicit value does replace the enforced default.
- **Not shown by the lab**: that an RC4-only client gets through under `0x1C` on an
  enforcing DC.  The one recorded run of exactly that case (14 April 2026, same build) was
  **blocked**.  That session's wider conclusion, that an explicit value cannot override
  enforcement, was reversed by the later retests, but the RC4-only-client case was not
  re-run with the client's etypes and the session key recorded.  On a pre-April build,
  before enforcement, `0x1C` gave a client that listed RC4 first an AES256 ticket with an
  RC4 session key.
- An unset account with no AES keys is expected to get an RC4 ticket.  That was verified
  with `msDS-SupportedEncryptionTypes` `0x1C` on the account (build 20348.5020), not
  through this registry value.

If the test client is still refused, put the old value back and apply
[Fix 1](#fix-1-per-account-exception) to each service account named in the 203 events.
That is what KB5073381 itself recommends ("explicitly enable RC4 within the
msds-SupportedEncryptionTypes bitmask on services that will need to accept RC4 usage"),
and it is the case the lab did verify on the enforcing build.

What it does **not** do:

- It does not help accounts with an explicit AES-only value (events 208/209).  Those need
  Fix 1.
- It does not make the KDC issue RC4 tickets to accounts that have AES keys, so it does not
  fix RC4-only keytabs.  Microsoft's last-resort value for that is `0x24`, which returns
  every unset account to RC4 tickets and, in Microsoft's words, "leaves all accounts in the
  domain vulnerable to CVE-2026-20833".  Prefer `36` on the individual accounts.

The KDC logs Kdcsvc 205 at every start while the value includes RC4.  Remove the value, or
set it to `24`, once the per-account work is done.

### Fix 3: Password reset for accounts without AES keys

An account whose password was last set before the domain could generate AES keys has only
an RC4 key.  One password reset on a domain at functional level 2008 or higher generates
AES keys.

- Reset the password **once**, update every service that runs under the account, and
  verify the keys (see [Auditing Kerberos Keys](account-key-audit.md)).
- A reset raises the account's key version number.  **Every keytab exported for that
  account stops working** and must be regenerated.
- Then set `msDS-SupportedEncryptionTypes` to `24` and remove any exception.

### Fix 4: Keytab regeneration for non-Windows services

An RC4-only keytab cannot decrypt an AES ticket, even when AD holds AES keys for the
account.  Regenerate the keytab so it contains AES256 (and AES128) keys for the current key
version, deploy it, restart the service, then set the account to `24`.

Classes of system to inventory, and what to check on each:

| Class | Check |
|---|---|
| Linux and Unix hosts joined with SSSD, Samba or `adcli` | The key types in the host keytab (`klist -ke`) and `permitted_enctypes` in `krb5.conf` |
| Web and application servers with exported keytabs (Apache, NGINX, Tomcat, Java application servers) | Which `-crypto` the keytab was created with; the Java runtime's enabled etypes |
| Databases and middleware using Kerberos | The service keytab and the account it maps to |
| NAS and storage appliances joined to AD | The vendor's "AES encryption for Kerberos" setting and the etypes on its computer object |
| Printers, scanners, hypervisors and other appliances with a computer or service account | Firmware support for AES Kerberos; whether the AD object declares its etypes |
| Big-data and cluster software with per-service principals | Every service keytab, not only the host keytab |

Product-specific steps belong to the vendor.  Microsoft's own advice for devices that
cannot accept AES tickets is to work with the vendor, and to use an explicit RC4 value on
the account only as a stopgap.

---

## When RC4 Must Also Be Allowed by the DC Filter

`SupportedEncryptionTypes` on a DC is a filter over everything the KDC issues, and it is
only read when the KDC service starts.  An account-level exception is not enough if the
filter excludes RC4:

- An account explicitly set to RC4-only (`4`) under an AES-only filter gets
  `KDC_ERR_ETYPE_NOSUPP`.  The filter does not "upgrade" it.
- In the lab an AES-only filter also blocked RC4 pre-authentication (one pre-April 2026
  Server 2022 build; not re-run on 20348.5020), so expect an AES-only filter to lock out
  users who have no AES keys.

If the Step 1 table shows a filter without the RC4 bit (`0x4`) and you need an RC4
exception, add RC4 to the filter on every DC and restart the KDC on each, one DC at a time.
On Server 2025, check that the value is at the path the KDC actually reads: the March 2026
build tested in the lab honored only the `Lsa` path, and later updates have not been
retested (see [Registry Settings](registry.md#supportedencryptiontypes-gpo-kdc-filter)).

---

## Why Did This Break Months After April?

- **The update was installed later.**  Enforcement starts when a DC receives the April
  2026 cumulative update or anything newer, whenever that happens.
- **A newly patched or newly built DC joined the pool.**  Clients that reach it see the new
  behavior; clients that reach older DCs do not.
- **A rollback value stopped working.**  A DC left at `RC4DefaultDisablementPhase` `0` or
  `1` kept issuing RC4 until, per Microsoft, the July 2026 update stopped reading the value.
- **A DC rebooted.**  The KDC etype filter is read only at service start.  A Group Policy
  change made weeks earlier takes effect at the next restart, DC by DC.
- **An old password finally mattered.**  An account with no AES keys works until the first
  request reaches an enforcing DC.
- **A cached ticket expired.**  Service tickets live for up to 10 hours by default, and
  services that hold long sessions may not request a new one for much longer.

---

## Removing Exceptions Afterwards

1. For each exception, confirm the cause is gone: the client offers AES, the account has
   AES keys, or the keytab contains AES keys.
2. Set the account back to `24` and confirm new tickets are AES256 (`klist`, or 4769
   `TicketEncryptionType` `0x12`) with no new 203/204/208/209 events.
3. When no unset account depends on RC4, delete the temporary
   `DefaultDomainSupportedEncTypes` value, or set it to `24`, on **every** DC.  Kdcsvc 205
   stops appearing at KDC start.
4. Deal with any leftover `RC4DefaultDisablementPhase` value, by build.  On a DC with the
   July 2026 update or later (Server 2022 build 20348.5386 or higher, Server 2025 build
   26100.33158 or higher) Microsoft says the value is no longer read: delete it so it
   cannot mislead a later audit.  On a DC that has only an April-June 2026 update, a `0`
   or `1` is still the rollback switch: that DC is issuing RC4 for unconfigured accounts,
   and deleting the value turns enforcement on at its next KDC restart.  Find out what
   depends on it first (at value `1` the DC logs audit events 201, 202, 206 and 207 for
   the requests that enforcement will refuse), then delete the value and restart the KDC
   in a maintenance window.
5. Only then consider removing RC4 from the DC etype filter.  The readiness checks are in
   the [Quick Start Guide](quick-start.md#are-you-ready-for-an-aes-only-dc-filter).

---

## Tools

- [Event Decoder](event-decoder.md): paste a 4768/4769/4771 event to label its fields.
- [Encryption Type Calculator](etype-calculator.md): decode or build a bitmask value.
- [`Get-KdcKerberosRegistryAudit.ps1`](https://github.com/StrongWind1/Kerberos/blob/main/scripts/Get-KdcKerberosRegistryAudit.ps1):
  per-DC registry audit.
- Microsoft's [Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto) scripts
  (`Get-KerbEncryptionUsage.ps1`, `List-AccountKeys.ps1`): event-based reports of which
  etypes and keys are in use, described in
  [Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos).
- [Troubleshooting](troubleshooting.md): `klist`, error codes and the KDC event reference.
