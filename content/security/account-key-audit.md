---
description: >-
  Five ways to find Active Directory accounts that have no AES Kerberos keys, from a
  password-age estimate and the 4768/4769 event fields to DSInternals, secretsdump and
  offline ntds.dit analysis, with the alerting and handling trade-offs of each.
---

# Auditing Kerberos Keys

An account without AES keys cannot be issued an AES ticket.  On a domain controller with
the April 2026 update or later that is no longer a theoretical concern: an account with no
AES keys and no explicit RC4 configuration **fails** with `KDC_ERR_ETYPE_NOSUPP` when a
service ticket is requested for it — the KDC does not fall back to RC4.  (That is the case
the lab ran, on Server 2022 build 20348.5020; a logon by such an account was not tested.)
So the question this page answers is both "what must be
fixed before I tighten anything" and "what is already broken, or only working because of an
RC4 exception".

There is no AD attribute that exposes an account's stored key types -- the keys are part of
the replicated secret data in `ntds.dit`.  This page covers five ways to surface that
information, each with different trade-offs.

| Method | Accuracy | Requires | Triggers Alerts |
|---|---|---|---|
| [PowerShell date comparison](#method-1-powershell-date-comparison-approximate) | Approximate | AD read access | No |
| [DSInternals](#method-2-dsinternals-definitive-online) | Definitive | Domain admin / DCSync rights | **Yes** (DCSync) |
| [Impacket secretsdump](#method-3-impacket-secretsdump-definitive-online) | Definitive | Domain admin / DCSync rights | **Yes** (DCSync) |
| [ntdsutil + ntdswolf](#method-4-ntdsutil-ntdswolf-definitive-offline) | Definitive | Local admin on DC | Minimal (backup event only) |
| [Security event fields](#detecting-accounts-that-need-password-reset-via-event-logs) | Definitive, but only for accounts that authenticated in the period you read | Event log read access on every DC | No |

If you want the least intrusive start, use Method 5 for the accounts that are in use and
Method 1 for the ones that are not.

---

## Method 1: PowerShell Date Comparison (Approximate)

The fastest method with no special tools.  Compare each account's `passwordLastSet` date
against the date AES key generation became available in the domain.

### How it works

--8<-- "includes/old-passwords-query.md"

### Why this is only approximate

- **The reference date is a proxy.**  The RID 521 group marks when the domain was prepared
  for Windows Server 2008 domain controllers.  A password change in the period just after
  that date was only given AES keys if a 2008-or-later DC processed it, so treat accounts
  with a `passwordLastSet` close to the reference date as uncertain.  Microsoft states the
  condition differently: "If the domain has a DFL of 2008 or greater and accounts have had
  at least one password rotation, AES keys are available"
  ([event 4768 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)).
  The group can be older than the functional-level raise, so a date after the reference
  date is not proof.
- **Dates can lie.**  `passwordLastSet` can be rewritten without a password change (the
  "user must change password at next logon" toggle resets it), which makes an old password
  look new.
- **Some password sets do not create Kerberos keys at all.**  A password written as an NT
  hash instead of as cleartext leaves the account with a recent `passwordLastSet` and only
  an RC4 key.  The lab reproduced this on Server 2022 with an NT-hash password set.
- **No key verification.**  This method infers key presence from dates.  It never reads
  the stored keys.

Use this method as a quick triage to estimate scope.  For anything you are going to act
on, use one of the methods below.

---

## Method 2: DSInternals (Definitive, Online)

[DSInternals](https://github.com/MichaelGrafnetter/DSInternals) reads account data
through the MS-DRSR replication protocol, including the supplemental credentials that
contain the actual Kerberos key types stored for each account.  This is the same data
the KDC uses when selecting encryption types.

### Install

```powershell
Install-Module -Name DSInternals -Scope CurrentUser
```

### Single account

```powershell
Get-ADReplAccount -SamAccountName svc_example -Server dc1.corp.local
```

In the output, look at the `SupplementalCredentials` → `KerberosNew` → `Credentials`
section.  An account **with** AES keys shows:

```
KerberosNew:
  Credentials:
    AES256_CTS_HMAC_SHA1_96
      Key: cd541be0...
    AES128_CTS_HMAC_SHA1_96
      Key: 5c889727...
    DES_CBC_MD5
      Key: 7f16bc4a...
```

An account **without** AES keys shows only:

```
Kerberos:
  Credentials:
    DES_CBC_MD5
      Key: 7f16bc4a...
```

No `KerberosNew` section, or `KerberosNew` contains only DES entries.

### All accounts: find those missing AES keys

```powershell title="Find all enabled accounts with no AES key via DSInternals"
Get-ADReplAccount -All -Server dc1.corp.local |
    Where-Object { $_.Enabled } |
    Where-Object {
        $keys = $_.SupplementalCredentials.KerberosNew.Credentials.KeyType
        -not ($keys -match 'AES')
    } |
    Select-Object SamAccountName, SamAccountType,
    @{N = 'PasswordLastSet'; E = { $_.PasswordLastSet } },
    @{N = 'HasSPN'; E = { [bool]$_.ServicePrincipalName } },
    @{N='KeyTypes'; E= {
            $k = $_.SupplementalCredentials.KerberosNew.Credentials.KeyType
            if ($k) { $k -join ', ' } else { '(none)' }
        }
    } |
    Format-Table -AutoSize
```

This outputs every enabled account that has no AES key in its supplemental credentials.
The `HasSPN` column tells you whether the KDC issues service tickets for the account —
those are the ones that fail on a patched DC, and the highest priority to fix.

`krbtgt` is a disabled account, so it does not appear in this list.  Check it on its own
with the single-account command above.

### Alert implications

!!! warning "This triggers DCSync detection"
    `Get-ADReplAccount` uses the MS-DRSR replication protocol -- the same protocol used
    by the DCSync attack.  Running it will trigger:

    - **Event 4662** (Directory Service Access) on the DC for each replicated object
    - **Microsoft Defender for Identity** (MDI) DCSync alerts
    - **CrowdStrike / SentinelOne / Elastic** DRSUAPI-based detections
    - Any SIEM rule monitoring for `DsGetNCChanges` calls from non-DC sources

    Coordinate with your SOC before running this.  Whitelist the source machine and
    account in your detection rules for the duration of the audit, or use
    [Method 4](#method-4-ntdsutil-ntdswolf-definitive-offline) to avoid network-based
    alerts entirely.

The command's output contains every account's password hashes.  Do not redirect it to a
file or a transcript; pipe it straight into the filter as shown.

---

## Method 3: Impacket secretsdump (Definitive, Online)

[Impacket](https://github.com/fortra/impacket) `secretsdump` extracts credentials
from a DC via the DRSUAPI protocol.  Like DSInternals, it reads the actual stored keys.

### Install

Install the tool on the audit workstation **before** any credential material arrives on
it.

```bash
# Install uv (Python package manager) if not already present
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install impacket as a CLI tool
uv tool install git+https://github.com/fortra/impacket.git
```

!!! warning "This machine is about to hold every credential in the domain"
    The two commands above run an installer script straight from the internet and build
    a tool from the head of a Git branch.  That is a reasonable convenience on a throwaway
    lab box; it is a supply-chain risk on the host that will hold the dump.  Prefer your
    distribution's `uv` package or a downloaded-and-reviewed installer, pin the tool to a
    release tag or commit you have reviewed (`...impacket.git@<tag-or-commit>`), and use a
    dedicated, hardened workstation that is wiped afterwards.

### Usage

```bash title="Dump all account credentials from a DC via DRSUAPI"
secretsdump.py -just-dc -outputfile domain_dump 'CORP.LOCAL/admin@dc1.corp.local'
```

Omitting the password after the username (no `:Password`) triggers an interactive prompt
so credentials are not stored in shell history.

This creates several files.  The Kerberos keys are in `domain_dump.ntds.kerberos`:

```
svc_example:aes256-cts-hmac-sha1-96:cd541be0838c...
svc_example:aes128-cts-hmac-sha1-96:5c88972747bd...
svc_example:des-cbc-md5:7f16bc4ada0b8a52
old_account:des-cbc-md5:a1b2c3d4e5f67890
```

Accounts with AES keys have `aes256-cts-hmac-sha1-96` lines.  Accounts without AES keys
only have `des-cbc-md5` lines, or do not appear in this file at all.

### Find accounts without AES keys

```bash title="Extract accounts without AES256 keys from secretsdump output"
# Every account in the dump (the .ntds file has one NT-hash line per account)
cut -d: -f1 domain_dump.ntds | sort -u > all_accounts.txt

# Accounts that have AES256 keys
grep 'aes256-cts-hmac-sha1-96' domain_dump.ntds.kerberos | cut -d: -f1 | sort -u > has_aes256.txt

# Accounts WITHOUT AES keys (in all_accounts but not in has_aes256)
comm -23 all_accounts.txt has_aes256.txt
```

The list of all accounts is taken from the `.ntds` file, not the `.kerberos` file: an
account with no Kerberos keys at all would be missing from the latter and silently
skipped.  The result includes disabled accounts and machine accounts; filter as needed.

### Alert implications

!!! warning "Same DCSync alerts as DSInternals"
    `secretsdump` uses the same DRSUAPI protocol as DSInternals.  It triggers identical
    alerts: Event 4662, MDI DCSync detection, and EDR alerts.

    Additionally, running impacket tools from a non-Windows machine may trigger extra
    anomaly detections (unusual DRSUAPI source OS, unusual network path to the DC).

    Coordinate with your SOC before running, or use
    [Method 4](#method-4-ntdsutil-ntdswolf-definitive-offline) instead.

### Cleanup

The dump files contain every account's NTLM hash and Kerberos keys.  Delete them
securely after analysis:

```bash title="Securely delete credential dump files after analysis"
shred -u domain_dump.ntds domain_dump.ntds.kerberos domain_dump.ntds.cleartext
rm -f all_accounts.txt has_aes256.txt
```

`shred` is not reliable on SSDs, copy-on-write file systems or snapshotted volumes.  Keep
the dump on an encrypted volume and destroy the volume key when you are done.

---

## Method 4: ntdsutil + ntdswolf (Definitive, Offline)

This method creates an offline copy of the AD database, transfers it to a Linux machine,
and parses it with [ntdswolf](https://github.com/StrongWind1/NTDSWolf).  Because
the key extraction happens offline against a file copy, no DCSync traffic crosses the
network and no DRSUAPI-based alerts fire.

### Step 1: Create an IFM backup with ntdsutil

On any domain controller, open an elevated command prompt:

```cmd title="Create an IFM backup of the AD database"
ntdsutil "activate instance ntds" "ifm" "create full C:\IFM" quit quit
```

This creates:

```
C:\IFM\
├── Active Directory\
│   ├── ntds.dit          ← the AD database
│   └── ntds.jfm
└── registry\
    ├── SYSTEM            ← contains the boot key to decrypt ntds.dit
    └── SECURITY
```

`C:\IFM` now holds a complete, decryptable copy of the domain's credentials, readable by
any local administrator of that DC.  It stays there until you delete it (Step 6).

### Step 2: Transfer to a Linux machine

Copy `ntds.dit` and `SYSTEM` to a secure Linux workstation.  Use whatever transfer
method your environment allows (SCP, USB, SMB share).  These files contain every
credential in the domain -- treat them accordingly.

```bash title="Copy ntds.dit and SYSTEM hive from DC for offline analysis"
# Example: SCP from the DC
scp administrator@dc1:'C:\IFM\Active Directory\ntds.dit' ./ntds.dit
scp administrator@dc1:'C:\IFM\registry\SYSTEM' ./SYSTEM
```

### Step 3: Install ntdswolf

Install the tool on the analysis workstation **before** you copy the database to it.

```bash
# Install uv (Python package manager) if not already present
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install ntdswolf as a CLI tool
uv tool install git+https://github.com/StrongWind1/NTDSWolf.git
```

!!! warning "Do not pipe installers into a shell on the host that holds `ntds.dit`"
    The same caution as for Method 3 applies, with higher stakes: this machine will hold
    the database and the key that decrypts it.  Install from a reviewed installer or your
    distribution's package, pin the tool to a commit you have reviewed
    (`...NTDSWolf.git@<commit>`), and take the workstation off the network before the
    files arrive if you can.

### Step 4: Parse the database

```bash title="Parse the AD database and extract user objects"
ntdswolf ntds.dit --system SYSTEM -e user -o ./ntds_output
```

This parses all user objects from `ntds.dit` and writes NDJSON (one JSON object per line)
to `./ntds_output/users.ndjson`.

To also include computer accounts:

```bash title="Parse the AD database including computer accounts"
ntdswolf ntds.dit --system SYSTEM -e user,computer -o ./ntds_output
```

### Step 5: Find accounts without AES keys

The NDJSON output contains each account's Kerberos keys under the `kerberos` array, with
each entry carrying an `etypeName` field.  Use `jq` to filter for accounts missing AES keys:

```bash title="Find enabled accounts without AES256 keys in ntdswolf NDJSON output"
# Find enabled accounts without AES256 Kerberos keys
jq -r '
  select((.userAccountControl.flags // []) | index("ACCOUNTDISABLE") | not) |
  select(
    (.kerberos // [] | map(.etypeName) |
     any(. == "AES256-CTS-HMAC-SHA1-96")) | not
  ) |
  [.sAMAccountName, .pwdLastSet, (.servicePrincipalName // [] | length | tostring)] |
  @tsv
' ./ntds_output/users.ndjson |
  sort -t$'\t' -k2 |
  column -t -s$'\t' -N 'Account,PasswordLastSet,SPNCount'
```

### Step 6: Clean up — on the DC first

The copy on the domain controller is the one most likely to be forgotten.  Remove it as
soon as the transfer has been verified:

```powershell title="Remove the IFM copy from the domain controller"
Remove-Item -LiteralPath 'C:\IFM' -Recurse -Force
Test-Path -LiteralPath 'C:\IFM'    # must print False
```

Also remove any intermediate copy made during the transfer (an SMB share, a USB stick, a
jump host's download folder).  Then remove the files from the analysis workstation:

```bash title="Securely delete extracted AD database files after analysis"
shred -u ntds.dit SYSTEM
rm -rf ./ntds_output
```

As with Method 3, `shred` is not reliable on SSDs or snapshotted file systems; an
encrypted volume whose key you destroy is the dependable option.

### Alert implications

- **No DCSync alerts.**  No DRSUAPI traffic crosses the network.
- **Event 327** (ESENT) on the DC when ntdsutil creates the IFM backup.  This is a
  standard administrative operation -- DCs generate IFM backups for RODC deployment and
  disaster recovery.  Most SOCs do not alert on this.
- The extracted files (`ntds.dit`, `SYSTEM`) contain the full domain credential set.
  Handle them with the same security controls as a domain controller.

---

## Method 5: Security Event Fields (No Replication Rights) { #detecting-accounts-that-need-password-reset-via-event-logs }

Since the January 2025 cumulative update, the domain controllers write the key types of
the accounts involved into every Kerberos audit event.  Reading those fields needs no
replication rights and triggers no DCSync alert.  The limit is coverage: you only learn
about accounts that requested a TGT, or were the target of a service ticket request,
within the period your Security logs cover.

### The fields

Kerberos auditing must be enabled on the DCs:

--8<-- "includes/verify-kerberos-auditing.md"

Both subcategories must show **Success and Failure**.

The fields are read by **name** from the event XML.  The numeric positions shift between
event versions, so position-based code (`Properties[16]`) breaks silently when an update
adds a field.

| Field | In 4768 (TGT request) | In 4769 (service ticket request) |
|---|---|---|
| `TargetUserName` | The account logging on | The requesting account |
| `ServiceName` | `krbtgt` | The target service account; on a refused request it can be the requested SPN string instead |
| `AccountAvailableKeys` | Key types stored for the account logging on | `N/A` on a successful request |
| `AccountSupportedEncryptionTypes` | That account's effective etype set | `N/A` on a successful request |
| `ServiceAvailableKeys` | Key types stored for `krbtgt` | Key types stored for the target service account |
| `ServiceSupportedEncryptionTypes` | `krbtgt`'s effective etype set | The target's **effective** set, after the DC has substituted its fallback for an unset attribute |
| `ClientAdvertizedEncryptionTypes` | Etypes the client offered | Etypes the client offered |
| `PreAuthEncryptionType` | Etype used for pre-authentication | — |
| `TicketEncryptionType` | TGT etype | Service ticket etype; `0xFFFFFFFF` when no ticket was issued |
| `SessionKeyEncryptionType` | Session key etype | Session key etype |
| `Status` | `0x0` on success | `0x0` on success; `0xE` is `KDC_ERR_ETYPE_NOSUPP` |

!!! warning "Event format varies by Windows version"
    These fields exist only in the event format introduced with the January 2025 updates.
    Events from DCs without it do not contain them, and such DCs contribute nothing to the
    queries below.

    The key list is also written differently by OS version:

    - **Server 2022**: keys reported as `AES-SHA1, RC4` (aggregated)
    - **Server 2025**: keys reported individually, for example
      `AES128-SHA96, AES256-SHA96, RC4`

    Both contain the string `AES` when AES keys exist, which is what the query tests.

    **A dash is not a key list.**  On a refused request a DC can write `-` in the key and
    etype fields: Microsoft's own example of a failed 4769 (status `0xE`) shows
    `Available Keys: -` for the account, the service and the DC.  In the lab, a refused
    request on Server 2022 build 20348.5020 carried the requested SPN in `ServiceName`
    and a blank or `-` in `ServiceSupportedEncryptionTypes`.  Such an event says nothing
    about anyone's keys, and the query below ignores it.

### Microsoft's scripts

Microsoft maintains two scripts in its
[Kerberos-Crypto repository](https://github.com/microsoft/Kerberos-Crypto/tree/main/scripts)
that read exactly these fields and handle both key-list formats:

| Script | What it answers |
|---|---|
| `List-AccountKeys.ps1` | Which key types each account seen in the logs has |
| `Get-KerbEncryptionUsage.ps1` | Which ticket and session-key etypes were issued; `-Encryption RC4` filters to RC4 |

Microsoft's walkthrough is
[Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos).
Use them when you can.  The query below does the same job in a form you can read and
adapt.

### Query: accounts whose stored keys do not include AES

```powershell title="List accounts with no AES keys, from events 4768/4769 on every DC"
$Since = (Get-Date).AddHours(-24)   # widen once you know how long one DC takes
$DCs = (Get-ADDomainController -Filter *).HostName

$noAes = foreach ($dc in $DCs) {
    try {
        Get-WinEvent -ComputerName $dc -ErrorAction Stop -FilterHashtable @{
            LogName = 'Security'; Id = 4768, 4769; StartTime = $Since
        } | ForEach-Object {
            $ev = $_
            $d = @{}
            ([xml]$ev.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }

            # Each event describes up to two principals: the account and the service.
            $principals = @(
                [PSCustomObject]@{ Who = $d.TargetUserName; Role = 'Logon account'
                    KeyList = $d.AccountAvailableKeys; Etypes = $d.AccountSupportedEncryptionTypes
                },
                [PSCustomObject]@{ Who = $d.ServiceName; Role = 'Service'
                    KeyList = $d.ServiceAvailableKeys; Etypes = $d.ServiceSupportedEncryptionTypes
                }
            )
            foreach ($p in $principals) {
                # 'N/A' and '-' mean "not looked up", not "no keys"
                if ($p.KeyList -and $p.KeyList -notin @('N/A', '-') -and $p.KeyList -notmatch 'AES') {
                    [PSCustomObject]@{
                        Account         = $p.Who
                        Role            = $p.Role
                        AvailableKeys   = $p.KeyList
                        EffectiveEtypes = $p.Etypes
                        LastStatus      = $d.Status
                        LastSeen        = $ev.TimeCreated
                        DC              = $dc
                    }
                }
            }
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Write-Information "${dc}: no 4768/4769 events since $Since" -InformationAction Continue
        }
        else {
            Write-Warning "${dc}: NOT CHECKED - $($_.Exception.Message)"
        }
    }
}

$noAes | Sort-Object Account, Role, LastSeen -Descending |
    Group-Object Account, Role | ForEach-Object { $_.Group[0] } |
    Format-Table Account, Role, AvailableKeys, EffectiveEtypes, LastStatus, LastSeen, DC -AutoSize
```

How to read the result:

- **Every row is an account that needs a password reset** to gain AES keys — or, if it is
  a service that genuinely cannot use AES, a recorded RC4 exception.
- **`LastStatus` of `0xE`** means the most recent request involving that account was
  refused: the KDC wanted AES for it and had no AES key.  These accounts are broken now.
- **`LastStatus` of `0x0`** with RC4-only keys means something is explicitly allowing RC4
  for the account (its own `msDS-SupportedEncryptionTypes`, or a
  `DefaultDomainSupportedEncTypes` that includes RC4).  It works today and stops working
  the moment that allowance is removed.
- **A row for `krbtgt`** means the domain's TGT key has no AES — fix that first, using the
  [KRBTGT rotation procedure](mitigations.md#priority-9-krbtgt-password-rotation).
- **A DC that printed `NOT CHECKED` contributed nothing.**  An empty result is only clean
  if every DC was read.

The query reads every 4768 and 4769 in the period from every DC and parses each one, which
is slow on a busy domain.  Start with a short period on one DC to get a feel for the
volume.

What this method cannot show: an RC4 **session key** in an otherwise healthy event says
nothing about the account's keys.  The session key etype follows what the *client* offered,
so an AES-keyed service account regularly appears with an RC4 session key when an RC4-only
client talks to it.

---

## Which Method to Use

| Scenario | Recommended Method |
|---|---|
| Quick estimate of how many accounts might lack AES keys | Method 1 (PowerShell dates) |
| Accounts in active use, without requesting replication rights | Method 5 (event fields) |
| Definitive audit, SOC can whitelist DCSync alerts | Method 2 (DSInternals) -- best PowerShell integration |
| Definitive audit from a Linux audit workstation | Method 3 (secretsdump) |
| Definitive audit, cannot trigger DCSync alerts | Method 4 (ntdsutil + ntdswolf) |
| Regular ongoing monitoring (scheduled task) | Method 5 for continuous coverage, Method 2 or 4 for periodic verification of dormant accounts |

---

## Generating AES Keys Without Changing the Password

Some service accounts cannot have their password changed without coordinated downtime
across multiple systems.  In these cases, you can generate AES keys by resetting the
password **to the same value** — AD derives a complete new set of keys on every password
set operation, whether or not the password string changed.

### No temporary password policy is needed

An administrative **reset** is a different operation from a user-initiated **change**.
Password history and minimum password age are enforced on a change.  On a reset, a domain
controller applies them only when the caller explicitly asks for it with the
`LDAP_SERVER_POLICY_HINTS_OID` control ([MS-ADTS] section 3.1.1.3.4.1.27); the standard
tools, including `Set-ADAccountPassword -Reset`, do not send it.  Complexity and minimum
length still apply.

Earlier versions of this page created a temporary Fine-Grained Password Policy with no
history, no minimum length and no complexity to get around the history check.  Do not do
that: the policy is unnecessary, and if the session dies half-way it leaves a
precedence-1 policy that removes every password rule from the account.

This statement is from the protocol specification, not from this site's lab.  If a reset
to the same value is refused in your environment — a password filter, or an identity
product that sends the policy-hints control — do not weaken policy to force it through.
Schedule a real password change instead.

### Step-by-Step

!!! danger "A mistyped password becomes the account's password"
    A reset does not ask the directory whether what you typed is the current password.
    Microsoft's reference for `Set-ADAccountPassword -Reset` says: "You do not need to
    specify the *OldPassword* parameter."  Typed wrongly, the typo **is** the new password,
    nobody knows what it is, and every service that uses the account stops authenticating
    until a real, coordinated password change is made.

    The script below therefore proves the typed password against the domain controller
    first, and stops without changing anything when the DC does not accept it.

```powershell title="Regenerate an account's keys by resetting it to its current password (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$Account = 'svc_example'
$DC = 'dc1.corp.local'    # every step runs against this one DC
$DryRun = $true           # $true = check the password, show the reset, change nothing

# ---- Logic: one block, paste it whole or save it as a .ps1 --------------------
& {
    $ErrorActionPreference = 'Stop'
    if ($DryRun -isnot [bool]) {
        throw '$DryRun must be $true or $false: run the settings lines first.'
    }
    $props = 'PasswordLastSet', 'msDS-KeyVersionNumber'
    $user = Get-ADUser -Identity $Account -Server $DC -Properties $props
    $logonName = "$((Get-ADDomain -Server $DC).NetBIOSName)\$($user.SamAccountName)"
    #
    # The operator types the CURRENT password.  It never appears on the command line,
    # in the console history, or in a script-block log.
    $pw = Read-Host -AsSecureString -Prompt "Current password of $logonName"
    if ($pw.Length -eq 0) { throw 'STOPPED: nothing was typed.  Nothing was changed.' }
    #
    # Prove it IS the current password: read the account from the same DC, signed in
    # as the account itself.  -Reset would accept anything, so this is the only check.
    $cred = New-Object System.Management.Automation.PSCredential ($logonName, $pw)
    try {
        $null = Get-ADUser -Identity $user -Server $DC -Credential $cred
    }
    catch {
        throw "STOPPED: nothing was changed.  $DC did not accept that password for $logonName ($($_.Exception.Message))"
    }
    Write-Information "$DC accepted the password for $logonName." -InformationAction Continue
    #
    Set-ADAccountPassword -Identity $user -Reset -NewPassword $pw -Server $DC -WhatIf:$DryRun
    $after = Get-ADUser -Identity $user -Server $DC -Properties $props
    [PSCustomObject]@{
        Account             = $after.SamAccountName
        'KeyVersion before' = $user.'msDS-KeyVersionNumber'
        'KeyVersion after'  = $after.'msDS-KeyVersionNumber'
        PasswordLastSet     = $after.PasswordLastSet
    } | Format-List | Out-Host
    if ($DryRun) {
        Write-Information 'Dry run: the password was checked; the reset was NOT performed.' -InformationAction Continue
    }
}
```

What to expect:

- **The DC accepts the password.**  The dry run prints a `What if:` line for the reset and
  both key version numbers are the same.  With `$DryRun = $false` the reset is performed
  and `KeyVersion after` is higher.
- **The DC does not accept it.**  The script stops with `STOPPED: nothing was changed`.
  The account's password is untouched.  The check is a real sign-in attempt, so a wrong
  password counts towards the
  [account lockout threshold](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold)
  — at least once; Microsoft notes that Kerberos "can automatically retry account sign-in
  attempts that count toward the threshold limits that you set in this policy setting".
  Look at what you typed before you try again.
- **The DC refuses the sign-in although the password is right.**  The message is the same.
  Causes: a disabled, locked-out or expired account; logon restrictions; membership of
  Protected Users (Microsoft: members "can only authenticate using Kerberos with AES", so
  one without AES keys can never pass); or an account that has only RC4 keys, checked from
  a machine whose etype policy no longer offers RC4 while NTLM is blocked.  Run it from a
  machine that still offers RC4, fix the cause, or schedule a real password change; do not
  remove the check to get past it.
- **Not within minutes of a password change.**  For NTLM, Microsoft documents that "Domain
  users can use their old password to access the network for five minutes after the
  password is changed"
  ([NTLM network authentication behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/new-setting-modifies-ntlm-network-authentication));
  `OldPasswordAllowedPeriod` on the DC can lengthen it.  In that window the check can accept
  the previous password.
- **There is no undo.**  A reset cannot be taken back.  After a successful run the password
  is the same string as before and the key version number is higher (see below).

Run the block as one piece.  The password prompt reads the next thing that reaches the
console, so nothing else may be pasted after the closing brace.

Verify the result by reading the keys — with
[DSInternals](#method-2-dsinternals-definitive-online),
[ntdswolf](#method-4-ntdsutil-ntdswolf-definitive-offline), or the
`ServiceAvailableKeys` field of the next
[4769 event](#detecting-accounts-that-need-password-reset-via-event-logs) for the account.

### What this does and does not change

!!! warning "Same password, but not a no-op"
    - **The key version number goes up.**  `msDS-KeyVersionNumber` increments on every
      password set, including this one.  Any **keytab** exported for the account now
      carries the wrong version and usually has to be regenerated — so "without changing
      the password" does not mean "without touching a keytab-based service".
    - **The RC4 key is unchanged.**  The RC4 key is derived from the password alone, so
      the same password gives the same key (and the same NT hash).  Anyone who captured or
      cracked it before still has a valid credential.  This technique adds AES keys; it
      does not rotate a secret.  Plan a real password change for accounts whose RC4
      tickets may have been exposed.
    - **Replication and caches still apply.**  Other DCs learn the new keys through
      replication, and clients keep using service tickets they already hold until those
      expire (10 hours by default).
