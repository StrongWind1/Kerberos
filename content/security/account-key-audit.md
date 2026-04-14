# Auditing Kerberos Keys

Before migrating to AES, you need to know which accounts have AES keys and which only
have RC4.  There is no single AD attribute that directly exposes an account's stored
key types -- the keys are buried in the replicated secret data in `ntds.dit`.  This page
covers four methods to surface that information, each with different trade-offs.

| Method | Accuracy | Requires | Triggers Alerts |
|---|---|---|---|
| [PowerShell date comparison](#method-1-powershell-date-comparison-approximate) | Approximate | AD read access | No |
| [DSInternals](#method-2-dsinternals-definitive-online) | Definitive | Domain admin / DCSync rights | **Yes** (DCSync) |
| [Impacket secretsdump](#method-3-impacket-secretsdump-definitive-online) | Definitive | Domain admin / DCSync rights | **Yes** (DCSync) |
| [ntdsutil + ntdissector](#method-4-ntdsutil-ntdissector-definitive-offline) | Definitive | Local admin on DC | Minimal (backup event only) |

---

## Method 1: PowerShell Date Comparison (Approximate)

The fastest method with no special tools.  Compare each account's `passwordLastSet` date
against the date AES key generation became available (when DFL was raised to 2008).

### How it works

When the domain functional level is raised to 2008, AD creates the "Read-Only Domain
Controllers" group (RID 521).  Its `WhenCreated` timestamp marks the earliest point at
which password changes generate AES keys.  Any account whose `passwordLastSet` predates
that timestamp may lack AES keys.

### The query

```powershell title="Find enabled accounts whose passwords predate AES key generation"
$AESdate = (Get-ADGroup -Filter * -Properties SID, WhenCreated |
  Where-Object { $_.SID -like '*-521' }).WhenCreated

Write-Host "AES keys available since: $AESdate"

# All enabled accounts with passwords predating AES key generation
Get-ADUser -Filter 'Enabled -eq $true' `
  -Properties passwordLastSet, servicePrincipalName, 'msDS-SupportedEncryptionTypes' |
  Where-Object { $_.passwordLastSet -lt $AESdate } |
  Sort-Object passwordLastSet |
  Select-Object sAMAccountName,
    passwordLastSet,
    @{N='HasSPN'; E={[bool]$_.servicePrincipalName}},
    @{N='msDS-SET'; E={$_.'msDS-SupportedEncryptionTypes'}} |
  Format-Table -AutoSize
```

### Why this is only approximate

- **False positives**: an account created **after** DFL 2008 but whose password was
  never changed will show a `passwordLastSet` after the cutover date -- and will have
  AES keys.  This method cannot distinguish "password set at DFL 2008" from "password
  set before DFL 2008, account created after."
- **False negatives**: an account whose password was reset after DFL 2008 but whose
  `passwordLastSet` was manually tampered with (rare) would be missed.
- **No key verification**: this method infers key presence from dates.  It never reads
  the actual stored keys.  An account could have the right date but still lack AES keys
  due to a replication failure or database corruption.

Use this method as a quick triage to estimate scope.  For definitive results, use one of
the methods below.

---

## Method 2: DSInternals (Definitive, Online)

[DSInternals](https://github.com/MichaelGrafnetter/DSInternals) reads account data
through the MS-DRSR replication protocol, including the supplemental credentials that
contain the actual Kerberos key types stored for each account.  This is the same data
the KDC uses when selecting encryption types.

### Install

```powershell
Install-Module -Name DSInternals -Force
```

### Single account

```powershell
Get-ADReplAccount -SamAccountName svc_example -Server dc01.corp.local
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

No `KerberosNew` section, or `KerberosNew` contains only DES/RC4 entries.

### All accounts: find those missing AES keys

```powershell title="Find all enabled accounts with no AES key via DSInternals"
Get-ADReplAccount -All -Server dc01.corp.local |
  Where-Object { $_.Enabled } |
  Where-Object {
    $keys = $_.SupplementalCredentials.KerberosNew.Credentials.KeyType
    -not ($keys -match 'AES')
  } |
  Select-Object SamAccountName, SamAccountType,
    @{N='PasswordLastSet'; E={$_.PasswordLastSet}},
    @{N='HasSPN'; E={[bool]$_.ServicePrincipalName}},
    @{N='KeyTypes'; E={
      $k = $_.SupplementalCredentials.KerberosNew.Credentials.KeyType
      if ($k) { $k -join ', ' } else { '(none)' }
    }} |
  Format-Table -AutoSize
```

This outputs every enabled account that has no AES key in its supplemental credentials.
The `HasSPN` column tells you whether the account is Kerberoastable (SPN-bearing user
accounts are the highest priority to fix).

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
    [Method 4](#method-4-ntdsutil-ntdissector-definitive-offline) to avoid network-based
    alerts entirely.

---

## Method 3: Impacket secretsdump (Definitive, Online)

[Impacket](https://github.com/fortra/impacket) `secretsdump` extracts credentials
from a DC via the DRSUAPI protocol.  Like DSInternals, it reads the actual stored keys.

### Install

```bash
# Install uv (Python package manager) if not already present
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install impacket as a CLI tool
uv tool install git+https://github.com/fortra/impacket.git
```

### Usage

```bash title="Dump all account credentials from a DC via DRSUAPI"
secretsdump.py -just-dc -outputfile domain_dump 'CORP.LOCAL/admin@dc01.corp.local'
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
only have `des-cbc-md5` (and possibly `rc4-hmac-nt`).

### Find accounts without AES keys

```bash title="Extract accounts without AES256 keys from secretsdump output"
# All accounts that appear in the kerberos file
cut -d: -f1 domain_dump.ntds.kerberos | sort -u > all_kerberos.txt

# Accounts that have AES256 keys
grep 'aes256-cts-hmac-sha1-96' domain_dump.ntds.kerberos | cut -d: -f1 | sort -u > has_aes256.txt

# Accounts WITHOUT AES keys (in all_kerberos but not in has_aes256)
comm -23 all_kerberos.txt has_aes256.txt
```

### Alert implications

!!! warning "Same DCSync alerts as DSInternals"
    `secretsdump` uses the same DRSUAPI protocol as DSInternals.  It triggers identical
    alerts: Event 4662, MDI DCSync detection, and EDR alerts.

    Additionally, running impacket tools from a non-Windows machine may trigger extra
    anomaly detections (unusual DRSUAPI source OS, unusual network path to the DC).

    Coordinate with your SOC before running, or use
    [Method 4](#method-4-ntdsutil-ntdissector-definitive-offline) instead.

### Cleanup

The dump files contain every account's NTLM hash and Kerberos keys.  Delete them
securely after analysis:

```bash title="Securely delete credential dump files after analysis"
shred -u domain_dump.ntds domain_dump.ntds.kerberos domain_dump.ntds.cleartext
rm -f all_kerberos.txt has_aes256.txt
```

---

## Method 4: ntdsutil + ntdissector (Definitive, Offline)

This method creates an offline copy of the AD database, transfers it to a Linux machine,
and parses it with [ntdissector](https://github.com/StrongWind1/ntdissector).  Because
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

### Step 2: Transfer to a Linux machine

Copy `ntds.dit` and `SYSTEM` to a secure Linux workstation.  Use whatever transfer
method your environment allows (SCP, USB, SMB share).  These files contain every
credential in the domain -- treat them accordingly.

```bash title="Copy ntds.dit and SYSTEM hive from DC for offline analysis"
# Example: SCP from the DC
scp administrator@dc01:'C:\IFM\Active Directory\ntds.dit' ./ntds.dit
scp administrator@dc01:'C:\IFM\registry\SYSTEM' ./SYSTEM
```

### Step 3: Install ntdissector

```bash
# Install uv (Python package manager) if not already present
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install ntdissector as a CLI tool
uv tool install git+https://github.com/StrongWind1/ntdissector.git
```

### Step 4: Parse the database

```bash title="Parse the AD database and extract user objects to JSON"
ntdissector -ntds ntds.dit -system SYSTEM -f user -outputdir ./ntds_output -ts
```

This parses all user objects from `ntds.dit` and writes JSON files to `./ntds_output/`.
The output is organized by object class: `user.json` contains all user accounts with
their attributes and supplemental credentials.

To also include computer accounts:

```bash title="Parse the AD database including computer accounts"
ntdissector -ntds ntds.dit -system SYSTEM -f user,computer -outputdir ./ntds_output -ts
```

### Step 5: Find accounts without AES keys

The JSON output contains each account's supplemental credentials, including the Kerberos
key types.  Use `jq` to filter for accounts missing AES keys:

```bash title="Find enabled accounts without AES256 keys in ntdissector JSON output"
# Find enabled accounts without AES256 Kerberos keys
jq -r '
  .[] |
  select(.userAccountControl // 0 | . % 4 < 2) |
  select(
    (.supplementalCredentials.kpiNewerKeys // [] |
     map(.keytype) |
     any(. == "aes256-cts-hmac-sha1-96")) | not
  ) |
  [.sAMAccountName, .pwdLastSet, (.servicePrincipalName // [] | length | tostring)] |
  @tsv
' ./ntds_output/*/user.json 2>/dev/null |
  sort -t$'\t' -k2 |
  column -t -s$'\t' -N 'Account,PasswordLastSet,SPNCount'
```

!!! tip "Adapt the jq filter to the actual JSON structure"
    The exact field names in ntdissector's JSON output depend on the version and schema.
    Run `jq 'keys' ./ntds_output/*/user.json | head` first to inspect the top-level
    fields, then adjust the filter above to match.  The key information is in the
    supplemental credentials structure -- look for fields containing `kerberos`,
    `credentials`, or `keytype`.

### Alert implications

- **No DCSync alerts.**  No DRSUAPI traffic crosses the network.
- **Event 327** (ESENT) on the DC when ntdsutil creates the IFM backup.  This is a
  standard administrative operation -- DCs generate IFM backups for RODC deployment and
  disaster recovery.  Most SOCs do not alert on this.
- The extracted files (`ntds.dit`, `SYSTEM`) contain the full domain credential set.
  Handle them with the same security controls as a domain controller.

### Cleanup

```bash title="Securely delete extracted AD database files after analysis"
# Securely delete the extracted files after analysis
shred -u ntds.dit SYSTEM
rm -rf ./ntds_output
```

---

## Which Method to Use

| Scenario | Recommended Method |
|---|---|
| Quick estimate of how many accounts might lack AES keys | Method 1 (PowerShell dates) |
| Definitive audit, SOC can whitelist DCSync alerts | Method 2 (DSInternals) -- best PowerShell integration |
| Definitive audit from a Linux attack/audit box | Method 3 (secretsdump) |
| Definitive audit, cannot trigger DCSync alerts | Method 4 (ntdsutil + ntdissector) |
| Regular ongoing monitoring (scheduled task) | Method 1 for triage, Method 2 for periodic verification |

---

## Generating AES Keys Without Changing the Password

Some service accounts cannot have their password changed without coordinated downtime
across multiple systems.  In these cases, you can generate AES keys by resetting the
password **to the same value** — AD generates new key material on every password set
operation, regardless of whether the actual password string changes.

The catch: Active Directory's password history policy normally blocks reuse.  A temporary
Fine-Grained Password Policy (FGPP) with `PasswordHistoryCount = 0` bypasses this check
for the duration of the operation.

### Step-by-Step

```powershell title="Generate AES keys by resetting to the same password via temporary FGPP"
# 1. Create a temporary FGPP that allows password reuse
New-ADFineGrainedPasswordPolicy -Name "Temp-NoHistory" `
  -Precedence 1 `
  -PasswordHistoryCount 0 `
  -MinPasswordAge "00:00:00" `
  -MaxPasswordAge "00:00:00" `
  -MinPasswordLength 0 `
  -ComplexityEnabled $false

# 2. Apply the FGPP to the target account
Add-ADFineGrainedPasswordPolicySubject -Identity "Temp-NoHistory" `
  -Subjects "svc_example"

# 3. Reset the password to the same value
#    (the operator must know the current password)
Set-ADAccountPassword -Identity "svc_example" `
  -Reset -NewPassword (ConvertTo-SecureString "ExistingP@ssw0rd" -AsPlainText -Force)

# 4. Remove the temporary FGPP immediately
Remove-ADFineGrainedPasswordPolicySubject -Identity "Temp-NoHistory" `
  -Subjects "svc_example"
Remove-ADFineGrainedPasswordPolicy -Identity "Temp-NoHistory" -Confirm:$false
```

After the reset, the account's supplemental credentials will contain AES128 and AES256
keys derived from the (unchanged) password.  You can verify this with
[DSInternals](#method-2-dsinternals-definitive-online) or
[ntdissector](#method-4-ntdsutil-ntdissector-definitive-offline).

!!! warning "The FGPP must be removed immediately"
    Leaving a `PasswordHistoryCount = 0` FGPP in place disables password history for
    the affected account.  Always remove the FGPP and verify removal as the final step.

### Detecting Accounts That Need Password Reset via Event Logs

Accounts that have `msDS-SupportedEncryptionTypes` set to include AES but still show
RC4-encrypted tickets (etype `0x17`) in event logs are the clearest signal that a
password reset is needed — they have the AES **configuration** but no AES **keys**.

Look for Event ID 4768 (AS-REQ) or 4769 (TGS-REQ) where the ticket encryption type is
`0x17` (RC4-HMAC) for accounts you have already configured for AES.

#### Event 4768 / 4769 Property Index Reference

Recent Windows updates (January 2025+) extended events 4768 and 4769 with new
properties for `msDS-SupportedEncryptionTypes`, account keys, and the session key etype.
The table below shows the property indices used in the PowerShell examples on this page.

**Event 4769** (TGS-REQ) — 21 properties in the new format:

| Index | Field | Example Value |
|---|---|---|
| 0 | Requesting account (UPN) | `svc_sql@CORP.LOCAL` |
| 2 | Target service name | `MSSQLSvc/sql01.corp.local` |
| 5 | **Ticket encryption type** | `18` (AES256-SHA1) or `23` (RC4) |
| 6 | Client IP address | `192.168.1.50` |
| 15 | msDS-SupportedEncryptionTypes string | `0x1C (RC4, AES128-SHA96, AES256-SHA96)` |
| 16 | Account key types | `AES128-SHA96, AES256-SHA96, RC4` |
| 20 | **Session key encryption type** | `18` |

**Event 4768** (AS-REQ) — 24 properties in the new format:

| Index | Field | Example Value |
|---|---|---|
| 0 | Account name | `jsmith` |
| 3 | Target service | `krbtgt` |
| 7 | **Ticket encryption type** | `18` or `23` |
| 9 | Client IP address | `192.168.1.50` |
| 15 | msDS-SupportedEncryptionTypes string | `0x18 (AES128-SHA96, AES256-SHA96)` |
| 16 | Account key types | `AES128-SHA96, AES256-SHA96` |
| 22 | **Session key encryption type** | `18` |

!!! warning "Event format varies by Windows version"
    These property indices require the **new event format** from January 2025+ updates.
    Events from unpatched DCs have fewer properties (< 21 for 4769, < 24 for 4768) and
    do not contain the session key etype, account keys, or `msDS-SupportedEncryptionTypes`
    fields.

    Additionally, the account key string format differs between versions:

    - **Server 2022**: keys reported as `"AES-SHA1, RC4"` (aggregated)
    - **Server 2025+**: keys reported individually as `"AES128-SHA96, AES256-SHA96, RC4"`

    Microsoft's
    [`List-AccountKeys.ps1`](https://github.com/microsoft/Kerberos-Crypto/tree/main/scripts)
    normalizes both formats automatically.

#### Queries

**Splunk:**

```spl title="Find accounts configured for AES but still getting RC4 tickets"
index=wineventlog EventCode IN (4768, 4769) Ticket_Encryption_Type=0x17
| stats count dc(src) as KDC_count by Account_Name
| lookup ad_accounts sAMAccountName as Account_Name
    OUTPUT msDS_SupportedEncryptionTypes
| where msDS_SupportedEncryptionTypes >= 8
| table Account_Name msDS_SupportedEncryptionTypes count KDC_count
```

**KQL (Microsoft Sentinel):**

```kql title="Find AES-configured accounts receiving RC4 tickets"
SecurityEvent
| where EventID in (4768, 4769)
| where TicketEncryptionType == "0x17"
| summarize EventCount = count(), KDCs = dcount(Computer) by TargetAccount
```

**PowerShell cross-reference:**

```powershell title="Cross-reference AD etype config against event log RC4 usage"
# Get accounts configured for AES (bit 0x8 or 0x10 set)
$aesAccounts = Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -ge 8' `
  -Properties msDS-SupportedEncryptionTypes, servicePrincipalName |
  Where-Object { $_.servicePrincipalName } |
  Select-Object -ExpandProperty sAMAccountName

# Check event logs for RC4 tickets or RC4 session keys issued to those accounts.
# Properties[5] = ticket etype, Properties[20] = session key etype (new format).
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769 } |
  Where-Object {
    $_.Properties.Count -ge 21 -and
    $aesAccounts -contains $_.Properties[2].Value -and
    ($_.Properties[5].Value -eq '0x17' -or $_.Properties[20].Value -eq '0x17')
  } |
  Select-Object TimeCreated,
    @{N='Account'; E={$_.Properties[2].Value}},
    @{N='Service'; E={$_.Properties[0].Value}},
    @{N='TicketEtype'; E={$_.Properties[5].Value}},
    @{N='SessionKeyEtype'; E={$_.Properties[20].Value}} |
  Sort-Object Account -Unique |
  Format-Table -AutoSize
```

The query checks both the ticket etype and the session key etype.  An account using the
[AES-SK split](etype-decision-guide.md#the-aes-sk-split-when-ticket-and-session-key-differ) may show an AES ticket etype
but an RC4 session key etype — both fields must be checked.  The `Properties.Count -ge
21` guard ensures only events in the new format (January 2025+ updates) are processed.

Each account that appears in this output needs a password reset (or the
[FGPP same-password technique](#generating-aes-keys-without-changing-the-password) above)
to generate AES keys.
