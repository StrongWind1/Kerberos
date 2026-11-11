```powershell title="Bulk set msDS-SupportedEncryptionTypes on manually-managed SPN-bearing accounts (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$AccountType = 'User'     # 'User' (SPN-bearing user accounts), 'gMSA', 'MSA' or 'dMSA'
$Target = 24         # etype bits to write: 24 = 0x18 = AES128 + AES256
$OnlyFrom = @(0)       # current values this run may replace; 0 = unset.
# Widen deliberately, e.g. @(0, 28) -- never "everything".
$SearchBase = $null      # $null = whole domain; set an OU DN to pilot on one OU first
$Exceptions = @()        # sAMAccountNames to leave alone, e.g. @('svc_legacy')
$ExceptionGroup = $null      # or a group whose (nested) members are left alone
$BackupCsv = ".\msds-set-$AccountType-$(Get-Date -Format yyyyMMdd-HHmmss).csv"
$DryRun = $true      # $true = -WhatIf only. Set $false after reviewing the plan.

--8<-- "includes/set-aes-core.md"
```

What the script will and will not do:

- **Never touches `krbtgt`** or any `krbtgt_*` account (RODC and Entra ID Kerberos keys).
  `krbtgt` carries the SPN `kadmin/changepw`, so a plain "every user with an SPN" filter
  matches it.
- **Only replaces values listed in `$OnlyFrom`** (default: unset).  Accounts that already
  carry a deliberate value — an RC4 exception at `4`, `28` or `60`, for example — are
  listed as skipped, not flattened.
- **Skips accounts whose password predates AES key generation.**  Setting an AES-only
  value on an account without AES keys makes every ticket request for it fail with
  `KDC_ERR_ETYPE_NOSUPP`.  The date check is the same approximation used elsewhere on this
  site, and it is **not a key check**: an account that passes it can still have no AES keys
  (see [why it is only approximate](account-key-audit.md#why-this-is-only-approximate)).
  Confirm the accounts in the planned-changes table with a real key audit before you set
  `$DryRun = $false`.
- **Prints two tables before anything else**: the accounts it skips, with the reason, and
  the changes it plans, with the old and the new value.
- **Stops on a failed check.**  The logic is one block; a wrong setting, a failed lookup or
  a mistyped exception group throws, and nothing after it runs.  It refuses a `$Target`
  that has no AES bit.
- **Preserves bits 16-19** (FAST, compound identity, claims, resource-SID compression) and
  replaces only etype bits 0-5.
- **Saves the old values to a CSV before writing** (real runs only; UTF-8, keyed on
  `objectGUID`, never overwriting an existing file), and prints `Updated` only for writes
  that succeeded.  [Undo a bulk run](aes-standardization.md#undo-a-bulk-run) restores from
  that CSV.
