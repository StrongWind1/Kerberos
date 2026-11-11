```powershell title="Bulk set msDS-SupportedEncryptionTypes on Windows computer accounts in one OU (dry run by default)"
# ---- Operator settings -------------------------------------------------------
$AccountType = 'Computer'
$Target = 24         # etype bits to write: 24 = 0x18 = AES128 + AES256
$OnlyFrom = @(0)       # current values this run may replace; 0 = unset.
# Add 28 (RC4 + AES128 + AES256) to include hosts
# that registered that value themselves.
$SearchBase = 'OU=Workstations,DC=corp,DC=local'   # required: one OU at a time
$OperatingSystemLike = 'Windows*' # objects with any other (or blank) operatingSystem are skipped
$Exceptions = @()        # sAMAccountNames to leave alone, e.g. @('LEGACY-NAS$')
$ExceptionGroup = $null      # or a group whose (nested) members are left alone
$BackupCsv = ".\msds-set-$AccountType-$(Get-Date -Format yyyyMMdd-HHmmss).csv"
$DryRun = $true      # $true = -WhatIf only. Set $false after reviewing the plan.

--8<-- "includes/set-aes-core.md"
```

On a **Windows** machine this write does not last on its own.  Per KB5021131, "A computer
that is running a supported version of the Windows operating system automatically sets the
msds-SupportedEncryptionTypes for that machines account in Active Directory", so the
machine replaces your value with the one its own etype policy produces.  Use the script to
get ahead of the GPO, or for machines that will never process it; the GPO is what keeps the
value in place.

In addition to the safeguards of the user-account script, the computer run always skips:

- **Domain controllers and RODCs** (`primaryGroupID` 516 / 521) — their value is set by the
  DC itself and by the Domain Controllers GPO.
- **`AZUREADSSOACC` and `AzureADKerberos`** — Entra ID objects with their own key
  management; follow Microsoft's rollover procedure for those instead.
- **Failover-cluster name objects** (CNO/VCO, recognized by their `MSClusterVirtualServer/`
  SPN) — the cluster service owns these accounts.
- **Anything whose `operatingSystem` is not Windows** (NAS, Linux, appliances, pre-staged
  objects).  Those hosts decrypt tickets with a keytab or a vendor implementation; check
  each one by hand before you change what the KDC issues for it.
- **A domain-root `$SearchBase`** — the script refuses to run against the whole domain.
