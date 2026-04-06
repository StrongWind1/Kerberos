The RID 521 group (`Read-Only Domain Controllers`) is created when the domain functional level
is raised to 2008 — the earliest point at which password changes generate AES keys.  Any account
whose `passwordLastSet` predates that timestamp may lack AES keys entirely.

```powershell
$AESdate = (Get-ADGroup -Filter * -Properties SID, WhenCreated |
  Where-Object { $_.SID -like '*-521' }).WhenCreated

Write-Host "AES keys available since: $AESdate"

Get-ADUser -Filter 'Enabled -eq $true' -Properties passwordLastSet |
  Where-Object { $_.passwordLastSet -lt $AESdate } |
  Sort-Object passwordLastSet |
  Format-Table sAMAccountName, passwordLastSet, Enabled
```

This is an **approximation** — it identifies accounts that *may* lack AES keys based on password
age, not by reading the stored keys directly.  For definitive results (four methods, including
offline ntds.dit analysis), see [Auditing Kerberos Keys](account-key-audit.md).
