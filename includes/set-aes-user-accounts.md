```powershell title="Bulk set AES-only on all SPN-bearing user accounts"
$target = 24

Get-ADUser -Filter 'servicePrincipalName -like "*"' `
  -Properties 'msDS-SupportedEncryptionTypes' |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne $target } |
  ForEach-Object {
    Set-ADUser -Identity $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = $target }
    Write-Host "Updated: $($_.sAMAccountName)"
  }
```
