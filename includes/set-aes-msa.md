```powershell title="Bulk set AES-only on all MSA accounts"
Get-ADServiceAccount -Filter * -Properties objectClass, 'msDS-SupportedEncryptionTypes' |
  Where-Object { $_.objectClass -contains 'msDS-ManagedServiceAccount' } |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne 24 } |
  ForEach-Object {
    Set-ADServiceAccount -Identity $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
    Write-Host "Updated MSA: $($_.sAMAccountName)"
  }
```
