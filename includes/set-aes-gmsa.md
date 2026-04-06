```powershell title="Bulk set AES-only on all gMSA accounts"
Get-ADServiceAccount -Filter * -Properties objectClass, 'msDS-SupportedEncryptionTypes' |
  Where-Object { $_.objectClass -contains 'msDS-GroupManagedServiceAccount' } |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne 24 } |
  ForEach-Object {
    Set-ADServiceAccount -Identity $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
    Write-Host "Updated gMSA: $($_.sAMAccountName)"
  }
```
