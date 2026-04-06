```powershell title="Bulk set AES-only on all dMSA accounts"
Get-ADObject -LDAPFilter '(&(objectClass=msDS-DelegatedManagedServiceAccount)(servicePrincipalName=*))' `
  -Properties 'msDS-SupportedEncryptionTypes' |
  Where-Object { [int]$_.'msDS-SupportedEncryptionTypes' -ne 24 } |
  ForEach-Object {
    Set-ADObject -Identity $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
    Write-Host "Updated dMSA: $($_.Name)"
  }
```
