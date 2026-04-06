```powershell title="Verify Kerberos audit subcategories on a domain controller"
auditpol /get /subcategory:"Kerberos Authentication Service"
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```
