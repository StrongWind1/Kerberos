```powershell title="Verify Kerberos audit subcategories on a domain controller"
# auditpol reports the audit policy of the computer it runs on and has no remote-computer
# parameter.  Run this on each DC (or through Invoke-Command), not on a management host.
auditpol /get /subcategory:"Kerberos Authentication Service"
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```
