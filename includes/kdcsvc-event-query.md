```powershell title="Collect the RC4-change KDC events (201-209) from every DC"
$Since = (Get-Date).AddDays(-7)
$DCs = (Get-ADDomainController -Filter *).HostName

$kdcEvents = foreach ($dc in $DCs) {
    try {
        Get-WinEvent -ComputerName $dc -ErrorAction Stop -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'
            Id           = 201, 202, 203, 204, 205, 206, 207, 208, 209
            StartTime    = $Since
        } | Select-Object @{N = 'DC'; E = { $dc } }, TimeCreated, Id, Message
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Write-Information "${dc}: no 201-209 events since $Since" -InformationAction Continue
        }
        else {
            Write-Warning "${dc}: NOT CHECKED - $($_.Exception.Message)"
        }
    }
}

$kdcEvents | Group-Object DC, Id | Sort-Object Name |
    Select-Object Count, Name | Format-Table -AutoSize
$kdcEvents | Sort-Object TimeCreated -Descending |
    Select-Object -First 50 DC, TimeCreated, Id, Message | Format-List
```

A DC that prints `NOT CHECKED` has told you nothing — "no output" only counts as clean
for DCs that explicitly report no matching events.  201, 202, 206 and 207 are audit
events (the request was still served); 203, 204, 208 and 209 mean a request was refused.

Two limits on what "no events" means.  The query looks back seven days; widen `$Since` if
you are judging a longer period.  And a DC with an explicit `DefaultDomainSupportedEncTypes`
does not log 201-204 at all: KB5073381 says "Warning Event 201 is NOT logged if
DefaultDomainSupportedEncTypes is manually defined", and lists "The domain controller does
NOT have DDSET defined" as a condition for 203 and 204.  On such a DC, the absence of
201-204 says nothing about RC4 use.
