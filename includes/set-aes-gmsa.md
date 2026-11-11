Group managed service accounts use the **same bulk script** as user service accounts - shown in full under
[Bulk update](aes-standardization.md#bulk-update-script) - with one setting changed: set `$AccountType = 'gMSA'` in the settings header and
leave everything else as it is.

The script selects every gMSA object in `$SearchBase` (with or without an SPN) and applies
the same safeguards: allow-list of current values, exception list, CSV backup, dry run
by default.
