---
description: Decode Windows Security events 4768, 4769, 4770 and 4771 into KDC options, encryption types, result codes and etype diagnostics.
hide:
  - navigation
  - toc
---

# Kerberos Event Decoder

Paste a Windows Security event from a domain controller, as XML or as the text
Event Viewer shows, and get a human-readable breakdown of every field: KDC option
flags, encryption types, result codes, pre-authentication types, and warnings
about how the KDC arrived at the etypes it chose.

Everything runs in your browser.  Nothing you paste is sent anywhere, and the
event is never written to the address bar.  **Copy Link** puts a link that
contains the event on your clipboard, and only when you press it.

<div id="event-decoder">
<div class="evdec-input-section">
<label for="evdec-xml" class="evdec-label">Event XML or text</label>
<textarea id="evdec-xml" class="evdec-textarea" rows="10" spellcheck="false" aria-describedby="evdec-privacy-note"
  placeholder="Paste a Windows Security event here (4768, 4769, 4770 or 4771), as XML or as text...&#10;&#10;Event Viewer: right-click the event → Copy → Copy details as text (includes the XML),&#10;or Details tab → XML View → select all → copy.&#10;PowerShell: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -MaxEvents 1 | ForEach-Object { $_.ToXml() }"></textarea>
<div class="evdec-actions">
  <button id="evdec-decode" class="evdec-btn evdec-btn--primary" type="button">Decode</button>
  <button id="evdec-clear" class="evdec-btn" type="button">Clear</button>
  <button id="evdec-copy-link" class="evdec-btn" type="button">Copy Link</button>
  <span class="evdec-hint">Ctrl+Enter to decode</span>
</div>
<p id="evdec-privacy-note" class="evdec-privacy-note">Copy Link puts the whole pasted event (account names, SIDs, client addresses) into the link. Share it only with people who may see the event.</p>
</div>
<div class="evdec-examples">
<span class="evdec-examples-label">Examples:</span>
<button class="evdec-example-btn" data-example="4768-success" type="button">4768 TGT Success</button>
<button class="evdec-example-btn" data-example="4768-failure" type="button">4768 TGT Failure</button>
<button class="evdec-example-btn" data-example="4769-success" type="button">4769 TGS Success</button>
<button class="evdec-example-btn" data-example="4771-failure" type="button">4771 Pre-auth Failure</button>
<button class="evdec-example-btn" data-example="4770-renew" type="button">4770 Renewal</button>
</div>
<div id="evdec-error" class="evdec-error" role="alert" style="display:none"></div>
<div id="evdec-results" class="evdec-results" role="region" aria-label="Decoded event" tabindex="-1" style="display:none">
  <div id="evdec-result-actions" class="evdec-result-actions" style="display:none">
    <button id="evdec-copy-details" class="evdec-btn evdec-btn--secondary" type="button">Copy Details</button>
  </div>
  <div id="evdec-header" class="evdec-header"></div>
  <div id="evdec-warnings" class="evdec-warnings" style="display:none"></div>
  <div id="evdec-pipeline" class="evdec-pipeline" style="display:none"></div>
  <div id="evdec-fields" class="evdec-fields"></div>
  <div id="evdec-ticket-options" class="evdec-ticket-options" style="display:none"></div>
</div>
</div>

---

## Supported Events

These four events cover the Kerberos authentication lifecycle on domain controllers.
Enable **Audit Kerberos Authentication Service** and **Audit Kerberos Service Ticket
Operations** in Advanced Audit Policy to capture them.

| Event | Name | Generated When |
|---|---|---|
| **4768** | TGT Request (AS-REQ) | Client requests an initial TGT from the KDC |
| **4769** | Service Ticket (TGS-REQ) | Client uses a TGT to request a service ticket |
| **4770** | Ticket Renewed | An existing service ticket is renewed |
| **4771** | Pre-auth Failed | AS-REQ fails pre-authentication (wrong password, locked account, etc.) |

The decoder does not handle the KDC's System-log events (Kdcsvc 201-209 and KDC
14, 16, 26, 27).  [Troubleshooting](troubleshooting.md) and
[RC4 Deprecation](rc4-deprecation.md) describe those.

## What the Decoder Reads

**XML** is the complete form and the one to prefer.  Anything around the `<Event>`
element is ignored, so all of these work as pasted:

- Event Viewer **Copy details as text** (the text is followed by `Event Xml:`)
- Event Viewer **Details → XML View**, including the `-` markers in front of each node
- `$_.ToXml()` and `wevtutil ... /f:xml` output, with or without an `<Events>` wrapper

**Text** is accepted too: the General tab description, `Get-WinEvent | Format-List`
output, or an abridged excerpt such as the samples on this site.  The event ID is
taken from an `Event ID:` or `Id :` line, or from the first sentence of the
description.  A text excerpt carries fewer fields than the XML, so the breakdown
is only as complete as what you paste.  Only English-language text is recognised:
on a Windows with another display language, paste the XML, which the decoder reads
by field name rather than by the translated labels.

**One event is decoded at a time.**  When the paste holds several events, as XML
or as text, the decoder decodes the first one it handles and says at the top of
the result how many it found and which one it is showing.

## Reading the Result

**Ticket Options is the request's KDC options.**  The field holds the `kdc-options`
of the request ([RFC 4120 §5.4.1](https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.1)),
not the flags of the issued ticket.  Bit 14 is `cname-in-addl-tkt`, which marks an
S4U2Proxy (constrained delegation) request; some event documentation labels that
position "Request-anonymous".

**The SupportedEncryptionTypes fields are effective values.**  They show the set
the KDC evaluated for the account: `msDS-SupportedEncryptionTypes` if it is non-zero,
otherwise `DefaultDomainSupportedEncTypes` if set on the DC, otherwise the build
default (`0x27` before the April 2026 cumulative update, `0x18` on it or later).

**The KDC filter is not in the event.**  The `SupportedEncryptionTypes` registry
value on the DC can still narrow what is issued; check it on the DC when the event
alone does not explain a `KDC_ERR_ETYPE_NOSUPP`.

**Ticket etype and session key etype have different inputs.**  The ticket etype is
the strongest etype in the target account's effective set for which the account
has keys, subject to the KDC filter; the client's list is not consulted unless
`KdcUseRequestedEtypesForTickets` is 1.  The session key needs an etype present in
both the client's list and the target's effective set.  That is the rule for a
service ticket (4769).  On a TGT request (4768) the ticket is encrypted with one
of the krbtgt account's keys, subject to the KDC filter, and the session key is
the strongest etype in the client's list that the KDC allows.  See
[Etype Negotiation](etype-negotiation.md).

**"-" and "N/A" mean the event did not record the value.**  A failure event can
show `-` for the advertised etypes and for the SupportedEncryptionTypes and
Available Keys fields, as Microsoft's own example of a `0xE` failure does.  The
decoder draws no conclusion about the client or the account from such a field.

## How to Export Event XML

**Event Viewer GUI** - Right-click an event → **Copy** → **Copy details as text**,
or open the **Details** tab, choose **XML View**, and copy its contents.

**PowerShell** (single event):

```powershell
Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4768 } -MaxEvents 1 |
    ForEach-Object { $_.ToXml() }
```

**PowerShell** (failures only).  The `Keywords` value selects Audit Failure
(`0x10000000000000`), so the DC filters before anything is returned:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4768, 4769, 4771; Keywords = 0x10000000000000
} -MaxEvents 100 |
    ForEach-Object { $_.ToXml() }
```

**wevtutil** (command line).  `/rd:true` returns the most recent event first:

```cmd
wevtutil qe Security "/q:*[System[EventID=4768]]" /c:1 /rd:true /f:xml
```

## See Also

- [Encryption Type Calculator](etype-calculator.md) - decode msDS-SupportedEncryptionTypes bitmask values
- [Etype Negotiation](etype-negotiation.md) - how the KDC selects encryption types
- [Troubleshooting](troubleshooting.md) - error codes, KDC System-log events, and common scenarios
- [Registry Settings](registry.md) - registry paths that control Kerberos encryption
- [Group Policy](group-policy.md) - GPO settings for encryption type filtering
