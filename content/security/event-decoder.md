---
hide:
  - navigation
  - toc
---

# Kerberos Event Decoder

Paste a raw Windows Security Event XML from Event Viewer and get a
human-readable breakdown of every field — ticket options flags, encryption
types, result codes, pre-authentication types, and security warnings.

<div id="event-decoder">
<div class="evdec-input-section">
<label for="evdec-xml" class="evdec-label">Event XML</label>
<textarea id="evdec-xml" class="evdec-textarea" rows="10"
  placeholder="Paste a Windows Security Event XML here (events 4768, 4769, 4770, 4771)...&#10;&#10;Tip: In Event Viewer, right-click an event → Copy → Copy details as XML.&#10;Or use PowerShell: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -MaxEvents 1 | ForEach-Object { $_.ToXml() }"></textarea>
<div class="evdec-actions">
  <button id="evdec-decode" class="evdec-btn evdec-btn--primary" type="button">Decode</button>
  <button id="evdec-clear" class="evdec-btn" type="button">Clear</button>
  <button id="evdec-copy-link" class="evdec-btn" type="button">Copy Link</button>
  <span class="evdec-hint">Ctrl+Enter to decode</span>
</div>
</div>
<div class="evdec-examples">
<span class="evdec-examples-label">Examples:</span>
<button class="evdec-example-btn" data-example="4768-success" type="button">4768 TGT Success</button>
<button class="evdec-example-btn" data-example="4768-failure" type="button">4768 TGT Failure</button>
<button class="evdec-example-btn" data-example="4769-success" type="button">4769 TGS Success</button>
<button class="evdec-example-btn" data-example="4771-failure" type="button">4771 Pre-auth Failure</button>
<button class="evdec-example-btn" data-example="4770-renew" type="button">4770 Renewal</button>
</div>
<div id="evdec-error" class="evdec-error" style="display:none"></div>
<div id="evdec-results" class="evdec-results" style="display:none">
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

## How to Export Event XML

**Event Viewer GUI** — Right-click an event → **Copy** → **Copy details as XML**.

**PowerShell** (single event):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -MaxEvents 1 |
  ForEach-Object { $_.ToXml() }
```

**PowerShell** (export failures):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -MaxEvents 100 |
  Where-Object { $_.ToXml() -match 'Status.*0x[1-9a-fA-F]' } |
  ForEach-Object { $_.ToXml() }
```

**wevtutil** (command line):

```cmd
wevtutil qe Security "/q:*[System[EventID=4768]]" /c:1 /f:xml
```

## See Also

- [Encryption Type Calculator](etype-calculator.md) — decode msDS-SupportedEncryptionTypes bitmask values
- [Etype Negotiation](etype-negotiation.md) — how the KDC selects encryption types
- [Registry Settings](registry.md) — registry paths that control Kerberos encryption
- [Group Policy](group-policy.md) — GPO settings for encryption type filtering
