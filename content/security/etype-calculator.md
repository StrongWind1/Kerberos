---
description: Convert msDS-SupportedEncryptionTypes, DefaultDomainSupportedEncTypes and the Kerberos GPO value between decimal, hex and bit flags.
hide:
  - navigation
  - toc
---

# Encryption Type Calculator

Three settings control Kerberos encryption types in Active Directory, and each one
interprets the same bitmask differently.  Use this calculator to convert between
decimal, hex, and individual flags for any of the three settings.

The calculator converts and explains values.  It does not simulate which etype the
KDC issues for a given account, client and DC; for that, use the
[Etype Decision Guide](etype-decision-guide.md).

For the full reference on each setting, see
[msDS-SupportedEncryptionTypes](msds-supported.md),
[Registry Settings](registry.md), and
[Group Policy](group-policy.md).

<div id="etype-calculator">
<div class="etype-tabs" role="group" aria-label="Setting to interpret the value for">
  <button type="button" class="etype-tab etype-tab--active" data-setting="msds" aria-pressed="true">msDS-SupportedEncryptionTypes</button>
  <button type="button" class="etype-tab" data-setting="default" aria-pressed="false">DefaultDomainSupportedEncTypes</button>
  <button type="button" class="etype-tab" data-setting="gpo" aria-pressed="false">SupportedEncryptionTypes (GPO)</button>
</div>
<p id="etype-setting-desc" class="etype-setting-desc"></p>
<div id="etype-status" class="etype-status" role="status"></div>
<div class="etype-calc-grid">
<div class="etype-bits">
<h2>Bit Flags</h2>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="1" data-bit="0" aria-describedby="etype-note-0">
    <span class="etype-bit-info"><code>0x1</code> (1)</span>
    <span class="etype-bit-name">DES-CBC-CRC</span>
    <span class="etype-bit-etype">etype 1</span>
    <span class="etype-bit-badge etype-bit-badge--removed">Removed</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-0"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="2" data-bit="1" aria-describedby="etype-note-1">
    <span class="etype-bit-info"><code>0x2</code> (2)</span>
    <span class="etype-bit-name">DES-CBC-MD5</span>
    <span class="etype-bit-etype">etype 3</span>
    <span class="etype-bit-badge etype-bit-badge--removed">Removed</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-1"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="4" data-bit="2" aria-describedby="etype-note-2">
    <span class="etype-bit-info"><code>0x4</code> (4)</span>
    <span class="etype-bit-name">RC4-HMAC</span>
    <span class="etype-bit-etype">etype 23</span>
    <span class="etype-bit-badge etype-bit-badge--deprecated">Deprecated</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-2"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="8" data-bit="3" aria-describedby="etype-note-3">
    <span class="etype-bit-info"><code>0x8</code> (8)</span>
    <span class="etype-bit-name">AES128-CTS-HMAC-SHA1-96</span>
    <span class="etype-bit-etype">etype 17</span>
    <span class="etype-bit-badge etype-bit-badge--recommended">Recommended</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-3"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="16" data-bit="4" aria-describedby="etype-note-4">
    <span class="etype-bit-info"><code>0x10</code> (16)</span>
    <span class="etype-bit-name">AES256-CTS-HMAC-SHA1-96</span>
    <span class="etype-bit-etype">etype 18</span>
    <span class="etype-bit-badge etype-bit-badge--recommended">Recommended</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-4"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="32" data-bit="5" aria-describedby="etype-note-5">
    <span class="etype-bit-info"><code>0x20</code> (32)</span>
    <span class="etype-bit-name">AES256-CTS-HMAC-SHA1-96-SK</span>
    <span class="etype-bit-etype">session key</span>
    <span class="etype-bit-badge etype-bit-badge--special">AES-SK</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-5"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="64" data-bit="6" aria-describedby="etype-note-6">
    <span class="etype-bit-info"><code>0x40</code> (64)</span>
    <span class="etype-bit-name">AES128-CTS-HMAC-SHA256-128</span>
    <span class="etype-bit-etype">etype 19</span>
    <span class="etype-bit-badge etype-bit-badge--neutral">Off by default</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-6"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="128" data-bit="7" aria-describedby="etype-note-7">
    <span class="etype-bit-info"><code>0x80</code> (128)</span>
    <span class="etype-bit-name">AES256-CTS-HMAC-SHA384-192</span>
    <span class="etype-bit-etype">etype 20</span>
    <span class="etype-bit-badge etype-bit-badge--neutral">Off by default</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-7"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="65536" data-bit="16" aria-describedby="etype-note-16">
    <span class="etype-bit-info"><code>0x10000</code></span>
    <span class="etype-bit-name">FAST-supported</span>
    <span class="etype-bit-etype">bit 16</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-16"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="131072" data-bit="17" aria-describedby="etype-note-17">
    <span class="etype-bit-info"><code>0x20000</code></span>
    <span class="etype-bit-name">Compound-identity-supported</span>
    <span class="etype-bit-etype">bit 17</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-17"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="262144" data-bit="18" aria-describedby="etype-note-18">
    <span class="etype-bit-info"><code>0x40000</code></span>
    <span class="etype-bit-name">Claims-supported</span>
    <span class="etype-bit-etype">bit 18</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-18"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="524288" data-bit="19" aria-describedby="etype-note-19">
    <span class="etype-bit-info"><code>0x80000</code></span>
    <span class="etype-bit-name">Resource-SID-compression-disabled</span>
    <span class="etype-bit-etype">bit 19</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-19"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="2147483616" data-bit="future" aria-describedby="etype-note-future">
    <span class="etype-bit-info"><code>0x7FFFFFE0</code></span>
    <span class="etype-bit-name">Future encryption types</span>
    <span class="etype-bit-etype">bits 5-30</span>
    <span class="etype-bit-badge etype-bit-badge--neutral">GPO</span>
  </label>
  <span class="etype-bit-ignored-note" id="etype-note-future"></span>
</div>
</div>
<div class="etype-values">
<h2>Values</h2>
<div class="etype-field">
  <label for="etype-dec">Decimal</label>
  <div class="etype-input-row">
    <input type="text" inputmode="numeric" autocomplete="off" spellcheck="false" id="etype-dec" value="0" aria-describedby="etype-input-msg">
    <button type="button" class="etype-copy-btn" id="etype-copy-dec" title="Copy decimal value">Copy</button>
  </div>
</div>
<div class="etype-field">
  <label for="etype-hex">Hexadecimal</label>
  <div class="etype-input-row">
    <input type="text" autocomplete="off" spellcheck="false" id="etype-hex" value="0x0" aria-describedby="etype-input-msg">
    <button type="button" class="etype-copy-btn" id="etype-copy-hex" title="Copy hex value">Copy</button>
  </div>
</div>
<p id="etype-input-msg" class="etype-input-msg" role="alert"></p>
<div class="etype-field">
  <label for="etype-flags">Flag Names</label>
  <div class="etype-input-row">
    <output id="etype-flags" class="etype-flags" for="etype-dec etype-hex" aria-live="off">(not set)</output>
    <button type="button" class="etype-copy-btn" id="etype-copy-flags" title="Copy flag names">Copy</button>
  </div>
</div>
<p class="etype-link-row">
  <button type="button" class="etype-copy-btn" id="etype-copy-link" title="Copy a link that reopens this setting and value">Copy link to this value</button>
</p>
<h2>Quick Presets</h2>
<div id="etype-presets" class="etype-presets"></div>
<h2>Warnings</h2>
<div id="etype-warnings" class="etype-warnings" aria-live="polite" style="display:none"></div>
<p id="etype-no-warnings" class="etype-no-warnings">No warnings for the current configuration.</p>
<p class="etype-link-row">
  <button type="button" class="etype-copy-btn" id="etype-clear-undefined" hidden>Clear undefined bits</button>
</p>
<p id="etype-derived" class="etype-derived" aria-live="polite" hidden></p>
<h2 id="etype-ps-heading">PowerShell Command</h2>
<div class="etype-ps-block">
  <pre id="etype-powershell" class="etype-ps" role="region" tabindex="0" aria-labelledby="etype-ps-heading"></pre>
  <button type="button" class="etype-copy-btn" id="etype-copy-ps" title="Copy PowerShell command">Copy</button>
</div>
</div>
</div>
</div>

---

## How the Three Settings Differ

These three settings use the same bitmask format but serve different purposes and
interpret certain bits differently.

| Setting | Where | Scope | Key Difference |
|---|---|---|---|
| `msDS-SupportedEncryptionTypes` | AD attribute on each account | Per-account | When non-zero it **is** the account's effective etype set; the two fallbacks below are not consulted.  Carries etype bits (0-7) and protocol feature flags (16-19).  AES-SK (bit 5) is honored here.  It does not bypass the KDC filter: if nothing in the set passes the filter, or the account has no key for it, the request fails with `KDC_ERR_ETYPE_NOSUPP`. |
| `DefaultDomainSupportedEncTypes` | `HKLM\SYSTEM\CurrentControlSet\Services\Kdc` on each DC | Per-DC (not replicated) | The effective set for accounts whose `msDS-SupportedEncryptionTypes` is 0 or unset.  When the value is absent the build default applies: `0x27` before the April 2026 cumulative update, `0x18` (AES only) on it or later.  AES-SK (bit 5) is **honored** here.  Bits 16-19 are ignored. |
| `SupportedEncryptionTypes` | `HKLM\...\Policies\System\Kerberos\Parameters` | Per-machine (written by GPO) | On any machine: the etypes its Kerberos client offers.  On a DC it is also the KDC **filter**: it needs a KDC restart, and it is not recorded in events 4768/4769.  On Server 2025 the lab saw only the `Lsa\Kerberos\Parameters` path honored.  The GPO "Future encryption types" checkbox sets bits 5-30 (`0x7FFFFFE0`), not bit 31.  A computer writes only the low five bits to its own AD attribute. |

For the full precedence rules and worked examples, see
[Etype Decision Guide](etype-decision-guide.md).

---

## Bit Flag Reference

--8<-- "includes/etype-bits.md"

The Group Policy "Future encryption types" checkbox is not a bit of its own.  It
writes bits 5-30 as one unit (`0x7FFFFFE0`, decimal 2147483616) to the
`SupportedEncryptionTypes` registry value, which is why the calculator shows it as
a single row and only enables it on the GPO tab.
