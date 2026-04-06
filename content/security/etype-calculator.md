---
hide:
  - navigation
  - toc
---

# Encryption Type Calculator

Three settings control Kerberos encryption types in Active Directory, and each one
interprets the same bitmask differently.  Use this calculator to convert between
decimal, hex, and individual flags for any of the three settings.

For the full reference on each setting, see
[msDS-SupportedEncryptionTypes](msds-supported.md),
[Registry Settings](registry.md), and
[Group Policy](group-policy.md).

<div id="etype-calculator">
<div class="etype-tabs">
  <button class="etype-tab etype-tab--active" data-setting="msds">msDS-SupportedEncryptionTypes</button>
  <button class="etype-tab" data-setting="default">DefaultDomainSupportedEncTypes</button>
  <button class="etype-tab" data-setting="gpo">SupportedEncryptionTypes (GPO)</button>
</div>
<p id="etype-setting-desc" class="etype-setting-desc"></p>
<div id="etype-status" class="etype-status"></div>
<div class="etype-calc-grid">
<div class="etype-bits">
<h3>Bit Flags</h3>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="1">
    <span class="etype-bit-info"><code>0x1</code> (1)</span>
    <span class="etype-bit-name">DES-CBC-CRC</span>
    <span class="etype-bit-etype">etype 1</span>
    <span class="etype-bit-badge etype-bit-badge--removed">Removed</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="2">
    <span class="etype-bit-info"><code>0x2</code> (2)</span>
    <span class="etype-bit-name">DES-CBC-MD5</span>
    <span class="etype-bit-etype">etype 3</span>
    <span class="etype-bit-badge etype-bit-badge--removed">Removed</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="4">
    <span class="etype-bit-info"><code>0x4</code> (4)</span>
    <span class="etype-bit-name">RC4-HMAC</span>
    <span class="etype-bit-etype">etype 23</span>
    <span class="etype-bit-badge etype-bit-badge--deprecated">Deprecated</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="8">
    <span class="etype-bit-info"><code>0x8</code> (8)</span>
    <span class="etype-bit-name">AES128-CTS-HMAC-SHA1-96</span>
    <span class="etype-bit-etype">etype 17</span>
    <span class="etype-bit-badge etype-bit-badge--recommended">Recommended</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="16">
    <span class="etype-bit-info"><code>0x10</code> (16)</span>
    <span class="etype-bit-name">AES256-CTS-HMAC-SHA1-96</span>
    <span class="etype-bit-etype">etype 18</span>
    <span class="etype-bit-badge etype-bit-badge--recommended">Recommended</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="32">
    <span class="etype-bit-info"><code>0x20</code> (32)</span>
    <span class="etype-bit-name">AES256-CTS-HMAC-SHA1-96-SK</span>
    <span class="etype-bit-etype">session key</span>
    <span class="etype-bit-badge etype-bit-badge--special">AES-SK</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="65536">
    <span class="etype-bit-info"><code>0x10000</code></span>
    <span class="etype-bit-name">FAST-supported</span>
    <span class="etype-bit-etype">bit 16</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="131072">
    <span class="etype-bit-info"><code>0x20000</code></span>
    <span class="etype-bit-name">Compound-identity-supported</span>
    <span class="etype-bit-etype">bit 17</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="262144">
    <span class="etype-bit-info"><code>0x40000</code></span>
    <span class="etype-bit-name">Claims-supported</span>
    <span class="etype-bit-etype">bit 18</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="524288">
    <span class="etype-bit-info"><code>0x80000</code></span>
    <span class="etype-bit-name">Resource-SID-compression-disabled</span>
    <span class="etype-bit-etype">bit 19</span>
    <span class="etype-bit-badge etype-bit-badge--feature">Feature</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
<div class="etype-bit-row">
  <label>
    <input type="checkbox" class="etype-cb" value="2147483648">
    <span class="etype-bit-info"><code>0x80000000</code></span>
    <span class="etype-bit-name">Future encryption types</span>
    <span class="etype-bit-etype">bit 31</span>
    <span class="etype-bit-badge etype-bit-badge--neutral">Future</span>
  </label>
  <span class="etype-bit-ignored-note"></span>
</div>
</div>
<div class="etype-values">
<h3>Values</h3>
<div class="etype-field">
  <label for="etype-dec">Decimal</label>
  <div class="etype-input-row">
    <input type="number" id="etype-dec" min="0" max="4294967295" value="0">
    <button class="etype-copy-btn" id="etype-copy-dec" title="Copy decimal value">Copy</button>
  </div>
</div>
<div class="etype-field">
  <label for="etype-hex">Hexadecimal</label>
  <div class="etype-input-row">
    <input type="text" id="etype-hex" value="0x0">
    <button class="etype-copy-btn" id="etype-copy-hex" title="Copy hex value">Copy</button>
  </div>
</div>
<div class="etype-field">
  <label for="etype-flags">Flag Names</label>
  <div class="etype-input-row">
    <input type="text" id="etype-flags" value="(not set)" readonly>
    <button class="etype-copy-btn" id="etype-copy-flags" title="Copy flag names">Copy</button>
  </div>
</div>
<h3>Quick Presets</h3>
<div id="etype-presets" class="etype-presets"></div>
<h3>Warnings</h3>
<div id="etype-warnings" class="etype-warnings" style="display:none"></div>
<p id="etype-no-warnings" class="etype-no-warnings">No warnings for the current configuration.</p>
<h3>PowerShell Command</h3>
<div class="etype-ps-block">
  <pre><code id="etype-powershell"></code></pre>
  <button class="etype-copy-btn" id="etype-copy-ps" title="Copy PowerShell command">Copy</button>
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
| `msDS-SupportedEncryptionTypes` | AD attribute on each account | Per-account | Carries both etype bits (0-5) and protocol feature flags (16-19).  Always overrides the other two settings. |
| `DefaultDomainSupportedEncTypes` | `HKLM\...\Services\KDC` on each DC | Per-DC (not replicated) | Bit 5 (AES-SK) is **honored** — the only setting where the session key split works.  Bits 16-19 are not meaningful here. |
| `SupportedEncryptionTypes` | `HKLM\...\Policies\System\Kerberos\Parameters` | Per-machine (written by GPO) | Acts as a hard **filter**.  Bits 5 and 16-19 are not meaningful here.  Bit 31 is stripped when auto-written to AD. |

For the full precedence rules and 14 worked examples, see
[Etype Decision Guide](etype-decision-guide.md).

---

## Bit Flag Reference

Source: [MS-KILE] section 2.2.7 — Supported Encryption Types Bit Flags.

### Encryption Type Bits (0-5)

| Bit | Hex | Decimal | Name | Etype # | Status |
|---|---|---|---|---|---|
| 0 | `0x1` | 1 | DES-CBC-CRC | 1 | Removed in Server 2025 |
| 1 | `0x2` | 2 | DES-CBC-MD5 | 3 | Removed in Server 2025 |
| 2 | `0x4` | 4 | RC4-HMAC | 23 | Deprecated (July 2026) |
| 3 | `0x8` | 8 | AES128-CTS-HMAC-SHA1-96 | 17 | **Recommended** |
| 4 | `0x10` | 16 | AES256-CTS-HMAC-SHA1-96 | 18 | **Recommended** |
| 5 | `0x20` | 32 | AES256-CTS-HMAC-SHA1-96-SK | — | Session key variant (Nov 2022+).  Only honored in `DefaultDomainSupportedEncTypes`. |

### Protocol Feature Flags (16-19)

These bits are **not encryption types** — they are protocol feature flags defined in
[MS-KILE] section 2.2.7 and stored in the same `msDS-SupportedEncryptionTypes` bitmask.
They are only meaningful on the AD attribute, not in registry-based settings.

| Bit | Hex | Decimal | Name | Introduced | Description |
|---|---|---|---|---|---|
| 16 | `0x10000` | 65536 | FAST-supported | Server 2012 | Account supports Kerberos armoring ([RFC 6113]) |
| 17 | `0x20000` | 131072 | Compound-identity-supported | Server 2012 | Account supports compound identity for Dynamic Access Control |
| 18 | `0x40000` | 262144 | Claims-supported | Server 2012 | Account supports claims-based authentication |
| 19 | `0x80000` | 524288 | Resource-SID-compression-disabled | Server 2012 | Disables resource SID compression in the PAC |

### Reserved and Future Bits

| Bit | Hex | Decimal | Name | Notes |
|---|---|---|---|---|
| 6-15 | — | — | Reserved | Must be zero |
| 20-30 | — | — | Reserved | Must be zero |
| 31 | `0x80000000` | 2147483648 | Future encryption types | Allows future etypes added by Microsoft |
