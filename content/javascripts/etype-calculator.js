/**
 * Etype bitmask calculator — interactive converter for the three Kerberos
 * encryption type settings: msDS-SupportedEncryptionTypes,
 * DefaultDomainSupportedEncTypes, and SupportedEncryptionTypes (GPO).
 *
 * Pure vanilla JS, no dependencies.  Loaded only on the calculator page.
 */

(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /*  Constants                                                          */
  /* ------------------------------------------------------------------ */

  /** Maximum valid unsigned 32-bit value. */
  var MAX_U32 = 0xFFFFFFFF;

  /**
   * The Windows GPO "Future encryption types" checkbox sets bits 5-30
   * (0x7FFFFFE0), NOT bit 31 as some documentation implies.  Lab-validated
   * April 2026 against Windows Server 2022.  The GPO editor has exactly
   * 6 checkboxes: DES_CBC_CRC(0x1), DES_CBC_MD5(0x2), RC4(0x4),
   * AES128(0x8), AES256(0x10), Future(0x7FFFFFE0).
   */
  var GPO_FUTURE_VALUE = 0x7FFFFFE0;

  /* ------------------------------------------------------------------ */
  /*  Bit definitions — [MS-KILE] §2.2.7                                */
  /* ------------------------------------------------------------------ */

  var BITS = [
    { bit: 0, hex: "0x1", dec: 1, name: "DES-CBC-CRC", etype: 1, status: "removed", note: "Removed in Server 2025" },
    { bit: 1, hex: "0x2", dec: 2, name: "DES-CBC-MD5", etype: 3, status: "removed", note: "Removed in Server 2025" },
    { bit: 2, hex: "0x4", dec: 4, name: "RC4-HMAC", etype: 23, status: "deprecated", note: "Deprecated — July 2026" },
    { bit: 3, hex: "0x8", dec: 8, name: "AES128-CTS-HMAC-SHA1-96", etype: 17, status: "recommended", note: "" },
    { bit: 4, hex: "0x10", dec: 16, name: "AES256-CTS-HMAC-SHA1-96", etype: 18, status: "recommended", note: "" },
    { bit: 5, hex: "0x20", dec: 32, name: "AES256-CTS-HMAC-SHA1-96-SK", etype: null, status: "special", note: "Session key variant (Nov 2022+)" },
    { bit: 16, hex: "0x10000", dec: 65536, name: "FAST-supported", etype: null, status: "feature", note: "Kerberos armoring (Server 2012+)" },
    { bit: 17, hex: "0x20000", dec: 131072, name: "Compound-identity-supported", etype: null, status: "feature", note: "Server 2012+" },
    { bit: 18, hex: "0x40000", dec: 262144, name: "Claims-supported", etype: null, status: "feature", note: "Server 2012+" },
    { bit: 19, hex: "0x80000", dec: 524288, name: "Resource-SID-compression-disabled", etype: null, status: "feature", note: "Server 2012+" },
    { bit: 31, hex: "0x80000000", dec: 2147483648, name: "Future encryption types", etype: null, status: "special", note: "" }
  ];

  /** Index into BITS for the "Future encryption types" entry (bit 31). */
  var FUTURE_BIT_INDEX = BITS.length - 1;

  /* ------------------------------------------------------------------ */
  /*  Setting profiles                                                  */
  /*                                                                    */
  /*  ignoredBits  — bits STRIPPED from values (truly meaningless here)  */
  /*  disabledBits — checkboxes disabled in UI but bits NOT stripped     */
  /*                 (meaningful when set by other means, e.g. "Future") */
  /*  futureValue  — what the "Future encryption types" checkbox         */
  /*                 represents for this setting (0x80000000 or          */
  /*                 0x7FFFFFE0 for GPO)                                */
  /* ------------------------------------------------------------------ */

  var SETTINGS = {
    msds: {
      id: "msds",
      label: "msDS-SupportedEncryptionTypes",
      desc: "AD attribute on each account — controls which etypes the KDC uses for this account's service tickets.  Carries etype bits (0-5) and protocol feature flags (16-19).",
      ignoredBits: [],
      disabledBits: [31],
      futureValue: 0x80000000,
      presets: [
        { label: "AES-only", value: 0x18, rec: true },
        { label: "AES + AES-SK", value: 0x38 },
        { label: "RC4 + AES + AES-SK", value: 0x3C, rec: true },
        { label: "RC4 + AES (legacy)", value: 0x1C },
        { label: "Clear", value: 0 }
      ],
      powershell: function (v) {
        return 'Set-ADUser -Identity <account> -Replace @{\n  \'msDS-SupportedEncryptionTypes\' = ' + v + "\n}";
      }
    },
    default: {
      id: "default",
      label: "DefaultDomainSupportedEncTypes",
      desc: "Registry on each DC — assumed etypes for accounts with no explicit msDS-SupportedEncryptionTypes.  Honors AES-SK (bit 5).",
      ignoredBits: [16, 17, 18, 19, 31],
      disabledBits: [16, 17, 18, 19, 31],
      futureValue: 0x80000000,
      presets: [
        { label: "AES-only", value: 0x18, rec: true },
        { label: "AES + AES-SK", value: 0x38 },
        { label: "Pre-2025 default", value: 0x27 },
        { label: "Server 2025 default", value: 0x24 }
      ],
      powershell: function (v) {
        return 'New-ItemProperty `\n  -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\KDC" `\n  -Name "DefaultDomainSupportedEncTypes" `\n  -Value ' + v + " -PropertyType DWord -Force";
      }
    },
    gpo: {
      id: "gpo",
      label: "SupportedEncryptionTypes (GPO)",
      desc: "Registry written by Group Policy — controls which etypes the machine's Kerberos client requests and, on DCs, which etypes the KDC will issue.  The GPO \"Future encryption types\" checkbox sets bits 5-30 (0x7FFFFFE0).",
      ignoredBits: [],
      disabledBits: [5, 16, 17, 18, 19],
      futureValue: GPO_FUTURE_VALUE,
      presets: [
        { label: "AES-only", value: 0x18, rec: true },
        { label: "AES + AES-SK + Future", value: (0x38 | GPO_FUTURE_VALUE) >>> 0, rec: true },
        { label: "RC4 + AES + AES-SK + Future", value: (0x3C | GPO_FUTURE_VALUE) >>> 0 },
        { label: "RC4 + AES (legacy)", value: 0x1C }
      ],
      powershell: function (v) {
        return "# GPO: Network security: Configure encryption types allowed for Kerberos\n# Path: Computer Configuration > Policies > Windows Settings >\n#        Security Settings > Local Policies > Security Options\n# Set the decimal value to: " + v;
      }
    }
  };

  /* ------------------------------------------------------------------ */
  /*  State                                                             */
  /* ------------------------------------------------------------------ */

  var currentSetting = "msds";
  var currentValue = 0;
  /** Track which preset (by value) is actively selected, or null for custom. */
  var activePresetValue = null;

  /* ------------------------------------------------------------------ */
  /*  DOM references (set in init)                                      */
  /* ------------------------------------------------------------------ */

  var root;

  /** Safe querySelector — returns null instead of crashing on missing markup. */
  function q(sel) { return root ? root.querySelector(sel) : null; }
  function qa(sel) { return root ? root.querySelectorAll(sel) : []; }

  /* ------------------------------------------------------------------ */
  /*  Validation helpers                                                */
  /* ------------------------------------------------------------------ */

  /**
   * Clamp a numeric value to the unsigned 32-bit range [0, 0xFFFFFFFF].
   * Returns NaN if the input is not a finite number.
   */
  function toU32(v) {
    if (!isFinite(v) || isNaN(v)) return NaN;
    if (v < 0 || v > MAX_U32) return NaN;
    return v >>> 0;
  }

  /* ------------------------------------------------------------------ */
  /*  Core logic                                                        */
  /* ------------------------------------------------------------------ */

  /** Read checkboxes and compute the integer value using bitwise OR. */
  function valueFromCheckboxes() {
    var v = 0;
    qa(".etype-cb").forEach(function (cb) {
      if (cb.checked) v = (v | parseInt(cb.value, 10)) >>> 0;
    });
    return v;
  }

  /** Update checkboxes to match an integer value. */
  function setCheckboxes(v) {
    qa(".etype-cb").forEach(function (cb) {
      var bit = parseInt(cb.value, 10);
      /* Use unsigned right-shift to handle bit 31 and multi-bit values correctly */
      cb.checked = ((v & bit) >>> 0) === (bit >>> 0);
    });
  }

  /** Format an unsigned 32-bit int as hex with 0x prefix. */
  function toHex(v) {
    return "0x" + (v >>> 0).toString(16).toUpperCase();
  }

  /**
   * Parse a hex string (with or without 0x prefix).
   * Returns NaN if the string is not valid hex or exceeds 32 bits.
   */
  function parseHex(s) {
    s = s.replace(/^0x/i, "").trim();
    if (!s || !/^[0-9a-fA-F]+$/.test(s)) return NaN;
    /* Reject values that exceed 8 hex digits (> 0xFFFFFFFF) */
    if (s.replace(/^0+/, "").length > 8) return NaN;
    var v = parseInt(s, 16);
    return toU32(v);
  }

  /**
   * Parse a value string as either hex (0x prefix) or decimal.
   * Returns NaN if invalid or out of range.
   */
  function parseValue(s) {
    s = (s || "").trim();
    if (/^0x/i.test(s)) return parseHex(s);
    var v = Number(s);
    if (!Number.isInteger(v)) return NaN;
    return toU32(v);
  }

  /** Build comma-separated flag name list from value. */
  function flagNames(v) {
    if (v === 0) return "(not set)";
    var setting = SETTINGS[currentSetting];
    var names = [];
    BITS.forEach(function (b, idx) {
      /* Use the active futureValue for the "Future" checkbox */
      var checkVal = (idx === FUTURE_BIT_INDEX) ? (setting.futureValue >>> 0) : b.dec;
      if (((v & checkVal) >>> 0) === (checkVal >>> 0)) names.push(b.name);
    });
    return names.join(", ");
  }

  /** Build a bitmask of all ignored bits for the current setting. */
  function ignoredBitMask(settingId) {
    var mask = 0;
    var ignored = SETTINGS[settingId].ignoredBits;
    for (var i = 0; i < ignored.length; i++) {
      mask = (mask | (1 << ignored[i])) >>> 0;
    }
    return mask;
  }

  /** Strip ignored bits from a value so we only store meaningful bits. */
  function normalizeValue(v, settingId) {
    return (v & ~ignoredBitMask(settingId)) >>> 0;
  }

  /** Get the disabled bits for a setting (disabledBits if present, else ignoredBits). */
  function getDisabledBits(settingId) {
    var s = SETTINGS[settingId];
    return s.disabledBits || s.ignoredBits;
  }

  /** Evaluate the security status of the current value + setting. */
  function evaluateStatus(v, settingId) {
    if (v === 0) {
      if (settingId === "msds") return { cls: "etype-status--notset", text: "Not set — falls back to DefaultDomainSupportedEncTypes" };
      return { cls: "etype-status--notset", text: "Not set" };
    }
    var hasDES = (v & 0x3) !== 0;
    var hasRC4 = (v & 0x4) !== 0;
    var hasAES = (v & 0x18) !== 0;

    if (hasDES) return { cls: "etype-status--insecure", text: "Insecure — DES enabled" };
    if (hasRC4 && !hasAES) return { cls: "etype-status--insecure", text: "Insecure — RC4-only, no AES" };
    if (hasRC4 && hasAES) return { cls: "etype-status--transitional", text: "Transitional — RC4 still permitted" };
    if (hasAES && !hasRC4 && !hasDES) return { cls: "etype-status--secure", text: "Secure — AES only" };
    return { cls: "etype-status--notset", text: "Custom" };
  }

  /** Build warning messages for the current value + setting. */
  function getWarnings(v, settingId) {
    var w = [];
    if ((v & 0x3) !== 0) {
      w.push("DES-CBC-CRC and DES-CBC-MD5 were removed in Windows Server 2025. Service tickets encrypted with DES will fail on Server 2025 DCs.");
    }
    if ((v & 0x4) !== 0) {
      w.push("RC4-HMAC is deprecated. The April 2026 update enables enforcement by default; the July 2026 update makes it permanent (CVE-2026-20833).");
    }
    if ((v & 0x20) !== 0 && settingId === "gpo") {
      w.push("In the GPO, the AES-SK bit (0x20) is part of the \"Future encryption types\" checkbox (bits 5-30).  It does not independently control AES session keys.");
    }
    /* Warn about feature flags in non-msds settings */
    if (settingId !== "msds" && settingId !== "gpo" && (v & 0xF0000) !== 0) {
      w.push("Feature flag bits 16-19 are only meaningful on msDS-SupportedEncryptionTypes. They have no effect in " + SETTINGS[settingId].label + ".");
    }
    if (v === 0 && settingId === "msds") {
      w.push("Value 0 means the attribute is not set. The KDC falls back to DefaultDomainSupportedEncTypes, which includes RC4 by default.");
    }
    if (v !== 0 && (v & 0x18) === 0) {
      w.push("No AES bits are set. This account will fail authentication if RC4 is blocked by the KDC or Group Policy.");
    }
    return w;
  }

  /** Generate the PowerShell command for the current setting + value. */
  function getPowershell(v, settingId) {
    return SETTINGS[settingId].powershell(v);
  }

  /* ------------------------------------------------------------------ */
  /*  Preset matching                                                   */
  /* ------------------------------------------------------------------ */

  /** Check if the current value matches any preset for the current setting. */
  function findMatchingPreset() {
    var presets = SETTINGS[currentSetting].presets;
    for (var i = 0; i < presets.length; i++) {
      if ((presets[i].value >>> 0) === currentValue) return presets[i].value;
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /*  UI update                                                         */
  /* ------------------------------------------------------------------ */

  function updateUI() {
    var setting = SETTINGS[currentSetting];
    var disabledBits = getDisabledBits(currentSetting);

    /* Normalize: strip truly ignored bits for the active setting. */
    currentValue = normalizeValue(currentValue, currentSetting);

    /* Update the "Future encryption types" checkbox value to match the
       active setting.  For GPO this is 0x7FFFFFE0 (bits 5-30); for
       msDS-SET and DDSET it is 0x80000000 (bit 31). */
    var futureVal = setting.futureValue >>> 0;
    var futureCbs = qa(".etype-cb");
    futureCbs.forEach(function (cb) {
      var bitEntry = BITS[FUTURE_BIT_INDEX];
      if (parseInt(cb.value, 10) === (bitEntry.dec >>> 0) || cb.dataset.futureCb === "1") {
        cb.value = String(futureVal);
        cb.dataset.futureCb = "1";
        /* Update the hex/dec display in the checkbox row */
        var row = cb.closest(".etype-bit-row");
        if (row) {
          var infoEl = row.querySelector(".etype-bit-info");
          if (infoEl) {
            var code = infoEl.querySelector("code");
            if (code) code.textContent = toHex(futureVal);
            /* Update the decimal display if present (the text after the code) */
            var textAfterCode = infoEl.lastChild;
            if (textAfterCode && textAfterCode.nodeType === 3) {
              textAfterCode.textContent = " (" + futureVal + ")";
            }
          }
        }
      }
    });

    /* Update value displays */
    var decEl = q("#etype-dec");
    var hexEl = q("#etype-hex");
    var flagsEl = q("#etype-flags");
    if (decEl) decEl.value = currentValue;
    if (hexEl) hexEl.value = toHex(currentValue);
    if (flagsEl) flagsEl.value = flagNames(currentValue);

    /* Update checkboxes + disable per-setting bits */
    setCheckboxes(currentValue);
    qa(".etype-cb").forEach(function (cb) {
      var bitVal = parseInt(cb.value, 10);
      /* Find the bit number for this checkbox.  For the "Future" checkbox the
         value changes per-tab, so match on the data attribute instead. */
      var bitNum;
      if (cb.dataset.futureCb === "1") {
        bitNum = 31;
      } else {
        bitNum = BITS.reduce(function (found, b) {
          return b.dec === bitVal ? b.bit : found;
        }, -1);
      }
      var row = cb.closest(".etype-bit-row");
      var isDisabled = bitNum !== -1 && disabledBits.indexOf(bitNum) !== -1;
      if (row) {
        row.classList.toggle("etype-bit--ignored", isDisabled);
        var noteEl = row.querySelector(".etype-bit-ignored-note");
        if (noteEl) {
          if (isDisabled && currentSetting === "gpo" && (bitNum === 5 || (bitNum >= 16 && bitNum <= 19))) {
            noteEl.textContent = "(covered by Future encryption types)";
          } else if (isDisabled) {
            noteEl.textContent = "(not meaningful for this setting)";
          } else {
            noteEl.textContent = "";
          }
        }
      }
      cb.disabled = isDisabled;
      if (isDisabled) cb.checked = false;
    });

    /* Status badge */
    var status = evaluateStatus(currentValue, currentSetting);
    var badge = q("#etype-status");
    if (badge) {
      badge.className = "etype-status " + status.cls;
      badge.textContent = status.text;
    }

    /* Warnings — use safe DOM creation instead of innerHTML */
    var warnings = getWarnings(currentValue, currentSetting);
    var warnEl = q("#etype-warnings");
    var noWarnEl = q("#etype-no-warnings");
    if (warnEl) {
      warnEl.innerHTML = "";
      if (warnings.length === 0) {
        warnEl.style.display = "none";
        if (noWarnEl) noWarnEl.style.display = "";
      } else {
        warnEl.style.display = "block";
        warnings.forEach(function (w) {
          var div = document.createElement("div");
          div.className = "etype-warning-item";
          div.textContent = w;
          warnEl.appendChild(div);
        });
        if (noWarnEl) noWarnEl.style.display = "none";
      }
    }

    /* PowerShell */
    var psEl = q("#etype-powershell");
    if (psEl) psEl.textContent = getPowershell(currentValue, currentSetting);

    /* Setting description */
    var descEl = q("#etype-setting-desc");
    if (descEl) descEl.textContent = setting.desc;

    /* Presets — rebuild with checkmark on active match */
    activePresetValue = findMatchingPreset();
    var presetsEl = q("#etype-presets");
    if (presetsEl) {
      presetsEl.innerHTML = "";
      setting.presets.forEach(function (p) {
        var btn = document.createElement("button");
        btn.type = "button";
        var isActive = activePresetValue !== null && (p.value >>> 0) === (activePresetValue >>> 0);
        btn.className = "etype-preset-btn"
          + (p.rec ? " etype-preset-btn--rec" : "")
          + (isActive ? " etype-preset-btn--active" : "");
        btn.textContent = (isActive ? "\u2713 " : "") + p.label + " (" + toHex(p.value) + ")";
        btn.addEventListener("click", function () {
          var newVal = p.value >>> 0;
          if (currentValue === newVal) {
            /* Clicking the already-active preset deselects it (resets to 0) */
            currentValue = 0;
          } else {
            currentValue = newVal;
          }
          updateUI();
          pushHash();
        });
        presetsEl.appendChild(btn);
      });
    }

    /* Tab active states */
    qa(".etype-tab").forEach(function (tab) {
      tab.classList.toggle("etype-tab--active", tab.dataset.setting === currentSetting);
    });
  }

  /* ------------------------------------------------------------------ */
  /*  URL hash                                                          */
  /* ------------------------------------------------------------------ */

  /** Write the current state to the URL hash in hex format. */
  function pushHash() {
    try {
      var hash = "#" + currentSetting + "=" + toHex(currentValue);
      if (history.replaceState) {
        history.replaceState(null, "", hash);
      }
    } catch (_) {
      /* Swallow SecurityError in sandboxed iframes etc. */
    }
  }

  /** Read state from the URL hash.  Accepts both decimal and hex values. */
  function readHash() {
    try {
      var h = location.hash.replace(/^#/, "");
      if (!h) return;
      var parts = h.split("=");
      if (parts.length === 2 && SETTINGS[parts[0]]) {
        currentSetting = parts[0];
        var v = parseValue(parts[1]);
        if (!isNaN(v)) currentValue = v;
      }
    } catch (_) {
      /* Swallow if location is inaccessible */
    }
  }

  /* ------------------------------------------------------------------ */
  /*  Clipboard                                                         */
  /* ------------------------------------------------------------------ */

  function copyText(text, btn) {
    if (!btn) return;
    /* Try the modern clipboard API first, fall back to execCommand */
    var done = function () {
      var orig = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("etype-copy-btn--copied");
      setTimeout(function () {
        btn.textContent = orig;
        btn.classList.remove("etype-copy-btn--copied");
      }, 1200);
    };
    var fail = function () {
      var orig = btn.textContent;
      btn.textContent = "Failed";
      btn.classList.add("etype-copy-btn--failed");
      setTimeout(function () {
        btn.textContent = orig;
        btn.classList.remove("etype-copy-btn--failed");
      }, 1500);
    };
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(text).then(done).catch(fail);
    } else {
      /* Fallback: temporary textarea + execCommand */
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (ok) { done(); } else { fail(); }
      } catch (_) {
        fail();
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /*  Event handlers                                                    */
  /* ------------------------------------------------------------------ */

  function onCheckboxChange() {
    currentValue = valueFromCheckboxes();
    updateUI();
    pushHash();
  }

  function onDecInput() {
    var el = q("#etype-dec");
    if (!el) return;
    var raw = el.value.trim();
    if (raw === "") return; /* Let the user clear the field without side effects */
    var v = Number(raw);
    if (!Number.isInteger(v) || v < 0 || v > MAX_U32) {
      el.classList.add("etype-input--invalid");
      return;
    }
    el.classList.remove("etype-input--invalid");
    currentValue = v >>> 0;
    updateUI();
    pushHash();
  }

  function onHexInput() {
    var el = q("#etype-hex");
    if (!el) return;
    var raw = el.value.trim();
    /* Allow partial typing states like empty, "0", "0x" without flickering */
    if (raw === "" || raw === "0" || /^0x$/i.test(raw)) return;
    var v = parseHex(raw);
    if (isNaN(v)) {
      el.classList.add("etype-input--invalid");
      return;
    }
    el.classList.remove("etype-input--invalid");
    currentValue = v;
    updateUI();
    pushHash();
  }

  function onTabClick(e) {
    var tab = e.currentTarget;
    if (!tab || !tab.dataset.setting || !SETTINGS[tab.dataset.setting]) return;
    currentSetting = tab.dataset.setting;
    updateUI();
    pushHash();
  }

  /* ------------------------------------------------------------------ */
  /*  Safe event binding helper                                         */
  /* ------------------------------------------------------------------ */

  /** Bind an event listener only if the element exists. */
  function on(sel, event, handler) {
    var el = q(sel);
    if (el) el.addEventListener(event, handler);
  }

  /* ------------------------------------------------------------------ */
  /*  Init                                                              */
  /* ------------------------------------------------------------------ */

  function init() {
    try {
      root = document.getElementById("etype-calculator");
      if (!root) return;

      /* Prevent duplicate listeners on instant nav re-init */
      if (root.dataset.etypeInit) return;
      root.dataset.etypeInit = "1";

      /* Mark body for page-specific CSS (back-to-top hiding) */
      document.body.classList.add("etype-calculator-page");

      /* Reset state for fresh page load */
      currentSetting = "msds";
      currentValue = 0;
      activePresetValue = null;

      /* Tab clicks */
      qa(".etype-tab").forEach(function (tab) {
        tab.addEventListener("click", onTabClick);
      });

      /* Checkbox changes */
      qa(".etype-cb").forEach(function (cb) {
        cb.addEventListener("change", onCheckboxChange);
      });

      /* Decimal input */
      on("#etype-dec", "input", onDecInput);
      on("#etype-dec", "change", onDecInput);

      /* Hex input */
      on("#etype-hex", "input", onHexInput);
      on("#etype-hex", "change", onHexInput);

      /* Copy buttons */
      on("#etype-copy-dec", "click", function () {
        var el = q("#etype-dec");
        if (el) copyText(el.value, this);
      });
      on("#etype-copy-hex", "click", function () {
        var el = q("#etype-hex");
        if (el) copyText(el.value, this);
      });
      on("#etype-copy-flags", "click", function () {
        var el = q("#etype-flags");
        if (el) copyText(el.value, this);
      });
      on("#etype-copy-ps", "click", function () {
        var el = q("#etype-powershell");
        if (el) copyText(el.textContent, this);
      });

      /* Read URL hash */
      readHash();

      /* Initial render */
      updateUI();
    } catch (err) {
      /* Degrade gracefully — log but do not break the page */
      if (typeof console !== "undefined" && console.error) {
        console.error("etype-calculator init failed:", err);
      }
    }
  }

  /* Run after DOM is ready — handles both instant navigation and first load */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* mkdocs-material instant navigation re-triggers on page swap.
     Remove the body class first so it does not persist on non-calculator pages. */
  if (typeof document$ !== "undefined") {
    document$.subscribe(function () {
      document.body.classList.remove("etype-calculator-page");
      init();
    });
  }
})();
