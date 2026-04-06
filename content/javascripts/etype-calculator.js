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
    { bit: 31, hex: "0x80000000", dec: 2147483648, name: "Future encryption types", etype: null, status: "neutral", note: "" }
  ];

  /* ------------------------------------------------------------------ */
  /*  Setting profiles                                                  */
  /* ------------------------------------------------------------------ */

  var SETTINGS = {
    msds: {
      id: "msds",
      label: "msDS-SupportedEncryptionTypes",
      desc: "AD attribute on each account — controls which etypes the KDC uses for this account's service tickets.  Also carries protocol feature flags (bits 16-19).",
      ignoredBits: [5],
      presets: [
        { label: "AES-only", value: 0x18, rec: true },
        { label: "RC4 + AES", value: 0x1C },
        { label: "Legacy (DES+RC4+AES)", value: 0x1F },
        { label: "Clear (0)", value: 0 }
      ],
      powershell: function (v) {
        return 'Set-ADUser -Identity <account> -Replace @{\n  \'msDS-SupportedEncryptionTypes\' = ' + v + "\n}";
      }
    },
    default: {
      id: "default",
      label: "DefaultDomainSupportedEncTypes",
      desc: "Registry on each DC — assumed etypes for accounts with no explicit msDS-SupportedEncryptionTypes.",
      ignoredBits: [16, 17, 18, 19],
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
      desc: "Registry written by Group Policy — controls which etypes the machine's Kerberos client requests and, on DCs, which etypes the KDC will issue.",
      ignoredBits: [5, 16, 17, 18, 19],
      presets: [
        { label: "AES-only", value: 0x18, rec: true },
        { label: "AES + Future", value: 0x80000018 },
        { label: "RC4 + AES", value: 0x1C },
        { label: "RC4 + AES + Future", value: 0x8000001C }
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

  /* ------------------------------------------------------------------ */
  /*  DOM references (set in init)                                      */
  /* ------------------------------------------------------------------ */

  var root;

  function q(sel) { return root.querySelector(sel); }
  function qa(sel) { return root.querySelectorAll(sel); }

  /* ------------------------------------------------------------------ */
  /*  Core logic                                                        */
  /* ------------------------------------------------------------------ */

  /** Read checkboxes and compute the integer value. */
  function valueFromCheckboxes() {
    var v = 0;
    qa(".etype-cb").forEach(function (cb) {
      if (cb.checked) v = (v + parseInt(cb.value, 10)) >>> 0;
    });
    return v;
  }

  /** Update checkboxes to match an integer value. */
  function setCheckboxes(v) {
    qa(".etype-cb").forEach(function (cb) {
      var bit = parseInt(cb.value, 10);
      /* Use unsigned right-shift to handle bit 31 (0x80000000) correctly */
      cb.checked = ((v & bit) >>> 0) === (bit >>> 0);
    });
  }

  /** Format an unsigned 32-bit int as hex with 0x prefix. */
  function toHex(v) {
    return "0x" + (v >>> 0).toString(16).toUpperCase();
  }

  /** Parse a hex string (with or without 0x prefix). */
  function parseHex(s) {
    s = s.replace(/^0x/i, "").trim();
    if (!/^[0-9a-fA-F]+$/.test(s)) return NaN;
    return parseInt(s, 16) >>> 0;
  }

  /** Build comma-separated flag name list from value. */
  function flagNames(v) {
    if (v === 0) return "(not set)";
    var names = [];
    BITS.forEach(function (b) {
      if (((v & b.dec) >>> 0) === (b.dec >>> 0)) names.push(b.name);
    });
    return names.join(", ");
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
    if ((v & 0x20) !== 0 && settingId !== "default") {
      w.push("The AES-SK bit (0x20) is only honored in DefaultDomainSupportedEncTypes. It has no effect in " + SETTINGS[settingId].label + ".");
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
  /*  UI update                                                         */
  /* ------------------------------------------------------------------ */

  function updateUI() {
    var setting = SETTINGS[currentSetting];

    /* Update value displays */
    q("#etype-dec").value = currentValue;
    q("#etype-hex").value = toHex(currentValue);
    q("#etype-flags").value = flagNames(currentValue);

    /* Update checkboxes */
    setCheckboxes(currentValue);

    /* Disable/annotate ignored bits */
    qa(".etype-cb").forEach(function (cb) {
      var bitVal = parseInt(cb.value, 10);
      var bitNum = Math.log2(bitVal);
      var row = cb.closest(".etype-bit-row");
      if (setting.ignoredBits.indexOf(bitNum) !== -1) {
        row.classList.add("etype-bit--ignored");
        row.querySelector(".etype-bit-ignored-note").textContent = "(ignored for this setting)";
      } else {
        row.classList.remove("etype-bit--ignored");
        row.querySelector(".etype-bit-ignored-note").textContent = "";
      }
    });

    /* Status badge */
    var status = evaluateStatus(currentValue, currentSetting);
    var badge = q("#etype-status");
    badge.className = "etype-status " + status.cls;
    badge.textContent = status.text;

    /* Warnings */
    var warnings = getWarnings(currentValue, currentSetting);
    var warnEl = q("#etype-warnings");
    var noWarnEl = q("#etype-no-warnings");
    if (warnings.length === 0) {
      warnEl.style.display = "none";
      warnEl.innerHTML = "";
      if (noWarnEl) noWarnEl.style.display = "";
    } else {
      warnEl.style.display = "block";
      warnEl.innerHTML = warnings.map(function (w) {
        return '<div class="etype-warning-item">' + w + "</div>";
      }).join("");
      if (noWarnEl) noWarnEl.style.display = "none";
    }

    /* PowerShell */
    q("#etype-powershell").textContent = getPowershell(currentValue, currentSetting);

    /* Setting description */
    q("#etype-setting-desc").textContent = setting.desc;

    /* Presets */
    var presetsEl = q("#etype-presets");
    presetsEl.innerHTML = "";
    setting.presets.forEach(function (p) {
      var btn = document.createElement("button");
      btn.className = "etype-preset-btn" + (p.rec ? " etype-preset-btn--rec" : "");
      btn.textContent = p.label + " (" + toHex(p.value) + ")";
      btn.addEventListener("click", function () {
        currentValue = p.value >>> 0;
        updateUI();
        pushHash();
      });
      presetsEl.appendChild(btn);
    });

    /* Tab active states */
    qa(".etype-tab").forEach(function (tab) {
      tab.classList.toggle("etype-tab--active", tab.dataset.setting === currentSetting);
    });
  }

  /* ------------------------------------------------------------------ */
  /*  URL hash                                                          */
  /* ------------------------------------------------------------------ */

  function pushHash() {
    var hash = "#" + currentSetting + "=" + currentValue;
    if (history.replaceState) {
      history.replaceState(null, "", hash);
    }
  }

  function readHash() {
    var h = location.hash.replace(/^#/, "");
    if (!h) return;
    var parts = h.split("=");
    if (parts.length === 2 && SETTINGS[parts[0]]) {
      currentSetting = parts[0];
      var v = parseInt(parts[1], 10);
      if (!isNaN(v)) currentValue = v >>> 0;
    }
  }

  /* ------------------------------------------------------------------ */
  /*  Clipboard                                                         */
  /* ------------------------------------------------------------------ */

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
      var orig = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("etype-copy-btn--copied");
      setTimeout(function () {
        btn.textContent = orig;
        btn.classList.remove("etype-copy-btn--copied");
      }, 1200);
    });
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
    var v = parseInt(q("#etype-dec").value, 10);
    if (isNaN(v) || v < 0) v = 0;
    currentValue = v >>> 0;
    updateUI();
    pushHash();
  }

  function onHexInput() {
    var v = parseHex(q("#etype-hex").value);
    if (isNaN(v)) return;
    currentValue = v;
    updateUI();
    pushHash();
  }

  function onTabClick(e) {
    var tab = e.currentTarget;
    currentSetting = tab.dataset.setting;
    updateUI();
    pushHash();
  }

  /* ------------------------------------------------------------------ */
  /*  Init                                                              */
  /* ------------------------------------------------------------------ */

  function init() {
    root = document.getElementById("etype-calculator");
    if (!root) return;

    /* Prevent duplicate listeners on instant nav re-init */
    if (root.dataset.etypeInit) return;
    root.dataset.etypeInit = "1";

    /* Reset state for fresh page load */
    currentSetting = "msds";
    currentValue = 0;

    /* Tab clicks */
    qa(".etype-tab").forEach(function (tab) {
      tab.addEventListener("click", onTabClick);
    });

    /* Checkbox changes */
    qa(".etype-cb").forEach(function (cb) {
      cb.addEventListener("change", onCheckboxChange);
    });

    /* Decimal input */
    q("#etype-dec").addEventListener("input", onDecInput);
    q("#etype-dec").addEventListener("change", onDecInput);

    /* Hex input */
    q("#etype-hex").addEventListener("input", onHexInput);
    q("#etype-hex").addEventListener("change", onHexInput);

    /* Copy buttons */
    q("#etype-copy-dec").addEventListener("click", function () {
      copyText(q("#etype-dec").value, this);
    });
    q("#etype-copy-hex").addEventListener("click", function () {
      copyText(q("#etype-hex").value, this);
    });
    q("#etype-copy-flags").addEventListener("click", function () {
      copyText(q("#etype-flags").value, this);
    });
    q("#etype-copy-ps").addEventListener("click", function () {
      copyText(q("#etype-powershell").textContent, this);
    });

    /* Read URL hash */
    readHash();

    /* Initial render */
    updateUI();
  }

  /* Run after DOM is ready — handles both instant navigation and first load */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* mkdocs-material instant navigation re-triggers on page swap */
  if (typeof document$ !== "undefined") {
    document$.subscribe(function () { init(); });
  }
})();
