/**
 * Etype bitmask calculator - interactive converter for the three Kerberos
 * encryption type settings: msDS-SupportedEncryptionTypes,
 * DefaultDomainSupportedEncTypes, and SupportedEncryptionTypes (GPO).
 *
 * It converts between checkboxes, decimal, hex and flag names and explains
 * how each setting reads the value.  It does not simulate KDC etype selection.
 *
 * Plain browser script, no dependencies.  mkdocs.yml lists it under
 * extra_javascript, so it is loaded on every page; init() returns at once
 * when #etype-calculator is not on the page.  Under Node (tests/js) the pure
 * functions are exported and no DOM is touched.
 */

(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /*  Constants                                                          */
  /* ------------------------------------------------------------------ */

  /** Maximum valid unsigned 32-bit value. */
  var MAX_U32 = 0xFFFFFFFF;

  /**
   * The Group Policy "Future encryption types" checkbox sets bits 5-30 as one
   * unit (0x7FFFFFE0).  Bit 31 is not part of it and is not honored.  The
   * policy editor has exactly six checkboxes: DES_CBC_CRC (0x1), DES_CBC_MD5
   * (0x2), RC4_HMAC_MD5 (0x4), AES128_HMAC_SHA1 (0x8), AES256_HMAC_SHA1 (0x10)
   * and Future encryption types (0x7FFFFFE0).
   */
  var GPO_FUTURE_VALUE = 0x7FFFFFE0;

  /** DES, RC4, AES128-SHA1, AES256-SHA1: the bits a computer copies to its own account. */
  var LOW_ETYPE_MASK = 0x1F;

  /* ------------------------------------------------------------------ */
  /*  Bit definitions - [MS-KILE] §2.2.7                                */
  /*                                                                    */
  /*  The same table (bit + name) exists in event-decoder.js as         */
  /*  SET_BITS, and as checkbox rows in security/etype-calculator.md.   */
  /*  tests/js asserts that all three stay identical.                   */
  /* ------------------------------------------------------------------ */

  var BITS = [
    { bit: 0, name: "DES-CBC-CRC" },
    { bit: 1, name: "DES-CBC-MD5" },
    { bit: 2, name: "RC4-HMAC" },
    { bit: 3, name: "AES128-CTS-HMAC-SHA1-96" },
    { bit: 4, name: "AES256-CTS-HMAC-SHA1-96" },
    { bit: 5, name: "AES256-CTS-HMAC-SHA1-96-SK" },
    { bit: 6, name: "AES128-CTS-HMAC-SHA256-128" },
    { bit: 7, name: "AES256-CTS-HMAC-SHA384-192" },
    { bit: 16, name: "FAST-supported" },
    { bit: 17, name: "Compound-identity-supported" },
    { bit: 18, name: "Claims-supported" },
    { bit: 19, name: "Resource-SID-compression-disabled" }
  ];

  /** Name of the Group Policy checkbox that covers bits 5-30. */
  var FUTURE_NAME = "Future encryption types";

  /** Bitmask of a single bit number, unsigned. */
  function maskOf(bit) {
    return (1 << bit) >>> 0;
  }

  /** Every bit that has a definition in BITS. */
  var DEFINED_MASK = BITS.reduce(function (m, b) { return (m | maskOf(b.bit)) >>> 0; }, 0);

  /** Policy checkbox names, in the order the editor shows them. */
  var GPO_CHECKBOXES = [
    { mask: 0x1, name: "DES_CBC_CRC" },
    { mask: 0x2, name: "DES_CBC_MD5" },
    { mask: 0x4, name: "RC4_HMAC_MD5" },
    { mask: 0x8, name: "AES128_HMAC_SHA1" },
    { mask: 0x10, name: "AES256_HMAC_SHA1" },
    { mask: GPO_FUTURE_VALUE, name: FUTURE_NAME }
  ];

  /* ------------------------------------------------------------------ */
  /*  Setting profiles                                                  */
  /*                                                                    */
  /*  ignoredMask   - bits that have no meaning for this setting.  They */
  /*                  stay in the stored value and are shown as ignored. */
  /*  inactiveBits  - rows the user cannot tick for this setting.        */
  /*  futureActive  - whether the "Future encryption types" row is a     */
  /*                  real control (only the Group Policy has it).       */
  /* ------------------------------------------------------------------ */

  var SETTINGS = {
    msds: {
      id: "msds",
      label: "msDS-SupportedEncryptionTypes",
      desc: "AD attribute on each account. When non-zero it is the account's effective etype set: the KDC issues the strongest etype in it for which the account has keys, subject to the KDC filter. Also carries the AES-SK bit (5) and the protocol feature flags (16-19).",
      ignoredMask: 0,
      inactiveBits: [],
      inactiveNote: "",
      futureActive: false,
      /* 0x3C is kept so the value can be loaded and read, but it is listed
         after 0x1C and labelled as security/msds-supported.md describes it:
         Microsoft suggests it for the DC-wide default, and its effect on an
         account for clients that offer only RC4 is unverified. */
      presets: [
        { label: "AES-only", value: 0x18, rec: true },
        { label: "AES + AES-SK", value: 0x38 },
        { label: "RC4 + AES", value: 0x1C },
        { label: "RC4 + AES + AES-SK, unverified for RC4-only clients", value: 0x3C },
        { label: "Clear", value: 0 }
      ]
    },
    default: {
      id: "default",
      label: "DefaultDomainSupportedEncTypes",
      desc: "Registry value on each DC (HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc), not replicated. The effective etype set for accounts whose msDS-SupportedEncryptionTypes is 0 or unset. When this value is absent the build default applies: 0x27 before the April 2026 cumulative update, 0x18 (AES only) on it or later. Honors AES-SK (bit 5).",
      ignoredMask: 0x000F0000,
      inactiveBits: [16, 17, 18, 19],
      inactiveNote: "ignored by this setting",
      futureActive: false,
      presets: [
        { label: "AES-only", value: 0x18, rec: true },
        { label: "AES + AES-SK", value: 0x38 },
        { label: "RC4 + AES + AES-SK", value: 0x3C },
        { label: "Legacy build default (pre-April 2026 CU)", value: 0x27 }
      ]
    },
    gpo: {
      id: "gpo",
      label: "SupportedEncryptionTypes (GPO)",
      desc: "Registry value written by the policy \"Network security: Configure encryption types allowed for Kerberos\". On any machine it sets which etypes the Kerberos client offers. On a DC it is also the KDC filter: it takes effect after a KDC restart and is not recorded in events 4768/4769. On Server 2025 the lab saw only the Lsa\\Kerberos\\Parameters path honored. The \"Future encryption types\" checkbox is bits 5-30 (0x7FFFFFE0).",
      ignoredMask: 0,
      inactiveBits: [5, 6, 7, 16, 17, 18, 19],
      inactiveNote: "covered by Future encryption types",
      futureActive: true,
      presets: [
        { label: "AES128 + AES256", value: 0x18, rec: true },
        { label: "AES128 + AES256 + Future", value: (0x18 | GPO_FUTURE_VALUE) >>> 0, rec: true },
        { label: "RC4 + AES + Future", value: (0x1C | GPO_FUTURE_VALUE) >>> 0 },
        { label: "RC4 + AES", value: 0x1C }
      ]
    }
  };

  var DEFAULT_SETTING = "msds";

  /** Own-property test that is safe for keys such as "constructor" and "__proto__". */
  function hasOwn(obj, key) {
    return Object.prototype.hasOwnProperty.call(obj, key);
  }

  function isSetting(id) {
    return typeof id === "string" && hasOwn(SETTINGS, id);
  }

  /* ------------------------------------------------------------------ */
  /*  Parsing and formatting                                            */
  /* ------------------------------------------------------------------ */

  /**
   * Clamp a numeric value to the unsigned 32-bit range [0, 0xFFFFFFFF].
   * Returns NaN if the input is not a finite number in range.
   */
  function toU32(v) {
    if (typeof v !== "number" || !isFinite(v)) return NaN;
    if (v < 0 || v > MAX_U32) return NaN;
    return v >>> 0;
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
    s = String(s === null || s === undefined ? "" : s).trim().replace(/^0x/i, "");
    if (!s || !/^[0-9a-fA-F]+$/.test(s)) return NaN;
    /* Reject values that exceed 8 significant hex digits (> 0xFFFFFFFF). */
    if (s.replace(/^0+/, "").length > 8) return NaN;
    return toU32(parseInt(s, 16));
  }

  /** Parse an unsigned decimal string.  Returns NaN if invalid or out of range. */
  function parseDec(s) {
    s = String(s === null || s === undefined ? "" : s).trim();
    if (!/^[0-9]+$/.test(s)) return NaN;
    if (s.replace(/^0+/, "").length > 10) return NaN;
    return toU32(Number(s));
  }

  /** Parse a value string as hex (0x prefix) or decimal.  NaN if invalid. */
  function parseValue(s) {
    s = String(s === null || s === undefined ? "" : s).trim();
    if (/^0x/i.test(s)) return parseHex(s);
    return parseDec(s);
  }

  /**
   * Read what was typed or pasted into the Decimal ("dec") or Hexadecimal
   * ("hex") field.  Returns { value } for a complete value, { partial: true }
   * for text that is the beginning of one (nothing to report yet), and
   * { value: NaN } for anything else.
   *
   * Besides the plain forms the fields accept what admins copy from other
   * places: the event annotation "0x27 (DES, RC4, AES-Sk)", a 0x value in
   * the Decimal field, digit grouping ("2,147,483,640"), and the signed form
   * this tool prints for the msDS attribute (-2147483624).  A number is never
   * read from a prefix of the text: "1e3" and "24.0" are invalid, not 1 and 24.
   */
  function parseTyped(which, raw) {
    var s = String(raw === null || raw === undefined ? "" : raw).trim();
    if (s === "" || /^0x$/i.test(s) || (which === "dec" && s === "-")) return { partial: true };
    /* Annotation copied with the value from an event or a table. */
    s = s.replace(/\s*\([^()]*\)$/, "");

    if (which === "hex" || /^0x/i.test(s)) return { value: parseHex(s) };

    if (/^-[0-9]+$/.test(s)) {
      var n = Number(s);
      return { value: n >= -0x80000000 ? toU32(n >>> 0) : NaN };
    }
    /* Groups of three digits separated by commas or spaces. */
    if (/^[0-9]{1,3}(?:[, \u00a0][0-9]{3})+$/.test(s)) return { value: parseDec(s.replace(/[, \u00a0]/g, "")) };
    if (/^[0-9]{1,3}(?:[, \u00a0][0-9]{3})*[, \u00a0][0-9]{0,2}$/.test(s)) return { partial: true };
    return { value: parseDec(s) };
  }

  /* ------------------------------------------------------------------ */
  /*  Core logic (pure)                                                 */
  /* ------------------------------------------------------------------ */

  /** Set or clear the bits of mask in v without touching any other bit. */
  function toggleMask(v, mask, enable) {
    v = v >>> 0;
    mask = mask >>> 0;
    return enable ? (v | mask) >>> 0 : (v & ~mask) >>> 0;
  }

  /** True when the whole Group Policy "Future" range (bits 5-30) is set. */
  function futureWhole(v) {
    return ((v & GPO_FUTURE_VALUE) >>> 0) === GPO_FUTURE_VALUE;
  }

  /**
   * Bits in v that no label explains for this setting.
   * For the Group Policy value a complete bits-5-30 range is the "Future"
   * checkbox, so only bit 31 is left over; a partial range is not something
   * the policy editor can write, so its reserved bits are reported.
   */
  function undefinedMask(v, settingId) {
    v = v >>> 0;
    if (settingId === "gpo" && futureWhole(v)) {
      return (v & ~GPO_FUTURE_VALUE & ~DEFINED_MASK) >>> 0;
    }
    return (v & ~DEFINED_MASK) >>> 0;
  }

  /** The value as this setting reads it: ignored and undefined bits removed. */
  function effectiveValue(v, settingId) {
    v = v >>> 0;
    return (v & ~SETTINGS[settingId].ignoredMask & ~undefinedMask(v, settingId)) >>> 0;
  }

  /**
   * Comma-separated flag names for a value, low bit first.
   *
   * On the Group Policy setting a complete bits-5-30 range is named once as
   * "Future encryption types" and the bits it covers are not listed again.
   * Bits a setting ignores are marked "(ignored)".  Bits no label covers are
   * shown as raw hex so that a non-zero value never renders as an empty list.
   */
  function flagNames(v, settingId) {
    v = v >>> 0;
    if (v === 0) return "(not set)";
    var setting = SETTINGS[settingId];
    var whole = settingId === "gpo" && futureWhole(v);
    var names = [];
    var futureDone = false;

    BITS.forEach(function (b) {
      var mask = maskOf(b.bit);
      if (whole && b.bit >= 5) {
        if (!futureDone) { names.push(FUTURE_NAME); futureDone = true; }
        return;
      }
      if (((v & mask) >>> 0) !== mask) return;
      names.push(b.name + (((setting.ignoredMask & mask) >>> 0) !== 0 ? " (ignored)" : ""));
    });

    var leftover = undefinedMask(v, settingId);
    if (leftover !== 0) names.push(toHex(leftover) + " (undefined bits)");
    return names.join(", ");
  }

  /** Evaluate the security status of a value for a setting. */
  function evaluateStatus(v, settingId) {
    v = v >>> 0;
    if (v === 0) {
      if (settingId === "msds") {
        return { cls: "etype-status--notset", text: "Not set - the KDC uses DefaultDomainSupportedEncTypes, or the build default" };
      }
      if (settingId === "default") {
        return { cls: "etype-status--notset", text: "Not set - the build default applies" };
      }
      return { cls: "etype-status--notset", text: "Not set - no etype filter configured" };
    }
    var e = effectiveValue(v, settingId);
    var hasDES = (e & 0x3) !== 0;
    var hasRC4 = (e & 0x4) !== 0;
    var hasAES = (e & 0x18) !== 0;

    if (hasDES) return { cls: "etype-status--insecure", text: "Insecure - DES enabled" };
    if (hasRC4 && !hasAES) return { cls: "etype-status--insecure", text: "Insecure - RC4 without AES" };
    if (hasRC4) return { cls: "etype-status--transitional", text: "Transitional - RC4 still permitted" };
    if (hasAES) return { cls: "etype-status--secure", text: "Secure - AES only" };
    return { cls: "etype-status--notset", text: "No DES, RC4 or AES-SHA1 etype bit set" };
  }

  /** Warning messages for a value, worded for the setting it is used in. */
  function getWarnings(v, settingId) {
    v = v >>> 0;
    var w = [];
    var setting = SETTINGS[settingId];
    var e = effectiveValue(v, settingId);
    var hasLegacy = (e & 0x7) !== 0;
    var hasAES = (e & 0x18) !== 0;

    if (v === 0) {
      if (settingId === "msds") {
        w.push("Value 0 means the attribute is not set. The KDC uses DefaultDomainSupportedEncTypes if it is set on the DC; otherwise the build default: 0x27 (includes RC4) before the April 2026 cumulative update, 0x18 (AES only) on the April 2026 CU or later.");
      } else if (settingId === "default") {
        w.push("When this registry value is absent the KDC uses the build default for accounts with no msDS-SupportedEncryptionTypes: 0x27 (includes RC4) before the April 2026 cumulative update, 0x18 (AES only) on the April 2026 CU or later. Enforcement depends on the installed CU, not the calendar.");
      }
      return w;
    }

    if ((e & 0x3) !== 0) {
      w.push("DES-CBC-CRC and DES-CBC-MD5 are removed in Windows Server 2025. Do not rely on DES for anything a Server 2025 DC must issue or accept.");
    }

    if ((e & 0x4) !== 0) {
      if (settingId === "msds") {
        /* What an RC4-only client gets is lab-backed for RC4 + AES without
           the AES-SK bit (0x1C) only.  With the bit set (0x3C) [MS-KILE]
           says RC4 session keys are superseded, and the lab did not test it. */
        var rc4Session = "";
        if (hasAES && (e & 0x20) === 0) {
          rc4Session = " With AES keys present the ticket is still AES256; RC4 remains possible as a session key for clients that offer only RC4.";
        } else if (hasAES) {
          rc4Session = " With AES keys present the ticket is still AES256. The AES-SK bit (0x20) is also set, and [MS-KILE] \u00a72.2.7 defines it as superseding RC4 session keys with AES keys in all cases where an RC4 session key can be used. Do not count on an RC4 session key for clients that offer only RC4: this site's lab has not tested that combination.";
        }
        w.push("RC4 is listed explicitly, so the KDC can still use it for this account. Patched DCs (April 2026 cumulative update or later) no longer issue RC4 by default; it remains only where an account's msDS-SupportedEncryptionTypes or an explicit DefaultDomainSupportedEncTypes lists it." + rc4Session);
      } else if (settingId === "default") {
        w.push("An explicit DefaultDomainSupportedEncTypes that lists RC4 keeps RC4 available on this DC for every account with no msDS-SupportedEncryptionTypes. Patched DCs (April 2026 cumulative update or later) no longer issue RC4 by default; this value opts back in.");
      } else {
        w.push("RC4 is allowed by this value. On a client it means RC4 is offered in requests. On a DC it means the KDC filter lets RC4 through for accounts whose effective set lists it.");
      }
    }

    if (hasLegacy && !hasAES) {
      if (settingId === "msds") {
        w.push("No AES bit is set. Tickets for this account can only use RC4 or DES, and requests fail with KDC_ERR_ETYPE_NOSUPP when the KDC filter or the client does not allow them.");
      } else if (settingId === "default") {
        /* The filter does not simply block a fallback without AES: see
           includes/kdc-filter-matrix.md (measured on one build only). */
        w.push("No AES bit is set. Accounts with no msDS-SupportedEncryptionTypes get RC4 or DES tickets from this DC, and requests fail with KDC_ERR_ETYPE_NOSUPP when the client does not allow them. An AES-only KDC filter did not make such requests fail in this site's lab: on Server 2022 build 20348.5020, with this value set to RC4 (0x4), the filter upgraded the ticket to AES256.");
      } else {
        w.push("No AES bit is set. A client with this value offers only RC4 or DES. A DC with this filter fails requests for accounts whose effective set is AES-only with KDC_ERR_ETYPE_NOSUPP.");
      }
    } else if ((e & LOW_ETYPE_MASK) === 0 && settingId === "default") {
      w.push("No encryption-type bit (0x1-0x10) is set. In this site's lab a DefaultDomainSupportedEncTypes with no usable etype bit (0x100) made requests for accounts without msDS-SupportedEncryptionTypes fail with KDC_ERR_ETYPE_NOSUPP.");
    } else if ((e & LOW_ETYPE_MASK) === 0 && settingId === "msds") {
      /* 0x40 and 0x80 are etypes too (the AES-SHA2 pair), so "only flag
         bits" is said only when neither is set. */
      w.push(((e & 0xC0) !== 0
        ? "None of the DES, RC4 or AES-SHA1 etype bits (0x1-0x10) is set."
        : "No encryption-type bit (0x1-0x10) is set, only flag bits.")
        + " This site's lab has not tested how the KDC treats such a value; set the etype bits explicitly.");
    } else if ((e & LOW_ETYPE_MASK) === 0) {
      w.push("None of the five etype checkboxes (DES, RC4, AES128, AES256) is set, so this value allows no etype that Windows issues by default.");
    }

    if ((e & 0xC0) !== 0 && !(settingId === "gpo" && futureWhole(v))) {
      w.push("Bits 6-7 (0x40, 0x80) are the RFC 8009 AES-SHA2 etypes: supported on Windows 11 24H2 / Server 2025, disabled by default (MS-KILE \u00a72.2.7); not lab-tested on this site.");
    }

    if (((v & setting.ignoredMask) >>> 0) !== 0) {
      w.push("Bits 16-19 are protocol feature flags that only mean something on msDS-SupportedEncryptionTypes. " + setting.label + " ignores them. Effective value: " + toHex(e) + ".");
    }

    if (settingId === "gpo") {
      var range = (v & GPO_FUTURE_VALUE) >>> 0;
      if (range !== 0 && range !== GPO_FUTURE_VALUE) {
        w.push("Bits 5-30 are only partly set (" + toHex(range) + "). The policy editor's \"Future encryption types\" checkbox writes all of them (0x7FFFFFE0) or none, so this value was written by hand. Bit 0x20 is not a separate AES session key control here.");
      }
    }

    var undef = undefinedMask(v, settingId);
    if (((undef & 0x80000000) >>> 0) !== 0) {
      w.push("Bit 31 (0x80000000) is set. It is not defined in [MS-KILE] \u00a72.2.7 and is not honored; the Group Policy \"Future encryption types\" checkbox is bits 5-30 (0x7FFFFFE0), not bit 31.");
    }
    if (((undef & 0x7FFFFFFF) >>> 0) !== 0) {
      w.push("Reserved bits are set (" + toHex((undef & 0x7FFFFFFF) >>> 0) + "). [MS-KILE] \u00a72.2.7 says they must be zero when sent and are ignored when received.");
    }

    return w;
  }

  /**
   * Extra line for the Group Policy setting: what a computer that applies the
   * value writes to its own account.  Empty for the other settings.
   */
  function derivedNote(v, settingId) {
    v = v >>> 0;
    if (settingId !== "gpo" || v === 0) return "";
    var low = (v & LOW_ETYPE_MASK) >>> 0;
    return "A computer that applies this value writes its low five bits to its own account: msDS-SupportedEncryptionTypes = " + low + " (" + toHex(low) + ").";
  }

  /** Signed 32-bit form of a value, as the AD integer attribute stores it. */
  function toSigned(v) {
    return (v >>> 0) | 0;
  }

  /** Generate the PowerShell command (or policy instructions) for a setting + value. */
  function getPowershell(v, settingId) {
    v = v >>> 0;
    if (settingId === "msds") {
      /* A Windows computer writes this attribute on its own account from its
         Kerberos etype policy (KB5021131), so the command is not offered for
         computer accounts; that value is set on the GPO tab. */
      var note = "# For a user or service account.\n"
        + "# Set-ADServiceAccount takes the same\n"
        + "# arguments for a managed service account.\n"
        + "# Windows computer accounts: do not set the\n"
        + "# attribute by hand.  The computer writes it\n"
        + "# from its own Kerberos etype policy; use\n"
        + "# the SupportedEncryptionTypes (GPO) tab.\n";
      if (v === 0) {
        return note + "Set-ADUser -Identity <account> -Clear 'msDS-SupportedEncryptionTypes'";
      }
      var stored = toSigned(v);
      return note
        + (stored !== v ? "# The attribute is a signed 32-bit integer: " + toHex(v) + " is stored as " + stored + ".\n" : "")
        + "Set-ADUser -Identity <account> -Replace @{\n  'msDS-SupportedEncryptionTypes' = " + stored + "\n}";
    }

    if (settingId === "default") {
      var path = '"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc"';
      if (v === 0) {
        return "# Remove the value so the build default applies again.\nRemove-ItemProperty `\n  -Path " + path + " `\n  -Name \"DefaultDomainSupportedEncTypes\"";
      }
      var eff = effectiveValue(v, settingId);
      if (eff === 0) {
        /* Every bit of the value is one this setting ignores.  Writing the
           remainder would store 0, which is not the same as removing the
           value, so no command is produced. */
        return "# No command: " + toHex(v) + " has no bit that\n"
          + "# DefaultDomainSupportedEncTypes reads\n"
          + "# (ignored and undefined bits removed:\n"
          + "# " + toHex(v) + " -> 0x0).\n"
          + "# This tool does not generate a command\n"
          + "# that writes 0.\n"
          + "# Tick at least one encryption type.  To go\n"
          + "# back to the build default, enter 0: that\n"
          + "# gives the command that removes the value.";
      }
      return (eff !== v ? "# Ignored and undefined bits removed: " + toHex(v) + " -> " + toHex(eff) + ".\n" : "")
        + ((eff & LOW_ETYPE_MASK) === 0 ? "# No DES, RC4 or AES-SHA1 etype bit is set:\n# read the warning for this value before\n# running the command.\n" : "")
        + "# Per-DC value, not replicated: run on every domain controller.\n"
        + "New-ItemProperty `\n  -Path " + path + " `\n  -Name \"DefaultDomainSupportedEncTypes\" `\n  -Value " + eff + " -PropertyType DWord -Force";
    }

    var lines = [
      "# GPO: Network security: Configure encryption types allowed for Kerberos",
      "# Path: Computer Configuration > Policies > Windows Settings >",
      "#        Security Settings > Local Policies > Security Options"
    ];
    if (v === 0) {
      lines.push("# Leave the policy \"Not Defined\" (no SupportedEncryptionTypes value).");
      return lines.join("\n");
    }
    var boxes = [];
    var covered = 0;
    GPO_CHECKBOXES.forEach(function (c) {
      if (((v & c.mask) >>> 0) === c.mask) {
        boxes.push(c.name);
        covered = (covered | c.mask) >>> 0;
      }
    });
    var rest = (v & ~covered) >>> 0;
    if (rest !== 0) {
      lines.push("# The policy checkboxes cannot produce this value: bits " + toHex(rest) + " have no checkbox.");
      if (boxes.length) lines.push("# Closest checkbox selection: " + boxes.join(", "));
    } else {
      lines.push("# Tick: " + boxes.join(", "));
    }
    lines.push("# Registry result (SupportedEncryptionTypes, REG_DWORD): " + v + " (" + toHex(v) + ")");
    lines.push("# On a DC, restart the KDC service for the filter to take effect.");
    return lines.join("\n");
  }

  /* ------------------------------------------------------------------ */
  /*  URL state                                                         */
  /* ------------------------------------------------------------------ */

  /**
   * Read {setting, value} from a query string (?setting=gpo&value=0x18) or,
   * for links shared before the query form existed, a #gpo=0x18 hash.
   * Returns null when neither names a known setting.
   */
  function parseStateFromUrl(search, hash) {
    var m;
    var setting = null;
    var raw = null;
    var re = /[?&]([^=&#]+)=([^&#]*)/g;
    search = String(search || "");
    while ((m = re.exec(search)) !== null) {
      if (m[1] === "setting") setting = safeDecode(m[2]);
      if (m[1] === "value") raw = safeDecode(m[2]);
    }
    if (!isSetting(setting)) {
      var parts = String(hash || "").replace(/^#/, "").split("=");
      if (parts.length !== 2 || !isSetting(parts[0])) return null;
      setting = parts[0];
      raw = parts[1];
    }
    var v = parseValue(raw);
    return { setting: setting, value: isNaN(v) ? 0 : v };
  }

  function safeDecode(s) {
    try { return decodeURIComponent(s); } catch (_) { return ""; }
  }

  /** Query string that reproduces a setting + value. */
  function buildStateQuery(settingId, v) {
    return "?setting=" + encodeURIComponent(settingId) + "&value=" + toHex(v);
  }

  /* ------------------------------------------------------------------ */
  /*  Browser-only code below                                           */
  /* ------------------------------------------------------------------ */

  var currentSetting = DEFAULT_SETTING;
  var currentValue = 0;
  var presetsRenderedFor = null;
  var root = null;
  /**
   * { which, value } while the Decimal or Hexadecimal field is being edited:
   * the field and the value stored before the first keystroke.  Null when no
   * edit is in progress.
   */
  var editBase = null;

  /** Safe querySelector - returns null instead of crashing on missing markup. */
  function q(sel) { return root ? root.querySelector(sel) : null; }
  function qa(sel) { return root ? Array.prototype.slice.call(root.querySelectorAll(sel)) : []; }

  /** Bind an event listener only if the element exists. */
  function on(sel, event, handler) {
    var el = q(sel);
    if (el) el.addEventListener(event, handler);
  }

  /** Bitmask a checkbox row stands for (its value attribute). */
  function checkboxMask(cb) {
    var m = parseDec(cb.value);
    return isNaN(m) ? 0 : m;
  }

  function setInvalid(el, msg) {
    if (!el) return;
    var bad = Boolean(msg);
    el.classList.toggle("etype-input--invalid", bad);
    if (bad) { el.setAttribute("aria-invalid", "true"); } else { el.removeAttribute("aria-invalid"); }
    var msgEl = q("#etype-input-msg");
    if (msgEl) msgEl.textContent = msg || "";
  }

  /** Update the checkbox rows from the stored value. */
  function renderCheckboxes() {
    var setting = SETTINGS[currentSetting];
    var whole = futureWhole(currentValue);

    qa(".etype-cb").forEach(function (cb) {
      var mask = checkboxMask(cb);
      var isFuture = cb.dataset.bit === "future";
      var bit = isFuture ? -1 : parseInt(cb.dataset.bit, 10);
      var isSet = mask !== 0 && ((currentValue & mask) >>> 0) === mask;
      var inactive = isFuture ? !setting.futureActive : setting.inactiveBits.indexOf(bit) !== -1;
      var note = "";

      if (isFuture && inactive) {
        note = "Group Policy checkbox only (bits 5-30)";
      } else if (inactive) {
        note = setting.inactiveNote;
      }
      /* An inactive row that is set stays clickable so the stray bit can be
         cleared - except under a complete Group Policy "Future" range, where
         the Future checkbox is the control for those bits. */
      var locked = inactive && (!isSet || (currentSetting === "gpo" && whole));
      if (inactive && isSet && !locked) note += " - untick to clear";

      cb.checked = isSet;
      cb.disabled = locked;

      var row = cb.closest(".etype-bit-row");
      if (row) {
        row.classList.toggle("etype-bit--ignored", inactive);
        var noteEl = row.querySelector(".etype-bit-ignored-note");
        if (noteEl) noteEl.textContent = note ? "(" + note + ")" : "";
      }
    });
  }

  /** Build the preset buttons once per setting, then update them in place. */
  function renderPresets() {
    var presetsEl = q("#etype-presets");
    if (!presetsEl) return;
    var setting = SETTINGS[currentSetting];

    if (presetsRenderedFor !== currentSetting) {
      while (presetsEl.firstChild) presetsEl.removeChild(presetsEl.firstChild);
      setting.presets.forEach(function (p) {
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "etype-preset-btn" + (p.rec ? " etype-preset-btn--rec" : "");
        btn.dataset.value = String(p.value >>> 0);
        btn.dataset.label = p.label + " (" + toHex(p.value) + ")";
        btn.addEventListener("click", function () {
          var newVal = p.value >>> 0;
          /* Clicking the already-active preset deselects it (resets to 0). */
          currentValue = currentValue === newVal ? 0 : newVal;
          updateUI();
          pushState();
        });
        presetsEl.appendChild(btn);
      });
      presetsRenderedFor = currentSetting;
    }

    Array.prototype.slice.call(presetsEl.querySelectorAll(".etype-preset-btn")).forEach(function (btn) {
      var active = parseDec(btn.dataset.value) === currentValue;
      btn.classList.toggle("etype-preset-btn--active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
      btn.textContent = (active ? "✓ " : "") + btn.dataset.label;
    });
  }

  /**
   * Redraw everything from currentSetting + currentValue.
   * skipField ("dec" or "hex") leaves the field the user is typing in alone.
   */
  function updateUI(skipField) {
    var setting = SETTINGS[currentSetting];

    var decEl = q("#etype-dec");
    var hexEl = q("#etype-hex");
    var flagsEl = q("#etype-flags");
    if (decEl && skipField !== "dec") decEl.value = String(currentValue);
    if (hexEl && skipField !== "hex") hexEl.value = toHex(currentValue);
    /* An <output>, not an <input>: the list wraps instead of being cut off. */
    if (flagsEl) flagsEl.textContent = flagNames(currentValue, currentSetting);
    if (!skipField) {
      editBase = null;
      setInvalid(decEl, "");
      setInvalid(hexEl, "");
    }

    renderCheckboxes();

    var status = evaluateStatus(currentValue, currentSetting);
    var badge = q("#etype-status");
    if (badge) {
      badge.className = "etype-status " + status.cls;
      badge.textContent = status.text;
    }

    var warnings = getWarnings(currentValue, currentSetting);
    var warnEl = q("#etype-warnings");
    var noWarnEl = q("#etype-no-warnings");
    if (warnEl) {
      while (warnEl.firstChild) warnEl.removeChild(warnEl.firstChild);
      warnings.forEach(function (text) {
        var div = document.createElement("div");
        div.className = "etype-warning-item";
        div.textContent = text;
        warnEl.appendChild(div);
      });
      warnEl.style.display = warnings.length ? "block" : "none";
      if (noWarnEl) noWarnEl.style.display = warnings.length ? "none" : "";
    }

    var clearBtn = q("#etype-clear-undefined");
    if (clearBtn) clearBtn.hidden = undefinedMask(currentValue, currentSetting) === 0;

    var derivedEl = q("#etype-derived");
    if (derivedEl) {
      var derived = derivedNote(currentValue, currentSetting);
      derivedEl.textContent = derived;
      derivedEl.hidden = derived === "";
    }

    var psEl = q("#etype-powershell");
    if (psEl) psEl.textContent = getPowershell(currentValue, currentSetting);
    /* The Group Policy tab gives the checkboxes to tick, not a command. */
    var psHeading = q("#etype-ps-heading");
    if (psHeading) psHeading.textContent = currentSetting === "gpo" ? "Group Policy Setting" : "PowerShell Command";
    var psCopy = q("#etype-copy-ps");
    if (psCopy) psCopy.title = currentSetting === "gpo" ? "Copy policy setting" : "Copy PowerShell command";

    var descEl = q("#etype-setting-desc");
    if (descEl) descEl.textContent = setting.desc;

    renderPresets();

    qa(".etype-tab").forEach(function (tab) {
      var active = tab.dataset.setting === currentSetting;
      tab.classList.toggle("etype-tab--active", active);
      tab.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  /**
   * Keep the state in the query string.  A #setting=value hash is overwritten
   * by Material's navigation.tracking as soon as the reader scrolls; the query
   * string survives it.  An old-style state hash is dropped, any other hash
   * (a heading anchor) is kept.
   */
  function pushState() {
    try {
      if (!history.replaceState) return;
      var hash = location.hash;
      var hashKey = hash.replace(/^#/, "").split("=")[0];
      if (isSetting(hashKey)) hash = "";
      history.replaceState(history.state, "", location.pathname + buildStateQuery(currentSetting, currentValue) + hash);
    } catch (_) {
      /* Swallow SecurityError in sandboxed iframes etc. */
    }
  }

  /** Absolute link to the current setting + value. */
  function stateUrl() {
    return location.origin + location.pathname + buildStateQuery(currentSetting, currentValue);
  }

  function readState() {
    try {
      var st = parseStateFromUrl(location.search, location.hash);
      if (st) {
        currentSetting = st.setting;
        currentValue = st.value;
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
    var flash = function (label, cls, ms) {
      var orig = btn.dataset.label || btn.textContent;
      btn.dataset.label = orig;
      btn.textContent = label;
      btn.classList.add(cls);
      setTimeout(function () {
        btn.textContent = orig;
        btn.classList.remove(cls);
      }, ms);
    };
    var done = function () { flash("Copied", "etype-copy-btn--copied", 1200); };
    var fail = function () { flash("Failed", "etype-copy-btn--failed", 1500); };
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(text).then(done).catch(fail);
      return;
    }
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

  /* ------------------------------------------------------------------ */
  /*  Event handlers                                                    */
  /* ------------------------------------------------------------------ */

  /** Toggle only the bits the clicked checkbox stands for. */
  function onCheckboxChange(e) {
    var cb = e.currentTarget;
    currentValue = toggleMask(currentValue, checkboxMask(cb), cb.checked);
    updateUI();
    pushState();
  }

  /**
   * Shared handler for the decimal and hex fields.  While typing ("input")
   * the field itself is left alone.  On "change" (blur or Enter) a valid
   * value re-synchronises both fields from the stored value.
   *
   * Text that is not a value never changes the stored value, not even by its
   * leading digits: the value from before the edit is restored, the text
   * stays in the field, and the error stays on screen until the text is
   * corrected or another control sets the value.
   */
  function onValueInput(which, e) {
    var el = q(which === "dec" ? "#etype-dec" : "#etype-hex");
    var other = q(which === "dec" ? "#etype-hex" : "#etype-dec");
    if (!el) return;
    var commit = e.type === "change";
    if (editBase === null || editBase.which !== which) editBase = { which: which, value: currentValue };
    var typed = parseTyped(which, el.value);

    /* The other field is rewritten from the stored value below, so an error
       left on it no longer applies. */
    setInvalid(other, "");

    if (!typed.partial && !isNaN(typed.value)) {
      currentValue = typed.value;
      setInvalid(el, "");
      updateUI(commit ? null : which);
      pushState();
      return;
    }

    var before = editBase.value;
    var changed = currentValue !== before;
    currentValue = before;
    /* Leaving an empty field (or a bare "0x") just restores it. */
    if (commit && el.value.trim().replace(/^0x$/i, "") === "") {
      updateUI();
    } else {
      updateUI(which);
      setInvalid(el, typed.partial && !commit ? "" : (which === "dec"
        ? "Enter a whole number from 0 to 4294967295."
        : "Enter up to 8 hex digits, for example 0x18.") + " The value is unchanged: " + before + " (" + toHex(before) + ").");
    }
    if (changed) pushState();
  }

  function onTabClick(e) {
    var id = e.currentTarget.dataset.setting;
    if (!isSetting(id)) return;
    currentSetting = id;
    updateUI();
    pushState();
  }

  /* ------------------------------------------------------------------ */
  /*  Init                                                              */
  /* ------------------------------------------------------------------ */

  var BODY_CLASS = "etype-calculator-page";

  function init() {
    try {
      root = document.getElementById("etype-calculator");
      /* The body class is a fallback for browsers without :has(); it must
         not survive an instant navigation to another page. */
      document.body.classList.toggle(BODY_CLASS, Boolean(root));
      if (!root) return;

      /* Prevent duplicate listeners when instant navigation re-runs init. */
      if (root.dataset.etypeInit) return;
      root.dataset.etypeInit = "1";

      currentSetting = DEFAULT_SETTING;
      currentValue = 0;
      presetsRenderedFor = null;

      qa(".etype-tab").forEach(function (tab) {
        tab.addEventListener("click", onTabClick);
      });
      qa(".etype-cb").forEach(function (cb) {
        cb.addEventListener("change", onCheckboxChange);
      });

      ["dec", "hex"].forEach(function (which) {
        var handler = function (e) { onValueInput(which, e); };
        on("#etype-" + which, "input", handler);
        on("#etype-" + which, "change", handler);
      });

      on("#etype-copy-dec", "click", function (e) {
        var el = q("#etype-dec");
        if (el) copyText(el.value, e.currentTarget);
      });
      on("#etype-copy-hex", "click", function (e) {
        var el = q("#etype-hex");
        if (el) copyText(el.value, e.currentTarget);
      });
      on("#etype-copy-flags", "click", function (e) {
        var el = q("#etype-flags");
        if (el) copyText(el.textContent, e.currentTarget);
      });
      on("#etype-copy-ps", "click", function (e) {
        var el = q("#etype-powershell");
        if (el) copyText(el.textContent, e.currentTarget);
      });
      on("#etype-copy-link", "click", function (e) {
        copyText(stateUrl(), e.currentTarget);
      });
      on("#etype-clear-undefined", "click", function () {
        currentValue = (currentValue & ~undefinedMask(currentValue, currentSetting)) >>> 0;
        updateUI();
        pushState();
      });

      readState();
      updateUI();
    } catch (err) {
      /* Degrade gracefully - log but do not break the page */
      if (typeof console !== "undefined" && console.error) {
        console.error("etype-calculator init failed:", err);
      }
    }
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      BITS: BITS,
      SETTINGS: SETTINGS,
      GPO_FUTURE_VALUE: GPO_FUTURE_VALUE,
      toU32: toU32,
      toHex: toHex,
      parseHex: parseHex,
      parseDec: parseDec,
      parseValue: parseValue,
      parseTyped: parseTyped,
      toggleMask: toggleMask,
      undefinedMask: undefinedMask,
      effectiveValue: effectiveValue,
      flagNames: flagNames,
      evaluateStatus: evaluateStatus,
      getWarnings: getWarnings,
      derivedNote: derivedNote,
      getPowershell: getPowershell,
      parseStateFromUrl: parseStateFromUrl,
      buildStateQuery: buildStateQuery
    };
  }

  if (typeof document === "undefined") return;

  /* Run after DOM is ready - covers the first page load. */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* Material's instant navigation swaps the page body without reloading
     scripts; document$ emits after every swap. */
  if (typeof document$ !== "undefined") {
    document$.subscribe(init);
  }
})();
