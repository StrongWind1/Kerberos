"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { CALC_JS, REPO, loadCalculator } = require("./helpers");
const calc = require(`${REPO}/${CALC_JS}`);

const GPO_FUTURE = 0x7FFFFFE0;

/* ------------------------------------------------------------------ */
/*  Pure functions                                                     */
/* ------------------------------------------------------------------ */

test("parseHex accepts 32-bit hex with or without prefix and rejects the rest", () => {
  assert.equal(calc.parseHex("0x18"), 0x18);
  assert.equal(calc.parseHex("1c"), 0x1C);
  assert.equal(calc.parseHex("0x0"), 0);
  assert.equal(calc.parseHex("0xFFFFFFFF"), 0xFFFFFFFF);
  assert.equal(calc.parseHex("0x00000000000018"), 0x18);
  for (const bad of ["", "0x", "0x1FFFFFFFF", "zz", "0x-1", "1.5", null, undefined]) {
    assert.ok(Number.isNaN(calc.parseHex(bad)), `parseHex(${JSON.stringify(bad)})`);
  }
});

test("parseDec and parseValue reject negatives, floats and out-of-range values", () => {
  assert.equal(calc.parseDec("24"), 24);
  assert.equal(calc.parseDec("0"), 0);
  assert.equal(calc.parseDec("4294967295"), 0xFFFFFFFF);
  for (const bad of ["", "-1", "1.5", "4294967296", "99999999999", "1e3", "0x18", " "]) {
    assert.ok(Number.isNaN(calc.parseDec(bad)), `parseDec(${JSON.stringify(bad)})`);
  }
  assert.equal(calc.parseValue("0x7FFFFFFF"), 0x7FFFFFFF);
  assert.equal(calc.parseValue("2147483648"), 0x80000000);
  assert.ok(Number.isNaN(calc.parseValue("0x1FFFFFFFF")));
});

test("toggleMask changes only the bits of the mask", () => {
  assert.equal(calc.toggleMask(0xD8, 0x4, true), 0xDC);
  assert.equal(calc.toggleMask(0x80000018, 0x4, true), 0x8000001C);
  assert.equal(calc.toggleMask(0x118, 0x4, true), 0x11C);
  assert.equal(calc.toggleMask(0x7FFFFFFC, 0x4, false), 0x7FFFFFF8);
  assert.equal(calc.toggleMask(0x18, GPO_FUTURE, true), 0x7FFFFFF8);
});

test("flagNames names every set bit exactly once", () => {
  assert.equal(calc.flagNames(0, "msds"), "(not set)");
  assert.equal(calc.flagNames(0x18, "msds"), "AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96");
  assert.equal(calc.flagNames(0x1F, "msds").includes("-SK"), false, "0x1F has no AES-SK bit");
  assert.match(calc.flagNames(0x27, "default"), /^DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC, AES256-CTS-HMAC-SHA1-96-SK$/);
  assert.equal(calc.flagNames(0xC0, "msds"), "AES128-CTS-HMAC-SHA256-128, AES256-CTS-HMAC-SHA384-192");
  /* The whole GPO range is one checkbox; its member bits are not repeated. */
  assert.equal(calc.flagNames(0x7FFFFFF8, "gpo"), "AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96, Future encryption types");
  /* A partial range is not the checkbox. */
  assert.equal(calc.flagNames(0x38, "gpo"), "AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96-SK");
  /* Bit 31 is never "Future". */
  assert.equal(calc.flagNames(0x80000018, "msds"), "AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96, 0x80000000 (undefined bits)");
  assert.equal(calc.flagNames(0xFFFFFFFF, "gpo").endsWith("0x80000000 (undefined bits)"), true);
  assert.match(calc.flagNames(0x10018, "default"), /FAST-supported \(ignored\)$/);
  assert.match(calc.flagNames(0x118, "msds"), /0x100 \(undefined bits\)$/);
});

test("effectiveValue drops ignored and undefined bits without touching the input", () => {
  assert.equal(calc.effectiveValue(0x10018, "default"), 0x18);
  assert.equal(calc.effectiveValue(0x10018, "msds"), 0x10018);
  assert.equal(calc.effectiveValue(0x80000018, "msds"), 0x18);
  assert.equal(calc.effectiveValue(0x7FFFFFF8, "gpo"), 0x7FFFFFF8);
  assert.equal(calc.undefinedMask(0xFFFFFFFF, "gpo"), 0x80000000);
  assert.equal(calc.undefinedMask(0x118, "gpo"), 0x100);
});

test("evaluateStatus follows the effective etype bits", () => {
  const cls = (v, s) => calc.evaluateStatus(v, s).cls;
  assert.equal(cls(0x18, "msds"), "etype-status--secure");
  assert.equal(cls(0x7FFFFFF8, "gpo"), "etype-status--secure");
  assert.equal(cls(0x1C, "msds"), "etype-status--transitional");
  assert.equal(cls(0x3C, "default"), "etype-status--transitional");
  assert.equal(cls(0x4, "msds"), "etype-status--insecure");
  assert.equal(cls(0x27, "default"), "etype-status--insecure");
  assert.equal(cls(0, "msds"), "etype-status--notset");
  assert.equal(cls(0x10000, "msds"), "etype-status--notset");
  assert.match(calc.evaluateStatus(0, "msds").text, /build default/);
});

test("warnings describe the setting they are shown for", () => {
  const all = (v, s) => calc.getWarnings(v, s).join("\n");

  /* Unset: the fallback chain and both build defaults, no blanket "includes RC4". */
  assert.match(all(0, "msds"), /0x27 .*before the April 2026 cumulative update, 0x18 \(AES only\) on the April 2026 CU or later/);
  assert.match(all(0, "default"), /build default/);
  assert.deepEqual(calc.getWarnings(0, "gpo"), []);

  /* "This account" wording only on the per-account attribute. */
  assert.match(all(0x4, "msds"), /Tickets for this account can only use RC4 or DES/);
  assert.doesNotMatch(all(0x27, "default"), /This account/i);
  assert.doesNotMatch(all(0x4, "gpo"), /This account/i);
  assert.match(all(0x27, "default"), /Accounts with no msDS-SupportedEncryptionTypes/);

  /* Flag-only values do not get the "no AES" outage warning. */
  assert.doesNotMatch(all(0x10000, "msds"), /KDC_ERR_ETYPE_NOSUPP/);
  assert.match(all(0x10000, "msds"), /only flag bits/);
  assert.match(all(0x80000000, "msds"), /Bit 31 .* not honored/);

  /* The recommended GPO preset must not warn about its own Future range. */
  assert.deepEqual(calc.getWarnings(0x7FFFFFF8, "gpo"), []);
  assert.match(all(0x38, "gpo"), /only partly set/);

  /* 0x1C with AES keys is an AES256 ticket. */
  assert.match(all(0x1C, "msds"), /ticket is still AES256/);

  /* Ignored bits are reported, not deleted. */
  assert.match(all(0x10018, "default"), /Effective value: 0x18/);

  /* No dated future-tense strings. */
  for (const s of ["msds", "default", "gpo"]) {
    for (const v of [0, 0x4, 0x1C, 0x27, 0x3C, 0xC0, 0xFFFFFFFF]) {
      assert.doesNotMatch(all(v, s), /July 2026|will be|permanent/i, `${s} ${v}`);
    }
  }
});

test("AES-SHA2 bits carry the one agreed status", () => {
  assert.match(calc.getWarnings(0xD8, "msds").join("\n"),
    /supported on Windows 11 24H2 \/ Server 2025, disabled by default \(MS-KILE §2\.2\.7\); not lab-tested on this site/);
});

test("an RC4 session key is promised only without the AES-SK bit", () => {
  const all = (v) => calc.getWarnings(v, "msds").join("\n");
  /* 0x1C: lab-backed. */
  assert.match(all(0x1C), /RC4 remains possible as a session key for clients that offer only RC4/);
  /* 0x3C and every other RC4 + AES value with bit 0x20: MS-KILE 2.2.7 says
     RC4 session keys are superseded, and the lab did not test it. */
  for (const v of [0x3C, 0x3F, 0x7FFFFFFF, 0xFFFFFFFF]) {
    assert.doesNotMatch(all(v), /RC4 remains possible as a session key/, calc.toHex(v));
    assert.match(all(v), /AES-SK bit \(0x20\) is also set, and \[MS-KILE\] §2\.2\.7 defines it as superseding RC4 session keys with AES keys/, calc.toHex(v));
    assert.match(all(v), /Do not count on an RC4 session key for clients that offer only RC4: this site's lab has not tested that combination/, calc.toHex(v));
  }
  /* RC4 + AES-SK without AES (0x24): neither sentence applies. */
  assert.doesNotMatch(all(0x24), /RC4 remains possible as a session key|AES-SK bit \(0x20\) is also set/);
});

test("a DDSET without AES is described as the filter matrix measured it", () => {
  /* includes/kdc-filter-matrix.md: msDS-SET 0, DDSET = RC4, AES-only filter
     gave an AES256 ticket ("upgraded") on Server 2022 build 20348.5020. */
  const { read } = require("./helpers");
  assert.match(read("includes/kdc-filter-matrix.md"), /Measured on Server 2022 build 20348\.5020/);
  assert.match(read("includes/kdc-filter-matrix.md"), /\| AES-only \(`0x18`\) \| `KDC_ERR_ETYPE_NOSUPP` \| AES256 \| \*\*AES256\*\* \(upgraded\) \|/);
  for (const v of [0x4, 0x7, 0x27]) {
    const w = calc.getWarnings(v, "default").join("\n");
    assert.doesNotMatch(w, /when the KDC filter or the client does not allow them/, calc.toHex(v));
    assert.match(w, /An AES-only KDC filter did not make such requests fail in this site's lab: on Server 2022 build 20348\.5020, with this value set to RC4 \(0x4\), the filter upgraded the ticket to AES256\./, calc.toHex(v));
  }
  /* An explicit msDS-SET without AES does fail under an AES-only filter (same matrix). */
  assert.match(calc.getWarnings(0x4, "msds").join("\n"), /fail with KDC_ERR_ETYPE_NOSUPP when the KDC filter or the client does not allow them/);
});

test("the msDS 0x3C preset is labelled as the msDS page describes that use", () => {
  const { read } = require("./helpers");
  assert.match(read("content/security/msds-supported.md"), /`0x3C` for that purpose as \*\*unverified\*\*/);
  const msds = calc.SETTINGS.msds.presets;
  const p = msds.find((x) => x.value === 0x3C);
  assert.ok(p, "0x3C can still be loaded from a preset");
  assert.match(p.label, /unverified for RC4-only clients/);
  assert.notEqual(p.rec, true);
  assert.ok(msds.findIndex((x) => x.value === 0x1C) < msds.indexOf(p), "the lab-backed 0x1C comes first");
  /* Microsoft suggests 0x3C for the DC-wide default (KB5021131): that preset keeps its plain label. */
  assert.equal(calc.SETTINGS.default.presets.find((x) => x.value === 0x3C).label, "RC4 + AES + AES-SK");
  /* Decoding 0x3C is unaffected. */
  assert.equal(calc.flagNames(0x3C, "msds"), "RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96-SK");
  const t = loadCalculator("https://example.test/security/etype-calculator/?setting=msds&value=0x3C");
  const active = t.$(".etype-preset-btn--active");
  assert.equal(active.textContent, "✓ RC4 + AES + AES-SK, unverified for RC4-only clients (0x3C)");
  assert.match(t.$("#etype-warnings").textContent, /Do not count on an RC4 session key for clients that offer only RC4/);
});

test("AES-SHA2 bits are not called flag bits", () => {
  for (const v of [0x40, 0x80, 0xC0, 0x100C0]) {
    const w = calc.getWarnings(v, "msds").join("\n");
    assert.doesNotMatch(w, /only flag bits/, calc.toHex(v));
    assert.match(w, /None of the DES, RC4 or AES-SHA1 etype bits \(0x1-0x10\) is set/, calc.toHex(v));
  }
  assert.match(calc.getWarnings(0xF0000, "msds").join("\n"), /only flag bits/);
});

/** The comment lines of a generated command as running text (they are wrapped to fit the block). */
function commentText(ps) {
  return ps.split("\n").filter((line) => line.startsWith("#")).map((line) => line.replace(/^#\s*/, "")).join(" ");
}

test("the DefaultDomainSupportedEncTypes command never writes 0", () => {
  /* Values whose every bit this setting ignores or does not define. */
  for (const v of [0x10000, 0xF0000, 0x100, 0x80000000, 0x800F0100]) {
    const ps = calc.getPowershell(v, "default");
    assert.doesNotMatch(ps, /New-ItemProperty|Set-ItemProperty|-Value/, calc.toHex(v));
    assert.match(commentText(ps), /^No command: 0x[0-9A-F]+ has no bit that DefaultDomainSupportedEncTypes reads/, calc.toHex(v));
    assert.match(commentText(ps), /This tool does not generate a command that writes 0\./, calc.toHex(v));
    assert.ok(ps.split("\n").every((line) => line.startsWith("#")), `${calc.toHex(v)}: comment lines only`);
  }
  /* No value at all produces "-Value 0": single bits, pairs of bits, and the extremes. */
  const values = [0, 0xFFFFFFFF, 0x7FFFFFFF];
  for (let a = 0; a < 32; a++) {
    values.push(2 ** a);
    for (let b = a + 1; b < 32; b++) values.push(2 ** a + 2 ** b);
  }
  for (const v of values) {
    const ps = calc.getPowershell(v, "default");
    assert.doesNotMatch(ps, /-Value 0(?![0-9x])/, calc.toHex(v));
    if (/New-ItemProperty/.test(ps)) {
      assert.equal(Number(/-Value (\d+) /.exec(ps)[1]), calc.effectiveValue(v, "default"), calc.toHex(v));
    }
  }
  /* Typing 0 is still the way to remove the value. */
  assert.match(calc.getPowershell(0, "default"), /^# Remove the value[^\n]*\nRemove-ItemProperty/);
  /* A value with no DES, RC4 or AES-SHA1 bit keeps its command but points at the warning. */
  assert.match(commentText(calc.getPowershell(0x20, "default")), /No DES, RC4 or AES-SHA1 etype bit is set: read the warning for this value before running the command\./);
  assert.match(calc.getPowershell(0x20, "default"), /-Value 32 /);
  assert.doesNotMatch(calc.getPowershell(0x18, "default"), /read the warning/);
});

test("the msDS command is not offered for Windows computer accounts", () => {
  for (const v of [0, 24, 0x80000018]) {
    const ps = calc.getPowershell(v, "msds");
    assert.doesNotMatch(ps, /Set-ADComputer/, String(v));
    assert.match(commentText(ps), /Windows computer accounts: do not set the attribute by hand\. +The computer writes it from its own Kerberos etype policy; use the SupportedEncryptionTypes \(GPO\) tab\./, String(v));
    assert.match(ps, /^Set-ADUser -Identity <account> /m, String(v));
    /* The comment fits the command block without sideways scrolling. */
    for (const line of ps.split("\n").slice(0, 7)) assert.ok(line.startsWith("#") && line.length <= 46, line);
  }
});

test("parseTyped reads whole values only, in the forms admins copy", () => {
  const val = (which, s) => calc.parseTyped(which, s).value;
  assert.equal(val("dec", "24"), 24);
  assert.equal(val("dec", " 2,147,483,640 "), 0x7FFFFFF8);
  assert.equal(val("dec", "2 147 483 640"), 0x7FFFFFF8);
  assert.equal(val("dec", "0x18"), 0x18);
  assert.equal(val("dec", "-2147483624"), 0x80000018, "signed form of the AD attribute");
  assert.equal(val("dec", "-1"), 0xFFFFFFFF);
  assert.equal(val("dec", "39 (DES, RC4, AES-Sk)"), 39);
  assert.equal(val("hex", "0x27 (DES, RC4, AES-Sk)"), 0x27);
  assert.equal(val("hex", "1c"), 0x1C);
  /* Never a number from a prefix of the text. */
  for (const bad of ["1e3", "24.0", "2,1474,83640", "4,294,967,296", "-2147483649", "12abc", "24 ("]) {
    const r = calc.parseTyped("dec", bad);
    assert.ok(!r.partial && Number.isNaN(r.value), `dec ${JSON.stringify(bad)}`);
  }
  assert.ok(Number.isNaN(val("hex", "0x1FFFFFFFF")));
  assert.ok(Number.isNaN(val("hex", "-1")));
  /* The beginning of a value is neither a value nor an error. */
  for (const partial of ["", "  ", "0x", "-", "2,", "2,1", "2,14", "2,147,4", "1,5"]) {
    assert.deepEqual(calc.parseTyped("dec", partial), { partial: true }, JSON.stringify(partial));
  }
  assert.deepEqual(calc.parseTyped("hex", "0X"), { partial: true });
});

test("getPowershell matches the setting", () => {
  assert.match(calc.getPowershell(0, "msds"), /-Clear 'msDS-SupportedEncryptionTypes'/);
  assert.match(calc.getPowershell(24, "msds"), /'msDS-SupportedEncryptionTypes' = 24\n/);
  /* The AD attribute is a signed 32-bit integer. */
  assert.match(calc.getPowershell(0x80000018, "msds"), /= -2147483624\n/);

  assert.match(calc.getPowershell(0x18, "default"), /Services\\Kdc"/);
  assert.doesNotMatch(calc.getPowershell(0x18, "default"), /Kdc\\Parameters/);
  assert.match(calc.getPowershell(0x10018, "default"), /-Value 24 /);
  assert.match(calc.getPowershell(0, "default"), /Remove-ItemProperty/);

  const gpo = calc.getPowershell(0x7FFFFFF8, "gpo");
  assert.match(gpo, /# Tick: AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types/);
  assert.match(gpo, /2147483640 \(0x7FFFFFF8\)/);
  assert.match(calc.getPowershell(0x38, "gpo"), /cannot produce this value/);
});

test("derivedNote gives the computer-account value for the GPO only", () => {
  assert.match(calc.derivedNote(0x7FFFFFFF, "gpo"), /= 31 \(0x1F\)/);
  assert.match(calc.derivedNote(0x7FFFFFF8, "gpo"), /= 24 \(0x18\)/);
  assert.equal(calc.derivedNote(0x18, "msds"), "");
  assert.equal(calc.derivedNote(0, "gpo"), "");
});

test("parseStateFromUrl reads the query form, the legacy hash, and nothing else", () => {
  assert.deepEqual(calc.parseStateFromUrl("?setting=gpo&value=0x7FFFFFF8", ""), { setting: "gpo", value: 0x7FFFFFF8 });
  assert.deepEqual(calc.parseStateFromUrl("?value=24&setting=default", "#some-heading"), { setting: "default", value: 24 });
  assert.deepEqual(calc.parseStateFromUrl("", "#msds=0x18"), { setting: "msds", value: 0x18 });
  assert.deepEqual(calc.parseStateFromUrl("", "#default=0x10018"), { setting: "default", value: 0x10018 });
  assert.deepEqual(calc.parseStateFromUrl("?setting=gpo&value=nonsense", ""), { setting: "gpo", value: 0 });
  for (const hash of ["#constructor=1", "#__proto__=1", "#toString=24", "#hasOwnProperty=1", "#reserved-and-future-bits", ""]) {
    assert.equal(calc.parseStateFromUrl("", hash), null, hash);
  }
  assert.equal(calc.parseStateFromUrl("?setting=constructor&value=1", ""), null);
  assert.equal(calc.buildStateQuery("gpo", 0x7FFFFFF8), "?setting=gpo&value=0x7FFFFFF8");
});

/* ------------------------------------------------------------------ */
/*  Behaviour in a page                                                */
/* ------------------------------------------------------------------ */

function state(t) {
  return { dec: t.$("#etype-dec").value, hex: t.$("#etype-hex").value, flags: t.$("#etype-flags").textContent };
}
function typeInto(t, sel, text, commit) {
  const el = t.$(sel);
  el.value = text;
  t.fire(el, "input");
  if (commit) t.fire(el, "change");
}
function tab(t, id) {
  t.$(`.etype-tab[data-setting="${id}"]`).click();
}
function box(t, bit) {
  return t.$(`.etype-cb[data-bit="${bit}"]`);
}

test("page loads clean with the default state", () => {
  const t = loadCalculator();
  assert.deepEqual(t.errors, []);
  assert.deepEqual(state(t), { dec: "0", hex: "0x0", flags: "(not set)" });
  assert.equal(t.$$("#etype-presets button").length, 5);
  assert.equal(t.doc.body.classList.contains("etype-calculator-page"), true);
  assert.equal(t.$('.etype-tab[data-setting="msds"]').getAttribute("aria-pressed"), "true");
});

test("ticking a checkbox keeps bits that have no checkbox", () => {
  for (const [start, expected] of [["0xD8", "0xDC"], ["0x80000018", "0x8000001C"], ["0x118", "0x11C"]]) {
    const t = loadCalculator();
    typeInto(t, "#etype-hex", start, true);
    box(t, 2).click();
    assert.equal(state(t).hex, expected, start);
    assert.deepEqual(t.errors, []);
  }
});

test("GPO tab: a stray bit 0x20 survives ticking RC4", () => {
  const t = loadCalculator();
  tab(t, "gpo");
  typeInto(t, "#etype-hex", "0x38", true);
  box(t, 2).click();
  assert.equal(state(t).hex, "0x3C");
});

test("GPO tab: the Future checkbox toggles bits 5-30 as a unit", () => {
  const t = loadCalculator();
  tab(t, "gpo");
  typeInto(t, "#etype-hex", "0x18", true);
  const future = box(t, "future");
  assert.equal(future.disabled, false);
  future.click();
  assert.equal(state(t).hex, "0x7FFFFFF8");
  assert.equal(box(t, 5).checked, true);
  assert.equal(box(t, 5).disabled, true, "covered bits are driven by the Future checkbox");
  future.click();
  assert.equal(state(t).hex, "0x18");
  tab(t, "msds");
  assert.equal(box(t, "future").disabled, true, "Future is a Group Policy checkbox only");
});

test("DDSET tab never rewrites the value being typed", () => {
  const t = loadCalculator();
  tab(t, "default");
  typeInto(t, "#etype-dec", "2147483647", true);
  assert.equal(state(t).dec, "2147483647");
  assert.equal(state(t).hex, "0x7FFFFFFF");
  typeInto(t, "#etype-hex", "0x7FFFFFFF", true);
  assert.equal(state(t).hex, "0x7FFFFFFF");
  typeInto(t, "#etype-dec", "65560", true);
  assert.equal(state(t).dec, "65560");
  assert.match(state(t).flags, /FAST-supported \(ignored\)/);
  assert.match(t.$("#etype-warnings").textContent, /Effective value: 0x18/);
});

test("switching tabs never changes the stored value", () => {
  const t = loadCalculator();
  typeInto(t, "#etype-hex", "0x80018", true);
  tab(t, "default");
  tab(t, "gpo");
  tab(t, "msds");
  assert.equal(state(t).hex, "0x80018");
});

test("an ignored bit that is set can be cleared from its own row", () => {
  const t = loadCalculator();
  tab(t, "default");
  typeInto(t, "#etype-hex", "0x10018", true);
  const fast = box(t, 16);
  assert.equal(fast.checked, true);
  assert.equal(fast.disabled, false);
  assert.match(t.$("#etype-note-16").textContent, /ignored by this setting/);
  fast.click();
  assert.equal(state(t).hex, "0x18");
  assert.equal(box(t, 16).disabled, true);
});

test("partial and invalid input keep the two fields in step", () => {
  const t = loadCalculator();
  typeInto(t, "#etype-dec", "24", true);

  /* "0" in the hex field is a real zero. */
  typeInto(t, "#etype-hex", "0", true);
  assert.deepEqual(state(t), { dec: "0", hex: "0x0", flags: "(not set)" });

  /* Clearing a field and leaving it restores the stored value. */
  typeInto(t, "#etype-dec", "28", true);
  typeInto(t, "#etype-hex", "", true);
  assert.equal(state(t).hex, "0x1C");

  /* Invalid text is flagged while typing and stays flagged after leaving the
     field: the text is kept, the stored value is the one from before. */
  typeInto(t, "#etype-dec", "99999999999", false);
  const dec = t.$("#etype-dec");
  assert.equal(dec.getAttribute("aria-invalid"), "true");
  assert.notEqual(t.$("#etype-input-msg").textContent, "");
  t.fire(dec, "change");
  assert.equal(dec.getAttribute("aria-invalid"), "true");
  assert.equal(dec.classList.contains("etype-input--invalid"), true);
  assert.equal(dec.value, "99999999999");
  assert.match(t.$("#etype-input-msg").textContent, /whole number from 0 to 4294967295.*unchanged: 28 \(0x1C\)/);
  assert.equal(state(t).hex, "0x1C");

  /* Correcting the text clears the error. */
  typeInto(t, "#etype-dec", "24", true);
  assert.equal(dec.hasAttribute("aria-invalid"), false);
  assert.equal(t.$("#etype-input-msg").textContent, "");
  assert.deepEqual(state(t), { dec: "24", hex: "0x18", flags: "AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96" });
  typeInto(t, "#etype-dec", "28", true);

  /* A later checkbox click also clears an invalid marker on the other field. */
  typeInto(t, "#etype-hex", "0xZZ", false);
  assert.equal(t.$("#etype-hex").getAttribute("aria-invalid"), "true");
  box(t, 3).click();
  assert.equal(t.$("#etype-hex").hasAttribute("aria-invalid"), false);
  assert.deepEqual(t.errors, []);
});

test("typing does not move the text under the caret", () => {
  const t = loadCalculator();
  typeInto(t, "#etype-hex", "0x1c", false);
  assert.equal(t.$("#etype-hex").value, "0x1c", "field being typed in is left alone");
  assert.equal(state(t).dec, "28");
});

/** Type text one character at a time, as a keyboard does, then leave the field. */
function typeSlowly(t, sel, text) {
  const el = t.$(sel);
  for (let i = 1; i <= text.length; i++) {
    el.value = text.slice(0, i);
    t.fire(el, "input");
  }
  t.fire(el, "change");
}

test("a mistyped decimal is never half-applied, and its error stays until corrected", () => {
  for (const typo of ["1e3", "24.0", "2,1474,83640", "12abc"]) {
    const t = loadCalculator();
    typeInto(t, "#etype-dec", "28", true);
    typeSlowly(t, "#etype-dec", typo);
    const dec = t.$("#etype-dec");
    /* Not the leading digits of the typo: the value from before the edit. */
    assert.equal(state(t).hex, "0x1C", typo);
    assert.equal(t.win.location.search, "?setting=msds&value=0x1C", typo);
    assert.match(t.$("#etype-status").textContent, /Transitional/, typo);
    /* The text and the error are still there after leaving the field. */
    assert.equal(dec.value, typo, typo);
    assert.equal(dec.getAttribute("aria-invalid"), "true", typo);
    assert.match(t.$("#etype-input-msg").textContent, /Enter a whole number from 0 to 4294967295\. The value is unchanged: 28 \(0x1C\)\./, typo);
    assert.deepEqual(t.errors, [], typo);
  }
});

test("digit grouping, pasted event values and signed values are accepted", () => {
  const t = loadCalculator();
  typeSlowly(t, "#etype-dec", "2,147,483,640");
  assert.deepEqual({ dec: state(t).dec, hex: state(t).hex }, { dec: "2147483640", hex: "0x7FFFFFF8" });
  assert.equal(t.$("#etype-dec").hasAttribute("aria-invalid"), false);
  assert.equal(t.$("#etype-input-msg").textContent, "");

  /* Pasted in one go. */
  typeInto(t, "#etype-dec", "2 147 483 640", true);
  assert.equal(state(t).hex, "0x7FFFFFF8");
  typeInto(t, "#etype-hex", "0x27 (DES, RC4, AES-Sk)", true);
  assert.deepEqual({ dec: state(t).dec, hex: state(t).hex }, { dec: "39", hex: "0x27" });
  typeInto(t, "#etype-dec", "0x18", true);
  assert.deepEqual({ dec: state(t).dec, hex: state(t).hex }, { dec: "24", hex: "0x18" });
  typeInto(t, "#etype-dec", "-2147483624", true);
  assert.deepEqual({ dec: state(t).dec, hex: state(t).hex }, { dec: "2147483672", hex: "0x80000018" });

  /* An unfinished group is an error once the field is left, not a value. */
  typeInto(t, "#etype-dec", "24", true);
  typeSlowly(t, "#etype-dec", "2,14");
  assert.equal(state(t).hex, "0x18");
  assert.equal(t.$("#etype-dec").getAttribute("aria-invalid"), "true");
  assert.deepEqual(t.errors, []);
});

test("an error on one field is dropped when the other field sets the value", () => {
  const t = loadCalculator();
  typeInto(t, "#etype-dec", "1e3", true);
  assert.equal(t.$("#etype-dec").getAttribute("aria-invalid"), "true");
  typeInto(t, "#etype-hex", "0x18", false);
  assert.equal(t.$("#etype-dec").hasAttribute("aria-invalid"), false);
  assert.equal(t.$("#etype-dec").value, "24");
  assert.equal(t.$("#etype-input-msg").textContent, "");
});

test("flag names are shown in full, in an element that wraps", () => {
  const t = loadCalculator();
  const flags = t.$("#etype-flags");
  assert.equal(flags.tagName, "OUTPUT", "a one-line <input> cut the list off");
  assert.equal(t.$('label[for="etype-flags"]').textContent, "Flag Names");
  typeInto(t, "#etype-hex", "0xFFFFFFFF", true);
  for (const b of calc.BITS) assert.ok(flags.textContent.includes(b.name), b.name);
  assert.match(flags.textContent, /, 0xFFF0FF00 \(undefined bits\)$/);
  let copied = null;
  Object.defineProperty(t.win.navigator, "clipboard", { value: { writeText: (s) => { copied = s; return Promise.resolve(); } }, configurable: true });
  t.$("#etype-copy-flags").click();
  assert.equal(copied, calc.flagNames(0xFFFFFFFF, "msds"));
});

test("the command block is headed for what it holds, and stays safe across tabs", () => {
  const t = loadCalculator();
  assert.equal(t.$("#etype-ps-heading").textContent, "PowerShell Command");
  typeInto(t, "#etype-hex", "0x10000", true);
  tab(t, "default");
  assert.equal(t.$("#etype-ps-heading").textContent, "PowerShell Command");
  assert.doesNotMatch(t.$("#etype-powershell").textContent, /New-ItemProperty|-Value/);
  assert.match(t.$("#etype-powershell").textContent, /^# No command: 0x10000/);
  tab(t, "gpo");
  assert.equal(t.$("#etype-ps-heading").textContent, "Group Policy Setting", "the GPO tab lists checkboxes, not a command");
  assert.ok(t.$("#etype-powershell").textContent.split("\n").every((line) => line.startsWith("#")));
  tab(t, "msds");
  assert.equal(t.$("#etype-ps-heading").textContent, "PowerShell Command");
});

test("state comes from the URL, and hostile hashes are ignored", () => {
  let t = loadCalculator("https://example.test/security/etype-calculator/?setting=gpo&value=0x7FFFFFF8");
  assert.equal(state(t).hex, "0x7FFFFFF8");
  assert.equal(t.$('.etype-tab[data-setting="gpo"]').getAttribute("aria-pressed"), "true");

  t = loadCalculator("https://example.test/security/etype-calculator/#default=0x10018");
  assert.equal(state(t).hex, "0x10018", "legacy hash links keep working, bits intact");

  for (const hash of ["#constructor=1", "#__proto__=1", "#toString=24"]) {
    t = loadCalculator(`https://example.test/security/etype-calculator/${hash}`);
    assert.deepEqual(t.errors, [], hash);
    assert.equal(t.$$("#etype-presets button").length, 5, hash);
    box(t, 4).click();
    assert.equal(state(t).hex, "0x10", hash);
  }
});

test("state is written to the query string, where scroll tracking cannot overwrite it", () => {
  const t = loadCalculator("https://example.test/security/etype-calculator/#msds=0x18");
  tab(t, "gpo");
  box(t, 2).click();
  assert.equal(t.win.location.search, "?setting=gpo&value=0x1C");
  assert.equal(t.win.location.hash, "", "the legacy state hash is replaced, not kept beside the query");

  /* What navigation.tracking does on scroll: replace the hash only. */
  t.win.history.replaceState(null, "", "#bit-flag-reference");
  assert.equal(t.win.location.search, "?setting=gpo&value=0x1C");
  box(t, 2).click();
  assert.equal(t.win.location.search, "?setting=gpo&value=0x18");
  assert.equal(t.win.location.hash, "#bit-flag-reference", "a heading anchor is preserved");
});

test("presets update in place and report their state", () => {
  const t = loadCalculator();
  const first = t.$("#etype-presets button");
  first.click();
  assert.equal(state(t).hex, "0x18");
  assert.equal(t.$("#etype-presets button"), first, "button is not rebuilt, so keyboard focus stays on it");
  assert.equal(first.getAttribute("aria-pressed"), "true");
  first.click();
  assert.equal(state(t).hex, "0x0");
  assert.equal(first.getAttribute("aria-pressed"), "false");
});

test("GPO presets are named for the checkboxes they tick", () => {
  const t = loadCalculator();
  tab(t, "gpo");
  const labels = t.$$("#etype-presets button").map((b) => b.textContent);
  assert.ok(labels.some((l) => l.startsWith("AES128 + AES256 + Future (0x7FFFFFF8)")), labels.join(" | "));
  assert.ok(!labels.some((l) => /AES-SK/.test(l)), "the GPO has no AES-SK checkbox");
  t.$$("#etype-presets button")[1].click();
  assert.equal(t.$("#etype-warnings").style.display, "none");
  assert.match(t.$("#etype-derived").textContent, /= 24 \(0x18\)/);
  assert.equal(t.$("#etype-derived").hidden, false);
});

test("undefined bits can be cleared with one button", () => {
  const t = loadCalculator();
  typeInto(t, "#etype-hex", "0x80000118", true);
  const btn = t.$("#etype-clear-undefined");
  assert.equal(btn.hidden, false);
  btn.click();
  assert.equal(state(t).hex, "0x18");
  assert.equal(btn.hidden, true);
});

test("live regions and control state are exposed to assistive technology", () => {
  const t = loadCalculator();
  assert.equal(t.$("#etype-status").getAttribute("role"), "status");
  assert.equal(t.$("#etype-warnings").getAttribute("aria-live"), "polite");
  assert.equal(t.$("#etype-input-msg").getAttribute("role"), "alert");
  for (const cb of t.$$(".etype-cb")) {
    const note = t.doc.getElementById(cb.getAttribute("aria-describedby"));
    assert.ok(note && note.classList.contains("etype-bit-ignored-note"), cb.dataset.bit);
  }
  tab(t, "default");
  assert.deepEqual(t.$$(".etype-tab").map((b) => b.getAttribute("aria-pressed")), ["false", "true", "false"]);
});

test("re-running init on the same page does not double-bind or drop the body class", () => {
  const t = loadCalculator();
  /* Stand-in for Material's document$: re-evaluating the script runs init again. */
  t.win.eval(require("./helpers").read(CALC_JS));
  box(t, 3).click();
  assert.equal(state(t).hex, "0x8", "one handler per click");
  assert.equal(t.doc.body.classList.contains("etype-calculator-page"), true);
});

test("on a page without the tool the script does nothing", () => {
  const { JSDOM } = require("jsdom");
  const dom = new JSDOM("<!doctype html><body class='etype-calculator-page'><p>other page</p></body>", { runScripts: "outside-only" });
  dom.window.eval(require("./helpers").read(CALC_JS));
  assert.equal(dom.window.document.body.classList.contains("etype-calculator-page"), false, "stale body class is removed");
});
