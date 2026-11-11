"use strict";

/* The two tools are separate plain scripts, so the tables they share are
 * written out twice, and the calculator's checkbox rows and reference tables
 * are written a third time in Markdown.  These tests are what keeps the
 * copies from drifting. */

const test = require("node:test");
const assert = require("node:assert/strict");
const { JSDOM } = require("jsdom");
const { CALC_JS, CALC_MD, DECODER_JS, DECODER_MD, REPO, read, toolMarkup } = require("./helpers");
const calc = require(`${REPO}/${CALC_JS}`);
const dec = require(`${REPO}/${DECODER_JS}`);

test("bit names are identical in the calculator and the decoder", () => {
  assert.deepEqual(dec.SET_BITS, calc.BITS);
});

test("both tools parse hex the same way", () => {
  for (const s of ["0x18", "1C", "0xffffffff", "0x1FFFFFFFF", "", "0x", "zz", "0x0", "00000018", " 0x27 "]) {
    const a = calc.parseHex(s);
    const b = dec.parseHex(s);
    assert.ok(Object.is(a, b), `${JSON.stringify(s)}: calculator ${a}, decoder ${b}`);
  }
});

test("etype names agree between the bit table and the etype table", () => {
  const etypeOf = { 0: 0x1, 1: 0x3, 2: 0x17, 3: 0x11, 4: 0x12, 6: 0x13, 7: 0x14 };
  for (const [bit, etype] of Object.entries(etypeOf)) {
    const bitName = calc.BITS.find((b) => b.bit === Number(bit)).name;
    assert.equal(dec.ENCRYPTION_TYPES[etype].name, bitName, `bit ${bit}`);
  }
});

test("calculator checkbox rows match the bit table", () => {
  const doc = new JSDOM(toolMarkup(CALC_MD, "etype-calculator")).window.document;
  const rows = Array.from(doc.querySelectorAll(".etype-bit-row")).map((row) => {
    const cb = row.querySelector(".etype-cb");
    return {
      bit: cb.dataset.bit,
      value: Number(cb.value),
      hex: row.querySelector(".etype-bit-info code").textContent,
      name: row.querySelector(".etype-bit-name").textContent,
    };
  });
  const future = rows.pop();
  assert.deepEqual(future, { bit: "future", value: calc.GPO_FUTURE_VALUE, hex: "0x7FFFFFE0", name: "Future encryption types" });
  assert.deepEqual(
    rows.map((r) => ({ bit: Number(r.bit), name: r.name })),
    calc.BITS,
  );
  for (const r of rows) {
    assert.equal(r.value, 2 ** Number(r.bit), `value of bit ${r.bit}`);
    assert.equal(r.hex, calc.toHex(r.value), `hex label of bit ${r.bit}`);
  }
});

test("the shared bit-flag reference table matches the bit table", () => {
  /* security/etype-calculator.md (and other pages) render this include. */
  assert.match(read(CALC_MD), /^--8<-- "includes\/etype-bits\.md"$/m);
  const md = read("includes/etype-bits.md");
  /* Rows of the form | 3 | `0x8` | 8 | NAME | … */
  const found = new Map();
  for (const m of md.matchAll(/^\| (\d+) \| `(0x[0-9A-Fa-f]+)` \| (\d+) \| ([^|]+?) \|/gm)) {
    found.set(Number(m[1]), { hex: m[2], dec: Number(m[3]), name: m[4] });
  }
  for (const b of calc.BITS) {
    const row = found.get(b.bit);
    assert.ok(row, `includes/etype-bits.md has no row for bit ${b.bit}`);
    assert.equal(row.name, b.name, `bit ${b.bit}`);
    assert.equal(row.dec, 2 ** b.bit, `bit ${b.bit}`);
    assert.equal(Number(row.hex), 2 ** b.bit, `bit ${b.bit}`);
  }
  assert.doesNotMatch(found.get(31).name, /future/i, "bit 31 must not be presented as the Future flag");
});

test("every preset is a value the setting can represent without warnings about itself", () => {
  for (const [id, setting] of Object.entries(calc.SETTINGS)) {
    for (const p of setting.presets) {
      assert.equal(calc.undefinedMask(p.value, id), 0, `${id} preset ${p.label}`);
      assert.equal(calc.effectiveValue(p.value, id), p.value >>> 0, `${id} preset ${p.label}`);
    }
  }
});

test("decoder example buttons and examples line up", () => {
  const doc = new JSDOM(toolMarkup(DECODER_MD, "event-decoder")).window.document;
  const buttons = Array.from(doc.querySelectorAll(".evdec-example-btn")).map((b) => b.dataset.example).sort();
  assert.deepEqual(buttons, Object.keys(dec.EXAMPLES).sort());
});

test("the element ids each script looks up exist in its page", () => {
  for (const [js, md, id] of [[CALC_JS, CALC_MD, "etype-calculator"], [DECODER_JS, DECODER_MD, "event-decoder"]]) {
    const doc = new JSDOM(toolMarkup(md, id)).window.document;
    const src = read(js);
    const ids = new Set();
    for (const m of src.matchAll(/["'](#(?:etype|evdec)-[a-z-]+)["']/g)) ids.add(m[1]);
    /* The calculator builds two selectors by concatenation. */
    if (id === "etype-calculator") { ids.delete("#etype-"); ids.add("#etype-dec"); ids.add("#etype-hex"); }
    assert.ok(ids.size > 5, `${js}: found only ${ids.size} selectors`);
    for (const sel of ids) assert.ok(doc.querySelector(sel), `${md} has no element ${sel} used by ${js}`);
  }
});

test("neither script assigns HTML strings", () => {
  for (const js of [CALC_JS, DECODER_JS]) {
    assert.doesNotMatch(read(js), /\.(innerHTML|outerHTML)\b|insertAdjacentHTML|document\.write/, js);
  }
});
