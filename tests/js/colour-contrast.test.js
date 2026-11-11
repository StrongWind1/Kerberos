"use strict";

/* Every text colour the two tools use must reach WCAG AAA contrast (7:1) on
 * every surface it is drawn on, in both colour schemes.  The colours live in
 * content/stylesheets/theme.css; this test recomputes each pair from that
 * file, so a palette edit that drops below 7:1 fails here rather than in a
 * manual audit. */

const test = require("node:test");
const assert = require("node:assert/strict");
const { read } = require("./helpers");

const THEME = "content/stylesheets/theme.css";
const EXTRA = "content/stylesheets/extra.css";
const AAA = 7;
const NON_TEXT = 3;

/* Surfaces Material paints, which theme.css does not define.  Slate values
 * are Material's hsla(var(--md-hue), 15%, 14%) and (…, 15%, 18%) at the
 * --md-hue: 225deg set in theme.css. */
const SURFACES = {
  default: { page: "#ffffff", code: "#f5f5f5" },
  slate: { page: "#1e2129", code: "#272a35" },
};

function parseHex(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  assert.ok(m, `not a 6-digit hex colour: ${hex}`);
  return [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16));
}
function luminance(hex) {
  const [r, g, b] = parseHex(hex).map((v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a, b) {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** Custom properties declared in every rule whose selector matches `selector`. */
function declarations(css, selector) {
  const vars = {};
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(css.replace(/\/\*[\s\S]*?\*\//g, ""))) !== null) {
    if (m[1].trim() !== selector) continue;
    for (const d of m[2].matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) vars[d[1]] = d[2].trim();
  }
  return vars;
}

const css = read(THEME);
const shared = declarations(css, ":root > *");
const palettes = {
  default: { ...shared, ...declarations(css, '[data-md-color-scheme="default"]') },
  slate: { ...shared, ...declarations(css, '[data-md-color-scheme="slate"]') },
};

/* [text colour, background] - a background is a variable or a surface name. */
const TEXT_PAIRS = [
  ["--md-primary-bg-color", "--md-primary-fg-color"],
  /* Material's own foregrounds, restated in theme.css as opaque colours. */
  ["--md-default-fg-color", "page"],
  ["--md-default-fg-color", "code"],
  ["--md-default-fg-color--light", "page"],
  ["--md-default-fg-color--light", "code"],
  ["--md-default-fg-color--lighter", "page"],
  ["--md-default-fg-color--lighter", "code"],
  ["--md-code-hl-number-color", "code"],
  ["--md-code-hl-special-color", "code"],
  ["--md-code-hl-function-color", "code"],
  ["--md-code-hl-constant-color", "code"],
  ["--md-code-hl-keyword-color", "code"],
  ["--md-code-hl-string-color", "code"],
  ["--md-default-fg-color", "--md-typeset-mark-color"],
  ["--md-footer-fg-color--light", "--md-footer-bg-color"],
  ["--md-footer-fg-color--lighter", "--md-footer-bg-color"],
  ["--md-accent-fg-color", "page"],
  ["--md-accent-fg-color", "code"],
  ["--md-typeset-a-color", "page"],
  ["--md-typeset-a-color", "code"],
  ["--md-accent-bg-color", "--md-accent-fg-color"],
  ["--tool-muted", "page"],
  ["--tool-muted", "code"],
  ["--tool-note", "page"],
  ["--tool-note", "code"],
  ["--tool-alert", "page"],
  ["--tool-caution", "--tool-caution-bg"],
  ["--tool-ok-fg", "--tool-ok-bg"],
  ["--tool-warn-fg", "--tool-warn-bg"],
  ["--tool-bad-fg", "--tool-bad-bg"],
  ["--tool-info-fg", "--tool-info-bg"],
  ["--tool-feature-fg", "--tool-feature-bg"],
  ["--tool-neutral-fg", "--tool-neutral-bg"],
  ["--tool-solid-fg", "--tool-solid-ok-bg"],
  ["--tool-solid-fg", "--tool-solid-bad-bg"],
];

/* Borders and focus rings that carry meaning need 3:1 against the page. */
const NON_TEXT_PAIRS = [
  ["--tool-control-border", "page"],
  ["--tool-control-border", "code"],
  ["--md-accent-fg-color", "page"],
  ["--tool-caution-border", "page"],
];

function resolve(scheme, name) {
  if (name in SURFACES[scheme]) return SURFACES[scheme][name];
  const v = palettes[scheme][name];
  assert.ok(v, `${scheme}: ${name} is not defined in ${THEME}`);
  /* A transparent background shows the page through it. */
  return v === "transparent" ? SURFACES[scheme].page : v;
}

for (const scheme of ["default", "slate"]) {
  test(`${scheme} scheme: every text pair is AAA (>= ${AAA}:1)`, () => {
    const report = [];
    for (const [fg, bg] of TEXT_PAIRS) {
      const ratio = contrast(resolve(scheme, fg), resolve(scheme, bg));
      report.push(`${ratio.toFixed(2).padStart(6)}  ${fg} on ${bg}`);
      assert.ok(ratio >= AAA, `${scheme}: ${fg} (${resolve(scheme, fg)}) on ${bg} (${resolve(scheme, bg)}) is ${ratio.toFixed(2)}:1`);
    }
    if (process.env.CONTRAST_REPORT) console.log(`\n${scheme}\n${report.join("\n")}`);
  });

  test(`${scheme} scheme: control borders and focus rings are visible (>= ${NON_TEXT}:1)`, () => {
    for (const [fg, bg] of NON_TEXT_PAIRS) {
      const ratio = contrast(resolve(scheme, fg), resolve(scheme, bg));
      assert.ok(ratio >= NON_TEXT, `${scheme}: ${fg} on ${bg} is ${ratio.toFixed(2)}:1`);
    }
  });
}

test("the tool stylesheet takes every colour from the palette", () => {
  const extra = read(EXTRA).replace(/\/\*[\s\S]*?\*\//g, "");
  assert.deepEqual(extra.match(/#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(/g) || [], [], "colour literal in extra.css");
  /* Material's dimmed foregrounds are below AA; opacity dims text invisibly to checkers. */
  assert.doesNotMatch(extra, /--md-default-fg-color--(light|lighter|lightest)/);
  assert.doesNotMatch(extra, /opacity:\s*0?\.\d/);

  /* Every palette variable the stylesheet uses exists in both schemes. */
  const used = new Set(extra.match(/--tool-[a-z-]+/g));
  assert.ok(used.size > 15);
  for (const name of used) {
    for (const scheme of ["default", "slate"]) assert.ok(palettes[scheme][name], `${scheme}: ${name} used in ${EXTRA} but not defined`);
  }
});
