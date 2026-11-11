"use strict";

/* Shared test helpers: load the two tools into jsdom with the real markup
 * taken from the Markdown pages, so a test fails when markup and script drift
 * apart. */

const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const REPO = path.resolve(__dirname, "..", "..");
const CALC_JS = "content/javascripts/etype-calculator.js";
const DECODER_JS = "content/javascripts/event-decoder.js";
const CALC_MD = "content/security/etype-calculator.md";
const DECODER_MD = "content/security/event-decoder.md";

function read(rel) {
  return fs.readFileSync(path.join(REPO, rel), "utf8");
}

/** The raw HTML block of a tool: from <div id="…"> to the first "---" rule after it. */
function toolMarkup(mdFile, id) {
  const md = read(mdFile);
  const start = md.indexOf(`<div id="${id}">`);
  if (start === -1) throw new Error(`${mdFile}: no <div id="${id}">`);
  const end = md.indexOf("\n---", start);
  return md.substring(start, end);
}

/**
 * A jsdom window with one tool's markup and script, as a browser would have
 * after page load.  Uncaught errors and console.error output are collected.
 */
function loadTool(mdFile, id, jsFile, url) {
  const dom = new JSDOM(`<!doctype html><html><body>${toolMarkup(mdFile, id)}</body></html>`, {
    url,
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const errors = [];
  dom.window.console.error = (...args) => errors.push(args.map(String).join(" "));
  dom.window.addEventListener("error", (e) => errors.push(`uncaught: ${e.message}`));
  dom.window.eval(read(jsFile));
  const doc = dom.window.document;
  return {
    dom,
    win: dom.window,
    doc,
    errors,
    $: (sel) => doc.querySelector(sel),
    $$: (sel) => Array.from(doc.querySelectorAll(sel)),
    fire(el, type) {
      el.dispatchEvent(new dom.window.Event(type, { bubbles: true }));
    },
  };
}

function loadCalculator(url = "https://example.test/security/etype-calculator/") {
  return loadTool(CALC_MD, "etype-calculator", CALC_JS, url);
}

function loadDecoder(url = "https://example.test/security/event-decoder/") {
  return loadTool(DECODER_MD, "event-decoder", DECODER_JS, url);
}

/** Give Node a DOMParser so parseEventXml can run outside a window. */
function installDomParser() {
  if (!globalThis.DOMParser) globalThis.DOMParser = new JSDOM("").window.DOMParser;
}

module.exports = {
  REPO, CALC_JS, DECODER_JS, CALC_MD, DECODER_MD,
  read, toolMarkup, loadCalculator, loadDecoder, installDomParser,
};
