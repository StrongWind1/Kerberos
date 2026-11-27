"use strict";

/* The decoder reads event XML with its own reader, readXmlElement, so that
 * pasted text is never handed to a DOM parser.  These tests hold the reader to
 * what a DOM parser makes of the same text: jsdom's, on the built-in examples,
 * on documents built at random, and on all of them damaged at random. */

const test = require("node:test");
const assert = require("node:assert/strict");
const { JSDOM } = require("jsdom");
const { CALC_JS, DECODER_JS, REPO, loadDecoder, read } = require("./helpers");
const dec = require(`${REPO}/${DECODER_JS}`);

const EX = dec.EXAMPLES;
const DomParser = new JSDOM("").window.DOMParser;
const PARSER_ERROR_NS = "http://www.mozilla.org/newlayout/xml/parsererror.xml";

/** Characters by code, for the ones that should not sit in a source file as themselves. */
const chr = (...codes) => String.fromCharCode(...codes);

function byName(pairs) {
  return Object.fromEntries(pairs.sort((a, b) => (a[0] < b[0] ? -1 : 1)));
}

/** The elements a DOM parser finds, in document order, or null when the text is not well-formed. */
function viaDomParser(xml) {
  const doc = new DomParser().parseFromString(xml, "text/xml");
  const root = doc.documentElement;
  if (!root || root.namespaceURI === PARSER_ERROR_NS) return null;
  return Array.from(doc.getElementsByTagName("*"), (el) => ({
    name: el.tagName,
    local: el.localName,
    attributes: byName(Array.from(el.attributes, (a) => [a.name, a.value])),
    text: el.textContent,
  }));
}

/** The same from the decoder's reader, or null when it refuses the text. */
function viaReader(xml) {
  try {
    return dec.readXmlElement(xml).map((e) => ({
      name: e.name,
      local: e.local,
      attributes: byName(Object.keys(e.attributes).map((k) => [k, e.attributes[k]])),
      text: e.text,
    }));
  } catch (e) {
    if (!e.isDecodeError) throw e;
    return null;
  }
}

function refusal(xml) {
  try {
    dec.readXmlElement(xml);
  } catch (e) {
    assert.equal(e.isDecodeError, true, xml);
    return e.message;
  }
  return assert.fail("expected the reader to refuse " + JSON.stringify(xml));
}

/* ------------------------------------------------------------------ */
/*  Event XML in the forms it arrives in                               */
/* ------------------------------------------------------------------ */

test("an event reads the same however its XML is written", () => {
  const xml = EX["4768-success"];
  const want = dec.parseEvent(xml);
  const variants = {
    "single quotes, as wevtutil writes": xml.replace(/"/g, "'"),
    "one element per line, indented": xml.replace(/></g, ">\r\n    <"),
    "space inside tags": xml.replace(/<Data Name=/g, "<Data\tName = ").replace(/<\/Data>/g, "</Data\n>").replace(/\/>/g, " />"),
    "empty fields as empty elements": xml.replace(/<Data Name="(Cert\w+)"><\/Data>/g, '<Data Name="$1"/>'),
    "comments and a processing instruction": xml.replace("<EventData>", "<!-- exported 2026 --><?export tool?><EventData><!--fields-->"),
    "values in CDATA sections": xml.replace(/(<Data Name="\w+">)([^<]+)(<\/Data>)/g, "$1<![CDATA[$2]]>$3"),
    "values as character references": xml.replace(">DC1$<", ">&#68;&#x43;1&#x24;<").replace(">krbtgt<", ">&#x6B;rbtgt<"),
    "a namespace prefix on every element inside": xml
      .replace("<Event ", '<Event xmlns:e="http://schemas.microsoft.com/win/2004/08/events/event" ')
      .replace(/<(\/?)(?!\/?Event[ >])(\w)/g, "<$1e:$2"),
    "no namespace": xml.replace(/ xmlns="[^"]*"/, ""),
  };
  for (const [label, input] of Object.entries(variants)) {
    assert.notEqual(input, xml, label + ": the variant is not the example itself");
    const got = dec.parseEvent(input);
    for (const key of ["eventId", "time", "computer", "fields", "fieldOrder"]) {
      assert.deepEqual(got[key], want[key], `${label}: ${key}`);
    }
  }
});

test("field text is everything inside the element, with references resolved", () => {
  const field = (inner, extra = "") => dec.parseEvent(
    EX["4769-success"].replace('<Data Name="ServiceName">DC1$</Data>', `<Data Name="ServiceName"${extra}>${inner}</Data>`),
  ).fields.ServiceName;
  assert.equal(field("a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"), "a & b <c> \"d\" 'e'");
  assert.equal(field("&#955;&#x3BB;&#x1F600;"), "λλ" + chr(0xD83D, 0xDE00));
  assert.equal(field("x<![CDATA[<y> & ]] ]]>z"), "x<y> & ]] z");
  assert.equal(field("a<b>b<c/>c</b>d<!-- no -->e<?no no?>f"), "abcdef");
  assert.equal(field("  spaced\n"), "spaced");
  assert.equal(field("v", " Other='&lt;1&#9;2&gt;'"), "v");
  /* The first Data element of a name wins, as it did with a DOM parser. */
  assert.equal(field('first</Data><Data Name="ServiceName">second'), "first");
});

/* ------------------------------------------------------------------ */
/*  The reader against a DOM parser                                    */
/* ------------------------------------------------------------------ */

/** A small seeded generator (mulberry32): the documents are the same on every run. */
function random(seed) {
  let a = seed;
  return () => {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Well-formed documents that use every construct the reader knows. */
function documentMaker(rand) {
  const pick = (list) => list[Math.floor(rand() * list.length)];
  const chance = (p) => rand() < p;
  const upTo = (max) => Math.floor(rand() * (max + 1));
  const space = () => pick(["", "", " ", "  ", "\n", "\t", " \n "]);
  const space1 = () => pick([" ", " ", "  ", "\n", "\t", "\r\n"]);

  const names = ["Event", "System", "EventData", "Data", "EventID", "TimeCreated", "Computer", "a", "b-c", "d.e", "_f", "él", "x1", "中", "A" + chr(0xB7) + "b", chr(0xD840, 0xDC00) + "n"];
  const attributeNames = ["Name", "SystemTime", "Guid", "id", "a-b", "_c", "d.1", "é"];
  const textPieces = ["text", "0x12", " ", "\n", "\t", "&amp;", "&lt;", "&gt;", "&quot;", "&apos;", "&#65;", "&#x1F600;", "&#9;", "&#xA;", "&#13;", "é", chr(0xD83D, 0xDE00), ">", "'", "\"", "]]", "]", "-", "--", "=", "/", "a b", "\r\n"];
  const cdataPieces = ["<", "&", "]]", "]", ">", "x", "&amp;", "<a>", "</a>", "<!--", "\n"];
  const commentPieces = ["c", " ", "-", " - ", "<", "&", ">", "]]>", "<a>", "\n"];
  const some = (pieces) => Array.from({ length: upTo(4) }, () => pick(pieces)).join("");

  /* No ]]> in text, and none formed with the text that follows. */
  const text = () => some(textPieces).replace(/\]\]>/g, "]] >").replace(/\]$/, "] ");
  const value = (quote) => some(textPieces).split(quote).join(quote === "\"" ? "&quot;" : "&apos;");
  const cdata = () => "<![CDATA[" + some(cdataPieces).replace(/\]\]>/g, "]]") + "]]>";
  const comment = () => "<!--" + some(commentPieces).replace(/--+/g, "-").replace(/-$/, "- ") + "-->";
  const instruction = () => "<?" + pick(["pi", "x-y", "_t", "xml-stylesheet", "xm"])
    + (chance(0.5) ? "" : space1() + pick(["data", "a=\"b\"", "? >", "<&>", ""])) + "?>";

  function element(depth, inherited) {
    let prefixes = inherited;
    const attributes = [];
    const used = new Set();
    const add = (name, fixed) => {
      if (used.has(name)) return;
      used.add(name);
      attributes.push([name, fixed]);
    };
    if (chance(0.15)) {
      const prefix = pick(["p", "q", "ns1"]);
      prefixes = [...new Set([...inherited, prefix])];
      add("xmlns:" + prefix, `urn:${prefix}:${upTo(3)}`);
    }
    if (chance(0.15)) add("xmlns", pick(["http://schemas.microsoft.com/win/2004/08/events/event", "urn:d", ""]));
    /* One prefix per element, so that no two attributes are the same one under two prefixes. */
    const attributePrefix = prefixes.length > 0 && chance(0.3) ? pick(prefixes) + ":" : "";
    for (let n = upTo(3); n > 0; n--) add((chance(0.3) ? attributePrefix : "") + pick(attributeNames), null);
    if (chance(0.05)) add("xml:lang", "en");

    const name = (prefixes.length > 0 && chance(0.3) ? pick(prefixes) + ":" : "") + pick(names);
    let out = "<" + name;
    for (const [attribute, fixed] of attributes) {
      const quote = pick(["\"", "\"", "'"]);
      out += space1() + attribute + space() + "=" + space() + quote + (fixed === null ? value(quote) : fixed) + quote;
    }
    if (chance(0.2)) return out + space() + "/>";
    out += space() + ">";
    for (let n = upTo(depth > 3 ? 1 : 4); n > 0; n--) {
      const kind = rand();
      if (kind < 0.4) out += text();
      else if (kind < 0.75 && depth < 5) out += element(depth + 1, prefixes);
      else if (kind < 0.85) out += cdata();
      else if (kind < 0.93) out += comment();
      else out += instruction();
    }
    return out + "</" + name + space() + ">";
  }

  return () => (chance(0.1) ? pick([" ", "\n", comment(), instruction()]) : "")
    + element(0, [])
    + (chance(0.1) ? pick([" ", "\n", comment(), instruction()]) : "");
}

/* What damage is made of: the characters XML gives a meaning to, whole pieces
   of markup, references good and bad, and characters XML does not allow. */
const DAMAGE = [
  "<", ">", "&", ";", "\"", "'", "=", "/", "!", "?", "-", "[", "]", "#", "x", ":", " ", "\n", "\t", "\r",
  "a", "Z", "0", "9", "_", ".", "é", chr(0xB7), chr(0x300), chr(0x1), chr(0xB), chr(0xFFFE), chr(0xD83D), chr(0xDE00), chr(0xD83D, 0xDE00),
  "]]>", "--", "<!--", "-->", "<![CDATA[", "<?", "?>", "</", "/>",
  "&amp;", "&#x41;", "&#0;", "&#xD800;", "&#x110000;", "&#65", "&lt;", "&bogus;", "&;", "&#;", "&#x;",
  "xmlns", "xmlns:", "xml:", "p:", 'xmlns:p="urn:p:0"', 'xmlns:xml="http://www.w3.org/XML/1998/namespace"', 'xmlns="http://www.w3.org/2000/xmlns/"',
  "<a>", "</a>", "<a/>", "<?xml?>", "<?XML x?>", "<!x>", ' Name="Status"', " a='b'", "<Data>", "</Data>", "</Event>", "<Event>",
];

/** One or two random edits: a character removed, swapped or replaced, a run cut out or doubled, a piece put in. */
function damage(xml, rand) {
  let out = xml;
  for (let edits = 1 + Math.floor(rand() * 2); edits > 0; edits--) {
    const i = Math.floor(rand() * (out.length + 1));
    const piece = DAMAGE[Math.floor(rand() * DAMAGE.length)];
    const run = 1 + Math.floor(rand() * 12);
    const kind = Math.floor(rand() * 6);
    if (kind === 0) out = out.slice(0, i) + out.slice(i + 1);
    else if (kind === 1) out = out.slice(0, i) + piece + out.slice(i);
    else if (kind === 2) out = out.slice(0, i) + piece + out.slice(i + 1);
    else if (kind === 3) out = out.slice(0, i) + out.slice(i + run);
    else if (kind === 4) out = out.slice(0, i + run) + out.slice(i, i + run) + out.slice(i + run);
    else out = out.slice(0, i) + out.charAt(i + 1) + out.charAt(i) + out.slice(i + 2);
  }
  return out;
}

/* jsdom's parser lets a processing instruction's name run straight into a "?"
   that does not close it (<?a?b?>).  XML requires white space there, the reader
   refuses it, and so does Chrome's parser; such text is left out of the comparison. */
const PARSER_IS_LAX = /<\?[^ \t\r\n?>]*\?(?!>)/;

test("the reader and a DOM parser read random and damaged documents alike", () => {
  const rand = random(20261127);
  const make = documentMaker(rand);
  const bases = [...Object.values(EX), EX["4769-success"].replace(/"/g, "'")].map((xml) => ({ xml, copies: 150 }));
  for (let n = 0; n < 150; n++) bases.push({ xml: make(), copies: 20 });

  const seen = { wellFormed: 0, refused: 0, leftOut: 0 };
  const compare = (xml, label) => {
    if (PARSER_IS_LAX.test(xml)) {
      seen.leftOut++;
      return;
    }
    const want = viaDomParser(xml);
    assert.deepEqual(viaReader(xml), want, `${label}: ${JSON.stringify(xml)}`);
    seen[want === null ? "refused" : "wellFormed"]++;
  };

  bases.forEach(({ xml, copies }, n) => {
    assert.notEqual(viaDomParser(xml), null, `document ${n} is well-formed: ${JSON.stringify(xml)}`);
    compare(xml, `document ${n}`);
    for (let m = 0; m < copies; m++) compare(damage(xml, rand), `document ${n}, damaged copy ${m}`);
  });

  /* The comparison means something only while both outcomes are well represented. */
  assert.ok(seen.wellFormed > 800, JSON.stringify(seen));
  assert.ok(seen.refused > 2000, JSON.stringify(seen));
  assert.ok(seen.leftOut < 20, JSON.stringify(seen));
});

/* ------------------------------------------------------------------ */
/*  What the reader refuses                                            */
/* ------------------------------------------------------------------ */

test("text that is not well-formed is refused, and the message says what is wrong", () => {
  const cases = [
    ["<a><b></a>", /<\/a> closes <b>/],
    ["<a><b>", /<b> is never closed/],
    ["<a></a></a>", /<\/a> closes nothing/],
    ["<a/><b/>", /second outermost element/],
    ["<a/>text", /text after the closing tag/],
    ["text<a/>", /text before the first tag/],
    ["", /there is no element/],
    ["<a", /the tag <a is not finished/],
    ["<a b></a>", /attribute b of <a> has no value/],
    ["<a b=c></a>", /attribute b of <a> is not in quotes/],
    ['<a b="c></a>', /attribute b of <a> has no closing quote/],
    ['<a b="1"c="2"/>', /neither an attribute nor its end/],
    ['<a b="1" b="2"/>', /attribute b appears twice in <a>/],
    ['<a xmlns:p="urn:x" xmlns:q="urn:x" p:b="1" q:b="2"/>', /attribute q:b appears twice in <a>/],
    ['<a b="<"/>', /holds a <, which is written &lt;/],
    ["<a>1 < 2</a>", /a < that does not begin a tag/],
    ["<a>AT&T</a>", /an & that does not begin an entity or a character reference/],
    ["<a>&nbsp;</a>", /the entity &nbsp; is not defined/],
    ["<a>&#0;</a>", /&#0; does not name a character that XML allows/],
    ["<a>&#xD800;</a>", /&#xD800; does not name a character/],
    ["<a>&#x110000;</a>", /&#x110000; does not name a character/],
    ["<a>&#X41;</a>", /does not begin an entity or a character reference/],
    ["<a>" + chr(0x1) + "</a>", /a character that XML does not allow/],
    ["<a>" + chr(0xFFFE) + "</a>", /a character that XML does not allow/],
    ["<a>]]></a>", /holds \]\]>/],
    ["<a><!-- b -- c --></a>", /a comment holds --/],
    ["<a><!-- b</a>", /a comment is not closed/],
    ["<a><![CDATA[b</a>", /a CDATA section is not closed/],
    ["<![CDATA[b]]><a/>", /a CDATA section is outside/],
    ["<a><?b</a>", /a processing instruction is not closed/],
    ["<a><? b?></a>", /a processing instruction has no name/],
    ["<a><?b?c?></a>", /not followed by white space/],
    ["<a><?b:c?></a>", /holds a colon/],
    ["<a><?xml version='1.0'?></a>", /XML declaration/],
    ["<a><!ELEMENT b></a>", /<! declaration is not allowed/],
    ["<p:a/>", /namespace prefix of <p:a> is not declared/],
    ['<a p:b="1"/>', /namespace prefix of the attribute p:b is not declared/],
    ['<a><p:b xmlns:p="urn:p"/><p:c/></a>', /namespace prefix of <p:c> is not declared/],
    ["<a:b:c/>", /not a namespace prefix, one colon and a name/],
    ['<xmlns:a xmlns:xmlns="urn:x"/>', /reserved/],
    ['<a xmlns:p=""/>', /xmlns:p has no namespace name/],
    ['<a xmlns:xml="urn:x"/>', /reserved/],
    ['<a xmlns="http://www.w3.org/2000/xmlns/"/>', /reserved/],
    ["<1a/>", /a < that does not begin a tag/],
    ["< a/>", /a < that does not begin a tag/],
    ["</>", /a closing tag has no name/],
  ];
  for (const [xml, pattern] of cases) {
    const message = refusal(xml);
    assert.match(message, /^Invalid XML: /, xml);
    assert.match(message, pattern, xml);
    if (!PARSER_IS_LAX.test(xml)) assert.equal(viaDomParser(xml), null, `a DOM parser refuses it too: ${xml}`);
  }
});

test("a DOCTYPE is refused wherever it is, before anything is read", () => {
  const xml = EX["4768-success"];
  for (const input of [
    xml.replace("<System>", "<!DOCTYPE x><System>"),
    xml.replace("<System>", '<!doctype x [<!ENTITY e "x">]><System>'),
    xml.replace("<System>", "<!-- <!ENTITY e 'x'> --><System>"),
  ]) {
    assert.throws(() => dec.parseEvent(input), (e) => e.isDecodeError && /DOCTYPE\/ENTITY declarations are not allowed/.test(e.message));
  }
});

test("half of a surrogate pair is read as U+FFFD, as a browser reads it", () => {
  for (const half of [chr(0xD83D), chr(0xDE00)]) {
    const xml = `<a b="${half}">${half}${half}</a>`;
    const fffd = chr(0xFFFD);
    assert.deepEqual(viaReader(xml), [{ name: "a", local: "a", attributes: { b: fffd }, text: fffd + fffd }]);
    assert.deepEqual(viaReader(xml), viaDomParser(xml));
  }
  const pair = chr(0xD83D, 0xDE00);
  assert.equal(viaReader(`<a>${pair}</a>`)[0].text, pair);
});

test("deep nesting does not slow the reader down", () => {
  /* A reader that built each element's text as it went, or looked a prefix up
     through every enclosing element, would need minutes for these. */
  const depth = 200000;
  let elements = dec.readXmlElement("<a>x".repeat(depth) + "</a>".repeat(depth));
  assert.equal(elements.length, depth);
  assert.equal(elements[0].text, "x".repeat(depth));
  assert.equal(elements[depth - 1].text, "x");

  elements = dec.readXmlElement('<p:a xmlns:p="urn:p" p:b="1">y'.repeat(depth) + "</p:a>".repeat(depth));
  assert.equal(elements.length, depth);
  assert.equal(elements[depth - 2].text, "yy");
  assert.equal(elements[depth - 1].attributes["p:b"], "1");

  /* A prefix is in scope inside the element that declares it, and nowhere else. */
  assert.match(refusal('<a><b xmlns:p="urn:p"><p:c/></b><p:d/></a>'), /prefix of <p:d> is not declared/);
  assert.match(refusal('<a><b xmlns:p="urn:p"/><p:d/></a>'), /prefix of <p:d> is not declared/);
});

test("a message never repeats an endless name", () => {
  const message = refusal("<" + "n".repeat(100000) + "></x>");
  assert.match(message, /^Invalid XML: <\/x> closes <nnn/);
  assert.ok(message.length < 400, String(message.length));
});

/* ------------------------------------------------------------------ */
/*  No DOM parser                                                      */
/* ------------------------------------------------------------------ */

test("neither script hands text to a DOM parser", () => {
  for (const js of [CALC_JS, DECODER_JS]) {
    assert.doesNotMatch(read(js), /DOMParser|parseFromString|createContextualFragment|XMLHttpRequest|createHTMLDocument/, js);
  }
});

test("the page decodes with no DOM parser to call", () => {
  const shared = dec.buildShareHash(EX["4771-failure"]);
  const t = loadDecoder("https://example.test/security/event-decoder/" + shared, (win) => {
    win.DOMParser = function DOMParser() {
      throw new Error("a DOM parser was called");
    };
  });
  assert.match(t.$("#evdec-header").textContent, /4771/, "the shared event is decoded on load");
  for (const xml of Object.values(EX)) {
    t.$("#evdec-xml").value = xml;
    t.$("#evdec-decode").click();
    assert.equal(t.$("#evdec-error").style.display, "none");
    assert.equal(t.$("#evdec-results").style.display, "block");
  }
  t.$("#evdec-xml").value = EX["4768-success"].replace("</EventData>", "</EventDataX>");
  t.$("#evdec-decode").click();
  assert.match(t.$("#evdec-error").textContent, /^Invalid XML: <\/EventDataX> closes <EventData>\.$/);
  assert.deepEqual(t.errors, []);
});
