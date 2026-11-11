/* Kerberos -- layout for wide content: tables, diagrams, long identifiers.
 *
 * Three things the stylesheet cannot do on its own, each a small pass over
 * the article after it is rendered (and again after every instant
 * navigation, and after the theme has drawn the Mermaid diagrams):
 *
 *   1. Break points in long identifiers.  "DefaultDomainSupportedEncTypes"
 *      has no place a browser may wrap it, so a narrow table column or a
 *      phone-width heading either overflowed or split it mid-word.  A <wbr>
 *      is inserted at each word boundary inside it; <wbr> adds no character,
 *      so copying, searching and double-click selection see the same text.
 *
 *   2. Tables.  When a table is far too wide for the room it has, each
 *      column that holds sentences gets a minimum width from its longest
 *      cell, so the table scrolls sideways instead of stacking a paragraph
 *      four words wide.  The scrolling wrapper then
 *      becomes a labelled, focusable region (arrow keys scroll it), reports
 *      where it is scrolled to so extra.css can fade the edge that has more
 *      beyond it, and keeps a narrow first column in view.
 *
 *   3. Diagrams.  The theme scales every Mermaid diagram down to the column
 *      width, which took some to 4px text.  One that would shrink below
 *      FIT_SCALE of its natural size is drawn at SCROLL_SCALE instead and
 *      scrolls like a wide table.  A few colours the theme's diagram
 *      stylesheet misses are corrected inside the diagram's shadow tree,
 *      which hooks/mermaid_bundle.py opens for this purpose.
 *
 * No colour is defined here: the corrections below only point at the
 * variables the theme already uses for the neighbouring parts of a diagram.
 */

(function () {
  "use strict";

  /* ================================================================ */
  /*  1. Break points in long identifiers                              */
  /* ================================================================ */

  /* Shortest run of non-space characters worth marking, and the shortest
     piece a break may leave on either side of it. */
  var LONG_RUN = 14;
  var MIN_PIECE = 3;
  var SEPARATORS = "\\/_.:=,;";
  var BREAKABLE =
    ".md-typeset table:not([class]) th:not([data-breaks]), " +
    ".md-typeset table:not([class]) td:not([data-breaks]), " +
    ".md-typeset h1:not([data-breaks]), .md-typeset h2:not([data-breaks]), " +
    ".md-typeset h3:not([data-breaks]), .md-typeset h4:not([data-breaks])";
  var SKIP = "pre, script, style, textarea, svg, .headerlink";

  function isUpper(c) { return c >= "A" && c <= "Z"; }
  function isLower(c) { return c >= "a" && c <= "z"; }
  function isDigit(c) { return c >= "0" && c <= "9"; }

  /** Offsets inside `word` where a line may break: after a separator, and at
      camelCase and ACRONYMWord boundaries. */
  function breakPoints(word) {
    var points = [];
    var last = 0;
    for (var i = 1; i < word.length; i++) {
      var a = word.charAt(i - 1);
      var b = word.charAt(i);
      var afterSeparator = SEPARATORS.indexOf(a) !== -1 && SEPARATORS.indexOf(b) === -1;
      var camel = (isLower(a) || isDigit(a)) && isUpper(b);
      var acronym = isUpper(a) && isUpper(b) && isLower(word.charAt(i + 1));
      if ((afterSeparator || camel || acronym) && i - last >= MIN_PIECE && word.length - i >= MIN_PIECE) {
        points.push(i);
        last = i;
      }
    }
    return points;
  }

  function markText(node) {
    var text = node.nodeValue;
    var offsets = [];
    var re = /\S+/g;
    var match;
    while ((match = re.exec(text)) !== null) {
      if (match[0].length < LONG_RUN) continue;
      var points = breakPoints(match[0]);
      for (var i = 0; i < points.length; i++) offsets.push(match.index + points[i]);
    }
    /* Back to front, so earlier offsets stay valid as the node is split. */
    for (var j = offsets.length - 1; j >= 0; j--) {
      var tail = node.splitText(offsets[j]);
      tail.parentNode.insertBefore(document.createElement("wbr"), tail);
    }
  }

  function markBreaks(scope) {
    var elements = scope.querySelectorAll(BREAKABLE);
    for (var i = 0; i < elements.length; i++) {
      var element = elements[i];
      element.setAttribute("data-breaks", "");
      var walker = document.createTreeWalker(element, window.NodeFilter.SHOW_TEXT);
      var nodes = [];
      while (walker.nextNode()) {
        if (!walker.currentNode.parentElement.closest(SKIP)) nodes.push(walker.currentNode);
      }
      nodes.forEach(markText);
    }
  }

  /* ================================================================ */
  /*  Regions that scroll sideways (shared by tables and diagrams)     */
  /* ================================================================ */

  /** Keep `region` focusable, labelled and marked with its scroll position
      for as long as its content is wider than it is.  `hooks.fit` runs when
      the region or its content changes size, to adjust the content to the
      width now available; `hooks.after` runs on every update with whether
      the region scrolls.  Scrolling itself never refits: changing the
      content's width under the reader would move what they are looking at. */
  function trackScroll(region, label, watched, hooks) {
    function update() {
      var max = region.scrollWidth - region.clientWidth;
      var scrolls = max > 1;
      if (scrolls) {
        var x = Math.abs(region.scrollLeft);
        region.setAttribute("data-scroll", x <= 1 ? "start" : x >= max - 1 ? "end" : "middle");
        region.setAttribute("tabindex", "0");
        region.setAttribute("role", "group");
        region.setAttribute("aria-label", label);
      } else if (region.hasAttribute("data-scroll")) {
        ["data-scroll", "tabindex", "role", "aria-label"].forEach(function (name) { region.removeAttribute(name); });
      }
      if (hooks.after) hooks.after(scrolls);
    }
    function refit() {
      if (hooks.fit) hooks.fit();
      update();
    }
    region.addEventListener("scroll", update, { passive: true });
    if (window.ResizeObserver) {
      var observer = new window.ResizeObserver(refit);
      observer.observe(region);
      if (watched) observer.observe(watched);
    }
    refit();
  }

  /* ================================================================ */
  /*  2. Tables                                                        */
  /* ================================================================ */

  /* A column of sentences is comfortable at N / CHARS_PER_EM em for a longest
     cell of N characters, capped at MAX_FLOOR_EM: wide enough that the cell
     wraps to about four lines (an em holds two characters or so) rather
     than twenty.  Columns that would get less than MIN_FLOOR_EM are left to
     the browser. */
  var CHARS_PER_EM = 8;
  var MIN_FLOOR_EM = 6;
  var MAX_FLOOR_EM = 18;
  /* Those widths become minimums only when the table would need more than
     this multiple of the room it has to reach them.  Up to that point the
     browser squeezes the columns a little and the table still fits; past it
     the table scrolls sideways at the comfortable widths.  Without the
     margin a table 50px too wide would scroll for those 50px. */
  var SQUEEZE_LIMIT = 1.25;
  /* The first column stays in view only if it leaves this much of the
     visible width for the columns that scroll. */
  var PIN_MAX_SHARE = 0.4;

  /** Record on each header cell the comfortable width of its column, in em. */
  function measureColumns(table) {
    var head = table.tHead && table.tHead.rows[0];
    var body = table.tBodies[0];
    if (!head || !body) return;
    for (var c = 0; c < head.cells.length; c++) {
      var longest = 0;
      for (var r = 0; r < body.rows.length; r++) {
        var cell = body.rows[r].cells[c];
        if (cell && cell.colSpan === 1) longest = Math.max(longest, cell.textContent.trim().length);
      }
      var comfortable = Math.min(MAX_FLOOR_EM, Math.round(longest / CHARS_PER_EM));
      if (comfortable >= MIN_FLOOR_EM && head.cells[c].colSpan === 1) head.cells[c].setAttribute("data-comfortable", comfortable);
    }
  }

  /** Width the wrapper offers the table: its own, less the gutter Material
      puts either side of the table inside it. */
  function availableWidth(wrap, table) {
    var style = window.getComputedStyle(table.parentElement);
    return wrap.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
  }

  /** Decide, for `available` px of room, whether the comfortable widths
      apply as minimums (see SQUEEZE_LIMIT). */
  function fitColumns(table, available) {
    var head = table.tHead && table.tHead.rows[0];
    if (!head || !head.querySelector("[data-comfortable]")) return;
    var cells = Array.prototype.slice.call(head.cells);
    cells.forEach(function (cell) { cell.style.minWidth = ""; });

    var em = parseFloat(window.getComputedStyle(head.cells[0]).fontSize);
    var needed = 0;
    cells.forEach(function (cell) {
      needed += Math.max(cell.offsetWidth, (Number(cell.getAttribute("data-comfortable")) || 0) * em);
    });
    if (needed <= available * SQUEEZE_LIMIT) return;
    cells.forEach(function (cell) {
      if (cell.hasAttribute("data-comfortable")) cell.style.minWidth = cell.getAttribute("data-comfortable") + "em";
    });
  }

  function trackTable(wrap) {
    var table = wrap.querySelector("table");
    if (!table) return;
    wrap.setAttribute("data-tracked", "");
    measureColumns(table);
    var fittedFor = -1;
    trackScroll(wrap, "Table, scrolls sideways", table, {
      /* Only when the room changes: applying the minimums resizes the table,
         which reports here again, and that second report must be a no-op. */
      fit: function () {
        var available = availableWidth(wrap, table);
        if (available === fittedFor) return;
        fittedFor = available;
        fitColumns(table, available);
      },
      after: function (scrolls) {
        var first = table.rows[0] && table.rows[0].cells[0];
        var pin = scrolls && first && first.offsetWidth <= wrap.clientWidth * PIN_MAX_SHARE;
        if (pin) wrap.setAttribute("data-pin", "");
        else wrap.removeAttribute("data-pin");
      },
    });
  }

  function enhanceTables(scope) {
    var wraps = scope.querySelectorAll(".md-typeset__scrollwrap:not([data-tracked])");
    for (var i = 0; i < wraps.length; i++) trackTable(wraps[i]);
  }

  /* ================================================================ */
  /*  3. Diagrams                                                      */
  /* ================================================================ */

  /* Mermaid lays text out at 16px.  A diagram is shrunk to fit the column as
     long as that leaves it at FIT_SCALE or more of its natural size (10.4px
     text, about the smallest text elsewhere on the site).  Below that it is
     drawn at SCROLL_SCALE instead (12.8px, the size of table text) and the
     reader scrolls it sideways.  Two thresholds rather than one, so that a
     diagram a few pixels too wide shrinks a little instead of gaining a
     scrollbar for those few pixels. */
  var FIT_SCALE = 0.65;
  var SCROLL_SCALE = 0.8;

  var DIAGRAM_KINDS = {
    sequence: "Sequence diagram",
    "flowchart-v2": "Flowchart",
    flowchart: "Flowchart",
  };

  /* Added inside each diagram's shadow tree, after the theme's own rules.
     Mermaid 11 prefixes every marker id with the diagram id
     ("__mermaid_0-arrowhead"); the theme still selects "#arrowhead", so its
     colours never reach them and Mermaid's built-in #333 and black show
     through -- invisible on the dark scheme.  !important because Mermaid's
     own rules carry the diagram id and outrank anything written here. */
  var LINE = "var(--md-mermaid-sequence-message-line-color)";
  var EDGE = "var(--md-mermaid-edge-color)";
  var DIAGRAM_FIXES = [
    "svg { display: block; }",
    /* Sequence diagrams: arrowheads and the other line endings. */
    'marker[id$="-arrowhead"] path, marker[id$="-filled-head"] path, marker[id$="ArrowHead"]:not([id*="stick"]) path' +
      " { fill: " + LINE + " !important; stroke: none !important; }",
    'marker[id$="-crosshead"] path, marker[id*="-stick"] path { stroke: ' + LINE + " !important; }",
    'marker[id$="-sequencenumber"] { fill: var(--md-mermaid-sequence-number-bg-color) !important; }',
    /* Sequence diagrams: the label of every alt/else/par section after the
       first is a .sectionTitle, which the theme does not colour. */
    ".sectionTitle, .sectionTitle > tspan { fill: var(--md-mermaid-sequence-loop-fg-color) !important;" +
      " font-family: var(--md-mermaid-font-family) !important; stroke: none !important; }",
    /* Flowcharts: the outline of each arrowhead. */
    ".arrowMarkerPath { stroke: " + EDGE + " !important; }",
    /* Flowcharts: a node given its own colours with `style X fill:..,color:..`
       carries that text colour on the label <span>; the theme colours the <p>
       inside it directly, so the node's own colour never showed and dark fills
       had dark text on the light scheme. */
    ".nodeLabel p { color: inherit !important; }",
    "@media print { svg { min-width: 0 !important; } }",
  ].join("\n");

  function enhanceDiagram(host) {
    var root = host.shadowRoot;
    var svg = root && root.querySelector("svg");
    if (!svg || host.hasAttribute("data-diagram")) return;

    var style = document.createElement("style");
    style.textContent = DIAGRAM_FIXES;
    root.appendChild(style);

    /* Mermaid states the natural width as an inline max-width. */
    var natural = parseFloat(svg.style.maxWidth) || (svg.viewBox && svg.viewBox.baseVal.width) || 0;

    var kind = DIAGRAM_KINDS[svg.getAttribute("aria-roledescription")] || "Diagram";
    host.setAttribute("data-diagram", kind);
    trackScroll(host, kind + ", scrolls sideways", svg, {
      fit: function () {
        var tooSmall = natural && host.clientWidth < natural * FIT_SCALE;
        svg.style.minWidth = tooSmall ? Math.round(natural * SCROLL_SCALE) + "px" : "";
      },
    });

    /* A top-down flowchart starts from a node in the middle of its width.  If
       the diagram scrolls and that first node is out of view, start there
       rather than on the empty corner to its left. */
    var first = svg.querySelector(".node");
    if (first && host.scrollWidth > host.clientWidth + 1) {
      var box = first.getBoundingClientRect();
      var frame = host.getBoundingClientRect();
      if (box.right > frame.right) host.scrollLeft = box.left + box.width / 2 - frame.left - host.clientWidth / 2;
    }
  }

  function enhanceDiagrams(scope) {
    var hosts = scope.querySelectorAll("div.mermaid:not([data-diagram])");
    for (var i = 0; i < hosts.length; i++) enhanceDiagram(hosts[i]);
  }

  /* ================================================================ */
  /*  Wiring                                                           */
  /* ================================================================ */

  function run() {
    markBreaks(document);
    enhanceTables(document);
    enhanceDiagrams(document);
  }

  /* One observer covers every way content arrives: the first load, instant
     navigation swapping the article, the theme wrapping each table, and
     Mermaid replacing each code fence with its drawing some time later.
     Every pass skips what it has already handled, so the pass caused by its
     own <wbr> insertions finds nothing to do and the loop ends there. */
  if (typeof document === "undefined" || !window.MutationObserver) return;
  new window.MutationObserver(run).observe(document.documentElement, { childList: true, subtree: true });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
  else run();
})();
