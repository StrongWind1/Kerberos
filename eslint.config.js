"use strict";

/* Lint config for the two browser tools, their tests, and the Node scripts in tools/.
 *
 * content/javascripts/*.js are plain ES5-style scripts loaded by MkDocs on
 * every page (no bundler, no modules), so they are linted as scripts with
 * only the browser globals they actually use.  tests/js/*.js run under Node.
 */

const browserGlobals = {
  window: "readonly",
  document: "readonly",
  navigator: "readonly",
  history: "readonly",
  location: "readonly",
  console: "readonly",
  setTimeout: "readonly",
  DOMParser: "readonly",
  btoa: "readonly",
  atob: "readonly",
  escape: "readonly",
  unescape: "readonly",
  /* Material for MkDocs: observable that emits after every instant navigation. */
  document$: "readonly",
  /* Present only under Node, where the tools export their pure functions. */
  module: "readonly",
};

const nodeGlobals = {
  require: "readonly",
  module: "writable",
  __dirname: "readonly",
  console: "readonly",
  globalThis: "readonly",
  process: "readonly",
  Buffer: "readonly",
};

const rules = {
  "no-undef": "error",
  "no-unused-vars": ["error", { args: "all", argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
  "no-redeclare": "error",
  "no-shadow": "error",
  "no-throw-literal": "error",
  "no-prototype-builtins": "error",
  "no-useless-escape": "error",
  "no-implicit-globals": "error",
  "no-eval": "error",
  "guard-for-in": "error",
  eqeqeq: "error",
  /* innerHTML with pasted event data would be DOM XSS; the tools build nodes
     with createElement/textContent only. */
  "no-restricted-properties": ["error",
    { property: "innerHTML", message: "Build DOM nodes with createElement/textContent." },
    { property: "outerHTML", message: "Build DOM nodes with createElement/textContent." },
    { property: "insertAdjacentHTML", message: "Build DOM nodes with createElement/textContent." },
  ],
};

module.exports = [
  {
    files: ["content/javascripts/*.js"],
    languageOptions: { ecmaVersion: 2018, sourceType: "script", globals: browserGlobals },
    rules,
  },
  {
    files: ["tests/js/*.js", "tools/*.js", "eslint.config.js"],
    languageOptions: { ecmaVersion: 2022, sourceType: "commonjs", globals: { ...nodeGlobals, URL: "readonly" } },
    rules: { ...rules, "no-restricted-properties": "off" },
  },
];
