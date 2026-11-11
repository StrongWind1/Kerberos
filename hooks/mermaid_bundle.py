"""Correct two things in the theme's script bundle that concern Mermaid diagrams.

The Material theme draws ``mermaid`` code fences in the browser. Its bundle fetches the
Mermaid library the first time a page contains a diagram, renders each diagram to SVG
and places the SVG in a shadow tree. Two details of that are wrong for this site, and
neither has a configuration switch, so the built bundle is corrected here.

1. **Where the library is loaded from.** The ``privacy`` plugin downloads Mermaid at
   build time and rewrites the bundle to point at the copy -- as an absolute URL made
   from ``site_url``. Every build that is not served from the production host (a local
   preview, a pull-request preview, a fork) therefore fetches the library from the live
   site, cross-origin. The URL is rewritten to resolve against ``__md_scope``, the
   site root the theme computes on every page, so the copy beside the page is used.

2. **The shadow tree is closed.** The theme's own diagram stylesheet lives inside that
   tree and nothing outside can add to it, which leaves no way to correct the colours
   it gets wrong (sequence-diagram arrowheads, for one), to read a diagram's natural
   width, or to give a wide diagram a scroll container. The mode is changed to
   ``open``; ``content/javascripts/layout.js`` does the rest.

Each correction must match exactly once. If the theme or the plugin changes the text,
the hook logs a warning -- which fails a ``--strict`` build -- rather than silently
shipping an uncorrected bundle.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mkdocs.config.defaults import MkDocsConfig

log = logging.getLogger("mkdocs.hooks.mermaid_bundle")

_CLOSED = 'attachShadow({mode:"closed"})'
_OPEN = 'attachShadow({mode:"open"})'
# What a corrected library URL looks like; a bundle that already has it (a rebuild into
# the same directory under `mkdocs serve`) is left alone without a warning.
_RELATIVE = re.compile(r'new URL\("assets/external/[^"]*?mermaid[^"]*?\.js",__md_scope\)')


def _library_url(site_url: str) -> re.Pattern[str]:
    """Match the quoted absolute URL of the local Mermaid copy; group 1 is its site path."""
    return re.compile(r'"' + re.escape(site_url) + r'(assets/external/[^"]*?mermaid[^"]*?\.js)"')


def patch(script: str, site_url: str) -> tuple[str, list[str]]:
    """Return the corrected bundle text and a list of corrections that did not apply."""
    missed: list[str] = []

    script, count = _library_url(site_url).subn(r'new URL("\1",__md_scope)', script)
    if count != 1 and not _RELATIVE.search(script):
        missed.append(f"the Mermaid library URL (matched {count} time(s))")

    count = script.count(_CLOSED)
    if count == 1:
        script = script.replace(_CLOSED, _OPEN)
    elif _OPEN not in script:
        missed.append(f"the diagram shadow root (matched {count} time(s))")

    return script, missed


def on_post_build(config: MkDocsConfig, **kwargs: Any) -> None:  # noqa: ARG001
    """Patch the bundle in the built site, after the ``privacy`` plugin has written it."""
    # Without a site_url the plugin writes the path with no prefix at all.
    site_url = config.site_url.rstrip("/") + "/" if config.site_url else ""
    bundles = sorted(Path(config.site_dir).glob("assets/javascripts/bundle.*.min.js"))
    if len(bundles) != 1:
        log.warning("mermaid_bundle: expected one theme bundle, found %d", len(bundles))
        return

    original = bundles[0].read_text(encoding="utf-8")
    patched, missed = patch(original, site_url)
    for what in missed:
        log.warning("mermaid_bundle: could not correct %s in %s", what, bundles[0].name)
    if patched != original:
        bundles[0].write_text(patched, encoding="utf-8")
