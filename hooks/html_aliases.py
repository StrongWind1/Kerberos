"""Emit legacy ``<page>.html`` aliases beside every directory URL.

This site used to build with ``use_directory_urls`` disabled. That was not a
deliberate choice - it is a side effect of Material's ``offline`` plugin, which
forces the setting off so the docs can be browsed straight off a filesystem. The
consequence was that every page published at ``<path>.html`` while the other nine
sites under strongwind.dev published directory URLs, and those ``.html`` paths are
now sitting in search indexes and in other people's links.

Dropping ``offline`` puts this site on directory URLs like its siblings. To avoid
404ing the old paths, this hook writes a small redirect stub at each one after the
build. GitHub Pages serves static files only - there is no server-side redirect to
reach for - so an instant client-side redirect plus a canonical link is the
strongest signal available. Google treats an instant meta refresh as a permanent
redirect.

The stub redirects from script first, because only script can see the rest of the
address: ``location.replace`` carries the query string and the fragment across, so an
old deep link such as ``rc4-deprecation.html#timeline`` or a shared calculator link
(``etype-calculator.html?setting=msds&value=0x1C``) still lands where it pointed. A
meta refresh cannot do that - its target is fixed text - so it is kept only as the
fallback for readers and crawlers without script, inside ``<noscript>``; left outside,
it would race the script and could win, dropping the fragment again.

``mkdocs-redirects`` cannot do this job: its ``get_html_path()`` routes every
non-index page to ``<name>/index.html`` when ``use_directory_urls`` is on, so it
has no way to emit a file at ``<name>.html``.

Stubs are written in ``on_post_build``, after ``sitemap.xml`` has been rendered from
the page list, so they never enter the sitemap.

Delete this hook once the legacy URLs have aged out of search results.
"""

from __future__ import annotations

import html
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mkdocs.config.defaults import MkDocsConfig

log = logging.getLogger("mkdocs.hooks.html_aliases")

# The redirect target is relative so the stub also works under `mkdocs serve` and
# in a locally opened build; the canonical must be absolute per the sitemap spec.
# {script_target} is the same target as a JavaScript string literal.
_STUB = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Redirecting</title>
    <link rel="canonical" href="{canonical}">
    <script>location.replace({script_target} + location.search + location.hash);</script>
    <noscript><meta http-equiv="refresh" content="0; url={target}"></noscript>
  </head>
  <body>
    <p>This page has moved to <a href="{target}">{canonical}</a>.</p>
  </body>
</html>
"""


def on_post_build(config: MkDocsConfig, **kwargs: Any) -> None:  # noqa: ARG001
    """Write a ``<name>.html`` redirect beside every ``<name>/index.html``.

    Runs over the built output rather than a hardcoded page map, so it keeps
    working as pages are added, renamed or removed.
    """
    site_dir = Path(config.site_dir)
    site_url = (config.site_url or "").rstrip("/")

    written = 0
    for index_file in sorted(site_dir.rglob("index.html")):
        page_dir = index_file.parent
        # The site root is served directly; there is no path above it to alias.
        if page_dir == site_dir:
            continue

        # Build the sibling name by hand - with_suffix() would mangle any
        # directory whose name already contains a dot.
        alias = page_dir.parent / f"{page_dir.name}.html"
        # Never clobber a real page that legitimately owns this path.
        if alias.exists():
            continue

        relative = page_dir.relative_to(site_dir).as_posix()
        target = f"{page_dir.name}/"
        alias.write_text(
            _STUB.format(
                target=html.escape(target),
                # json.dumps gives a valid JS string literal; "</" cannot end the script.
                script_target=json.dumps(target).replace("</", "<\\/"),
                canonical=html.escape(f"{site_url}/{relative}/"),
            ),
            encoding="utf-8",
        )
        written += 1

    log.info("html_aliases: wrote %d legacy .html redirect(s)", written)
