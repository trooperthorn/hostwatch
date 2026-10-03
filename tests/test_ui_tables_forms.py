"""Filter forms and tables: static checks on the shipped CSS, markup and script.

The page is static and has no browser test harness, so these checks read the shipped files. They cover
the stacked-label grid, sticky headers, zebra and hover rules, monospace classes, HTTP status badges,
the Audit log detail format, the empty state and the absence of inline styles (the CSP forbids them).
"""

from __future__ import annotations

import re
from importlib.resources import files


def text(name):
    return files("hostwatch").joinpath("web", name).read_text(encoding="utf-8")


def test_css_filter_grid_with_stacked_labels():
    css = text("app.css")
    assert re.search(r"\.filters \{[^}]*grid-template-columns: repeat\(auto-fit, minmax\(", css)
    assert re.search(r"\.filters \.field \{[^}]*flex-direction: column", css)
    assert re.search(r"\.filters input\[type=\"text\"\], \.filters select \{[^}]*height: 2\.5rem", css)
    assert re.search(r"\.filters \.form-action \{[^}]*height: 2\.5rem", css)


def test_css_table_rules():
    css = text("app.css")
    assert re.search(r"thead th[^{]*\{[^}]*position: sticky; top: 0", css)
    assert re.search(r"thead th[^{]*\{[^}]*background: var\(--surface\)[^}]*border-bottom: 2px", css)
    assert "tbody tr:nth-child(even)" in css and "tbody tr:hover" in css
    assert re.search(r"\.num[^{]*\{[^}]*text-align: right", css)
    assert re.search(r"\.mono[^{]*\{[^}]*monospace", css)
    for kind in ("2xx", "4xx", "5xx"):
        assert f".http-{kind} {{" in css


def test_every_filter_control_sits_in_a_field_with_its_label():
    html = text("index.html")
    for fid in ("f-host", "f-source", "f-kind", "f-since", "a-kind", "a-actor", "a-since", "h-series", "h-range"):
        assert re.search(rf'<div class="field">\s*<label for="{fid}">[^<]+</label>\s*<(input|select) id="{fid}"', html)


def test_script_renders_http_badge_and_compact_detail_as_text():
    js = text("app.js")
    assert "innerHTML" not in js
    assert 'badge.appendChild(document.createTextNode(String(code) + " " + word))' in js
    assert '"http-badge http-" + kind' in js
    assert 'k + ": " +' in js and 'join(", ")' in js
    assert re.search(r'el\("td", detailText\(r\.detail\)', js)
    assert "JSON.stringify(r.detail)" not in js


def test_empty_state_and_load_more_markup():
    html = text("index.html")
    js = text("app.js")
    assert 'id="audit-empty" class="empty-state" hidden>No audit rows match these filters.' in html
    assert 'byId("audit-empty").hidden = body.children.length !== 0' in js
    assert 'id="audit-more" class="more" hidden' in html


def test_no_inline_styles_in_shipped_html_or_script():
    html = text("index.html")
    assert not re.search(r"\sstyle\s*=", html)
    assert ".style." not in text("app.js") and "setAttribute(\"style\"" not in text("app.js")
