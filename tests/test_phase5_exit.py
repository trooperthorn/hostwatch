"""Phase 5 exit criteria: a degraded or crash state is obvious, worst first, in colour and in text.

The 5-second criterion itself needs a real browser and is recorded in UNVERIFIED.md. What can be
proved here is that the data the page renders puts the worst host first with a text label, and that
the page shows the banner before the tiles and renders the text and a state class for every tile.
The test also checks that the web assets are part of the installed package data.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from importlib.resources import files
from pathlib import Path

from test_ui_status import build, login, seed

ROOT = Path(__file__).resolve().parent.parent


def web(name):
    return files("hostwatch").joinpath("web", name).read_text(encoding="utf-8")


def test_degraded_host_is_first_and_labelled_in_text(tmp_path):
    client, store = build(tmp_path)
    for name in ("aaa-ok", "bbb-ok", "ccc-warn"):
        seed(store, name, missing=("hwmon",) if name == "ccc-warn" else ())
    seed(store, "zzz-degraded", degraded=1)
    login(client)
    doc = client.get("/api/v1/ui/status").json()
    first = doc["hosts"][0]
    assert first["host"] == "zzz-degraded"
    assert first["status"] == 2 and first["status_text"] == "Critical"
    assert doc["banner"]["host"] == "zzz-degraded"
    assert "Critical" in doc["banner"]["text"] and "zzz-degraded" in doc["banner"]["text"]
    assert [h["status_text"] for h in doc["hosts"]][:2] == ["Critical", "Warning"]
    assert any(r["state_text"] == "Critical" for r in first["raid"])


def test_page_shows_banner_before_tiles_and_renders_text_and_class():
    html = web("index.html")
    assert html.index('id="banner"') < html.index('id="tiles"')
    js = web("app.js")
    assert "h.status_text" in js and "textContent" in js
    assert "classList" in js or "className" in js
    css = web("app.css")
    assert re.search(r"prefers-color-scheme:\s*dark", css)


def test_installed_package_contains_web_assets():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = data["tool"]["setuptools"]["package-data"]["hostwatch"]
    shipped = {p.name for p in (ROOT / "hostwatch" / "web").iterdir()
               if any(fnmatch.fnmatch(f"web/{p.name}", pat) for pat in patterns)}
    assert {"index.html", "app.css", "app.js"} <= shipped
    for name in ("index.html", "app.css", "app.js"):
        assert files("hostwatch").joinpath("web", name).is_file()
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY hostwatch ./hostwatch" in dockerfile and "pip install --no-cache-dir ." in dockerfile
