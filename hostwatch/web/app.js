"use strict";
(function () {
  var CSRF_COOKIE = "hostwatch_csrf";
  var csrfToken = "";

  function byId(id) { return document.getElementById(id); }

  function readCookie(name) {
    var parts = document.cookie.split("; ");
    for (var i = 0; i < parts.length; i++) {
      var eq = parts[i].indexOf("=");
      if (eq > 0 && parts[i].slice(0, eq) === name) { return decodeURIComponent(parts[i].slice(eq + 1)); }
    }
    return "";
  }

  var refreshTimer = null;

  function el(tag, text, cls) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    if (cls) { node.className = cls; }
    return node;
  }

  // Every state, order and text below comes from /api/v1/ui/status. Nothing here compares a
  // value to a limit or decides what is healthy.
  function describe(c) {
    var text = c.name + ": ";
    if (c.value !== null && c.value !== undefined) { text += c.value + " " + c.unit + " "; }
    return text + "(" + c.state_text + ")" + (c.reason ? " " + c.reason : "");
  }

  function addList(tile, title, items) {
    tile.appendChild(el("h4", title));
    var list = el("ul");
    items.forEach(function (c) {
      list.appendChild(el("li", describe(c), "st-" + c.state));
    });
    tile.appendChild(list);
  }

  function renderTile(h) {
    var tile = el("article", null, "tile");
    tile.setAttribute("data-status", String(h.status));
    var head = el("h3");
    head.appendChild(el("span", h.host));
    head.appendChild(el("span", h.status_text, "badge badge-head"));
    tile.appendChild(head);
    if (h.reason) { tile.appendChild(el("p", h.reason)); }
    if (h.disappeared.length) { tile.appendChild(el("p", "Disappeared: " + h.disappeared.join(", "), "st-critical")); }
    if (h.not_present.length) { tile.appendChild(el("p", "Not present: " + h.not_present.join(", "), "st-not_present")); }
    if (h.last_seen !== null) { tile.appendChild(el("p", "Last seen " + new Date(h.last_seen * 1000).toLocaleString(), "muted")); }
    addList(tile, "CPU", [h.cpu]);
    addList(tile, "Memory", [h.memory]);
    addList(tile, "Power", [h.power]);
    addList(tile, "Temperatures", h.temperatures);
    addList(tile, "RAID", h.raid);
    addList(tile, "Pools", h.pools);
    addList(tile, "Disks", h.disks);
    addList(tile, "Sources", h.sources);
    return tile;
  }

  function render(doc) {
    var banner = byId("banner");
    banner.setAttribute("data-status", String(doc.banner.status));
    byId("banner-badge").textContent = doc.banner.status_text;
    byId("banner-text").textContent = doc.banner.text;
    var tiles = byId("tiles");
    while (tiles.firstChild) { tiles.removeChild(tiles.firstChild); }
    doc.hosts.forEach(function (h) { tiles.appendChild(renderTile(h)); });
    byId("refresh-note").textContent = "Updated " + new Date(doc.generated * 1000).toLocaleTimeString() +
      ". Refreshes every " + doc.refresh_s + " seconds.";
    return doc.refresh_s;
  }

  function stopRefresh() {
    if (refreshTimer !== null) { clearTimeout(refreshTimer); refreshTimer = null; }
  }

  function refresh() {
    stopRefresh();
    var wait = doc_refresh_default();
    fetch("/api/v1/ui/status", { credentials: "same-origin" }).then(function (resp) {
      if (resp.status === 401) { show(false, ""); return null; }
      if (!resp.ok) { throw new Error("status " + resp.status); }
      return resp.json();
    }).then(function (doc) {
      if (doc) { wait = render(doc); refreshTimer = setTimeout(refresh, wait * 1000); }
    }).catch(function () {
      byId("banner").setAttribute("data-status", "2");
      byId("banner-badge").textContent = "Unreachable";
      byId("banner-text").textContent = "The hub could not be reached. The tiles below may be out of date.";
      refreshTimer = setTimeout(refresh, wait * 1000);
    });
  }

  function doc_refresh_default() { return 15; }

  // Event timeline. Filtering and paging are done by GET /internal/v1/events; the page passes
  // the filters through and follows the X-Next-Before cursor headers it returns.
  var EVENT_PAGE = 50;
  var nextCursor = null;

  function eventParams(cursor) {
    var q = new URLSearchParams();
    ["host", "source", "kind"].forEach(function (name) {
      var v = byId("f-" + name).value.trim();
      if (v) { q.set(name, v); }
    });
    var span = Number(byId("f-since").value);
    if (span > 0) { q.set("since", String(Date.now() / 1000 - span)); }
    q.set("limit", String(EVENT_PAGE));
    if (cursor) { q.set("before", cursor.before); q.set("before_id", cursor.id); }
    return q.toString();
  }

  function eventRow(e) {
    var tr = el("tr");
    tr.tabIndex = -1;
    tr.setAttribute("data-severity", String(e.severity));
    tr.appendChild(el("td", new Date(e.ts * 1000).toLocaleString()));
    tr.appendChild(el("td", e.host));
    tr.appendChild(el("td", e.source));
    tr.appendChild(el("td", e.kind));
    tr.appendChild(el("td", e.severity, "sev-" + String(e.severity).replace(/[^a-z]/g, "")));
    tr.appendChild(el("td", e.title));
    return tr;
  }

  function loadEvents(append) {
    var body = byId("events-body");
    var note = byId("events-note");
    var cursor = append ? nextCursor : null;
    fetch("/internal/v1/events?" + eventParams(cursor), { credentials: "same-origin" }).then(function (resp) {
      if (resp.status === 401) { show(false, ""); return null; }
      if (!resp.ok) { throw new Error("status " + resp.status); }
      var before = resp.headers.get("X-Next-Before");
      var id = resp.headers.get("X-Next-Before-Id");
      nextCursor = before !== null && id !== null ? { before: before, id: id } : null;
      return resp.json();
    }).then(function (rows) {
      if (!rows) { return; }
      if (!append) { while (body.firstChild) { body.removeChild(body.firstChild); } }
      rows.forEach(function (e) { body.appendChild(eventRow(e)); });
      if (body.firstChild && !append) { body.firstChild.tabIndex = 0; }
      byId("events-more").hidden = nextCursor === null;
      note.textContent = body.children.length ? body.children.length + " events shown." : "No events match these filters.";
    }).catch(function () { note.textContent = "The events could not be loaded."; });
  }

  function onEventKey(event) {
    var rows = Array.prototype.slice.call(byId("events-body").children);
    var i = rows.indexOf(document.activeElement);
    if (i < 0) { return; }
    var to = -1;
    if (event.key === "ArrowDown") { to = Math.min(i + 1, rows.length - 1); }
    else if (event.key === "ArrowUp") { to = Math.max(i - 1, 0); }
    else if (event.key === "Home") { to = 0; }
    else if (event.key === "End") { to = rows.length - 1; }
    if (to < 0) { return; }
    event.preventDefault();
    rows[i].tabIndex = -1;
    rows[to].tabIndex = 0;
    rows[to].focus();
  }

  // History chart. Data comes from GET /api/v1/hosts/{host}/history (raw samples for short
  // ranges, hourly rollups for long ones, chosen by the hub) and gaps from /internal/v1/gaps.
  // The SVG is built with createElementNS and every label is set with textContent.
  var SVG_NS = "http://www.w3.org/2000/svg";
  var W = 720, H = 300, PAD_L = 60, PAD_R = 12, PAD_T = 12, PAD_B = 28;

  function svg(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, String(attrs[k])); });
    return node;
  }

  function svgText(x, y, text, anchor) {
    var t = svg("text", { x: x, y: y, "text-anchor": anchor || "middle", "class": "label" });
    t.textContent = text;
    return t;
  }

  function seriesName(s) {
    var keys = Object.keys(s.labels || {});
    return keys.length ? keys.map(function (k) { return k + "=" + s.labels[k]; }).join(", ") : "all";
  }

  function fmt(v) { return v === null || v === undefined ? "n/a" : String(Math.round(v * 100) / 100); }

  function buildChart(doc, gaps) {
    var lo = Infinity, hi = -Infinity;
    doc.series.forEach(function (s) {
      s.points.forEach(function (p) { lo = Math.min(lo, p.min); hi = Math.max(hi, p.max); });
    });
    if (lo === hi) { lo -= 1; hi += 1; }
    var t0 = doc.since, t1 = doc.until;
    function x(t) { return PAD_L + (t - t0) / (t1 - t0) * (W - PAD_L - PAD_R); }
    function y(v) { return PAD_T + (hi - v) / (hi - lo) * (H - PAD_T - PAD_B); }
    var root = svg("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-labelledby": "chart-t chart-d" });
    var title = svg("title", { id: "chart-t" });
    title.textContent = doc.metric + " on " + doc.host + " (" + doc.source + ")";
    var desc = svg("desc", { id: "chart-d" });
    desc.textContent = "Line chart of the average " + doc.metric + " in " + (doc.unit || "no unit") +
      ", from " + fmt(lo) + " to " + fmt(hi) + ", with " + gaps.length + " gaps. The same values are in the table below.";
    root.appendChild(title);
    root.appendChild(desc);
    [0, 0.25, 0.5, 0.75, 1].forEach(function (f) {
      var v = lo + (hi - lo) * f;
      root.appendChild(svg("line", { x1: PAD_L, x2: W - PAD_R, y1: y(v), y2: y(v), "class": "grid" }));
      root.appendChild(svgText(PAD_L - 4, y(v) + 4, fmt(v), "end"));
    });
    [0, 0.5, 1].forEach(function (f) {
      var t = t0 + (t1 - t0) * f;
      root.appendChild(svgText(x(t), H - 8, new Date(t * 1000).toLocaleString(), f === 0 ? "start" : (f === 1 ? "end" : "middle")));
    });
    gaps.forEach(function (g) {
      var a = Math.max(x(g[0]), PAD_L), b = Math.min(x(g[1]), W - PAD_R);
      if (b > a) { root.appendChild(svg("rect", { x: a, y: PAD_T, width: b - a, height: H - PAD_T - PAD_B, "class": "gap" })); }
    });
    root.appendChild(svg("line", { x1: PAD_L, x2: PAD_L, y1: PAD_T, y2: H - PAD_B, "class": "axis" }));
    root.appendChild(svg("line", { x1: PAD_L, x2: W - PAD_R, y1: H - PAD_B, y2: H - PAD_B, "class": "axis" }));
    doc.series.forEach(function (s, i) {
      var cls = "s" + (i % 5);
      var avg = s.points.map(function (p) { return x(p.ts) + "," + y(p.avg); }).join(" ");
      var upper = s.points.map(function (p) { return x(p.ts) + "," + y(p.max); });
      var lower = s.points.map(function (p) { return x(p.ts) + "," + y(p.min); }).reverse();
      if (s.points.length > 1) {
        root.appendChild(svg("polygon", { points: upper.concat(lower).join(" "), "class": "band " + cls }));
        root.appendChild(svg("polyline", { points: avg, "class": "line " + cls }));
      } else if (s.points.length === 1) {
        root.appendChild(svg("circle", { cx: x(s.points[0].ts), cy: y(s.points[0].avg), r: 3, "class": cls }));
      }
    });
    return root;
  }

  function fillTable(doc, gaps) {
    var body = byId("history-body");
    while (body.firstChild) { body.removeChild(body.firstChild); }
    doc.series.forEach(function (s) {
      var name = seriesName(s);
      s.points.forEach(function (p) {
        var tr = el("tr");
        [new Date(p.ts * 1000).toLocaleString(), name, fmt(p.min), fmt(p.avg), fmt(p.max), p.n].forEach(function (v) {
          tr.appendChild(el("td", v));
        });
        body.appendChild(tr);
      });
    });
    byId("history-caption").textContent = "Values for " + doc.metric + " (" + (doc.unit || "no unit") + ") on " +
      doc.host + ", " + doc.resolution + " data in steps of " + doc.step + " seconds.";
    byId("history-table").hidden = body.children.length === 0;
    var list = byId("history-gaps");
    while (list.firstChild) { list.removeChild(list.firstChild); }
    gaps.forEach(function (g) {
      list.appendChild(el("li", "No data from " + new Date(g[0] * 1000).toLocaleString() + " to " +
        new Date(g[1] * 1000).toLocaleString() + "."));
    });
    if (!gaps.length) { list.appendChild(el("li", "No gaps in this range.")); }
  }

  function loadSeries() {
    var pick = byId("h-series");
    fetch("/internal/v1/latest", { credentials: "same-origin" }).then(function (resp) {
      if (resp.status === 401) { show(false, ""); return null; }
      if (!resp.ok) { throw new Error("status " + resp.status); }
      return resp.json();
    }).then(function (rows) {
      if (!rows) { return; }
      var seen = {};
      while (pick.firstChild) { pick.removeChild(pick.firstChild); }
      rows.forEach(function (r) {
        var key = JSON.stringify([r.host, r.source, r.metric]);
        if (seen[key]) { return; }
        seen[key] = true;
        var o = el("option", r.host + " / " + r.source + " / " + r.metric);
        o.value = key;
        pick.appendChild(o);
      });
      byId("history-note").textContent = pick.children.length ? "" : "No metrics have been recorded yet.";
    }).catch(function () { byId("history-note").textContent = "The metric list could not be loaded."; });
  }

  function loadHistory() {
    var note = byId("history-note");
    var pick = byId("h-series").value;
    if (!pick) { note.textContent = "Choose a series first."; return; }
    var sel = JSON.parse(pick);
    var span = Number(byId("h-range").value);
    var until = Date.now() / 1000;
    var hq = new URLSearchParams({ source: sel[1], metric: sel[2], since: String(until - span), until: String(until) });
    var step = Math.max(60, span / 300);
    var gq = new URLSearchParams({ host: sel[0], source: sel[1], metric: sel[2], hours: String(span / 3600),
                                   max_gap_s: String(Math.max(120, step * 2)) });
    note.textContent = "Loading.";
    Promise.all([
      fetch("/api/v1/hosts/" + encodeURIComponent(sel[0]) + "/history?" + hq.toString(), { credentials: "same-origin" }),
      fetch("/internal/v1/gaps?" + gq.toString(), { credentials: "same-origin" })
    ]).then(function (resps) {
      if (resps[0].status === 401 || resps[1].status === 401) { show(false, ""); return null; }
      if (!resps[0].ok || !resps[1].ok) { throw new Error("status"); }
      return Promise.all([resps[0].json(), resps[1].json()]);
    }).then(function (docs) {
      if (!docs) { return; }
      var chart = byId("history-chart");
      while (chart.firstChild) { chart.removeChild(chart.firstChild); }
      var hist = docs[0], gaps = docs[1].gaps;
      fillTable(hist, gaps);
      if (!hist.series.length) { note.textContent = "No samples in this range."; return; }
      chart.appendChild(buildChart(hist, gaps));
      note.textContent = "Showing " + hist.resolution + " data, " + gaps.length + " gaps.";
    }).catch(function () { note.textContent = "The history could not be loaded."; });
  }

  function selectView(name) {
    var events = name === "events";
    var history = name === "history";
    byId("status-panel").hidden = events || history;
    byId("events-panel").hidden = !events;
    byId("history-panel").hidden = !history;
    byId("tab-status").setAttribute("aria-pressed", String(!events && !history));
    byId("tab-events").setAttribute("aria-pressed", String(events));
    byId("tab-history").setAttribute("aria-pressed", String(history));
    if (events) { loadEvents(false); }
    if (history) { loadSeries(); }
  }

  function show(signedIn, username) {
    if (!signedIn) { stopRefresh(); }
    byId("login-view").hidden = signedIn;
    byId("app-view").hidden = !signedIn;
    byId("logout").hidden = !signedIn;
    byId("app-user").textContent = signedIn ? "Signed in as " + username + "." : "";
    byId(signedIn ? "main" : "username").focus();
    if (signedIn) { refresh(); }
  }

  // State-changing requests carry the CSRF token in a header. The session cookie is HttpOnly
  // and never read here.
  function apiPost(path, body) {
    var headers = { "Content-Type": "application/json", "X-CSRF-Token": csrfToken || readCookie(CSRF_COOKIE) };
    return fetch(path, { method: "POST", headers: headers, credentials: "same-origin",
                         body: body === undefined ? undefined : JSON.stringify(body) });
  }

  function onLogin(event) {
    event.preventDefault();
    var error = byId("login-error");
    error.textContent = "";
    apiPost("/api/v1/login", { username: byId("username").value, password: byId("password").value })
      .then(function (resp) {
        if (!resp.ok) { error.textContent = "Sign in failed. Check the user name and password."; return null; }
        return resp.json();
      })
      .then(function (data) {
        if (!data) { return; }
        csrfToken = data.csrf_token;
        byId("password").value = "";
        show(true, data.username);
      })
      .catch(function () { error.textContent = "The hub could not be reached."; });
  }

  function onLogout() {
    apiPost("/api/v1/logout").then(function () { csrfToken = ""; show(false, ""); });
  }

  function start() {
    byId("login-form").addEventListener("submit", onLogin);
    byId("logout").addEventListener("click", onLogout);
    byId("tab-status").addEventListener("click", function () { selectView("status"); });
    byId("tab-events").addEventListener("click", function () { selectView("events"); });
    byId("tab-history").addEventListener("click", function () { selectView("history"); });
    byId("history-form").addEventListener("submit", function (e) { e.preventDefault(); loadHistory(); });
    byId("events-form").addEventListener("submit", function (e) { e.preventDefault(); loadEvents(false); });
    byId("events-more").addEventListener("click", function () { loadEvents(true); });
    byId("events-body").addEventListener("keydown", onEventKey);
    // An existing session shows the signed-in view; anything else shows the login form.
    fetch("/internal/v1/latest", { credentials: "same-origin" }).then(function (resp) {
      show(resp.ok, resp.ok ? "this session" : "");
    }).catch(function () { show(false, ""); });
  }

  start();
})();
